/**
 * Prekey Bundle Management for Ilyazh-Web3E2E v0.8
 *
 * Handles:
 * - Generating signed prekey bundles (X25519 + ML-KEM-768)
 * - Uploading to relay server
 * - Fetching peer prekey bundles
 * - Managing prekey secrets in IndexedDB
 */

import {
  generatePrekeyBundle,
  type IdentityKeyPair,
  type PrekeyBundle,
  serializePrekeyBundle,
  toBase64,
  fromBase64,
} from '@ilyazh/crypto';
import * as prim from '@ilyazh/crypto/primitives';
import { keystore } from './keystore';
import { getCryptoOrThrow } from './runtime/crypto-safe';
import { createAuthHeaders } from './identity';
import { getRelayUrl } from './relay-url';

/**
 * Stored prekey secrets (private keys)
 * These are needed to complete the handshake when someone initiates with our bundle
 */
export interface PrekeySecrets {
  bundleId: string;
  x25519SecretKey: Uint8Array;
  mlkemSecretKey: Uint8Array;
  timestamp: number;
}

/**
 * Normalize peer directory response to standard schema
 * Handles variations from relay, proxy, and dev mode
 */
function normalizePeerDirectory(raw: any) {
  if (!raw) return null;

  // NEW relay format: { identityPublicKey, prekeyBundle: { x25519Pub, ... }, prekeySignature }
  const id = raw.identity || {};
  const pk = raw.prekey || raw.prekeyBundle || {};

  return {
    username: raw.username || raw.userId || "peer",
    identity: {
      // Try new format first (identityPublicKey), then old nested format
      identityEd25519: raw.identityPublicKey || id.identityEd25519 || id.ed25519 || id.ed || "",
      identityMLDSA: raw.identityMLDSA || id.identityMLDSA || id["ml-dsa-65"] || id.mldsa || "",
    },
    prekey: {
      bundleId: pk.bundleId || "relay-bundle",
      // Try new format (x25519Pub) and old format (x25519Ephemeral)
      x25519Ephemeral: pk.x25519Pub || pk.x25519Ephemeral || pk.x25519 || pk["x25519-prekey"] || "",
      mlkemPublicKey: pk.pqKemPub || pk.mlkemPublicKey || pk.mlkem768 || pk["ml-kem-768"] || "",
      // Signature comes from top-level prekeySignature field now
      ed25519Signature: raw.prekeySignature || pk.ed25519Signature || pk.ed25519Sig || "",
      mldsaSignature: pk.mldsaSignature || pk.mldsaSig || "",
      timestamp: pk.timestamp || Date.now(),
    },
    dev: raw.dev === true,
  };
}

/**
 * Generate and upload a new SIGNED prekey bundle
 * - Generates ephemeral X25519 + ML-KEM keypairs
 * - Serializes bundle deterministically
 * - Signs with identity Ed25519 private key
 * - Uploads signed bundle to relay /directory/:username
 * - Stores secret keys in IndexedDB
 */
export async function generateAndUploadPrekeyBundle(
  username: string,
  identity: IdentityKeyPair
): Promise<void> {
  // Canonicalize username immediately
  const canonical = (username ?? "").toLowerCase().trim();
  if (!canonical) {
    throw new Error("Username is required");
  }

  console.log('[Prekey] Generating signed prekey bundle', { username, canonical });

  if (!identity?.ed25519?.publicKey || !identity?.ed25519?.secretKey) {
    throw new Error('No local identity to sign prekey bundle');
  }

  // Use polyfilled randomUUID (works in all browsers, including Safari < 15.4)
  const { randomUUID } = getCryptoOrThrow();
  const bundleId = randomUUID();

  // Generate bundle with internal signatures (for old relay endpoints)
  const bundle = await generatePrekeyBundle(identity, bundleId);

  console.log('[Prekey] Generated bundle:', bundleId);
  console.log('[Prekey] - X25519 ephemeral public:', Buffer.from(bundle.x25519Ephemeral).toString('hex').slice(0, 32) + '...');
  console.log('[Prekey] - ML-KEM public key:', Buffer.from(bundle.mlkemPublicKey).toString('hex').slice(0, 32) + '...');

  // Store secret keys in IndexedDB
  const secrets: PrekeySecrets = {
    bundleId: bundle.bundleId,
    x25519SecretKey: bundle.x25519SecretKey,
    mlkemSecretKey: bundle.mlkemSecretKey,
    timestamp: bundle.timestamp,
  };

  await keystore.init();
  await savePrekeySecrets(canonical, secrets);
  console.log('[Prekey] Saved prekey secrets to IndexedDB');

  // NEW: Serialize bundle deterministically and sign with identity key
  const canonicalBundle = serializePrekeyBundle({
    x25519Pub: bundle.x25519Ephemeral,
    pqKemPub: bundle.mlkemPublicKey.length > 0 ? bundle.mlkemPublicKey : undefined,
    pqSigPub: undefined, // No PQ sig key in prekey bundle
  });

  console.log('[Prekey] Serialized bundle for signing, length:', canonicalBundle.length);

  // Sign with identity Ed25519 private key
  const signature = prim.ed25519Sign(canonicalBundle, identity.ed25519.secretKey);
  console.log('[Prekey] Signed bundle with Ed25519, signature length:', signature.length);

  // Upload to NEW endpoint /directory/:username with signature
  const relayBase = getRelayUrl();

  // Build headers - MUST set Content-Type for JSON body
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  // Add Authorization header if we have a token
  const token = typeof window !== 'undefined' ? localStorage.getItem(`jwt_token_${canonical}`) : null;
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${relayBase}/directory/${encodeURIComponent(canonical)}`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      identityEd25519: toBase64(identity.ed25519.publicKey),
      identityMLDSA: toBase64(identity.mldsa.publicKey),
      prekeyBundle: {
        x25519Pub: toBase64(bundle.x25519Ephemeral),
        pqKemPub: bundle.mlkemPublicKey.length > 0 ? toBase64(bundle.mlkemPublicKey) : '',
        pqSigPub: '', // No PQ sig key
      },
      prekeySignature: toBase64(signature),
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    console.error('[Prekey] Failed to upload signed bundle', res.status, text);
    throw new Error('Failed to upload signed prekey bundle');
  }

  const result = await res.json();
  console.log('[Prekey] ✅ Signed prekey bundle uploaded to /directory');
  console.log('[Prekey] Response:', result);
}


/**
 * Fetch a peer's prekey bundle from relay directory
 * ALWAYS uses /api/relay proxy in browser
 */
export async function fetchPeerBundle(username: string, token?: string): Promise<{
  identity: {
    identityEd25519: string;
    identityMLDSA: string;
  };
  prekey: {
    bundleId: string;
    x25519Ephemeral: string;
    mlkemPublicKey: string;
    ed25519Signature: string;
    mldsaSignature: string;
    timestamp: number;
  };
  dev?: boolean;
}> {
  // Canonicalize username immediately
  const canonical = (username ?? "").toLowerCase().trim();
  if (!canonical) {
    throw new Error("Peer username is required");
  }

  console.debug('[Prekey] fetchPeerBundle', { username, canonical });

  const base = getRelayUrl();
  const url = `${base}/directory/${encodeURIComponent(canonical)}`;

  const res = await fetch(url, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  // If proxy synthesized a dev user, it will send 200
  if (res.ok) {
    const raw = await res.json();
    const normalized = normalizePeerDirectory(raw);
    if (!normalized) {
      throw new Error(`Invalid directory response for ${username}`);
    }
    return normalized;
  }

  // if still 404 → real not found
  if (res.status === 404) {
    throw new Error(`User not found: ${canonical}`);
  }

  // if still 503 → show nicer message but DO NOT spam console
  console.warn("[fetchPeerBundle] relay/proxy still returned", res.status, url);
  throw new Error(`Relay/proxy is not reachable for ${canonical}`);
}

/**
 * Load prekey secrets from IndexedDB with MULTI-KEY LOOKUP
 *
 * SECURITY: This function tries multiple canonical keys to find stored secrets.
 * If secrets are not found, it returns null - the caller must regenerate locally.
 * We NEVER try to download private keys from the relay - that would break E2E security.
 *
 * Multi-key lookup handles Clerk ID case variations:
 * 1. Exact username/userId as passed
 * 2. Lowercased version
 * 3. With 'prekey:' prefix
 * 4. Lowercased with prefix
 *
 * Returns first match found, or null if none exist.
 */
export async function loadPrekeySecrets(username: string): Promise<PrekeySecrets | null> {
  await keystore.init();

  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('ilyazh-keystore-v3', 2);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

  // Generate all possible keys to search
  const candidateKeys = generateCanonicalPrekeyKeys(username);

  console.log('[Prekey] loadPrekeySecrets: trying keys', candidateKeys);

  let secrets: any = null;

  // Try each candidate key in order
  for (const key of candidateKeys) {
    const result = await new Promise<any>((resolve, reject) => {
      const tx = db.transaction(['prekeys'], 'readonly');
      const store = tx.objectStore('prekeys');
      const request = store.get(key);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });

    if (result) {
      console.log('[Prekey] Found secrets under key:', key);
      secrets = result;
      break;
    }
  }

  db.close();

  if (!secrets) {
    console.log('[Prekey] No secrets found for any candidate key');
    return null;
  }

  return {
    bundleId: secrets.bundleId,
    x25519SecretKey: new Uint8Array(secrets.x25519SecretKey),
    mlkemSecretKey: new Uint8Array(secrets.mlkemSecretKey),
    timestamp: secrets.timestamp,
  };
}

/**
 * Load prekey secrets with AUTO-REGENERATION fallback
 *
 * SECURITY: If secrets are missing, this will regenerate a NEW bundle locally
 * and publish it to the relay. This is the correct E2E behavior - we NEVER
 * try to "recover" or "download" private keys from the server.
 *
 * Use this in the chat poller where missing secrets should be transparent.
 */
export async function loadPrekeySecretsOrRegenerate(
  username: string,
  identity: IdentityKeyPair
): Promise<PrekeySecrets> {
  // Try to load existing secrets
  let secrets = await loadPrekeySecrets(username);

  if (secrets) {
    return secrets;
  }

  // Secrets not found - regenerate locally
  console.warn(
    '[Prekey][Recovery] Local secrets not found for',
    username,
    '- regenerating and re-publishing...'
  );
  console.warn(
    '[Prekey][Recovery] This is normal E2E behavior - private keys are NEVER downloaded from server'
  );

  // Generate new bundle and upload
  await generateAndUploadPrekeyBundle(username, identity);

  // Load the newly generated secrets
  secrets = await loadPrekeySecrets(username);

  if (!secrets) {
    throw new Error(
      '[Prekey][Recovery] Failed to load secrets after regeneration - this should never happen'
    );
  }

  console.log('[Prekey][Recovery] Successfully regenerated and loaded new secrets');
  return secrets;
}

/**
 * Save prekey secrets to IndexedDB under MULTIPLE canonical keys
 *
 * SECURITY: These are PRIVATE keys that must NEVER be uploaded to the server.
 * They are stored locally only and used to complete incoming handshakes.
 * If missing, we MUST regenerate locally - never try to download from relay.
 *
 * Storage strategy: Save under multiple keys to handle Clerk ID case variations:
 * - Exact username/userId as passed
 * - Lowercased version
 * - With 'prekey:' prefix for canonical storage
 *
 * This prevents "No prekey secrets found" errors when different parts of the app
 * use different casing (Clerk IDs are case-sensitive but relay uses lowercase).
 */
async function savePrekeySecrets(username: string, secrets: PrekeySecrets): Promise<void> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('ilyazh-keystore-v3', 2);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      // Create object stores if they don't exist
      if (!db.objectStoreNames.contains('identities')) {
        db.createObjectStore('identities');
      }
      if (!db.objectStoreNames.contains('sessions')) {
        db.createObjectStore('sessions');
      }
      if (!db.objectStoreNames.contains('prekeys')) {
        db.createObjectStore('prekeys');
      }
      if (!db.objectStoreNames.contains('pendingSessions')) {
        db.createObjectStore('pendingSessions');
      }
    };
  });

  const secretsData = {
    bundleId: secrets.bundleId,
    x25519SecretKey: Array.from(secrets.x25519SecretKey),
    mlkemSecretKey: Array.from(secrets.mlkemSecretKey),
    timestamp: secrets.timestamp,
  };

  // Generate all possible keys for this user
  const canonicalKeys = generateCanonicalPrekeyKeys(username);

  console.log('[Prekey] Saving secrets under keys:', canonicalKeys);

  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(['prekeys'], 'readwrite');
    const store = tx.objectStore('prekeys');

    // Save under all canonical keys
    let completed = 0;
    const total = canonicalKeys.length;

    for (const key of canonicalKeys) {
      const request = store.put(secretsData, key);
      request.onsuccess = () => {
        completed++;
        if (completed === total) resolve();
      };
      request.onerror = () => reject(request.error);
    }
  });

  db.close();
}

/**
 * Generate all possible canonical keys for storing/loading prekey secrets
 * This handles Clerk ID case variations and different formats
 */
function generateCanonicalPrekeyKeys(userId: string): string[] {
  const keys = new Set<string>();

  // Original userId as-is
  keys.add(userId);

  // Lowercased version
  keys.add(userId.toLowerCase());

  // With 'prekey:' prefix (canonical storage)
  keys.add(`prekey:${userId}`);
  keys.add(`prekey:${userId.toLowerCase()}`);

  return Array.from(keys);
}

/**
 * Delete used prekey secrets after handshake completion
 * Should generate a new bundle immediately after
 */
export async function deletePrekeySecrets(username: string): Promise<void> {
  console.log('[Prekey] Deleting used prekey secrets for:', username);

  await keystore.init();

  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('ilyazh-keystore-v3', 2);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(['prekeys'], 'readwrite');
    const store = tx.objectStore('prekeys');
    const request = store.delete(username);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });

  db.close();
}

/**
 * Ensure prekey bundle is published to relay
 * Checks if relay has a valid signed bundle for this user
 * If not, generates and uploads a new signed bundle
 */
export async function ensurePrekeyPublished(
  username: string,
  identity: IdentityKeyPair
): Promise<void> {
  // Canonicalize username immediately
  const canonical = (username ?? "").toLowerCase().trim();
  if (!canonical) {
    throw new Error("Username is required");
  }

  console.log('[Prekey] ensurePrekeyPublished', { username, canonical });

  const base = getRelayUrl();

  // 1) Try to fetch existing entry from relay
  try {
    const res = await fetch(`${base}/directory/${encodeURIComponent(canonical)}`, {
      method: 'GET',
    });

    if (res.ok) {
      const existing = await res.json();

      // Check if it's really ours and has a signature
      const sameIdentity =
        existing.identityPublicKey &&
        existing.identityPublicKey === Buffer.from(identity.ed25519.publicKey).toString('base64');

      const hasSignature = !!existing.prekeySignature;

      if (sameIdentity && hasSignature) {
        console.log('[Prekey] ✅ Prekey bundle already published');
        return;
      }

      console.log('[Prekey] Existing entry invalid or missing signature, will re-publish');
    }
  } catch (err) {
    console.log('[Prekey] No existing entry or error fetching, will publish new one');
  }

  // 2) Generate new bundle with signatures
  console.log('[Prekey] Generating new prekey bundle...');
  await generateAndUploadPrekeyBundle(canonical, identity);
  console.log('[Prekey] ✅ Prekey bundle published successfully');
}
