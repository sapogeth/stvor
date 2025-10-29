/**
 * Prekey Bundle Management for Ilyazh-Web3E2E v0.8
 *
 * Handles:
 * - Generating signed prekey bundles (X25519 + ML-KEM-768)
 * - Uploading to relay server
 * - Fetching peer prekey bundles
 * - Managing prekey secrets in IndexedDB
 */

import { generatePrekeyBundle, type IdentityKeyPair, type PrekeyBundle } from '@ilyazh/crypto';
import { keystore } from './keystore';
import { getCryptoOrThrow } from './runtime/crypto-safe';
import { createAuthHeaders } from './identity';

const RELAY_URL = process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';

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
 * Generate and upload a new prekey bundle
 * - Generates ephemeral X25519 + ML-KEM keypairs
 * - Signs with identity keys (Ed25519 + ML-DSA-65)
 * - Uploads public bundle to relay
 * - Stores secret keys in IndexedDB
 */
export async function generateAndUploadPrekeyBundle(
  username: string,
  identity: IdentityKeyPair
): Promise<void> {
  console.log('[Prekey] Generating prekey bundle for:', username);

  // Use polyfilled randomUUID (works in all browsers, including Safari < 15.4)
  const { randomUUID } = getCryptoOrThrow();
  const bundleId = randomUUID();

  // Generate bundle with signatures
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
  await savePrekeySecrets(username, secrets);
  console.log('[Prekey] Saved prekey secrets to IndexedDB');

  // Upload public bundle to relay
  try {
    await uploadPrekeyBundle(username, bundle);
    console.log('[Prekey] Uploaded prekey bundle to relay');
  } catch (err) {
    console.error('[Prekey] Failed to upload bundle:', err);
    throw err;
  }
}

/**
 * Upload prekey bundle to relay server
 */
async function uploadPrekeyBundle(username: string, bundle: PrekeyBundle): Promise<void> {
  const response = await fetch(`${RELAY_URL}/prekey-bundle`, {
    method: 'POST',
    headers: createAuthHeaders(username), // SECURITY: Use JWT authentication
    body: JSON.stringify({
      userId: username,
      bundleId: bundle.bundleId,
      x25519Ephemeral: Buffer.from(bundle.x25519Ephemeral).toString('base64'),
      mlkemPublicKey: Buffer.from(bundle.mlkemPublicKey).toString('base64'),
      ed25519Signature: Buffer.from(bundle.ed25519Signature).toString('base64'),
      mldsaSignature: Buffer.from(bundle.mldsaSignature).toString('base64'),
      timestamp: bundle.timestamp,
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to upload prekey bundle: ${response.status} - ${error}`);
  }
}

/**
 * Fetch a peer's prekey bundle from relay directory
 */
export async function fetchPeerBundle(username: string): Promise<{
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
}> {
  console.log('[Prekey] Fetching peer bundle for:', username);

  const response = await fetch(`${RELAY_URL}/directory/${username}`);

  if (!response.ok) {
    throw new Error(`User not found: ${username}`);
  }

  const data = await response.json();

  if (!data.prekey) {
    throw new Error(`No prekey bundle found for user: ${username}`);
  }

  console.log('[Prekey] Fetched peer bundle:', data.prekey.bundleId);

  return data;
}

/**
 * Load prekey secrets from IndexedDB
 */
export async function loadPrekeySecrets(username: string): Promise<PrekeySecrets | null> {
  await keystore.init();

  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('ilyazh-keystore-v3', 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

  const secrets = await new Promise<any>((resolve, reject) => {
    const tx = db.transaction(['prekeys'], 'readonly');
    const store = tx.objectStore('prekeys');
    const request = store.get(username);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

  db.close();

  if (!secrets) {
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
 * Save prekey secrets to IndexedDB
 */
async function savePrekeySecrets(username: string, secrets: PrekeySecrets): Promise<void> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('ilyazh-keystore-v3', 1);
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
    };
  });

  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(['prekeys'], 'readwrite');
    const store = tx.objectStore('prekeys');
    const request = store.put({
      bundleId: secrets.bundleId,
      x25519SecretKey: Array.from(secrets.x25519SecretKey),
      mlkemSecretKey: Array.from(secrets.mlkemSecretKey),
      timestamp: secrets.timestamp,
    }, username);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });

  db.close();
}

/**
 * Delete used prekey secrets after handshake completion
 * Should generate a new bundle immediately after
 */
export async function deletePrekeySecrets(username: string): Promise<void> {
  console.log('[Prekey] Deleting used prekey secrets for:', username);

  await keystore.init();

  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('ilyazh-keystore-v3', 1);
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
