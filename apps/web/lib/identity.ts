/**
 * Identity Management for Ilyazh-Web3E2E v0.8
 *
 * Handles:
 * - Long-term identity keypair generation (Ed25519 + ML-DSA-65)
 * - Registration with relay server
 * - Loading existing identities from IndexedDB
 * - Device re-enrollment when keys are missing
 */

import type { IdentityKeyPair } from '@ilyazh/crypto';
// Avoid static imports from '@ilyazh/crypto' to prevent bundling server-only crypto in SSR/client build
async function cryptoMod() {
  return await import('@ilyazh/crypto');
}
import { keystore } from './keystore';
import { getRelayUrl } from './relay-url';
import { verifyRelaySignature, isRelayIdentityVerified } from './relay-identity';
import { logDebug, logInfo, logWarn, logError, redactToken, redactPublicKey } from './logger';

// ==================== Relay Identity Verification State ====================

/**
 * CRITICAL SECURITY: Track relay identity verification state
 *
 * When this flag is true, it indicates that identity verification against the relay
 * failed - either due to network issues preventing verification or actual mismatches.
 *
 * Application MUST:
 * 1. Call isRelayVerificationFailed() before trusting identity for critical operations
 * 2. If true, alert user: "Could not verify identity with relay. Be cautious of impersonation."
 * 3. In production, consider requiring explicit user confirmation before proceeding
 * 4. Track failed verifications in telemetry for network debugging
 *
 * Note: We distinguish between:
 * - Network timeouts (recoverable, app can retry)
 * - Network errors (recoverable, app should continue with caution)
 * - Verification failures (irrecoverable, indicates mismatch or tampering)
 */
let RELAY_VERIFICATION_FAILED = false;

/**
 * Check if relay identity verification failed
 * Returns true if identity could not be verified against relay
 */
export function isRelayVerificationFailed(): boolean {
  return RELAY_VERIFICATION_FAILED;
}

/**
 * Error thrown when identity exists on relay but private keys are missing locally
 * This indicates the user needs to re-enroll this device
 */
export class IdentityReEnrollError extends Error {
  constructor(
    public readonly username: string,
    public readonly remotePublicKey: string
  ) {
    super(
      'Identity exists on relay but private keys not found locally. ' +
      'This device needs to be re-enrolled.'
    );
    this.name = 'IdentityReEnrollError';
  }
}

// Keystore version for migration
// Increment this to force a clean keystore on all clients
// Version 3: Deterministic password derivation (fixes recovery on page reload)
const KEYSTORE_MIGRATION_VERSION = 3;

/**
 * Ensure keystore is fresh and migrated
 * Clears old identities if version has changed
 */
async function ensureFreshKeystore(): Promise<void> {
  if (typeof window === 'undefined') return;

  const storedVersion = localStorage.getItem('ilyazh-keystore-migration-version');
  const currentVersion = String(KEYSTORE_MIGRATION_VERSION);

  if (storedVersion !== currentVersion) {
    console.log(`[Identity] Migration needed: v${storedVersion || '0'} -> v${currentVersion}`);
    logInfo('identity', 'Clearing old identities (they were non-canonical)');

    try {
      // Clear all keystore data
      await keystore.deleteDatabase();
      logInfo('identity', 'Old keystore cleared');

      // Nuclear option: manually delete all ilyazh-related IndexedDB and localStorage keys
      // This ensures no stale data remains after migration
      const allKeys = Object.keys(localStorage);
      for (const key of allKeys) {
        // CRITICAL: Do NOT delete the migration version key itself, or we'll loop forever
        if (key === 'ilyazh-keystore-migration-version') {
          logDebug('identity', `Skipping migration version key: ${key}`);
          continue;
        }
        if (key.startsWith('jwt_token_') || key.includes('ilyazh') || key.includes('keystore')) {
          localStorage.removeItem(key);
          logDebug('identity', `Removed localStorage key: ${key}`);
        }
      }
      logInfo('identity', 'Old JWT tokens and cache cleared');

      // Try to list all IndexedDB databases and delete them
      if (typeof indexedDB !== 'undefined' && indexedDB.databases) {
        try {
          const dbs = await indexedDB.databases();
          for (const db of dbs) {
            if (db.name && db.name.includes('ilyazh')) {
              const deleteReq = indexedDB.deleteDatabase(db.name);
              await new Promise((resolve, reject) => {
                deleteReq.onsuccess = resolve;
                deleteReq.onerror = reject;
              });
              logInfo('identity', `Deleted IndexedDB: ${db.name}`);
            }
          }
        } catch (err) {
          logWarn('identity', 'Could not enumerate IndexedDB databases', { error: err });
        }
      }

      // Update migration version
      localStorage.setItem('ilyazh-keystore-migration-version', currentVersion);
      logInfo('identity', 'Migration complete - all old data cleared');
    } catch (err) {
      logError('identity', 'Migration failed', { error: err });
      // Continue anyway - worst case, user has to clear manually
    }
  }
}

/**
 * Get authentication token for a user
 * Returns JWT token from localStorage
 */
export function getAuthToken(username: string): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(`jwt_token_${username}`);
}

/**
 * Create authenticated headers with JWT token
 */
export function createAuthHeaders(username: string): HeadersInit {
  const token = getAuthToken(username);
  logDebug('auth', 'Creating auth headers', { username, hasToken: !!token });

  if (token) {
    logDebug('auth', 'Using JWT from localStorage', { token: redactToken(token) });
  }

  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  } else {
    logWarn('auth', 'No JWT token found for user', { username });
  }
  return headers;
}

/**
 * Get or create identity for the current user
 * CRITICAL: Relay is source of truth for identities
 * - Checks relay /directory first (canonical identity)
 * - If relay has identity, use it (even if local differs)
 * - If relay doesn't have identity, generate new one and push to relay
 * - Store in IndexedDB only after relay confirms
 */
export async function getOrCreateIdentity(username: string): Promise<IdentityKeyPair> {
  // CRITICAL: Canonicalize username FIRST (lowercase, trim)
  const canonical = username.toLowerCase().trim();
  logInfo('identity', 'Getting or creating CANONICAL identity', { username: canonical });
  if (canonical !== username) {
    logInfo('identity', 'Normalized username', { from: username, to: canonical });
  }

  // CRITICAL: Wait for PQ crypto (liboqs WASM) to be initialized before proceeding
  // This prevents race conditions where generateIdentity() tries to use ML-KEM-768/ML-DSA-65
  // before they're loaded. Without this, we get "crypto not ready" errors masquerading as PQ_NOT_READY.
  try {
    const { waitForPQReady } = await cryptoMod();
    await waitForPQReady();
  } catch (err) {
    logError('identity', 'PQ crypto initialization timed out - cannot proceed with identity generation', { error: err });
    throw new Error('PQ crypto initialization failed. Please refresh the page and try again.');
  }

  // STEP 0: Ensure keystore is migrated (clears old non-canonical identities)
  await ensureFreshKeystore();

  try {
    logInfo('identity', 'Initializing keystore');
    await keystore.init();
    logInfo('identity', 'Keystore initialized successfully');
  } catch (err) {
    logError('identity', 'Keystore initialization failed', { error: err });
    // If VersionError, delete old database and retry
    if (err instanceof Error && err.name === 'VersionError') {
      logWarn('identity', 'VersionError detected, deleting old database...');
      await keystore.deleteDatabase();
      logInfo('identity', 'Old database deleted, retrying init');
      await keystore.init();
      logInfo('identity', 'Database recreated successfully');
    } else {
      logError('identity', 'Fatal error during keystore init', { error: err });
      throw err;
    }
  }

  // STEP 1: Check local identity FIRST (idempotency!)
  // CRITICAL: If we have a valid local identity, use it immediately
  // This prevents regeneration due to transient network errors
  logInfo('identity', 'Checking local keystore first');

  // Set password for loading encrypted identity
  // Use deterministic password based on username (no timestamp for recovery)
  const password = `${canonical}:ilyazh:secure`;
  keystore.setPassword(password);
  logDebug('identity', 'Password set for keystore (deterministic from username)');

  const localIdentity = await keystore.loadIdentity(canonical);

  if (localIdentity) {
    logInfo('identity', 'Found existing local identity, using it (idempotent)');
    logInfo('identity', 'Identity loaded', { ed25519Public: redactPublicKey(localIdentity.ed25519.publicKey) });

    // CRITICAL: Verify it matches relay (with proper timeout and error handling)
    // We distinguish between:
    // 1. Network timeouts (recoverable, but security-degraded)
    // 2. Network errors (recoverable, but security-degraded)
    // 3. Verification failures (irrecoverable, indicates mismatch/tampering)
    const relayUrl = getRelayUrl();
    let verificationSucceeded = false;

    try {
      const response = await fetch(`${relayUrl}/directory/${username}`, {
        signal: AbortSignal.timeout(10000) // 10s timeout (more forgiving for prod networks)
      });
      if (response.ok) {
        const data = await response.json();
        const remoteEd25519Hex = Buffer.from(data.identity.ed25519, 'base64').toString('hex');
        const localEd25519Hex = Buffer.from(localIdentity.ed25519.publicKey).toString('hex');

        if (remoteEd25519Hex !== localEd25519Hex) {
          logError('identity', 'CRITICAL: Local identity differs from relay');
          logError('identity', 'This should never happen - suggests database corruption or tampering');
          logError('identity', 'Local key', { key: localEd25519Hex.slice(0, 32) + '...' });
          logError('identity', 'Remote key', { key: remoteEd25519Hex.slice(0, 32) + '...' });
          RELAY_VERIFICATION_FAILED = true;
          throw new Error('Identity mismatch: local vs relay. Clear browser data and re-register.');
        }
        logInfo('identity', 'Local identity verified against relay ✓');
        verificationSucceeded = true;
      }
    } catch (err) {
      // Check if this is an identity mismatch error (non-recoverable)
      if (err instanceof Error && err.message.includes('Identity mismatch')) {
        throw err; // Re-throw mismatch errors immediately
      }

      // Network timeout: recoverable but security-degraded
      if (err instanceof Error && err.name === 'AbortError') {
        RELAY_VERIFICATION_FAILED = true;
        logWarn('identity', '⚠️  Relay verification TIMEOUT (10s) - identity not verified');
        logWarn('identity', '⚠️  Possible causes: slow network, relay overloaded, relay offline');
        logWarn('identity', '⚠️  Using local identity WITHOUT relay confirmation');
        logWarn('identity', '⚠️  Risk: Client is vulnerable to impersonation if relay is compromised');
      } else {
        // Other network error: recoverable but security-degraded
        RELAY_VERIFICATION_FAILED = true;
        logWarn('identity', '⚠️  Relay verification FAILED (network error) - identity not verified');
        logWarn('identity', '⚠️  Error details:', { error: err });
        logWarn('identity', '⚠️  Using local identity WITHOUT relay confirmation');
        logWarn('identity', '⚠️  Risk: Client is vulnerable to impersonation if relay is compromised');
      }
    }

    if (!verificationSucceeded) {
      logWarn('identity', 'IMPORTANT: Relay verification did not complete. Application should:');
      logWarn('identity', '1. Call isRelayVerificationFailed() to detect this condition');
      logWarn('identity', '2. Show user warning: "Could not verify identity with relay"');
      logWarn('identity', '3. Consider requiring explicit user confirmation before proceeding');
      logWarn('identity', '4. Track this in telemetry for network debugging');
    }

    return localIdentity;
  }

  // STEP 2: No local identity - check relay for existing canonical identity
  logInfo('identity', 'No local identity, checking relay for canonical identity');
  const relayUrl = getRelayUrl();

  try {
    const response = await fetch(`${relayUrl}/directory/${username}`);

    if (response.ok) {
      const data = await response.json();
      logInfo('identity', 'Found canonical identity on relay', { username });

      // Relay has canonical identity but we don't have the private keys locally
      // This means user registered on another device or cleared browser data
      logWarn('identity', 'Remote identity exists but local keypair is missing');
      logInfo('identity', 'This device needs to be re-enrolled with a new keypair');
      logInfo('identity', 'Showing re-enrollment UI to user');

      const remoteEd25519 = Buffer.from(data.identity.ed25519, 'base64').toString('hex');

      // Throw special error that UI can catch and show re-enroll modal
      throw new IdentityReEnrollError(username, remoteEd25519);
    }

    // 404 = relay doesn't have identity yet - this is expected for new users
    logInfo('identity', 'Relay returned 404 - no canonical identity exists yet (new user)');
  } catch (err) {
    if (err instanceof IdentityReEnrollError) {
      throw err; // Re-throw re-enroll errors for UI to handle
    }
    // Network errors are acceptable here - we'll generate new identity
    logWarn('identity', 'Failed to check relay (network error?), will generate new identity', { error: err });
  }

  // STEP 3: Relay has no identity - we are the first - generate and push
  logInfo('identity', 'No canonical identity on relay, generating new one');

  // Generate new identity keypair
  const { generateIdentity } = await cryptoMod();
  const identity = await generateIdentity();

  logInfo('identity', 'Generated new identity keypair', {
    ed25519Public: redactPublicKey(identity.ed25519.publicKey),
    mldsaPublic: redactPublicKey(identity.mldsa.publicKey)
  });

  // STEP 4: Push to relay FIRST (make it canonical)
  logInfo('identity', 'Pushing to relay to make it canonical');
  try {
    await registerCanonicalIdentity(username, identity);
    logInfo('identity', 'Identity now canonical on relay');
  } catch (err) {
    logError('identity', 'Failed to register canonical identity on relay', { error: err });
    throw new Error('Failed to register identity on relay - cannot proceed');
  }

  // STEP 5: Save to IndexedDB only after relay confirms
  // SECURITY FIX: Set password for key protection (required after KDF hardening)
  // Use deterministic password based on canonical username (must be recoverable)
  // NOTE: This password is derived from username, not stored - it must be consistent
  const newPassword = `${canonical}:ilyazh:secure`;
  keystore.setPassword(newPassword);
  logDebug('identity', 'Password set for new identity (deterministic from username)');

  await keystore.saveIdentity(username, identity);
  logInfo('identity', 'Saved identity to IndexedDB');

  // Also register with /register endpoint for JWT token
  try {
    await registerWithRelay(username, identity);
    logInfo('identity', 'Successfully registered with relay register endpoint');
  } catch (err) {
    logError('identity', 'Failed to register with /register endpoint', { error: err });
    // Continue anyway - we have canonical identity
  }

  return identity;
}

/**
 * Register canonical identity with relay /directory endpoint
 * This makes the identity the source of truth
 */
async function registerCanonicalIdentity(username: string, identity: IdentityKeyPair): Promise<void> {
  const relayUrl = getRelayUrl();
  const endpoint = `${relayUrl}/directory/${username}`;
  logInfo('identity', 'Registering canonical identity on directory', { endpoint });

  // STEP 0: Check if directory entry already exists
  // This solves the cascade failure where 404 caused registration to fail
  try {
    const checkResponse = await fetch(endpoint, {
      signal: AbortSignal.timeout(5000) // 5s timeout for existence check
    });

    if (checkResponse.ok) {
      logInfo('identity', 'Directory entry already exists, skipping registration');
      return; // Entry exists, nothing to do
    }

    if (checkResponse.status !== 404) {
      logWarn('identity', 'Unexpected status checking directory', { status: checkResponse.status });
    }
    // 404 is expected - directory entry doesn't exist yet, continue to register
  } catch (err) {
    // Network error checking existence - continue to try registering anyway
    logWarn('identity', 'Could not check directory existence, will attempt registration', { error: err });
  }

  // STEP 1: Register the identity
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identityEd25519: Buffer.from(identity.ed25519.publicKey).toString('base64'),
        identityMLDSA: Buffer.from(identity.mldsa.publicKey).toString('base64'),
      }),
    });

    if (!response.ok) {
      const contentType = response.headers.get('content-type');
      let errorDetails = '';

      if (contentType?.includes('application/json')) {
        const data = await response.json().catch(() => ({}));
        errorDetails = JSON.stringify(data);
      } else {
        errorDetails = await response.text().catch(() => 'Unable to read response');
      }

      // Log detailed CORS error info
      logError('identity', 'Failed to register canonical identity', {
        status: response.status,
        statusText: response.statusText,
        endpoint,
        origin: window.location.origin
      });

      // Specific error for CORS issues
      if (response.status === 500 && errorDetails.includes('Not allowed by CORS')) {
        throw new Error(
          `CORS ERROR: Relay at ${relayUrl} blocked request from origin ${window.location.origin}. ` +
          `This is a relay misconfiguration, not a client error. ` +
          `The relay must add ${window.location.origin} to ALLOWED_ORIGINS.`
        );
      }

      throw new Error(`Failed to register canonical identity: ${response.status} - ${errorDetails}`);
    }

    const data = await response.json();
    logInfo('identity', 'Canonical identity registered', data);
  } catch (error) {
    // If it's a fetch error (network, CORS preflight failure), provide helpful context
    if (error instanceof TypeError && error.message.includes('Failed to fetch')) {
      logError('identity', 'Network/CORS error - likely CORS preflight failure', {
        origin: window.location.origin,
        relayUrl
      });
      throw new Error(
        `Failed to connect to relay at ${relayUrl}. ` +
        `Check: (1) Relay is running, (2) CORS allows ${window.location.origin}, (3) Network connectivity.`
      );
    }
    throw error;
  }
}

/**
 * Register identity with relay server
 * Uploads public keys for directory lookup
 */
async function registerWithRelay(username: string, identity: IdentityKeyPair): Promise<void> {
  const relayUrl = getRelayUrl();
  logInfo('identity', 'Registering with relay server', { relayUrl });

  const response = await fetch(`${relayUrl}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      userId: username,
      username: username,
      identityEd25519: Buffer.from(identity.ed25519.publicKey).toString('base64'),
      identityMLDSA: Buffer.from(identity.mldsa.publicKey).toString('base64'),
    }),
  });

  // 409 = already registered (OK, reuse token)
  // 429 = rate limit (user exists, reuse token)
  if (response.status === 409 || response.status === 429) {
    logInfo('identity', 'User already registered, using existing token', { status: response.status });

    // Try to parse response for token
    try {
      const data = await response.json();
      if (data.token) {
        localStorage.setItem(`jwt_token_${username}`, data.token);
        logInfo('identity', 'JWT token stored for existing user', { username });
        return;
      }
    } catch (e) {
      // Response might not be JSON
    }

    // If no token in response, try to get existing token from localStorage
    const existingToken = localStorage.getItem(`jwt_token_${username}`);
    if (existingToken) {
      logInfo('identity', 'Using existing JWT token from localStorage');
      return;
    }

    // Last resort: continue without token (dev mode should work anyway)
    logWarn('identity', 'No token available, continuing without authentication');
    return;
  }

  // Parse response for successful registration
  const data = await response.json();

  // Check for other errors
  if (!response.ok) {
    throw new Error(`Failed to register: ${response.status} - ${JSON.stringify(data)}`);
  }

  // SECURITY: Store JWT token for authenticated requests
  logInfo('identity', 'Registration response', { status: response.status, hasToken: !!data.token });

  if (data.token) {
    localStorage.setItem(`jwt_token_${username}`, data.token);
    logInfo('identity', 'JWT token stored for user', { username });
  } else {
    logWarn('identity', 'No JWT token in registration response', data);
  }
}

/**
 * Fetch a peer's identity from the relay directory
 * Returns their public identity keys
 * CRITICAL: Verifies relay signature to detect impersonation
 *
 * @param username - Username (will be normalized: "Izahii" → "izahii")
 * @returns Peer's public identity keys
 */
export async function fetchPeerIdentity(username: string): Promise<{
  identityEd25519: Uint8Array;
  identityMLDSA: Uint8Array;
} | null> {
  const relayUrl = getRelayUrl();

  // STEP 1: Normalize username (handle "Izahii", "izahii", "IZAHII", etc.)
  const { normalizeUsername } = await import('./usernames');
  const canonicalUsername = normalizeUsername(username);

  logInfo('identity', 'Fetching peer identity', { username });
  if (canonicalUsername !== username) {
    logInfo('identity', 'Normalized to', { username: canonicalUsername });
  }

  const response = await fetch(`${relayUrl}/directory/${canonicalUsername}`);

  if (!response.ok) {
    logWarn('identity', 'Peer not found in directory', { username: canonicalUsername, status: response.status });
    return null;
  }

  const data = await response.json();

  if (!data.identity) {
    logWarn('identity', 'No identity found for user', { username: canonicalUsername });
    return null;
  }

  // CRITICAL: Verify relay signed this bundle
  if (!isRelayIdentityVerified()) {
    throw new Error(
      '[Identity] CRITICAL: Relay identity verification disabled. ' +
      'Cannot verify bundle authenticity. Session REJECTED.'
    );
  }

  const bundleData = new TextEncoder().encode(JSON.stringify({
    username: canonicalUsername,
    ed25519: data.identity.ed25519PublicKey || data.identity.identityEd25519,
    mldsa: data.identity.mldsaPublicKey || data.identity.identityMLDSA,
  }));

  // HARD FAIL if signature missing or invalid
  if (!data.relaySignature) {
    throw new Error(
      '[Identity] CRITICAL: Relay signature missing from identity bundle. ' +
      'Peer identity cannot be verified. Session REJECTED. ' +
      'This indicates relay compromise or misconfiguration.'
    );
  }

  const signature = new Uint8Array(Buffer.from(data.relaySignature, 'base64'));
  await verifyRelaySignature(bundleData, signature);

  // Signature verified - safe to use
  logInfo('identity', `Peer identity verified with relay signature (${canonicalUsername})`);

  return {
    identityEd25519: new Uint8Array(Buffer.from(data.identity.identityEd25519 || data.identity.ed25519PublicKey, 'base64')),
    identityMLDSA: new Uint8Array(Buffer.from(data.identity.identityMLDSA || data.identity.mldsaPublicKey, 'base64')),
  };
}

/**
 * Re-enroll this device by generating a NEW keypair and overwriting server identity
 *
 * SECURITY:
 * - This OVERWRITES the existing identity on the relay server
 * - Old devices with old keys will NO LONGER be able to decrypt new messages
 * - This is INTENTIONAL: we cannot have two devices with different keys for same user
 * - User must explicitly confirm this action
 *
 * @param username - Username to re-enroll
 * @returns New identity keypair (already saved to IndexedDB and relay)
 */
export async function reEnrollDevice(username: string): Promise<IdentityKeyPair> {
  logWarn('identity', 'RE-ENROLLING DEVICE - This will overwrite server identity', { username });
  logInfo('identity', 'Old devices will no longer work after this operation');

  // Generate new identity keypair
  const { generateIdentity: generateIdentity2 } = await cryptoMod();
  const newIdentity = await generateIdentity2();

  logInfo('identity', 'Generated new identity keypair for re-enrollment', {
    ed25519Public: redactPublicKey(newIdentity.ed25519.publicKey),
    mldsaPublic: redactPublicKey(newIdentity.mldsa.publicKey)
  });

  // CRITICAL: Push to relay to overwrite old identity
  logWarn('identity', 'Overwriting relay identity (old devices will stop working)');
  try {
    await registerCanonicalIdentity(username, newIdentity);
    logInfo('identity', 'Relay identity overwritten successfully');
  } catch (err) {
    logError('identity', 'Failed to overwrite relay identity', { error: err });
    throw new Error('Failed to re-enroll device on relay - cannot proceed');
  }

  // Save to IndexedDB
  await keystore.init();
  await keystore.saveIdentity(username, newIdentity);
  logInfo('identity', 'New identity saved to IndexedDB');

  // Also register with /register endpoint for JWT token
  try {
    await registerWithRelay(username, newIdentity);
    logInfo('identity', 'Successfully re-registered with relay');
  } catch (err) {
    logError('identity', 'Failed to register with /register endpoint', { error: err });
    // Continue anyway - we have identity
  }

  logInfo('identity', 'Device re-enrollment complete');
  return newIdentity;
}

/**
 * Delete identity for a user
 * WARNING: This will permanently delete the identity keypair
 */
export async function deleteIdentity(username: string): Promise<void> {
  logInfo('identity', 'Deleting identity', { username });
  await keystore.init();

  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('ilyazh-keystore-v3', 2);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(['identities'], 'readwrite');
    const store = tx.objectStore('identities');
    const request = store.delete(username);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });

  db.close();
  logInfo('identity', 'Identity deleted');
}
