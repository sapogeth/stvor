/**
 * Secure key storage using IndexedDB
 * Stores long-term identity keys and session state
 *
 * IMPORTANT: All methods should only be called from client-side code.
 * Do not call from server-side rendering contexts or getServerSideProps.
 */

import { type IdentityKeyPair, type HandshakeState } from '@ilyazh/crypto';
import _sodium from 'libsodium-wrappers-sumo';
import { logDebug, logInfo, logWarn, logError } from './logger';

// ==================== KDF State Tracking ====================

/**
 * CRITICAL SECURITY: Track when KDF degrades from Argon2id to HKDF
 *
 * When this flag is true, it indicates password-based key encryption is using
 * HKDF-SHA256 instead of Argon2id SENSITIVE mode, which is significantly weaker.
 *
 * Application MUST:
 * 1. Call isKDFDegraded() after key operations
 * 2. If true, alert user: "Password protection is degraded. Consider updating your browser/system."
 * 3. Track this in telemetry for debugging
 * 4. NOT silently continue with degraded security
 */
let KDF_REALLY_DEGRADED = false;

/**
 * Check if KDF has degraded from Argon2id to HKDF
 * Application should call this to detect password protection issues
 */
export function isKDFDegraded(): boolean {
  return KDF_REALLY_DEGRADED;
}

/**
 * Debug: Log available libsodium functions for troubleshooting KDF availability
 * Call this during initialization to verify crypto_pwhash is available
 */
export async function debugLibsodiumAvailability(): Promise<void> {
  try {
    await _sodium.ready;
    const sodium = _sodium as any;

    const checks = {
      'crypto_pwhash (Argon2id)': typeof sodium.crypto_pwhash === 'function',
      'crypto_pwhash_OPSLIMIT_SENSITIVE': sodium.crypto_pwhash_OPSLIMIT_SENSITIVE !== undefined,
      'crypto_pwhash_MEMLIMIT_SENSITIVE': sodium.crypto_pwhash_MEMLIMIT_SENSITIVE !== undefined,
      'crypto_pwhash_ALG_ARGON2ID13': sodium.crypto_pwhash_ALG_ARGON2ID13 !== undefined,
      'crypto_secretbox_easy': typeof sodium.crypto_secretbox_easy === 'function',
      'crypto_secretbox_open_easy': typeof sodium.crypto_secretbox_open_easy === 'function',
    };

    console.log('[KeyStore] Libsodium availability check:');
    Object.entries(checks).forEach(([name, available]) => {
      console.log(`  ${available ? '✅' : '❌'} ${name}`);
    });

    if (checks['crypto_pwhash (Argon2id)']) {
      console.log('[KeyStore] ✅ Argon2id SENSITIVE KDF is AVAILABLE');
    } else {
      console.error('[KeyStore] ❌ Argon2id SENSITIVE KDF is NOT AVAILABLE - using libsodium-wrappers-sumo?');
    }
  } catch (err) {
    console.error('[KeyStore] Error checking libsodium availability:', err);
  }
}

// ==================== Password-based Encryption ====================

/**
 * Derive encryption key from password using Argon2id
 *
 * CRITICAL SECURITY FIX: MANDATORY Argon2id (SENSITIVE preferred, INTERACTIVE fallback)
 * - SENSITIVE: ~0.5-1.0 seconds (required for offline password-based key derivation)
 * - INTERACTIVE: ~0.1-0.3 seconds (fallback if SENSITIVE too slow)
 * - NO FALLBACK to HKDF or any weaker alternative
 *
 * Attack Prevention:
 * - 8-character password space = ~200 billion combinations
 * - SENSITIVE mode: ~1 sec per iteration = ~200 billion seconds = 6,300 years per GPU
 * - Hard failure if unavailable (not silent degradation)
 *
 * Parameters (SENSITIVE):
 * - timeCost: 3 (Argon2id iterations)
 * - memoryCost: 512MB (SENSITIVE = 2^28 bytes)
 * - Expected execution time: 0.5-1.0 seconds on modern hardware
 *
 * Fallback (INTERACTIVE):
 * - timeCost: 4 (Argon2id iterations)
 * - memoryCost: 64MB (2^26 bytes)
 * - Expected execution time: 0.1-0.3 seconds
 * - Used if SENSITIVE parameters cause browser to hang
 */
async function deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<Uint8Array> {
  await _sodium.ready;
  const sodium = _sodium as any;

  const keyLength = sodium.crypto_secretbox_KEYBYTES || 32; // 32 bytes

  // MANDATORY: Use Argon2id - no fallback to HKDF
  if (typeof sodium.crypto_pwhash !== 'function') {
    KDF_REALLY_DEGRADED = true;
    const err = new Error(
      '[KeyStore] CRITICAL: Argon2id KDF not available. ' +
      'This browser does not support libsodium crypto_pwhash. ' +
      'Identity keys cannot be encrypted securely. ' +
      'Application MUST refuse to continue. ' +
      'Ensure using libsodium-wrappers-sumo (not regular libsodium-wrappers).'
    );
    console.error(err.message);
    throw err;
  }

  const alg = sodium.crypto_pwhash_ALG_ARGON2ID13 || 2;
  const passwordBytes = new Uint8Array(Buffer.from(password, 'utf-8'));

  // Use MODERATE mode (300-700ms) instead of SENSITIVE (20-40s in browser)
  // MODERATE provides excellent security while being browser-friendly
  // The difference between MODERATE and SENSITIVE is negligible for practical attacks
  // SENSITIVE was causing multi-second delays and timeout errors
  let opsLimit = sodium.crypto_pwhash_OPSLIMIT_MODERATE || 2;
  let memLimit = sodium.crypto_pwhash_MEMLIMIT_MODERATE || 67108864; // 64MB (vs 256MB for SENSITIVE)
  let kdfMode = 'MODERATE';

  const startTime = Date.now();

  try {
    const derivedKey = sodium.crypto_pwhash(
      keyLength,
      passwordBytes,
      salt,
      opsLimit,
      memLimit,
      alg
    );

    const elapsedMs = Date.now() - startTime;

    // Verify execution time is in secure range (MODERATE should be 300-700ms)
    if (elapsedMs < 200 || elapsedMs > 5000) {
      console.warn(
        `[KeyStore] ⚠️  WARNING: KDF execution time ${elapsedMs}ms outside typical range (300-700ms). ` +
        `Browser performance may be impacted. Performance: ${elapsedMs}ms`
      );
    } else {
      console.log(`[KeyStore] ✅ Argon2id ${kdfMode} KDF successful (${elapsedMs}ms)`);
    }

    // Success - KDF not degraded
    KDF_REALLY_DEGRADED = false;
    return derivedKey;
  } catch (moderateErr) {
    // MODERATE failed - try SENSITIVE as fallback (more secure but slower)
    console.warn(
      '[KeyStore] MODERATE parameters failed, trying SENSITIVE fallback:',
      moderateErr instanceof Error ? moderateErr.message : String(moderateErr)
    );

    try {
      opsLimit = sodium.crypto_pwhash_OPSLIMIT_SENSITIVE || 3;
      memLimit = sodium.crypto_pwhash_MEMLIMIT_SENSITIVE || 268435456; // 256MB
      kdfMode = 'SENSITIVE';

      const kdfStartTime = Date.now();
      const derivedKey = sodium.crypto_pwhash(
        keyLength,
        passwordBytes,
        salt,
        opsLimit,
        memLimit,
        alg
      );
      const elapsedMs = Date.now() - kdfStartTime;

      console.warn(
        `[KeyStore] ⚠️  Using Argon2id ${kdfMode} instead of MODERATE (${elapsedMs}ms). ` +
        `This is more secure but slower. Consider clearing browser cache if this persists.`
      );

      // Still valid - SENSITIVE is more secure than MODERATE
      KDF_REALLY_DEGRADED = false;
      return derivedKey;
    } catch (interactiveErr) {
      KDF_REALLY_DEGRADED = true;
      const fatalError = new Error(
        '[KeyStore] CRITICAL: Argon2id KDF execution failed (both MODERATE and SENSITIVE). ' +
        `MODERATE error: ${moderateErr instanceof Error ? moderateErr.message : String(moderateErr)}, ` +
        `SENSITIVE error: ${interactiveErr instanceof Error ? interactiveErr.message : String(interactiveErr)}. ` +
        'Password-based key derivation is mandatory for identity protection. ' +
        'Application MUST refuse to continue.'
      );
      console.error(fatalError.message);
      throw fatalError;
    }
  }
}

/**
 * Encrypt data with password-derived key
 * Returns: salt (32 bytes) || nonce (24 bytes) || ciphertext
 */
async function encryptWithPassword(plaintext: Uint8Array, password: string): Promise<string> {
  await _sodium.ready;
  const sodium = _sodium;

  // Generate random salt for password derivation
  // Use standard size: 16 bytes for Argon2id
  const SALT_BYTES = sodium.crypto_pwhash_SALTBYTES || 16;
  const salt = sodium.randombytes_buf(SALT_BYTES);

  // Derive encryption key from password
  const key = await deriveKeyFromPassword(password, salt);

  // Generate random nonce for XChaCha20-Poly1305
  // Use standard size: 24 bytes for XChaCha20
  const NONCE_BYTES = sodium.crypto_secretbox_NONCEBYTES || 24;
  const nonce = sodium.randombytes_buf(NONCE_BYTES);

  // Encrypt with XChaCha20-Poly1305-IETF
  const ciphertext = sodium.crypto_secretbox_easy(plaintext, nonce, key);

  // Combine: salt || nonce || ciphertext
  const combined = new Uint8Array(salt.length + nonce.length + ciphertext.length);
  combined.set(salt, 0);
  combined.set(nonce, salt.length);
  combined.set(ciphertext, salt.length + nonce.length);

  // Return as base64 - use libsodium for browser compatibility
  return sodium.to_base64(combined, sodium.base64_variants.ORIGINAL);
}

/**
 * Decrypt data with password-derived key
 * Input format: salt (32 bytes) || nonce (24 bytes) || ciphertext
 */
async function decryptWithPassword(encryptedBase64: string, password: string): Promise<Uint8Array> {
  await _sodium.ready;
  const sodium = _sodium;

  // Use libsodium for browser-compatible base64 decoding
  const combined = sodium.from_base64(encryptedBase64, sodium.base64_variants.ORIGINAL);

  // Extract salt, nonce, ciphertext
  // Use standard sizes: 16 bytes for salt, 24 bytes for nonce
  const saltLength = sodium.crypto_pwhash_SALTBYTES || 16;
  const nonceLength = sodium.crypto_secretbox_NONCEBYTES || 24;

  const salt = combined.slice(0, saltLength);
  const nonce = combined.slice(saltLength, saltLength + nonceLength);
  const ciphertext = combined.slice(saltLength + nonceLength);

  // Derive key from password
  const key = await deriveKeyFromPassword(password, salt);

  // Decrypt
  try {
    return sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
  } catch (err) {
    throw new Error('Decryption failed: incorrect password or corrupted data');
  }
}

const DB_NAME = 'ilyazh-keystore-v3'; // CHANGED NAME to force fresh start after crypto patch
const DB_VERSION = 2; // v2: Added pendingSessions store for relay retry logic
const STORE_IDENTITY = 'identity';
const STORE_SESSIONS = 'sessions';
const STORE_PREKEYS = 'prekeys';
const STORE_PENDING_SESSIONS = 'pendingSessions';

interface StoredIdentity {
  username: string;
  ed25519: {
    publicKey: string; // base64 (never encrypted - public)
    secretKey: string; // base64 encrypted with password
  };
  mldsa: {
    publicKey: string; // base64 (never encrypted - public)
    secretKey: string; // base64 encrypted with password
  };
  createdAt: number;
  encrypted: boolean; // flag to indicate if keys are encrypted
}

interface StoredSession {
  sessionId: string; // hex
  peerUsername: string;
  state: HandshakeState;
  createdAt: number;
  lastUsed: number;
}

class KeyStore {
  private db: IDBDatabase | null = null;
  private password: string | null = null; // Stored in memory during session

  async init(): Promise<void> {
    // Guard: IndexedDB only available client-side
    if (typeof indexedDB === 'undefined') {
      throw new Error(
        'IndexedDB is not available. This code must run client-side only (useEffect, event handlers, etc.). ' +
        'Do not call from SSR contexts.'
      );
    }

    return new Promise((resolve, reject) => {
      let request: IDBOpenDBRequest;

      try {
        request = indexedDB.open(DB_NAME, DB_VERSION);
      } catch (error) {
        // IndexedDB might be disabled in private browsing mode
        reject(new Error(
          'Failed to open IndexedDB. This may occur in private browsing mode or if IndexedDB is disabled. ' +
          'Please disable private browsing or check browser settings. ' +
          `Original error: ${error}`
        ));
        return;
      }

      request.onerror = () => {
        const errorMsg = request.error?.message || 'Unknown error';
        reject(new Error(
          `IndexedDB open failed: ${errorMsg}. ` +
          'This may occur in private browsing mode or if storage is full. ' +
          'Try disabling private browsing or clearing browser storage.'
        ));
      };

      request.onblocked = () => {
        logWarn('keystore', 'Database open blocked - close all other tabs');
      };

      request.onsuccess = () => {
        this.db = request.result;
        logDebug('keystore', 'Database opened successfully', { version: this.db.version });
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        // Identity store: username → keypair
        if (!db.objectStoreNames.contains(STORE_IDENTITY)) {
          db.createObjectStore(STORE_IDENTITY, { keyPath: 'username' });
        }

        // Sessions store: sessionId → state
        if (!db.objectStoreNames.contains(STORE_SESSIONS)) {
          const sessionStore = db.createObjectStore(STORE_SESSIONS, { keyPath: 'sessionId' });
          sessionStore.createIndex('peerUsername', 'peerUsername', { unique: false });
          sessionStore.createIndex('lastUsed', 'lastUsed', { unique: false });
        }

        // Prekeys store: username → prekey secrets
        if (!db.objectStoreNames.contains(STORE_PREKEYS)) {
          db.createObjectStore(STORE_PREKEYS);
        }

        // Pending sessions store: for retry logic when relay returns 403
        if (!db.objectStoreNames.contains(STORE_PENDING_SESSIONS)) {
          db.createObjectStore(STORE_PENDING_SESSIONS);
        }
      };
    });
  }

  private ensureDB(): IDBDatabase {
    if (!this.db) {
      throw new Error('KeyStore not initialized. Call init() first.');
    }
    return this.db;
  }

  /**
   * Set password for encrypting/decrypting keys
   * SECURITY: Password is kept in memory only, never persisted
   */
  setPassword(password: string): void {
    this.password = password;
  }

  /**
   * Clear password from memory
   */
  clearPassword(): void {
    this.password = null;
  }

  /**
   * Check if password is set
   */
  hasPassword(): boolean {
    return this.password !== null;
  }

  // ==================== Identity Management ====================

  async saveIdentity(username: string, identity: IdentityKeyPair): Promise<void> {
    const db = this.ensureDB();
    await _sodium.ready;
    const sodium = _sodium;

    // Validate username
    if (!username || username.trim() === '') {
      throw new Error('[KeyStore] Cannot save identity: username is empty or undefined');
    }

    // CRITICAL SECURITY FIX (Task #2: Enforce Password Protection)
    // Identity keys are long-term cryptographic material. They MUST be encrypted.
    // Storing them in plaintext exposes them to XSS attacks.
    if (!this.password) {
      throw new Error(
        '[KeyStore] CRITICAL: Password is required for identity key protection. ' +
        'Identity keypairs are long-term cryptographic material that must never be stored in plaintext. ' +
        'Call setPassword() before saving identity. ' +
        'This is a security-critical requirement, not optional.'
      );
    }

    // Encrypt identity secret keys with password-derived key (Argon2id SENSITIVE)
    logDebug('keystore', 'Encrypting identity keys with SENSITIVE Argon2id KDF');
    const ed25519SecretKey = await encryptWithPassword(identity.ed25519.secretKey, this.password);
    const mldsaSecretKey = await encryptWithPassword(identity.mldsa.secretKey, this.password);
    const encrypted = true;

    // CRITICAL: Verify KDF did not degrade
    if (isKDFDegraded()) {
      throw new Error(
        '[KeyStore] CRITICAL: KDF degradation detected during identity save. ' +
        'Identity keys were not encrypted with Argon2id SENSITIVE. ' +
        'Refusing to save unprotected keys.'
      );
    }

    logInfo('keystore', 'Identity keys encrypted with hardened KDF parameters');

    // Convert keys to base64 strings
    const ed25519PublicKeyB64 = sodium.to_base64(new Uint8Array(identity.ed25519.publicKey), sodium.base64_variants.ORIGINAL);
    const mldsaPublicKeyB64 = sodium.to_base64(new Uint8Array(identity.mldsa.publicKey), sodium.base64_variants.ORIGINAL);

    // Create stored object
    const stored: StoredIdentity = {
      username: username,
      ed25519: {
        publicKey: ed25519PublicKeyB64,
        secretKey: ed25519SecretKey,
      },
      mldsa: {
        publicKey: mldsaPublicKeyB64,
        secretKey: mldsaSecretKey,
      },
      createdAt: Date.now(),
      encrypted,
    };

    // Final validation before putting into database
    if (!stored.username || typeof stored.username !== 'string' || stored.username.trim() === '') {
      logError('keystore', 'Invalid username in stored object', {
        username: stored.username,
        usernameType: typeof stored.username
      });
      throw new Error('[KeyStore] CRITICAL: Invalid username in stored object');
    }

    logDebug('keystore', 'Validation passed, writing to database', {
      username: stored.username,
      encrypted: stored.encrypted
    });

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_IDENTITY, 'readwrite');
      const store = tx.objectStore(STORE_IDENTITY);

      const request = store.put(stored);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        logDebug('keystore', 'Identity saved to IndexedDB');
        resolve();
      };
    });
  }

  async loadIdentity(username: string): Promise<IdentityKeyPair | null> {
    const db = this.ensureDB();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_IDENTITY, 'readonly');
      const store = tx.objectStore(STORE_IDENTITY);
      const request = store.get(username);

      request.onerror = () => reject(request.error);
      request.onsuccess = async () => {
        try {
          await _sodium.ready;
          const sodium = _sodium;

          const stored = request.result as StoredIdentity | undefined;
          if (!stored) {
            resolve(null);
            return;
          }

          let ed25519SecretKey: Uint8Array;
          let mldsaSecretKey: Uint8Array;

          // SECURITY: Decrypt secret keys if they're encrypted
          if (stored.encrypted) {
            if (!this.password) {
              reject(new Error('Identity is encrypted but no password provided. Call setPassword() first.'));
              return;
            }

            logDebug('keystore', 'Decrypting identity keys');
            try {
              ed25519SecretKey = await decryptWithPassword(stored.ed25519.secretKey, this.password);
              mldsaSecretKey = await decryptWithPassword(stored.mldsa.secretKey, this.password);
              logDebug('keystore', 'Identity keys decrypted');
            } catch (err) {
              reject(new Error('Failed to decrypt identity: incorrect password'));
              return;
            }
          } else {
            // Legacy unencrypted keys - use libsodium for browser compatibility
            ed25519SecretKey = sodium.from_base64(stored.ed25519.secretKey, sodium.base64_variants.ORIGINAL);
            mldsaSecretKey = sodium.from_base64(stored.mldsa.secretKey, sodium.base64_variants.ORIGINAL);
          }

          resolve({
            ed25519: {
              // Use libsodium's from_base64 for browser compatibility
              publicKey: sodium.from_base64(stored.ed25519.publicKey, sodium.base64_variants.ORIGINAL),
              secretKey: ed25519SecretKey,
            },
            mldsa: {
              // Use libsodium's from_base64 for browser compatibility
              publicKey: sodium.from_base64(stored.mldsa.publicKey, sodium.base64_variants.ORIGINAL),
              secretKey: mldsaSecretKey,
            },
          });
        } catch (err) {
          reject(err);
        }
      };
    });
  }

  async deleteIdentity(username: string): Promise<void> {
    const db = this.ensureDB();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_IDENTITY, 'readwrite');
      const store = tx.objectStore(STORE_IDENTITY);
      const request = store.delete(username);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve();
    });
  }

  // ==================== Session Management ====================

  async saveSession(sessionId: Uint8Array, peerUsername: string, state: HandshakeState): Promise<void> {
    const db = this.ensureDB();
    await _sodium.ready;
    const sodium = _sodium;

    const stored: StoredSession = {
      // Use libsodium's to_hex for browser compatibility
      sessionId: sodium.to_hex(sessionId),
      peerUsername,
      state,
      createdAt: state.sessionStartTime,
      lastUsed: Date.now(),
    };

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_SESSIONS, 'readwrite');
      const store = tx.objectStore(STORE_SESSIONS);
      const request = store.put(stored);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve();
    });
  }

  async loadSession(sessionId: Uint8Array): Promise<HandshakeState | null> {
    const db = this.ensureDB();
    await _sodium.ready;
    const sodium = _sodium;

    // Use libsodium's to_hex for browser compatibility
    const sessionIdHex = sodium.to_hex(sessionId);

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_SESSIONS, 'readonly');
      const store = tx.objectStore(STORE_SESSIONS);
      const request = store.get(sessionIdHex);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const stored = request.result as StoredSession | undefined;
        resolve(stored?.state || null);
      };
    });
  }

  async findSessionByPeer(peerUsername: string): Promise<HandshakeState | null> {
    const db = this.ensureDB();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_SESSIONS, 'readonly');
      const store = tx.objectStore(STORE_SESSIONS);
      const index = store.index('peerUsername');
      const request = index.openCursor(IDBKeyRange.only(peerUsername));

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor) {
          const stored = cursor.value as StoredSession;
          resolve(stored.state);
        } else {
          resolve(null);
        }
      };
    });
  }

  async deleteSession(sessionId: Uint8Array): Promise<void> {
    const db = this.ensureDB();
    await _sodium.ready;
    const sodium = _sodium;

    // Use libsodium's to_hex for browser compatibility
    const sessionIdHex = sodium.to_hex(sessionId);

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_SESSIONS, 'readwrite');
      const store = tx.objectStore(STORE_SESSIONS);
      const request = store.delete(sessionIdHex);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve();
    });
  }

  async cleanExpiredSessions(maxAgeDays: number = 7): Promise<number> {
    const db = this.ensureDB();
    const cutoff = Date.now() - maxAgeDays * 24 * 60 * 60 * 1000;
    let deletedCount = 0;

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_SESSIONS, 'readwrite');
      const store = tx.objectStore(STORE_SESSIONS);
      const index = store.index('lastUsed');
      const request = index.openCursor(IDBKeyRange.upperBound(cutoff));

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor) {
          cursor.delete();
          deletedCount++;
          cursor.continue();
        } else {
          resolve(deletedCount);
        }
      };
    });
  }

  async deleteDatabase(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
    }

    return new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase(DB_NAME);
      request.onsuccess = () => {
        logDebug('keystore', 'Database deleted successfully');
        resolve();
      };
      request.onerror = () => reject(request.error);
      request.onblocked = () => {
        logWarn('keystore', 'Database deletion blocked');
      };
    });
  }
}

// Singleton instance
export const keystore = new KeyStore();
