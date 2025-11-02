/**
 * Secure key storage using IndexedDB
 * Stores long-term identity keys and session state
 *
 * IMPORTANT: All methods should only be called from client-side code.
 * Do not call from server-side rendering contexts or getServerSideProps.
 */

import { type IdentityKeyPair, type HandshakeState } from '@ilyazh/crypto';
import _sodium from 'libsodium-wrappers';
import { logDebug, logInfo, logWarn, logError } from './logger';

// ==================== Password-based Encryption ====================

/**
 * Derive encryption key from password using scrypt
 * SECURITY: Uses high-cost scrypt parameters for password derivation
 */
async function deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<Uint8Array> {
  await _sodium.ready;
  const sodium = _sodium;

  // scrypt parameters (conservative - can be increased for more security)
  const opsLimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE; // ~0.1 seconds
  const memLimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE; // ~64MB
  const keyLength = sodium.crypto_secretbox_KEYBYTES; // 32 bytes

  return sodium.crypto_pwhash(
    keyLength,
    new Uint8Array(Buffer.from(password, 'utf-8')),
    salt,
    opsLimit,
    memLimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13 // Argon2id (more secure than scrypt)
  );
}

/**
 * Encrypt data with password-derived key
 * Returns: salt (32 bytes) || nonce (24 bytes) || ciphertext
 */
async function encryptWithPassword(plaintext: Uint8Array, password: string): Promise<string> {
  await _sodium.ready;
  const sodium = _sodium;

  // Generate random salt for password derivation
  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES); // 16 bytes

  // Derive encryption key from password
  const key = await deriveKeyFromPassword(password, salt);

  // Generate random nonce for XChaCha20-Poly1305
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES); // 24 bytes

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
  const saltLength = sodium.crypto_pwhash_SALTBYTES; // 16
  const nonceLength = sodium.crypto_secretbox_NONCEBYTES; // 24

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

    let ed25519SecretKey: string;
    let mldsaSecretKey: string;
    let encrypted = false;

    // SECURITY: Encrypt secret keys if password is set
    if (this.password) {
      logDebug('keystore', 'Encrypting identity keys');
      ed25519SecretKey = await encryptWithPassword(identity.ed25519.secretKey, this.password);
      mldsaSecretKey = await encryptWithPassword(identity.mldsa.secretKey, this.password);
      encrypted = true;
      logInfo('keystore', 'Identity keys encrypted');
    } else {
      logWarn('keystore', 'Saving identity WITHOUT encryption - set password for security');
      // Use libsodium's to_base64 for browser compatibility
      ed25519SecretKey = sodium.to_base64(new Uint8Array(identity.ed25519.secretKey), sodium.base64_variants.ORIGINAL);
      mldsaSecretKey = sodium.to_base64(new Uint8Array(identity.mldsa.secretKey), sodium.base64_variants.ORIGINAL);
    }

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
