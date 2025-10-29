/**
 * Secure key storage using IndexedDB
 * Stores long-term identity keys and session state
 *
 * IMPORTANT: All methods should only be called from client-side code.
 * Do not call from server-side rendering contexts or getServerSideProps.
 */

import { type IdentityKeyPair, type HandshakeState } from '@ilyazh/crypto';
import _sodium from 'libsodium-wrappers';

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

  // Return as base64
  return Buffer.from(combined).toString('base64');
}

/**
 * Decrypt data with password-derived key
 * Input format: salt (32 bytes) || nonce (24 bytes) || ciphertext
 */
async function decryptWithPassword(encryptedBase64: string, password: string): Promise<Uint8Array> {
  await _sodium.ready;
  const sodium = _sodium;

  const combined = Buffer.from(encryptedBase64, 'base64');

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
const DB_VERSION = 1; // Start fresh with v1
const STORE_IDENTITY = 'identity';
const STORE_SESSIONS = 'sessions';
const STORE_PREKEYS = 'prekeys';

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
        console.warn('[KeyStore] Database open blocked - close all other tabs');
      };

      request.onsuccess = () => {
        this.db = request.result;
        console.log('[KeyStore] Database opened successfully, version:', this.db.version);
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

    let ed25519SecretKey: string;
    let mldsaSecretKey: string;
    let encrypted = false;

    // SECURITY: Encrypt secret keys if password is set
    if (this.password) {
      console.log('[KeyStore] Encrypting identity keys with password...');
      ed25519SecretKey = await encryptWithPassword(identity.ed25519.secretKey, this.password);
      mldsaSecretKey = await encryptWithPassword(identity.mldsa.secretKey, this.password);
      encrypted = true;
      console.log('[KeyStore] ✅ Identity keys encrypted');
    } else {
      console.warn('[KeyStore] ⚠️ Saving identity WITHOUT encryption - set password for security!');
      ed25519SecretKey = Buffer.from(identity.ed25519.secretKey).toString('base64');
      mldsaSecretKey = Buffer.from(identity.mldsa.secretKey).toString('base64');
    }

    const stored: StoredIdentity = {
      username,
      ed25519: {
        publicKey: Buffer.from(identity.ed25519.publicKey).toString('base64'),
        secretKey: ed25519SecretKey,
      },
      mldsa: {
        publicKey: Buffer.from(identity.mldsa.publicKey).toString('base64'),
        secretKey: mldsaSecretKey,
      },
      createdAt: Date.now(),
      encrypted,
    };

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_IDENTITY, 'readwrite');
      const store = tx.objectStore(STORE_IDENTITY);
      const request = store.put(stored);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve();
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

            console.log('[KeyStore] Decrypting identity keys...');
            try {
              ed25519SecretKey = await decryptWithPassword(stored.ed25519.secretKey, this.password);
              mldsaSecretKey = await decryptWithPassword(stored.mldsa.secretKey, this.password);
              console.log('[KeyStore] ✅ Identity keys decrypted');
            } catch (err) {
              reject(new Error('Failed to decrypt identity: incorrect password'));
              return;
            }
          } else {
            // Legacy unencrypted keys
            ed25519SecretKey = Buffer.from(stored.ed25519.secretKey, 'base64');
            mldsaSecretKey = Buffer.from(stored.mldsa.secretKey, 'base64');
          }

          resolve({
            ed25519: {
              publicKey: Buffer.from(stored.ed25519.publicKey, 'base64'),
              secretKey: ed25519SecretKey,
            },
            mldsa: {
              publicKey: Buffer.from(stored.mldsa.publicKey, 'base64'),
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
    const stored: StoredSession = {
      sessionId: Buffer.from(sessionId).toString('hex'),
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
    const sessionIdHex = Buffer.from(sessionId).toString('hex');

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
    const sessionIdHex = Buffer.from(sessionId).toString('hex');

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
        console.log('[KeyStore] Database deleted successfully');
        resolve();
      };
      request.onerror = () => reject(request.error);
      request.onblocked = () => {
        console.warn('[KeyStore] Database deletion blocked');
      };
    });
  }
}

// Singleton instance
export const keystore = new KeyStore();
