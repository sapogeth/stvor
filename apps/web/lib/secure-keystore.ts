/**
 * Secure Keystore - Password-Protected E2E Key Storage
 *
 * SECURITY ARCHITECTURE:
 * - All long-term E2E keys (identity, prekeys, sessions) encrypted with password-derived key
 * - Uses PBKDF2 with 600,000 iterations (OWASP 2023 recommendation)
 * - AES-256-GCM for encryption (authenticated encryption)
 * - Random salt and IV per encryption
 * - Password NEVER leaves the device, NEVER sent to server
 * - Even with XSS, attacker cannot read keys without password
 *
 * THREAT MODEL:
 * - Protects against: XSS key theft, malicious browser extensions, disk forensics
 * - Does NOT protect against: keyloggers, memory dumps while unlocked, physical device access
 *
 * @module secure-keystore
 */

import type { IdentityKeyPair } from '@ilyazh/crypto';
import type { PrekeySecrets } from './prekeys';

/**
 * SECURITY: Keystore version for migration tracking
 * v1: Plaintext storage (insecure, legacy)
 * v2: Password-encrypted storage (current)
 */
export const KEYSTORE_VERSION = 2;

/**
 * SECURITY: PBKDF2 parameters (OWASP 2023 recommendations)
 * - 600,000 iterations for PBKDF2-SHA256
 * - This makes brute-force attacks extremely expensive
 */
const PBKDF2_ITERATIONS = 600000;
const PBKDF2_HASH = 'SHA-256';
const SALT_LENGTH = 32; // 256 bits
const AES_KEY_LENGTH = 256; // bits
const AES_IV_LENGTH = 12; // 96 bits (recommended for GCM)

/**
 * Encrypted keystore structure stored in IndexedDB
 * SECURITY: All sensitive data is in the encrypted ciphertext blob
 */
export interface EncryptedKeystoreRecord {
  version: 2;
  salt: string; // base64-encoded
  iv: string; // base64-encoded
  ciphertext: string; // base64-encoded
  createdAt: string; // ISO timestamp
  lastUsedAt: string; // ISO timestamp
}

/**
 * Decrypted keystore structure (in-memory only)
 * SECURITY: This object should NEVER be persisted in plaintext
 */
export interface DecryptedKeystore {
  version: 2;
  userId: string; // Clerk user ID
  identity?: IdentityKeyPair;
  prekeySecrets?: Record<string, PrekeySecrets>; // keyed by bundleId
  sessions?: Record<string, any>; // keyed by sessionId
  relayToken?: string; // Optional: encrypted relay JWT
  createdAt: string;
  lastUsedAt: string;
}

/**
 * Legacy plaintext keystore (v1) - INSECURE
 * Used only for migration to v2
 */
export interface PlaintextKeystoreRecord {
  version?: 1;
  userId: string;
  identity?: any;
  prekeySecrets?: any;
  sessions?: any;
  // No encryption metadata
}

/**
 * In-memory keystore state
 * SECURITY: Cleared on lock(), populated on unlock()
 */
class SecureKeystoreManager {
  private decryptedKeystore: DecryptedKeystore | null = null;
  private derivedKey: CryptoKey | null = null;
  private isLocked: boolean = true;

  /**
   * Check if keystore is currently unlocked
   */
  isUnlocked(): boolean {
    return !this.isLocked && this.decryptedKeystore !== null;
  }

  /**
   * Get decrypted keystore (throws if locked)
   * SECURITY: Only accessible when unlocked with correct password
   */
  getKeystore(): DecryptedKeystore {
    if (this.isLocked || !this.decryptedKeystore) {
      throw new Error('[SecureKeystore] Keystore is locked - call unlock() first');
    }
    return this.decryptedKeystore;
  }

  /**
   * Lock keystore and clear sensitive data from memory
   * SECURITY: Zeroes out in-memory keys (best-effort)
   */
  lock(): void {
    console.log('[SecureKeystore] Locking keystore and clearing memory');

    // Best-effort memory clearing (JavaScript limitations)
    if (this.decryptedKeystore) {
      // Clear identity keys if present
      if (this.decryptedKeystore.identity?.ed25519?.secretKey) {
        this.decryptedKeystore.identity.ed25519.secretKey.fill(0);
      }
      if (this.decryptedKeystore.identity?.mldsa?.secretKey) {
        this.decryptedKeystore.identity.mldsa.secretKey.fill(0);
      }

      // Clear prekey secrets
      if (this.decryptedKeystore.prekeySecrets) {
        for (const secrets of Object.values(this.decryptedKeystore.prekeySecrets)) {
          if (secrets.x25519SecretKey) secrets.x25519SecretKey.fill(0);
          if (secrets.mlkemSecretKey) secrets.mlkemSecretKey.fill(0);
        }
      }
    }

    this.decryptedKeystore = null;
    this.derivedKey = null;
    this.isLocked = true;
  }

  /**
   * Derive encryption key from password using PBKDF2
   * SECURITY: 600,000 iterations makes brute-force attacks expensive
   */
  private async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    console.log('[SecureKeystore] Deriving key from password (PBKDF2, 600k iterations)');

    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt.buffer as ArrayBuffer,
        iterations: PBKDF2_ITERATIONS,
        hash: PBKDF2_HASH,
      },
      passwordKey,
      { name: 'AES-GCM', length: AES_KEY_LENGTH },
      false, // not extractable
      ['encrypt', 'decrypt']
    );

    console.log('[SecureKeystore] Key derivation complete');
    return derivedKey;
  }

  /**
   * Encrypt keystore with password-derived key
   * SECURITY: Uses AES-256-GCM with random IV
   */
  private async encryptKeystore(
    keystore: DecryptedKeystore,
    password: string
  ): Promise<EncryptedKeystoreRecord> {
    console.log('[SecureKeystore] Encrypting keystore with AES-256-GCM');

    // Generate random salt and IV
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));

    // Derive key from password
    const key = await this.deriveKey(password, salt);

    // Serialize keystore to JSON
    const plaintextJson = JSON.stringify(keystore);
    const plaintextBytes = new TextEncoder().encode(plaintextJson);

    // Encrypt with AES-GCM (authenticated encryption)
    const ciphertextBytes = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      plaintextBytes
    );

    // Convert to base64 for storage
    const encryptedRecord: EncryptedKeystoreRecord = {
      version: 2,
      salt: btoa(String.fromCharCode(...salt)),
      iv: btoa(String.fromCharCode(...iv)),
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertextBytes))),
      createdAt: keystore.createdAt,
      lastUsedAt: new Date().toISOString(),
    };

    console.log('[SecureKeystore] Encryption complete');
    return encryptedRecord;
  }

  /**
   * Decrypt keystore with password-derived key
   * SECURITY: Returns null on wrong password (auth tag verification fails)
   */
  private async decryptKeystore(
    record: EncryptedKeystoreRecord,
    password: string
  ): Promise<DecryptedKeystore | null> {
    console.log('[SecureKeystore] Decrypting keystore');

    try {
      // Parse base64 metadata
      const salt = Uint8Array.from(atob(record.salt), (c) => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(record.iv), (c) => c.charCodeAt(0));
      const ciphertextBytes = Uint8Array.from(atob(record.ciphertext), (c) => c.charCodeAt(0));

      // Derive key from password
      const key = await this.deriveKey(password, salt);

      // Decrypt with AES-GCM
      const plaintextBytes = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        ciphertextBytes
      );

      // Parse JSON
      const plaintextJson = new TextDecoder().decode(plaintextBytes);
      const keystore = JSON.parse(plaintextJson) as DecryptedKeystore;

      // Restore Uint8Array fields (they were serialized as regular arrays)
      if (keystore.identity) {
        if (keystore.identity.ed25519) {
          keystore.identity.ed25519.publicKey = new Uint8Array(keystore.identity.ed25519.publicKey as any);
          keystore.identity.ed25519.secretKey = new Uint8Array(keystore.identity.ed25519.secretKey as any);
        }
        if (keystore.identity.mldsa) {
          keystore.identity.mldsa.publicKey = new Uint8Array(keystore.identity.mldsa.publicKey as any);
          keystore.identity.mldsa.secretKey = new Uint8Array(keystore.identity.mldsa.secretKey as any);
        }
      }

      if (keystore.prekeySecrets) {
        for (const bundleId in keystore.prekeySecrets) {
          const secrets = keystore.prekeySecrets[bundleId];
          secrets.x25519SecretKey = new Uint8Array(secrets.x25519SecretKey as any);
          secrets.mlkemSecretKey = new Uint8Array(secrets.mlkemSecretKey as any);
        }
      }

      console.log('[SecureKeystore] Decryption successful');
      return keystore;
    } catch (err) {
      // AES-GCM auth tag verification failed = wrong password
      console.error('[SecureKeystore] Decryption failed (wrong password or corrupted data)');
      return null;
    }
  }

  /**
   * Load encrypted keystore from IndexedDB
   * SECURITY: Returns encrypted blob, not decrypted data
   */
  async loadEncryptedRecord(userId: string): Promise<EncryptedKeystoreRecord | PlaintextKeystoreRecord | null> {
    const db = await this.openDB();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(['secure-keystore'], 'readonly');
      const store = tx.objectStore('secure-keystore');
      const request = store.get(userId);

      request.onsuccess = () => {
        db.close();
        resolve(request.result || null);
      };

      request.onerror = () => {
        db.close();
        reject(request.error);
      };
    });
  }

  /**
   * Save encrypted keystore to IndexedDB
   * SECURITY: Only saves encrypted data, never plaintext
   */
  async saveEncryptedRecord(userId: string, record: EncryptedKeystoreRecord): Promise<void> {
    const db = await this.openDB();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(['secure-keystore'], 'readwrite');
      const store = tx.objectStore('secure-keystore');
      const request = store.put(record, userId);

      request.onsuccess = () => {
        db.close();
        console.log('[SecureKeystore] Encrypted keystore saved to IndexedDB');
        resolve();
      };

      request.onerror = () => {
        db.close();
        reject(request.error);
      };
    });
  }

  /**
   * Open IndexedDB
   */
  private async openDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open('ilyazh-secure-keystore-v2', 1);

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains('secure-keystore')) {
          db.createObjectStore('secure-keystore');
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Unlock keystore with password
   * SECURITY: Only succeeds if password is correct
   */
  async unlock(userId: string, password: string): Promise<boolean> {
    console.log('[SecureKeystore] Attempting to unlock keystore for user:', userId);

    const record = await this.loadEncryptedRecord(userId);

    if (!record) {
      console.log('[SecureKeystore] No keystore found for user');
      return false;
    }

    // Check if it's an encrypted record (v2)
    if ('version' in record && record.version === 2) {
      const decrypted = await this.decryptKeystore(record as EncryptedKeystoreRecord, password);

      if (!decrypted) {
        console.error('[SecureKeystore] Wrong password');
        return false;
      }

      this.decryptedKeystore = decrypted;
      this.isLocked = false;
      console.log('[SecureKeystore] ✓ Keystore unlocked successfully');
      return true;
    }

    // Legacy plaintext record (v1) - should not happen after migration
    console.warn('[SecureKeystore] Found legacy plaintext keystore - migration required');
    return false;
  }

  /**
   * Create new encrypted keystore
   * SECURITY: Used for first-time setup
   */
  async createNewKeystore(userId: string, password: string): Promise<void> {
    console.log('[SecureKeystore] Creating new encrypted keystore');

    const newKeystore: DecryptedKeystore = {
      version: 2,
      userId,
      createdAt: new Date().toISOString(),
      lastUsedAt: new Date().toISOString(),
    };

    const encrypted = await this.encryptKeystore(newKeystore, password);
    await this.saveEncryptedRecord(userId, encrypted);

    this.decryptedKeystore = newKeystore;
    this.isLocked = false;

    console.log('[SecureKeystore] ✓ New keystore created and unlocked');
  }

  /**
   * Save current keystore state (re-encrypt and persist)
   * SECURITY: Must be unlocked to save
   */
  async save(password: string): Promise<void> {
    if (this.isLocked || !this.decryptedKeystore) {
      throw new Error('[SecureKeystore] Cannot save locked keystore');
    }

    // Update timestamp
    this.decryptedKeystore.lastUsedAt = new Date().toISOString();

    // Re-encrypt and save
    const encrypted = await this.encryptKeystore(this.decryptedKeystore, password);
    await this.saveEncryptedRecord(this.decryptedKeystore.userId, encrypted);
  }

  /**
   * Migrate legacy plaintext keystore to encrypted v2
   * SECURITY: One-time migration, then deletes plaintext data
   */
  async migratePlaintextKeystore(
    userId: string,
    plaintextRecord: PlaintextKeystoreRecord,
    password: string
  ): Promise<void> {
    console.warn('[SecureKeystore] Migrating plaintext keystore to encrypted v2');

    const newKeystore: DecryptedKeystore = {
      version: 2,
      userId,
      identity: plaintextRecord.identity,
      prekeySecrets: plaintextRecord.prekeySecrets,
      sessions: plaintextRecord.sessions,
      createdAt: new Date().toISOString(),
      lastUsedAt: new Date().toISOString(),
    };

    const encrypted = await this.encryptKeystore(newKeystore, password);
    await this.saveEncryptedRecord(userId, encrypted);

    this.decryptedKeystore = newKeystore;
    this.isLocked = false;

    console.log('[SecureKeystore] ✓ Migration complete');
  }

  /**
   * Check if keystore exists for user
   */
  async exists(userId: string): Promise<boolean> {
    const record = await this.loadEncryptedRecord(userId);
    return record !== null;
  }

  /**
   * Update identity in keystore
   * SECURITY: Must be unlocked
   */
  updateIdentity(identity: IdentityKeyPair): void {
    if (this.isLocked || !this.decryptedKeystore) {
      throw new Error('[SecureKeystore] Cannot update locked keystore');
    }
    this.decryptedKeystore.identity = identity;
  }

  /**
   * Update prekey secrets in keystore
   * SECURITY: Must be unlocked
   */
  updatePrekeySecrets(bundleId: string, secrets: PrekeySecrets): void {
    if (this.isLocked || !this.decryptedKeystore) {
      throw new Error('[SecureKeystore] Cannot update locked keystore');
    }
    if (!this.decryptedKeystore.prekeySecrets) {
      this.decryptedKeystore.prekeySecrets = {};
    }
    this.decryptedKeystore.prekeySecrets[bundleId] = secrets;
  }

  /**
   * Update session in keystore
   * SECURITY: Must be unlocked
   */
  updateSession(sessionId: string, session: any): void {
    if (this.isLocked || !this.decryptedKeystore) {
      throw new Error('[SecureKeystore] Cannot update locked keystore');
    }
    if (!this.decryptedKeystore.sessions) {
      this.decryptedKeystore.sessions = {};
    }
    this.decryptedKeystore.sessions[sessionId] = session;
  }

  /**
   * Update relay token in keystore
   * SECURITY: Must be unlocked
   */
  updateRelayToken(token: string): void {
    if (this.isLocked || !this.decryptedKeystore) {
      throw new Error('[SecureKeystore] Cannot update locked keystore');
    }
    this.decryptedKeystore.relayToken = token;
  }
}

// Singleton instance
export const secureKeystore = new SecureKeystoreManager();

/**
 * Check if legacy plaintext keystore exists and needs migration
 */
export async function needsMigration(userId: string): Promise<boolean> {
  const record = await secureKeystore.loadEncryptedRecord(userId);
  if (!record) return false;
  return !('version' in record) || (record.version as any) === 1;
}
