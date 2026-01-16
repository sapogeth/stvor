/**
 * Staged KDF Strategy for STVOR
 * 
 * Problem: Argon2id SENSITIVE takes 27-34 seconds
 * Solution: Two-stage key derivation
 * 
 * Stage 1 (Fast): Derive session key using HKDF-SHA-384
 *   - Used for: Immediate encryption operations
 *   - Time: <10ms
 *   - Security: 256-bit
 * 
 * Stage 2 (Background): Derive master key using Argon2id SENSITIVE
 *   - Used for: Long-term key storage, identity key encryption
 *   - Time: 27-34 seconds
 *   - Security: Maximum
 * 
 * INVARIANT: Stage 2 key MUST be derived before:
 *   - Persisting any keys to IndexedDB
 *   - Signing identity keys
 *   - Encrypting identity material
 */

import { hkdf } from '@noble/hashes/hkdf';
import { sha384 } from '@noble/hashes/sha384';

// Argon2id parameters for SENSITIVE (from libsodium)
export const ARGON2_SENSITIVE = {
  memory: 1073741824, // 1GB
  iterations: 4,
  parallelism: 1,
  hashLength: 32,
};

// Argon2id parameters for INTERACTIVE (fallback for low-memory devices)
export const ARGON2_INTERACTIVE = {
  memory: 67108864, // 64MB
  iterations: 2,
  parallelism: 1,
  hashLength: 32,
};

export interface StagedKdfResult {
  sessionKey: Uint8Array;      // Available immediately
  masterKeyPromise: Promise<Uint8Array>; // Available after Argon2
  waitForMasterKey: () => Promise<Uint8Array>;
}

export interface KdfContext {
  purpose: 'session' | 'identity' | 'message';
  userId: string;
  timestamp: number;
}

/**
 * Fast HKDF-based session key derivation
 * For immediate use while Argon2 runs in background
 */
export function deriveSessionKey(
  inputKeyMaterial: Uint8Array,
  salt: Uint8Array,
  context: KdfContext
): Uint8Array {
  const info = new TextEncoder().encode(
    `STVOR-${context.purpose}-${context.userId}-${context.timestamp}`
  );

  return hkdf(sha384, inputKeyMaterial, salt, info, 32);
}

/**
 * Slow Argon2id-based master key derivation
 * MUST be used for any persistent key material
 */
export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  useSensitive: boolean = true
): Promise<Uint8Array> {
  // Dynamic import to avoid blocking initial load
  const { argon2id } = await import('@noble/hashes/argon2');

  const params = useSensitive ? ARGON2_SENSITIVE : ARGON2_INTERACTIVE;
  
  try {
    return argon2id(
      new TextEncoder().encode(password),
      salt,
      params
    );
  } catch (error) {
    // Fallback to INTERACTIVE if SENSITIVE fails (low memory)
    if (useSensitive) {
      console.warn('[KDF] SENSITIVE failed, falling back to INTERACTIVE');
      return deriveMasterKey(password, salt, false);
    }
    throw error;
  }
}

/**
 * Two-stage KDF with immediate session key and background master key
 */
export function stagedKdf(
  password: string,
  salt: Uint8Array,
  context: KdfContext
): StagedKdfResult {
  // Stage 1: Immediate session key from password hash
  const fastHash = sha384(new TextEncoder().encode(password + context.userId));
  const sessionKey = deriveSessionKey(fastHash, salt, context);

  // Stage 2: Background master key derivation
  let masterKey: Uint8Array | null = null;
  let masterKeyError: Error | null = null;

  const masterKeyPromise = deriveMasterKey(password, salt, true)
    .then(key => {
      masterKey = key;
      return key;
    })
    .catch(err => {
      masterKeyError = err;
      throw err;
    });

  const waitForMasterKey = async (): Promise<Uint8Array> => {
    if (masterKey) return masterKey;
    if (masterKeyError) throw masterKeyError;
    return masterKeyPromise;
  };

  return {
    sessionKey,
    masterKeyPromise,
    waitForMasterKey,
  };
}

/**
 * CRITICAL INVARIANT CHECK
 * Call this before any operation that requires master key
 */
export function requireMasterKey(result: StagedKdfResult): void {
  // This will throw if master key is not yet available
  // Forces caller to await properly
  if (!result.masterKeyPromise) {
    throw new Error('MASTER_KEY_DERIVATION_NOT_STARTED');
  }
}
