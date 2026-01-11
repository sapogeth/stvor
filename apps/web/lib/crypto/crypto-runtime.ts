/**
 * Crypto Runtime Initialization
 * 
 * CRITICAL: Registers SHA-512 backend for @noble/ed25519
 * 
 * @noble/ed25519 requires explicit SHA-512 function registration
 * because it doesn't want to bundle hash implementations.
 * 
 * We use libsodium's constant-time SHA-512 for maximum security:
 * - Timing-attack resistant
 * - Battle-tested (used by Signal, Wire, Matrix)
 * - Same implementation in Node and Browser
 * - No WebCrypto quirks
 * 
 * MUST be called BEFORE any Ed25519 operations (signing, verification)
 */

import * as ed from '@noble/ed25519';

/**
 * Initialize crypto runtime - registers SHA-512 backend
 * 
 * Call this AFTER libsodium is initialized but BEFORE:
 * - generatePrekey
 * - ratchetInit
 * - serializeForSigning
 * - any Ed25519 operations
 * 
 * @example
 * ```typescript
 * await initCryptoRuntime();
 * // Now Ed25519 operations will work
 * const signature = await ed25519Sign(message, secretKey);
 * ```
 */
export async function initCryptoRuntime(): Promise<void> {
  // Get libsodium sha512 from already-initialized crypto module
  // This avoids direct import that causes webpack issues
  const crypto = await import('@/lib/crypto');
  
  if (typeof crypto.sha512Sodium !== 'function') {
    throw new Error('sha512Sodium not available from crypto module - ensure libsodium is initialized');
  }

  // Register constant-time SHA-512 from libsodium
  ed.etc.sha512Sync = (msg: Uint8Array): Uint8Array => {
    return crypto.sha512Sodium(msg);
  };

  // Also set async version (required by some @noble/ed25519 code paths)
  ed.etc.sha512Async = async (...messages: Uint8Array[]): Promise<Uint8Array> => {
    const concatenated = ed.etc.concatBytes(...messages);
    return crypto.sha512Sodium(concatenated);
  };

  console.log('[crypto-runtime] SHA-512 backend registered (libsodium constant-time)');
}
