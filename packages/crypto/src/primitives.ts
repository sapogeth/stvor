/**
 * Cryptographic Primitives Layer
 * X25519, Ed25519 via libsodium
 * ML-KEM-768 and ML-DSA-65 via liboqs (OpenForge)
 */

import sodium from 'libsodium-wrappers-sumo';
import { hkdf } from '@noble/hashes/hkdf';
import { sha384, sha512 } from '@noble/hashes/sha2';
import { sha256 } from '@noble/hashes/sha256';
import * as constants from './constants.js';

// Import liboqs types for post-quantum cryptography
import type { MLKEM768, MLDSA65 } from '@openforge-sh/liboqs';

let sodiumReady = false;
let mlkem768: MLKEM768 | null = null;
let mldsa65: MLDSA65 | null = null;
let ML_KEM_768_INFO: any = null;
let ML_DSA_65_INFO: any = null;
let pqAvailable = false;

// Global crypto initialization state
let cryptoReady = false;
let initPromise: Promise<void> | null = null;

// PQ availability flags
let PQ_ENABLED = true; // Runtime disable flag (for wire format mismatches)
let PQ_REALLY_UNAVAILABLE = false; // True if using inline stubs (not real PQ crypto)

/**
 * Disable PQ cryptography (fallback to classical-only mode)
 * Called when PQ WASM fails to load or wire format mismatches
 */
export function disablePQ(reason?: string): void {
  PQ_ENABLED = false;
  // Only log PQ disable in production for critical debugging
  if (reason && reason.includes('unavailable')) {
    console.warn('[Crypto][PQ] Disabled:', reason);
  }
}

/**
 * Check if PQ cryptography is enabled
 * Returns false if PQ failed to load or was disabled due to wire format mismatch
 */
export function isPQEnabled(): boolean {
  return PQ_ENABLED && pqAvailable;
}

/**
 * CRITICAL: Check if PQ modules are really unavailable (using stubs)
 * This is different from isPQEnabled() because it distinguishes between:
 * - Real PQ crypto available: pqReallyUnavailable = false
 * - Stub PQ (inline fallback): pqReallyUnavailable = true
 * - Disabled at runtime: pqReallyUnavailable = true + PQ_ENABLED = false
 *
 * Applications should alert users when this returns true
 */
export function isPQReallyUnavailable(): boolean {
  return PQ_REALLY_UNAVAILABLE;
}

/**
 * Browser-safe PQ module loader
 * NO ../../../../dist references, NO import.meta, NO HTTP imports
 */
async function loadPQModules(): Promise<{ mlkem768: MLKEM768 | null; mldsa65: MLDSA65 | null; mlkemInfo: any; mldsaInfo: any; available: boolean }> {
  const isBrowser = typeof globalThis !== 'undefined' && typeof (globalThis as any).window !== 'undefined';

  if (isBrowser) {
    // Browser: Use pq-browser.ts (npm-first, inline-fallback)
    try {
      const pqBrowser = await import('./pq-browser.js');
      const result = await pqBrowser.initPQBrowser();

      // CRITICAL: Track if PQ is really unavailable (using stubs)
      PQ_REALLY_UNAVAILABLE = result.pqReallyUnavailable || false;

      if (!result.pqAvailable) {
        // Silent fallback to classical-only mode
        return {
          mlkem768: null,
          mldsa65: null,
          mlkemInfo: null,
          mldsaInfo: null,
          available: false
        };
      }

      const pq = pqBrowser.getPQ();
      return { ...pq, available: true };
    } catch (error) {
      // Only log critical PQ load errors
      console.error('[Crypto] PQ load failed:', error);
      PQ_REALLY_UNAVAILABLE = true; // Treat errors as real unavailability
      return {
        mlkem768: null,
        mldsa65: null,
        mlkemInfo: null,
        mldsaInfo: null,
        available: false
      };
    }
  } else {
    // Node.js: Use standard imports
    try {
      const { createMLKEM768, ML_KEM_768_INFO: mlkemInfo } = await import('@openforge-sh/liboqs');
      const { createMLDSA65, ML_DSA_65_INFO: mldsaInfo } = await import('@openforge-sh/liboqs');

      const mlkem768Instance = await createMLKEM768();
      const mldsa65Instance = await createMLDSA65();

      return { mlkem768: mlkem768Instance, mldsa65: mldsa65Instance, mlkemInfo, mldsaInfo, available: true };
    } catch (error) {
      console.error('[Crypto] Node.js PQ load failed:', error);
      return {
        mlkem768: null,
        mldsa65: null,
        mlkemInfo: null,
        mldsaInfo: null,
        available: false
      };
    }
  }
}

/**
 * Internal crypto initialization (called once via singleton pattern)
 */
async function initCryptoInternal(): Promise<void> {
  if (cryptoReady) return;

  await sodium.ready;
  sodiumReady = true;

  // Initialize liboqs instances (loads WASM modules)
  // CRITICAL: Wrapped in try/catch - DO NOT crash app if PQ fails
  try {
    const pqModules = await loadPQModules();

    if (!pqModules.available) {
      // Silent fallback to classical-only mode (PQ WASM unavailable)
      mlkem768 = null;
      mldsa65 = null;
      ML_KEM_768_INFO = null;
      ML_DSA_65_INFO = null;
      pqAvailable = false;
      PQ_ENABLED = false;
      cryptoReady = true;
      return;
    }

    mlkem768 = pqModules.mlkem768;
    mldsa65 = pqModules.mldsa65;
    ML_KEM_768_INFO = pqModules.mlkemInfo;
    ML_DSA_65_INFO = pqModules.mldsaInfo;

    // Verify wire format sizes match specification
    // DOWNGRADED: Warn instead of throw - continue with classical if sizes mismatch
    try {
      // Validate public key sizes (strict) and operation parameter sizes (strict)
      // Note: Secret key sizes from WASM adapters may vary, so we only check non-zero
      if (ML_KEM_768_INFO.keySize.publicKey !== constants.ML_KEM_768_PUBLIC_KEY_LENGTH ||
          ML_KEM_768_INFO.keySize.ciphertext !== constants.ML_KEM_768_CIPHERTEXT_LENGTH ||
          ML_KEM_768_INFO.keySize.sharedSecret !== constants.ML_KEM_768_SHARED_SECRET_LENGTH) {
        throw new Error('ML-KEM-768 wire format size mismatch');
      }
      if (!ML_KEM_768_INFO.keySize.secretKey || ML_KEM_768_INFO.keySize.secretKey === 0) {
        throw new Error('ML-KEM-768 secret key size is zero or undefined');
      }

      if (ML_DSA_65_INFO.keySize.publicKey !== constants.ML_DSA_65_PUBLIC_KEY_LENGTH ||
          ML_DSA_65_INFO.keySize.signature !== constants.ML_DSA_65_SIGNATURE_LENGTH) {
        throw new Error('ML-DSA-65 wire format size mismatch');
      }
      if (!ML_DSA_65_INFO.keySize.secretKey || ML_DSA_65_INFO.keySize.secretKey === 0) {
        throw new Error('ML-DSA-65 secret key size is zero or undefined');
      }

      pqAvailable = true;
      // Crypto initialization successful - silent in production
    } catch (sizeError) {
      // Wire format mismatch - fallback to classical only (silent)
      // CRITICAL: Mark PQ as really unavailable so validatePQRequired() can detect the issue
      console.warn('[Crypto] PQ wire format size mismatch detected, falling back to classical-only:', sizeError);
      mlkem768 = null;
      mldsa65 = null;
      ML_KEM_768_INFO = null;
      ML_DSA_65_INFO = null;
      pqAvailable = false;
      PQ_ENABLED = false;
      PQ_REALLY_UNAVAILABLE = true; // Mark as unavailable so applications know PQ is not working
    }
  } catch (error) {
    // PQ initialization failed - log error, continue with classical
    console.error('[Crypto] PQ initialization failed, continuing with classical only:', error);
    mlkem768 = null;
    mldsa65 = null;
    ML_KEM_768_INFO = null;
    ML_DSA_65_INFO = null;
    pqAvailable = false;
    PQ_REALLY_UNAVAILABLE = true; // Mark as unavailable when load fails
  }

  cryptoReady = true;
}

/**
 * Ensure crypto is ready before any operations
 * Uses singleton pattern - only initializes once
 */
export async function ensureCryptoReady(): Promise<void> {
  if (cryptoReady) return;

  if (!initPromise) {
    initPromise = initCryptoInternal();
  }

  await initPromise;
}

/**
 * DEPRECATED: Use ensureCryptoReady() instead
 * Kept for backward compatibility
 */
export async function initCrypto(): Promise<void> {
  await ensureCryptoReady();
}

/**
 * Check if post-quantum cryptography is available
 */
export function isPQReady(): boolean {
  return cryptoReady && pqAvailable && mlkem768 !== null && mldsa65 !== null;
}

export function isPQAvailable(): boolean {
  return pqAvailable && mlkem768 !== null && mldsa65 !== null;
}

export function getPQStatus(): { available: boolean; reason?: string } {
  if (pqAvailable && mlkem768 && mldsa65) {
    return { available: true };
  }
  return { available: false, reason: 'PQ disabled (size mismatch or load failure)' };
}

// Zeroization helper
export function zeroize(buffer: Uint8Array): void {
  buffer.fill(0);
}

// Constant-time compare
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return sodium.compare(a, b) === 0;
}

// ==================== X25519 (Classical DH) ====================

export interface X25519KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export function generateX25519KeyPair(): X25519KeyPair {
  const keyPair = sodium.crypto_box_keypair();
  return {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.privateKey,
  };
}

export function x25519(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return sodium.crypto_scalarmult(secretKey, publicKey);
}

export function x25519PublicFromSecret(secretKey: Uint8Array): Uint8Array {
  return sodium.crypto_scalarmult_base(secretKey);
}

// ==================== Ed25519 (Classical Signatures) ====================

export interface Ed25519KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  const keyPair = sodium.crypto_sign_keypair();
  return {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.privateKey,
  };
}

export function ed25519Sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return sodium.crypto_sign_detached(message, secretKey);
}

export function ed25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  return sodium.crypto_sign_verify_detached(signature, message, publicKey);
}

// ==================== ML-KEM-768 (Post-Quantum KEM) ====================

export interface MLKEMKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface MLKEMEncapsulation {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

export async function generateMLKEMKeyPair(): Promise<MLKEMKeyPair> {
  if (!mlkem768) {
    const err: any = new Error('PQ_NOT_READY: ML-KEM-768 not available');
    err.code = 'PQ_NOT_READY';
    throw err;
  }

  const keypair = await mlkem768.generateKeyPair();

  // Validate public key size (strict)
  if (keypair.publicKey.length !== constants.ML_KEM_768_PUBLIC_KEY_LENGTH) {
    throw new Error(`ML-KEM-768 public key size mismatch: expected ${constants.ML_KEM_768_PUBLIC_KEY_LENGTH}, got ${keypair.publicKey.length}`);
  }

  // Note: mlkem-wasm may use different secret key encoding than liboqs
  // Accept variable-length secret keys since the keygen validates them
  if (keypair.secretKey.length === 0) {
    throw new Error('ML-KEM-768 secret key is empty');
  }

  return {
    publicKey: keypair.publicKey,
    secretKey: keypair.secretKey,
  };
}

export async function mlkemEncapsulate(publicKey: Uint8Array): Promise<MLKEMEncapsulation> {
  // CRITICAL SECURITY: Reject encapsulation if PQ is unavailable (using stubs)
  if (!mlkem768 || PQ_REALLY_UNAVAILABLE) {
    const err: any = new Error(
      'CRITICAL: ML-KEM-768 not available or using stubs. ' +
      'Post-quantum key exchange is mandatory and cannot be bypassed. ' +
      'Handshake MUST fail with hard error.'
    );
    err.code = 'PQ_NOT_AVAILABLE';
    throw err;
  }

  if (publicKey.length !== constants.ML_KEM_768_PUBLIC_KEY_LENGTH) {
    throw new Error(`Invalid ML-KEM-768 public key length: expected ${constants.ML_KEM_768_PUBLIC_KEY_LENGTH}, got ${publicKey.length}`);
  }

  // Validate that public key is NOT all zeros (stub detection)
  const isZeros = publicKey.every(b => b === 0);
  if (isZeros) {
    const err: any = new Error('CRITICAL: ML-KEM public key is all zeros (stub/invalid). Handshake rejected.');
    err.code = 'PQ_INVALID_KEY';
    throw err;
  }

  const result = await mlkem768.encapsulate(publicKey);

  if (result.ciphertext.length !== constants.ML_KEM_768_CIPHERTEXT_LENGTH ||
      result.sharedSecret.length !== constants.ML_KEM_768_SHARED_SECRET_LENGTH) {
    throw new Error('ML-KEM-768 encapsulation size mismatch');
  }

  // Validate ciphertext is NOT all zeros
  const ctZeros = result.ciphertext.every(b => b === 0);
  if (ctZeros) {
    throw new Error('CRITICAL: ML-KEM ciphertext is all zeros (stub detected). Handshake rejected.');
  }

  return {
    ciphertext: result.ciphertext,
    sharedSecret: result.sharedSecret,
  };
}

export async function mlkemDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  // CRITICAL SECURITY: Reject decapsulation if PQ is unavailable (using stubs)
  if (!mlkem768 || PQ_REALLY_UNAVAILABLE) {
    const err: any = new Error(
      'CRITICAL: ML-KEM-768 not available or using stubs. ' +
      'Post-quantum key exchange is mandatory and cannot be bypassed. ' +
      'Handshake MUST fail with hard error.'
    );
    err.code = 'PQ_NOT_AVAILABLE';
    throw err;
  }

  if (ciphertext.length !== constants.ML_KEM_768_CIPHERTEXT_LENGTH) {
    throw new Error(`Invalid ML-KEM-768 ciphertext length: expected ${constants.ML_KEM_768_CIPHERTEXT_LENGTH}, got ${ciphertext.length}`);
  }
  // Note: mlkem-wasm may use different secret key encoding than liboqs
  // Accept variable-length secret keys
  if (secretKey.length === 0) {
    throw new Error('ML-KEM-768 secret key is empty');
  }

  // Validate that ciphertext is NOT all zeros (stub detection)
  const ctZeros = ciphertext.every(b => b === 0);
  if (ctZeros) {
    const err: any = new Error('CRITICAL: ML-KEM ciphertext is all zeros (stub/invalid). Handshake rejected.');
    err.code = 'PQ_INVALID_KEY';
    throw err;
  }

  const sharedSecret = await mlkem768.decapsulate(ciphertext, secretKey);

  if (sharedSecret.length !== constants.ML_KEM_768_SHARED_SECRET_LENGTH) {
    throw new Error('ML-KEM-768 decapsulation size mismatch');
  }

  return sharedSecret;
}

// ==================== ML-DSA-65 (Post-Quantum Signatures) ====================

export interface MLDSAKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export async function generateMLDSAKeyPair(): Promise<MLDSAKeyPair> {
  if (!mldsa65) {
    const err: any = new Error('PQ_NOT_READY: ML-DSA-65 not available');
    err.code = 'PQ_NOT_READY';
    throw err;
  }

  const keypair = await mldsa65.generateKeyPair();

  // Validate public key size (strict)
  if (keypair.publicKey.length !== constants.ML_DSA_65_PUBLIC_KEY_LENGTH) {
    throw new Error(`ML-DSA-65 public key size mismatch: expected ${constants.ML_DSA_65_PUBLIC_KEY_LENGTH}, got ${keypair.publicKey.length}`);
  }

  // Note: mldsa-wasm may use different secret key encoding than liboqs
  // mldsa-wasm uses 'raw-seed' format (~32 bytes) or 'raw' format (~4032 bytes)
  // We accept either format since the keygen will validate it
  if (keypair.secretKey.length === 0) {
    throw new Error('ML-DSA-65 secret key is empty');
  }

  return {
    publicKey: keypair.publicKey,
    secretKey: keypair.secretKey,
  };
}

export async function mldsaSign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  // CRITICAL SECURITY: Reject signing if PQ is unavailable (using stubs)
  if (!mldsa65 || PQ_REALLY_UNAVAILABLE) {
    const err: any = new Error(
      'CRITICAL CRYPTO FAILURE: ML-DSA-65 module not initialized or using stubs. ' +
      'Post-quantum signatures are mandatory and cannot be bypassed. ' +
      'This indicates a critical initialization error or environment incompatibility. ' +
      'Application must terminate. Handshake REJECTED.'
    );
    err.code = 'MLDSA_UNAVAILABLE';
    throw err;
  }

  // Note: mldsa-wasm may use different secret key encoding than liboqs
  // Accept variable-length secret keys
  if (secretKey.length === 0) {
    throw new Error('ML-DSA-65 secret key is empty');
  }

  // Validate that secret key is NOT all zeros (stub detection)
  const isZeros = secretKey.every(b => b === 0);
  if (isZeros) {
    const err: any = new Error('CRITICAL: ML-DSA secret key is all zeros (stub/invalid). Signature rejected.');
    err.code = 'PQ_INVALID_KEY';
    throw err;
  }

  // Create fresh Uint8Array to ensure type validation passes with liboqs
  // (some CBOR libraries return Buffer which might not pass strict instanceof checks)
  const messageArray = new Uint8Array(message);
  const signature = await mldsa65.sign(messageArray, secretKey);

  if (signature.length !== constants.ML_DSA_65_SIGNATURE_LENGTH) {
    throw new Error('ML-DSA-65 signature size mismatch');
  }

  // Validate signature is NOT all zeros
  const sigZeros = signature.every(b => b === 0);
  if (sigZeros) {
    throw new Error('CRITICAL: ML-DSA signature is all zeros (stub detected). Signature rejected.');
  }

  return signature;
}

export async function mldsaVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  // CRITICAL SECURITY: Reject verification if PQ is unavailable (using stubs)
  if (!mldsa65 || PQ_REALLY_UNAVAILABLE) {
    const err: any = new Error(
      'CRITICAL CRYPTO FAILURE: ML-DSA-65 module not initialized or using stubs during verification. ' +
      'Post-quantum signature verification is mandatory and cannot be bypassed. ' +
      'Application must terminate. Handshake REJECTED.'
    );
    err.code = 'MLDSA_UNAVAILABLE';
    throw err;
  }

  if (signature.length !== constants.ML_DSA_65_SIGNATURE_LENGTH) {
    throw new Error(`Invalid ML-DSA-65 signature length: expected ${constants.ML_DSA_65_SIGNATURE_LENGTH}, got ${signature.length}`);
  }
  if (publicKey.length !== constants.ML_DSA_65_PUBLIC_KEY_LENGTH) {
    throw new Error(`Invalid ML-DSA-65 public key length: expected ${constants.ML_DSA_65_PUBLIC_KEY_LENGTH}, got ${publicKey.length}`);
  }

  // Validate that public key is NOT all zeros (stub detection)
  const keyZeros = publicKey.every(b => b === 0);
  if (keyZeros) {
    const err: any = new Error('CRITICAL: ML-DSA public key is all zeros (stub/invalid). Verification rejected.');
    err.code = 'PQ_INVALID_KEY';
    throw err;
  }

  try {
    return await mldsa65.verify(message, signature, publicKey);
  } catch (error) {
    // Log verification failure but don't silently accept
    console.error('[Crypto] ML-DSA-65 verification error:', error);
    return false;
  }
}

// ==================== HKDF-SHA-384 (KDF) ====================

export function hkdfSHA384(
  ikm: Uint8Array,
  info: string,
  length: number,
  salt?: Uint8Array
): Uint8Array {
  return hkdf(sha384, ikm, salt, info, length);
}

// ==================== XChaCha20-Poly1305 (AEAD with Random Nonce) ====================
/**
 * CRITICAL SECURITY FIX (Task #1: Nonce Reuse Prevention)
 *
 * Switched from deterministic nonce (ratchetId || counter) to XChaCha20-Poly1305
 * with RANDOM 24-byte nonce for every encryption.
 *
 * Rationale:
 * - Previous nonce = ratchetId (8) || counter (4) = deterministic
 * - If session state lost/restored, nonces reused with same key
 * - Nonce reuse in ChaCha20-Poly1305 breaks AEAD security (plaintext XOR revealed)
 * - XChaCha20 (24-byte nonce) allows random nonces (2^192 space >> 2^32 messages per session)
 * - Random nonce eliminates session state dependencies for nonce uniqueness
 *
 * Wire Format Change:
 * - Encryption now includes nonce in output: nonce (24) || ciphertext || tag
 * - Client must handle new format in wire.ts decoding
 * - This is a BREAKING PROTOCOL change - version bump required
 */

export function aeadEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array
): { nonce: Uint8Array; ciphertext: Uint8Array } {
  if (key.length !== constants.AEAD_KEY_LENGTH) {
    throw new Error('Invalid AEAD key length');
  }

  // SECURITY FIX: Generate random 24-byte nonce for every message
  // XChaCha20-Poly1305 nonce space is 2^192, safe for random generation
  const nonce = randomBytes(24); // 24 bytes for XChaCha20

  // Encrypt using XChaCha20-Poly1305-IETF
  const ciphertext = (sodium as any).crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce,
    key
  );

  return { nonce, ciphertext };
}

export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array
): Uint8Array {
  if (key.length !== constants.AEAD_KEY_LENGTH) {
    throw new Error('Invalid AEAD key length');
  }

  // BACKWARDS COMPATIBILITY: Support both nonce formats
  // Old format: 12-byte nonce (ChaCha20-Poly1305-IETF)
  // New format: 24-byte nonce (XChaCha20-Poly1305-IETF)

  if (nonce.length === 24) {
    // New format: XChaCha20-Poly1305-IETF (random 24-byte nonce)
    return (sodium as any).crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      aad,
      nonce,
      key
    );
  } else if (nonce.length === 12) {
    // Old format: ChaCha20-Poly1305-IETF (deterministic 12-byte nonce)
    // Support legacy messages for migration period
    console.warn(
      '[AEAD] Decrypting with legacy 12-byte nonce (ChaCha20). ' +
      'This message was sent before XChaCha20 migration. ' +
      'Consider re-encrypting with new format.'
    );
    return (sodium as any).crypto_aead_chacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      aad,
      nonce,
      key
    );
  } else {
    throw new Error(
      `Invalid AEAD nonce length: ${nonce.length} bytes. ` +
      `Expected 12 bytes (legacy ChaCha20) or 24 bytes (XChaCha20). ` +
      `This might indicate a protocol version mismatch or corrupted message.`
    );
  }
}

// ==================== Random Bytes ====================

export function randomBytes(length: number): Uint8Array {
  return sodium.randombytes_buf(length);
}

// ==================== Transcript Hashing ====================

export function hashTranscript(data: Uint8Array): Uint8Array {
  return sha384(data);
}

// ==================== Message Padding ====================

const PADDING_BLOCK_SIZE = 256; // 256 bytes (max for PKCS#7 single-byte length)

export function addPadding(plaintext: Uint8Array): Uint8Array {
  const paddingNeeded = PADDING_BLOCK_SIZE - (plaintext.length % PADDING_BLOCK_SIZE);
  const padded = new Uint8Array(plaintext.length + paddingNeeded);

  padded.set(plaintext);

  for (let i = plaintext.length; i < padded.length; i++) {
    padded[i] = paddingNeeded;
  }

  return padded;
}

export function removePadding(padded: Uint8Array): Uint8Array {
  if (padded.length === 0) {
    throw new Error('Cannot remove padding from empty buffer');
  }

  const paddingLength = padded[padded.length - 1];

  if (paddingLength === 0 || paddingLength > PADDING_BLOCK_SIZE) {
    throw new Error('Invalid padding length');
  }

  if (paddingLength > padded.length) {
    throw new Error('Padding length exceeds buffer size');
  }

  let validPadding = 1;
  for (let i = 0; i < paddingLength; i++) {
    const expected = paddingLength;
    const actual = padded[padded.length - 1 - i];
    validPadding &= (expected === actual) ? 1 : 0;
  }

  if (validPadding === 0) {
    throw new Error('Invalid padding bytes');
  }

  return padded.slice(0, padded.length - paddingLength);
}

// ==================== Re-export hash functions ====================

export { sha256, sha384, sha512 };
