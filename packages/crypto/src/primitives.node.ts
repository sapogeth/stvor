/**
 * Cryptographic Primitives Layer
 * X25519, Ed25519 via libsodium
 * ML-KEM-768 and ML-DSA-65 via liboqs (OpenForge)
 */

import sodium from 'libsodium-wrappers';
import { hkdf } from '@noble/hashes/hkdf';
import { sha384, sha512 } from '@noble/hashes/sha2';
import { sha256 } from '@noble/hashes/sha256';
import * as constants from './constants.js';

// Import liboqs for post-quantum cryptography
import { createMLKEM768, ML_KEM_768_INFO } from '@openforge-sh/liboqs';
import { createMLDSA65, ML_DSA_65_INFO } from '@openforge-sh/liboqs';
import type { MLKEM768 } from '@openforge-sh/liboqs';
import type { MLDSA65 } from '@openforge-sh/liboqs';

let sodiumReady = false;
let mlkem768: MLKEM768 | null = null;
let mldsa65: MLDSA65 | null = null;

export async function initCrypto(): Promise<void> {
  if (sodiumReady && mlkem768 && mldsa65) return;

  await sodium.ready;
  sodiumReady = true;

  // Initialize liboqs instances (loads WASM modules)
  mlkem768 = await createMLKEM768();
  mldsa65 = await createMLDSA65();

  console.log('[Crypto] ✅ Cryptography initialized (libsodium + liboqs ML-KEM-768 + ML-DSA-65)');

  // Verify wire format sizes match specification
  if (ML_KEM_768_INFO.keySize.publicKey !== constants.ML_KEM_768_PUBLIC_KEY_LENGTH ||
      ML_KEM_768_INFO.keySize.secretKey !== constants.ML_KEM_768_SECRET_KEY_LENGTH ||
      ML_KEM_768_INFO.keySize.ciphertext !== constants.ML_KEM_768_CIPHERTEXT_LENGTH ||
      ML_KEM_768_INFO.keySize.sharedSecret !== constants.ML_KEM_768_SHARED_SECRET_LENGTH) {
    throw new Error('ML-KEM-768 wire format size mismatch');
  }

  if (ML_DSA_65_INFO.keySize.publicKey !== constants.ML_DSA_65_PUBLIC_KEY_LENGTH ||
      ML_DSA_65_INFO.keySize.secretKey !== constants.ML_DSA_65_SECRET_KEY_LENGTH ||
      ML_DSA_65_INFO.keySize.signature !== constants.ML_DSA_65_SIGNATURE_LENGTH) {
    throw new Error('ML-DSA-65 wire format size mismatch');
  }
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

/**
 * ML-KEM-768 Key Generation (FIPS 203)
 * Uses liboqs real post-quantum KEM implementation
 */
export async function generateMLKEMKeyPair(): Promise<MLKEMKeyPair> {
  if (!mlkem768) {
    throw new Error('ML-KEM-768 not initialized. Call initCrypto() first.');
  }

  const keypair = await mlkem768.generateKeyPair();

  // Verify sizes match specification
  if (keypair.publicKey.length !== constants.ML_KEM_768_PUBLIC_KEY_LENGTH ||
      keypair.secretKey.length !== constants.ML_KEM_768_SECRET_KEY_LENGTH) {
    throw new Error('ML-KEM-768 keypair size mismatch');
  }

  return {
    publicKey: keypair.publicKey,
    secretKey: keypair.secretKey,
  };
}

/**
 * ML-KEM-768 Encapsulation (FIPS 203)
 * Generates a shared secret and encrypts it to the recipient's public key
 */
export async function mlkemEncapsulate(publicKey: Uint8Array): Promise<MLKEMEncapsulation> {
  if (!mlkem768) {
    throw new Error('ML-KEM-768 not initialized. Call initCrypto() first.');
  }

  if (publicKey.length !== constants.ML_KEM_768_PUBLIC_KEY_LENGTH) {
    throw new Error(`Invalid ML-KEM-768 public key length: expected ${constants.ML_KEM_768_PUBLIC_KEY_LENGTH}, got ${publicKey.length}`);
  }

  const result = await mlkem768.encapsulate(publicKey);

  // Verify sizes match specification
  if (result.ciphertext.length !== constants.ML_KEM_768_CIPHERTEXT_LENGTH ||
      result.sharedSecret.length !== constants.ML_KEM_768_SHARED_SECRET_LENGTH) {
    throw new Error('ML-KEM-768 encapsulation size mismatch');
  }

  return {
    ciphertext: result.ciphertext,
    sharedSecret: result.sharedSecret,
  };
}

/**
 * ML-KEM-768 Decapsulation (FIPS 203)
 * Decrypts the ciphertext using the secret key to recover the shared secret
 */
export async function mlkemDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  if (!mlkem768) {
    throw new Error('ML-KEM-768 not initialized. Call initCrypto() first.');
  }

  if (ciphertext.length !== constants.ML_KEM_768_CIPHERTEXT_LENGTH) {
    throw new Error(`Invalid ML-KEM-768 ciphertext length: expected ${constants.ML_KEM_768_CIPHERTEXT_LENGTH}, got ${ciphertext.length}`);
  }
  if (secretKey.length !== constants.ML_KEM_768_SECRET_KEY_LENGTH) {
    throw new Error(`Invalid ML-KEM-768 secret key length: expected ${constants.ML_KEM_768_SECRET_KEY_LENGTH}, got ${secretKey.length}`);
  }

  const sharedSecret = await mlkem768.decapsulate(ciphertext, secretKey);

  // Verify size matches specification
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

/**
 * ML-DSA-65 Key Generation (FIPS 204)
 * Uses liboqs real post-quantum signature implementation
 */
export async function generateMLDSAKeyPair(): Promise<MLDSAKeyPair> {
  if (!mldsa65) {
    throw new Error('ML-DSA-65 not initialized. Call initCrypto() first.');
  }

  const keypair = await mldsa65.generateKeyPair();

  // Verify sizes match specification
  if (keypair.publicKey.length !== constants.ML_DSA_65_PUBLIC_KEY_LENGTH ||
      keypair.secretKey.length !== constants.ML_DSA_65_SECRET_KEY_LENGTH) {
    throw new Error('ML-DSA-65 keypair size mismatch');
  }

  return {
    publicKey: keypair.publicKey,
    secretKey: keypair.secretKey,
  };
}

/**
 * ML-DSA-65 Sign (FIPS 204)
 * Signs a message using the secret key
 */
export async function mldsaSign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  if (!mldsa65) {
    throw new Error('ML-DSA-65 not initialized. Call initCrypto() first.');
  }

  if (secretKey.length !== constants.ML_DSA_65_SECRET_KEY_LENGTH) {
    throw new Error(`Invalid ML-DSA-65 secret key length: expected ${constants.ML_DSA_65_SECRET_KEY_LENGTH}, got ${secretKey.length}`);
  }

  const signature = await mldsa65.sign(message, secretKey);

  // Verify size matches specification
  if (signature.length !== constants.ML_DSA_65_SIGNATURE_LENGTH) {
    throw new Error('ML-DSA-65 signature size mismatch');
  }

  return signature;
}

/**
 * ML-DSA-65 Verify (FIPS 204)
 * Verifies a signature on a message using the public key
 */
export async function mldsaVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  if (!mldsa65) {
    throw new Error('ML-DSA-65 not initialized. Call initCrypto() first.');
  }

  if (signature.length !== constants.ML_DSA_65_SIGNATURE_LENGTH) {
    return false;
  }
  if (publicKey.length !== constants.ML_DSA_65_PUBLIC_KEY_LENGTH) {
    return false;
  }

  try {
    return await mldsa65.verify(message, signature, publicKey);
  } catch (error) {
    // Verification failure should return false, not throw
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

// ==================== ChaCha20-Poly1305-IETF (AEAD) ====================
// Using ChaCha20-Poly1305 (IETF variant) for authenticated encryption
// Note: This is superior to AES-GCM for pure software implementations
// and avoids timing attacks that can occur with AES on CPUs without AES-NI

export function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array
): Uint8Array {
  if (key.length !== constants.AEAD_KEY_LENGTH) {
    throw new Error('Invalid AEAD key length');
  }
  if (nonce.length !== constants.AEAD_NONCE_LENGTH) {
    throw new Error('Invalid AEAD nonce length');
  }

  return (sodium as any).crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key);
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
  if (nonce.length !== constants.AEAD_NONCE_LENGTH) {
    throw new Error('Invalid AEAD nonce length');
  }

  return (sodium as any).crypto_aead_chacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, key);
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
// Add fixed-block padding to resist size correlation attacks
// Uses PKCS#7-style padding

const PADDING_BLOCK_SIZE = 256; // 256 bytes (max for PKCS#7 single-byte length)

/**
 * Add PKCS#7-style padding to plaintext
 * Pads to the nearest multiple of PADDING_BLOCK_SIZE
 */
export function addPadding(plaintext: Uint8Array): Uint8Array {
  const paddingNeeded = PADDING_BLOCK_SIZE - (plaintext.length % PADDING_BLOCK_SIZE);
  const padded = new Uint8Array(plaintext.length + paddingNeeded);

  // Copy plaintext
  padded.set(plaintext);

  // Add PKCS#7 padding: fill with padding byte value
  for (let i = plaintext.length; i < padded.length; i++) {
    padded[i] = paddingNeeded;
  }

  return padded;
}

/**
 * Remove PKCS#7-style padding from plaintext
 * Returns original plaintext without padding
 */
export function removePadding(padded: Uint8Array): Uint8Array {
  if (padded.length === 0) {
    throw new Error('Cannot remove padding from empty buffer');
  }

  // Get padding length from last byte
  const paddingLength = padded[padded.length - 1];

  // Validate padding length
  if (paddingLength === 0 || paddingLength > PADDING_BLOCK_SIZE) {
    throw new Error('Invalid padding length');
  }

  if (paddingLength > padded.length) {
    throw new Error('Padding length exceeds buffer size');
  }

  // Verify all padding bytes are correct (constant-time check)
  let validPadding = 1;
  for (let i = 0; i < paddingLength; i++) {
    const expected = paddingLength;
    const actual = padded[padded.length - 1 - i];
    validPadding &= (expected === actual) ? 1 : 0;
  }

  if (validPadding === 0) {
    throw new Error('Invalid padding bytes');
  }

  // Return unpadded data
  return padded.slice(0, padded.length - paddingLength);
}

// ==================== Re-export hash functions ====================

export { sha256, sha384, sha512 };
