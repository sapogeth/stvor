/**
 * Cryptographic Primitives Layer
 * X25519, Ed25519 via libsodium
 * ML-KEM-768 and ML-DSA-65 via liboqs (OpenForge)
 */

import sodium from 'libsodium-wrappers';
import { hkdf } from '@noble/hashes/hkdf';
import { sha384, sha512 } from '@noble/hashes/sha2';
import { sha256 } from '@noble/hashes/sha256';
import { createMLKEM768, createMLDSA65 } from '@openforge-sh/liboqs';
import type { MLKEM768, MLDSA65 } from '@openforge-sh/liboqs';
import * as constants from './constants.js';

let sodiumReady = false;
let mlkemInstance: MLKEM768 | null = null;
let mldsaInstance: MLDSA65 | null = null;

export async function initCrypto(): Promise<void> {
  if (sodiumReady) return;

  // Initialize libsodium
  await sodium.ready;
  sodiumReady = true;

  // Initialize PQC algorithms
  if (!mlkemInstance) {
    mlkemInstance = await createMLKEM768();
    console.log('[Crypto] ✅ ML-KEM-768 initialized (real PQC, not mocked)');
  }

  if (!mldsaInstance) {
    mldsaInstance = await createMLDSA65();
    console.log('[Crypto] ✅ ML-DSA-65 initialized (real PQC, not mocked)');
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
 * Generate ML-KEM-768 key pair using real post-quantum cryptography
 * Implementation via @openforge-sh/liboqs
 */
export function generateMLKEMKeyPair(): MLKEMKeyPair {
  if (!mlkemInstance) {
    throw new Error('ML-KEM-768 not initialized. Call initCrypto() first.');
  }

  const keyPair = mlkemInstance.generateKeyPair();

  // Validate key sizes match FIPS 203 specification
  if (keyPair.publicKey.length !== constants.ML_KEM_768_PUBLIC_KEY_LENGTH) {
    throw new Error(`ML-KEM-768 public key size mismatch: expected ${constants.ML_KEM_768_PUBLIC_KEY_LENGTH}, got ${keyPair.publicKey.length}`);
  }
  if (keyPair.secretKey.length !== constants.ML_KEM_768_SECRET_KEY_LENGTH) {
    throw new Error(`ML-KEM-768 secret key size mismatch: expected ${constants.ML_KEM_768_SECRET_KEY_LENGTH}, got ${keyPair.secretKey.length}`);
  }

  return {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
  };
}

export function mlkemEncapsulate(publicKey: Uint8Array): MLKEMEncapsulation {
  if (!mlkemInstance) {
    throw new Error('ML-KEM-768 not initialized. Call initCrypto() first.');
  }

  if (publicKey.length !== constants.ML_KEM_768_PUBLIC_KEY_LENGTH) {
    throw new Error('Invalid ML-KEM-768 public key length');
  }

  const result = mlkemInstance.encapsulate(publicKey);

  // Validate output sizes match FIPS 203 specification
  if (result.ciphertext.length !== constants.ML_KEM_768_CIPHERTEXT_LENGTH) {
    throw new Error(`ML-KEM-768 ciphertext size mismatch: expected ${constants.ML_KEM_768_CIPHERTEXT_LENGTH}, got ${result.ciphertext.length}`);
  }
  if (result.sharedSecret.length !== constants.ML_KEM_768_SHARED_SECRET_LENGTH) {
    throw new Error(`ML-KEM-768 shared secret size mismatch: expected ${constants.ML_KEM_768_SHARED_SECRET_LENGTH}, got ${result.sharedSecret.length}`);
  }

  return {
    ciphertext: result.ciphertext,
    sharedSecret: result.sharedSecret,
  };
}

export function mlkemDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (!mlkemInstance) {
    throw new Error('ML-KEM-768 not initialized. Call initCrypto() first.');
  }

  if (ciphertext.length !== constants.ML_KEM_768_CIPHERTEXT_LENGTH) {
    throw new Error('Invalid ML-KEM-768 ciphertext length');
  }
  if (secretKey.length !== constants.ML_KEM_768_SECRET_KEY_LENGTH) {
    throw new Error('Invalid ML-KEM-768 secret key length');
  }

  const sharedSecret = mlkemInstance.decapsulate(ciphertext, secretKey);

  // Validate shared secret size
  if (sharedSecret.length !== constants.ML_KEM_768_SHARED_SECRET_LENGTH) {
    throw new Error(`ML-KEM-768 shared secret size mismatch: expected ${constants.ML_KEM_768_SHARED_SECRET_LENGTH}, got ${sharedSecret.length}`);
  }

  return sharedSecret;
}

// ==================== ML-DSA-65 (Post-Quantum Signatures) ====================

export interface MLDSAKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/**
 * Generate ML-DSA-65 key pair using real post-quantum cryptography
 * Implementation via @openforge-sh/liboqs
 */
export function generateMLDSAKeyPair(): MLDSAKeyPair {
  if (!mldsaInstance) {
    throw new Error('ML-DSA-65 not initialized. Call initCrypto() first.');
  }

  const keyPair = mldsaInstance.generateKeyPair();

  // Validate key sizes match FIPS 204 specification
  if (keyPair.publicKey.length !== constants.ML_DSA_65_PUBLIC_KEY_LENGTH) {
    throw new Error(`ML-DSA-65 public key size mismatch: expected ${constants.ML_DSA_65_PUBLIC_KEY_LENGTH}, got ${keyPair.publicKey.length}`);
  }
  if (keyPair.secretKey.length !== constants.ML_DSA_65_SECRET_KEY_LENGTH) {
    throw new Error(`ML-DSA-65 secret key size mismatch: expected ${constants.ML_DSA_65_SECRET_KEY_LENGTH}, got ${keyPair.secretKey.length}`);
  }

  return {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
  };
}

export function mldsaSign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (!mldsaInstance) {
    throw new Error('ML-DSA-65 not initialized. Call initCrypto() first.');
  }

  if (secretKey.length !== constants.ML_DSA_65_SECRET_KEY_LENGTH) {
    throw new Error('Invalid ML-DSA-65 secret key length');
  }

  const signature = mldsaInstance.sign(message, secretKey);

  // Validate signature size match FIPS 204 specification
  if (signature.length !== constants.ML_DSA_65_SIGNATURE_LENGTH) {
    throw new Error(`ML-DSA-65 signature size mismatch: expected ${constants.ML_DSA_65_SIGNATURE_LENGTH}, got ${signature.length}`);
  }

  return signature;
}

export function mldsaVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (!mldsaInstance) {
    throw new Error('ML-DSA-65 not initialized. Call initCrypto() first.');
  }

  if (signature.length !== constants.ML_DSA_65_SIGNATURE_LENGTH) {
    return false;
  }
  if (publicKey.length !== constants.ML_DSA_65_PUBLIC_KEY_LENGTH) {
    return false;
  }

  return mldsaInstance.verify(message, signature, publicKey);
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
