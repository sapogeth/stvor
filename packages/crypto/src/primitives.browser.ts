/**
 * Browser-Safe Cryptographic Primitives Loader
 * Uses public static paths for WASM bundles
 */

import sodium from 'libsodium-wrappers';
import { hkdf } from '@noble/hashes/hkdf';
import { sha384, sha512 } from '@noble/hashes/sha2';
import { sha256 } from '@noble/hashes/sha256';
import * as constants from './constants.js';

// Browser-safe paths for PQ WASM bundles
const ML_KEM_PATH = '/oqs/ml-kem-768.min.js';
const ML_DSA_PATH = '/oqs/ml-dsa-65.min.js';

// Type definitions
interface MLKEM768 {
  generateKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }>;
  encapsulate(publicKey: Uint8Array): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }>;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array>;
}

interface MLDSA65 {
  generateKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }>;
  sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array>;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
}

let sodiumReady = false;
let mlkem768: MLKEM768 | null = null;
let mldsa65: MLDSA65 | null = null;

/**
 * Load PQ WASM bundle from browser-accessible path
 */
async function loadPQModule<T>(path: string, moduleName: string): Promise<T> {
  const isBrowser = typeof globalThis !== 'undefined' && typeof (globalThis as any).document !== 'undefined';
  if (!isBrowser) {
    throw new Error(`${moduleName} loader requires browser environment`);
  }

  try {
    // Dynamic import from public path
    const module = await import(/* @vite-ignore */ path);

    if (!module || typeof module.default !== 'function') {
      throw new Error(`${moduleName}: Invalid module structure`);
    }

    const instance = await module.default();
    console.log(`[Crypto] ✅ ${moduleName} loaded from ${path}`);
    return instance as T;
  } catch (error) {
    console.error(`[Crypto] ❌ Failed to load ${moduleName} from ${path}:`, error);
    throw new Error(`PQ module ${moduleName} not available: ${error}`);
  }
}

export async function initCrypto(): Promise<void> {
  if (sodiumReady && mlkem768 && mldsa65) {
    console.log('[Crypto] Already initialized');
    return;
  }

  try {
    // Step 1: Initialize libsodium
    await sodium.ready;
    sodiumReady = true;
    console.log('[Crypto] ✅ libsodium ready');

    // Step 2: Load ML-KEM-768 from public path
    mlkem768 = await loadPQModule<MLKEM768>(ML_KEM_PATH, 'ML-KEM-768');

    // Step 3: Load ML-DSA-65 from public path
    mldsa65 = await loadPQModule<MLDSA65>(ML_DSA_PATH, 'ML-DSA-65');

    console.log('[Crypto] ✅ All cryptography initialized (libsodium + PQ)');
  } catch (error) {
    console.error('[Crypto] ❌ Initialization failed:', error);
    throw error;
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

export async function generateMLKEMKeyPair(): Promise<MLKEMKeyPair> {
  if (!mlkem768) {
    throw new Error('ML-KEM-768 not initialized. Call initCrypto() first.');
  }
  return await mlkem768.generateKeyPair();
}

export async function mlkemEncapsulate(publicKey: Uint8Array): Promise<MLKEMEncapsulation> {
  if (!mlkem768) {
    throw new Error('ML-KEM-768 not initialized. Call initCrypto() first.');
  }
  return await mlkem768.encapsulate(publicKey);
}

export async function mlkemDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  if (!mlkem768) {
    throw new Error('ML-KEM-768 not initialized. Call initCrypto() first.');
  }
  return await mlkem768.decapsulate(ciphertext, secretKey);
}

// ==================== ML-DSA-65 (Post-Quantum Signatures) ====================

export interface MLDSAKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export async function generateMLDSAKeyPair(): Promise<MLDSAKeyPair> {
  if (!mldsa65) {
    throw new Error('ML-DSA-65 not initialized. Call initCrypto() first.');
  }
  return await mldsa65.generateKeyPair();
}

export async function mldsaSign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  if (!mldsa65) {
    throw new Error('ML-DSA-65 not initialized. Call initCrypto() first.');
  }
  return await mldsa65.sign(message, secretKey);
}

export async function mldsaVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  if (!mldsa65) {
    throw new Error('ML-DSA-65 not initialized. Call initCrypto() first.');
  }
  try {
    return await mldsa65.verify(message, signature, publicKey);
  } catch {
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
  console.log('[removePadding] Input length:', padded.length);
  console.log('[removePadding] Last 10 bytes:', Array.from(padded.slice(-10)));

  if (padded.length === 0) {
    throw new Error('Cannot remove padding from empty buffer');
  }
  const paddingLength = padded[padded.length - 1];
  console.log('[removePadding] Padding length from last byte:', paddingLength);

  if (paddingLength === 0 || paddingLength > PADDING_BLOCK_SIZE || paddingLength > padded.length) {
    console.error('[removePadding] ❌ Invalid padding length:', paddingLength);
    throw new Error('Invalid padding');
  }
  // Constant-time validation
  let validPadding = 1;
  for (let i = 0; i < paddingLength; i++) {
    validPadding &= (padded[padded.length - 1 - i] === paddingLength) ? 1 : 0;
  }
  if (validPadding === 0) {
    console.error('[removePadding] ❌ Invalid padding bytes - not all equal to paddingLength');
    throw new Error('Invalid padding bytes');
  }

  const result = padded.slice(0, padded.length - paddingLength);
  console.log('[removePadding] Output length:', result.length);
  return result;
}

// Re-export hash functions
export { sha256, sha384, sha512 };
