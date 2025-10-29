/**
 * Ilyazh-Web3E2E Protocol Constants
 * Normative values per specification
 */

export const PROTOCOL_VERSION = 0x08; // v0.8
export const SUITE_ID = new Uint8Array([
  0x49, 0x4c, 0x59, 0x41, 0x5a, 0x48, // "ILYAZH"
  0x00, 0x08 // version 0.8
]);

// KDF Domain-separated labels (MUST use verbatim)
export const LABEL_SESSION_ID = "ilyazh/v0.8/session id";
export const LABEL_ROOT_KEY = "ilyazh/v0.8/root key";
export const LABEL_CHAIN_KEYS = "ilyazh/v0.8/chain keys";
export const LABEL_MESSAGE_KEY = "mk";
export const LABEL_CHAIN_KEY = "ck";

// Key sizes (bytes)
export const X25519_PUBLIC_KEY_LENGTH = 32;
export const X25519_SECRET_KEY_LENGTH = 32;
export const ED25519_PUBLIC_KEY_LENGTH = 32;
export const ED25519_SECRET_KEY_LENGTH = 64;
export const ED25519_SIGNATURE_LENGTH = 64;

// ML-KEM-768 sizes (FIPS 203)
export const ML_KEM_768_PUBLIC_KEY_LENGTH = 1184;
export const ML_KEM_768_SECRET_KEY_LENGTH = 2400;
export const ML_KEM_768_CIPHERTEXT_LENGTH = 1088;
export const ML_KEM_768_SHARED_SECRET_LENGTH = 32;

// ML-DSA-65 sizes (FIPS 204)
export const ML_DSA_65_PUBLIC_KEY_LENGTH = 1952;
export const ML_DSA_65_SECRET_KEY_LENGTH = 4032;
export const ML_DSA_65_SIGNATURE_LENGTH = 3309;

// Derived key sizes
export const SESSION_ID_LENGTH = 32;
export const ROOT_KEY_LENGTH = 64;
export const CHAIN_KEY_LENGTH = 64;
export const MESSAGE_KEY_LENGTH = 32;
export const AEAD_KEY_LENGTH = 32; // AES-256
export const AEAD_NONCE_LENGTH = 12; // GCM nonce
export const AEAD_TAG_LENGTH = 16;

// Nonce structure: R64 || C32
export const RATCHET_ID_LENGTH = 8; // 64-bit ratchet epoch ID
export const COUNTER_LENGTH = 4; // 32-bit monotonic counter

// Mandated cadence limits (normative)
export const REKEY_MESSAGE_LIMIT = 1 << 20; // 2^20 messages per epoch
export const REKEY_TIME_LIMIT_MS = 24 * 60 * 60 * 1000; // 24 hours
export const SESSION_MESSAGE_CAP = Math.pow(2, 32); // 2^32 total messages
export const SESSION_TIME_CAP_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// Wire format
export const AAD_MIN_LENGTH = 8 + 8 + 32 + 8; // Version(8) + Suite(8) + sid(32) + Seq(8)
