/**
 * Type declarations for libsodium-wrappers-sumo
 * Extended version of libsodium-wrappers that includes crypto_pwhash (Argon2id)
 */

declare module 'libsodium-wrappers-sumo' {
  // Re-export everything from libsodium-wrappers but with extended interface
  interface Libsodium {
    // Standard libsodium functions
    ready: Promise<void>;
    crypto_secretbox_KEYBYTES: number;
    crypto_secretbox_NONCEBYTES: number;
    crypto_secretbox_easy(
      plaintext: Uint8Array,
      nonce: Uint8Array,
      key: Uint8Array
    ): Uint8Array;
    crypto_secretbox_open_easy(
      ciphertext: Uint8Array,
      nonce: Uint8Array,
      key: Uint8Array
    ): Uint8Array;
    randombytes_buf(len: number): Uint8Array;
    to_base64(
      buffer: Uint8Array,
      variant?: number
    ): string;
    from_base64(
      encoded: string,
      variant?: number
    ): Uint8Array;
    to_hex(buffer: Uint8Array): string;
    from_hex(encoded: string): Uint8Array;
    base64_variants: {
      ORIGINAL: number;
      ORIGINAL_NO_PADDING: number;
      URLSAFE: number;
      URLSAFE_NO_PADDING: number;
    };

    // Extended: crypto_pwhash (only in -sumo)
    crypto_pwhash(
      keyLength: number,
      password: Uint8Array | Buffer,
      salt: Uint8Array,
      opslimit: number,
      memlimit: number,
      alg: number
    ): Uint8Array;

    crypto_pwhash_OPSLIMIT_SENSITIVE?: number;
    crypto_pwhash_MEMLIMIT_SENSITIVE?: number;
    crypto_pwhash_OPSLIMIT_INTERACTIVE?: number;
    crypto_pwhash_MEMLIMIT_INTERACTIVE?: number;
    crypto_pwhash_ALG_ARGON2ID13?: number;
    crypto_pwhash_SALTBYTES?: number;
  }

  const instance: Libsodium;
  export default instance;
}
