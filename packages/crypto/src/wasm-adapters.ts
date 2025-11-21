/**
 * WASM Adapter Modules
 * Converts WebCrypto-style APIs from mlkem-wasm and mldsa-wasm
 * into our expected MLKEM768 and MLDSA65 interfaces
 *
 * These packages provide:
 * - mlkem-wasm: ML-KEM-768 WebAssembly with WebCrypto API
 * - mldsa-wasm: ML-DSA-65 WebAssembly with WebCrypto API
 *
 * Both are single JS files with embedded WASM, no external files needed
 */

import type { MLKEM768, MLDSA65 } from '@openforge-sh/liboqs';

// Lazy-loaded WebCrypto implementations
let mlkemWasm: any = null;
let mldsaWasm: any = null;

/**
 * Lazy-load mlkem-wasm from npm
 */
async function getMlkemWasm() {
  if (!mlkemWasm) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    mlkemWasm = (await import('mlkem-wasm')) as any;
  }
  return mlkemWasm.default;
}

/**
 * Lazy-load mldsa-wasm from npm
 */
async function getMldsaWasm() {
  if (!mldsaWasm) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    mldsaWasm = (await import('mldsa-wasm')) as any;
  }
  return mldsaWasm.default;
}

/**
 * Adapter for mlkem-wasm → MLKEM768 interface
 * Converts WebCrypto-style API to liboqs-compatible API
 */
export async function createMLKEM768Adapter(): Promise<MLKEM768> {
  const mlkem = await getMlkemWasm();

  // Return object matching MLKEM768 interface
  // Note: Functions are async internally but return non-Promise values
  const adapter = {
    generateKeyPair: async () => {
      const keyPair = await mlkem.generateKey(
        { name: 'ML-KEM-768' },
        true, // extractable
        ['encapsulateBits', 'decapsulateBits']
      );

      // Export keys in raw format
      const publicKeyBuffer = await mlkem.exportKey('raw-public', keyPair.publicKey);
      const secretKeyBuffer = await mlkem.exportKey('raw-seed', keyPair.privateKey);

      return {
        publicKey: new Uint8Array(publicKeyBuffer),
        secretKey: new Uint8Array(secretKeyBuffer),
      };
    },

    encapsulate: async (publicKey: Uint8Array) => {
      // Import the public key
      const publicKeyObj = await mlkem.importKey(
        'raw-public',
        publicKey,
        { name: 'ML-KEM-768' },
        false, // not extractable (public key only)
        ['encapsulateBits']
      );

      // Encapsulate
      const result = await mlkem.encapsulateBits(
        { name: 'ML-KEM-768' },
        publicKeyObj
      );

      return {
        ciphertext: new Uint8Array(result.ciphertext),
        sharedSecret: new Uint8Array(result.sharedKey),
      };
    },

    decapsulate: async (ciphertext: Uint8Array, secretKey: Uint8Array) => {
      // Import the secret key
      const secretKeyObj = await mlkem.importKey(
        'raw-seed',
        secretKey,
        { name: 'ML-KEM-768' },
        false, // not extractable
        ['decapsulateBits']
      );

      // Decapsulate
      const sharedSecret = await mlkem.decapsulateBits(
        { name: 'ML-KEM-768' },
        secretKeyObj,
        ciphertext
      );

      return new Uint8Array(sharedSecret);
    },

    destroy: () => {
      // WASM memory management (no-op for wasm-based impl)
    },

    info: {
      keySize: {
        publicKey: 1184, // ML-KEM-768 public key size
        secretKey: 2400, // ML-KEM-768 secret key size
        ciphertext: 1088, // ML-KEM-768 ciphertext size
        sharedSecret: 32, // ML-KEM-768 shared secret size
      },
    },
  } as unknown as MLKEM768;

  return adapter;
}

/**
 * Adapter for mldsa-wasm → MLDSA65 interface
 * Converts WebCrypto-style API to liboqs-compatible API
 */
export async function createMLDSA65Adapter(): Promise<MLDSA65> {
  const mldsa = await getMldsaWasm();

  const adapter = {
    generateKeyPair: async () => {
      const keyPair = await mldsa.generateKey(
        { name: 'ML-DSA-65' },
        true, // extractable
        ['sign', 'verify']
      );

      // Export keys in raw format
      const publicKeyBuffer = await mldsa.exportKey('raw-public', keyPair.publicKey);
      const secretKeyBuffer = await mldsa.exportKey('raw-seed', keyPair.privateKey);

      return {
        publicKey: new Uint8Array(publicKeyBuffer),
        secretKey: new Uint8Array(secretKeyBuffer),
      };
    },

    sign: async (message: Uint8Array, secretKey: Uint8Array) => {
      // Import the secret key
      const secretKeyObj = await mldsa.importKey(
        'raw-seed',
        secretKey,
        { name: 'ML-DSA-65' },
        false, // not extractable
        ['sign']
      );

      // Sign
      const signature = await mldsa.sign(
        { name: 'ML-DSA-65' },
        secretKeyObj,
        message
      );

      return new Uint8Array(signature);
    },

    verify: async (message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array) => {
      // Import the public key
      const publicKeyObj = await mldsa.importKey(
        'raw-public',
        publicKey,
        { name: 'ML-DSA-65' },
        false, // not extractable
        ['verify']
      );

      // Verify
      try {
        const isValid = await mldsa.verify(
          { name: 'ML-DSA-65' },
          publicKeyObj,
          signature,
          message
        );
        return isValid;
      } catch (error) {
        console.error('[MLDSA65] Verification error:', error);
        return false;
      }
    },

    destroy: () => {
      // WASM memory management (no-op for wasm-based impl)
    },

    info: {
      keySize: {
        publicKey: 1952, // ML-DSA-65 public key size
        secretKey: 4032, // ML-DSA-65 secret key size (includes seed)
        signature: 3309, // ML-DSA-65 signature size
      },
    },
  } as unknown as MLDSA65;

  return adapter;
}
