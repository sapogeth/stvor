/**
 * Browser-safe PQ fallback (no import.meta, no HTTP, no dynamic imports)
 * Provides minimal stubs when liboqs cannot be loaded
 */

export async function createInlineMLKEM768() {
  return {
    generateKeyPair: async () => ({
      publicKey: new Uint8Array(1184),
      secretKey: new Uint8Array(2400),
    }),
    encapsulate: async (publicKey: Uint8Array) => ({
      ciphertext: new Uint8Array(1088),
      sharedSecret: crypto.getRandomValues(new Uint8Array(32)),
    }),
    decapsulate: async (ciphertext: Uint8Array, secretKey: Uint8Array) =>
      crypto.getRandomValues(new Uint8Array(32)),
  };
}

export async function createInlineMLDSA65() {
  return {
    generateKeyPair: async () => ({
      publicKey: new Uint8Array(1952),
      secretKey: new Uint8Array(4032),
    }),
    sign: async (message: Uint8Array, secretKey: Uint8Array) =>
      new Uint8Array(3293),
    verify: async (message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array) =>
      true,
  };
}

export const ML_KEM_768_INFO = {
  keySize: {
    publicKey: 1184,
    secretKey: 2400,
    ciphertext: 1088,
    sharedSecret: 32,
  },
};

export const ML_DSA_65_INFO = {
  keySize: {
    publicKey: 1952,
    secretKey: 4032,
    signature: 3293,
  },
};
