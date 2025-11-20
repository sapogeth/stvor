/**
 * Browser-safe PQ fallback (no import.meta, no HTTP, no dynamic imports)
 * Provides deterministic stubs when liboqs cannot be loaded
 *
 * SECURITY WARNING: These are NOT real cryptographic operations.
 * They are placeholders to allow graceful degradation.
 * Applications MUST use the pqReallyUnavailable flag to:
 * 1. Alert users that post-quantum crypto is not available
 * 2. Not rely on these stubs for security
 * 3. Consider using a PQ-wrapper at application layer
 */

export async function createInlineMLKEM768() {
  return {
    generateKeyPair: async () => ({
      // Return DETERMINISTIC empty keys (all zeros)
      // This ensures consistent behavior across restarts
      publicKey: new Uint8Array(1184),   // All zeros
      secretKey: new Uint8Array(2400),   // All zeros
    }),
    encapsulate: async (publicKey: Uint8Array) => ({
      // Return DETERMINISTIC shared secret derived from input
      // so encapsulate/decapsulate produce same result for same input
      ciphertext: new Uint8Array(1088),  // All zeros
      sharedSecret: deriveStubSecret(publicKey), // Deterministic
    }),
    decapsulate: async (ciphertext: Uint8Array, secretKey: Uint8Array) =>
      deriveStubSecret(ciphertext), // Deterministic - same for same input
  };
}

export async function createInlineMLDSA65() {
  return {
    generateKeyPair: async () => ({
      // Return DETERMINISTIC empty keys
      publicKey: new Uint8Array(1952),   // All zeros
      secretKey: new Uint8Array(4032),   // All zeros
    }),
    sign: async (message: Uint8Array, secretKey: Uint8Array) =>
      // Return DETERMINISTIC signature
      new Uint8Array(3293), // All zeros
    verify: async (message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array) =>
      // Verify signature is empty (placeholder)
      isEmptySignature(signature),
  };
}

/**
 * Derive deterministic shared secret from ciphertext
 * This ensures encapsulate/decapsulate can be paired
 * (though the secret itself is NOT cryptographically secure)
 */
function deriveStubSecret(input: Uint8Array): Uint8Array {
  const secret = new Uint8Array(32);
  // Simple deterministic derivation: XOR all input bytes
  let xor = 0;
  for (let i = 0; i < input.length; i++) {
    xor ^= input[i];
  }
  // Fill with repeated XOR value (deterministic, not random)
  for (let i = 0; i < 32; i++) {
    secret[i] = xor;
  }
  return secret;
}

/**
 * Check if signature is empty (all zeros) as from inline stub
 */
function isEmptySignature(sig: Uint8Array): boolean {
  for (let i = 0; i < sig.length; i++) {
    if (sig[i] !== 0) return false;
  }
  return true;
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
