/**
 * SECURITY-CRITICAL: Secure Random Bytes Abstraction
 * 
 * Provides SYNCHRONOUS cryptographically secure random number generation across:
 * - Browser (Web Crypto API via globalThis.crypto.getRandomValues)
 * - Node.js (crypto.randomBytes)
 * - SSR contexts (Next.js server components)
 * 
 * ARCHITECTURE:
 * - 100% synchronous (no async/await, no Promises, no dynamic imports)
 * - Runtime detection (browser vs Node.js)
 * - NEVER uses Math.random() for security operations
 * - NEVER leaks Node crypto into browser bundles
 * - Build-safe (no module-level side effects)
 * 
 * @see https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
 * @see https://nodejs.org/api/crypto.html#cryptorandombytessize-callback
 */

/**
 * Generate cryptographically secure random bytes (SYNCHRONOUS).
 * 
 * @param length - Number of random bytes to generate (1-65536)
 * @returns Uint8Array containing secure random bytes
 * @throws Error if no secure random source is available
 * 
 * @security This function GUARANTEES CSPRNG usage:
 * - Browser: Uses Web Crypto API (getRandomValues)
 * - Node.js: Uses crypto.randomBytes (synchronous)
 * - NEVER falls back to Math.random()
 * 
 * @example
 * ```ts
 * const randomBytes = getSecureRandomBytes(32);
 * const hexString = Buffer.from(randomBytes).toString('hex');
 * ```
 */
export function getSecureRandomBytes(length: number): Uint8Array {
  if (length <= 0 || length > 65536) {
    throw new Error(`Invalid random bytes length: ${length} (must be 1-65536)`);
  }

  // Strategy 1: Browser with Web Crypto API
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.getRandomValues) {
    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);
    return bytes;
  }

  // Strategy 2: Node.js crypto module (SSR, API routes, middleware)
  // Use direct require (not dynamic import) for synchronous operation
  if (typeof process !== 'undefined' && process.versions?.node) {
    try {
      // This require is safe: webpack/turbo will externalize 'crypto' for Node
      const nodeCrypto = require('crypto');
      if (nodeCrypto && typeof nodeCrypto.randomBytes === 'function') {
        const buffer = nodeCrypto.randomBytes(length);
        return new Uint8Array(buffer);
      }
    } catch (err) {
      // Ignore - continue to error below
    }
  }

  // FAIL SAFE: No secure random source available
  throw new Error(
    'SECURITY ERROR: No cryptographically secure random source available. ' +
    'This environment lacks both Web Crypto API (globalThis.crypto.getRandomValues) ' +
    'and Node.js crypto.randomBytes. Cannot generate secure random bytes.'
  );
}

/**
 * Generate a random 32-byte seed encoded as base64 (SYNCHRONOUS).
 * 
 * Common use case: keystore seeds, session tokens, CSRF tokens.
 * 
 * @returns 43-character base64 string (32 bytes)
 * 
 * @example
 * ```ts
 * const seed = generateSecureSeed();
 * localStorage.setItem('keystore_seed', seed);
 * ```
 */
export function generateSecureSeed(): string {
  const bytes = getSecureRandomBytes(32);
  
  // Use Buffer if available (Node), otherwise manual base64 encoding
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  
  // Browser fallback: btoa with Uint8Array -> String conversion
  return btoa(String.fromCharCode(...Array.from(bytes)));
}

/**
 * Generate a random hex string of specified byte length.
 * 
 * @param byteLength - Number of random bytes (output will be 2x this length)
 * @returns Hex string (lowercase)
 * 
 * @example
 * generateSecureHex(16) // Returns 32-char hex string
 */
export function generateSecureHex(byteLength: number): string {
  const bytes = getSecureRandomBytes(byteLength);
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Runtime environment detection for diagnostics.
 * 
 * @returns Object describing the random source being used
 */
export function detectRandomSource(): {
  source: 'web-crypto' | 'node-crypto' | 'none';
  available: boolean;
  secure: boolean;
} {
  // Check Web Crypto API
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.getRandomValues) {
    return {
      source: 'web-crypto',
      available: true,
      secure: true,
    };
  }

  // Check Node.js crypto
  if (typeof require !== 'undefined') {
    try {
      const nodeCrypto = require('crypto');
      if (nodeCrypto?.randomBytes) {
        return {
          source: 'node-crypto',
          available: true,
          secure: true,
        };
      }
    } catch {
      // Fall through
    }
  }

  return {
    source: 'none',
    available: false,
    secure: false,
  };
}
