/**
 * Unit tests for crypto environment detection and UUID polyfill
 *
 * Tests:
 * - Environment detection across SSR/CSR/Worker contexts
 * - RFC4122 v4 UUID polyfill correctness
 * - Feature detection accuracy
 * - Error handling and validation
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  detectCryptoEnv,
  uuidv4_gRV,
  randomUUID,
  validateCryptoEnvironment,
  type CryptoEnv,
} from '../crypto-env';

describe('detectCryptoEnv', () => {
  it('should detect crypto availability in browser environment', () => {
    const env = detectCryptoEnv();

    expect(env).toHaveProperty('hasWindow');
    expect(env).toHaveProperty('hasSelf');
    expect(env).toHaveProperty('isSecure');
    expect(env).toHaveProperty('hasSubtle');
    expect(env).toHaveProperty('hasGetRandomValues');
    expect(env).toHaveProperty('hasRandomUUID');
    expect(env).toHaveProperty('cryptoRef');
    expect(env).toHaveProperty('context');
  });

  it('should correctly identify browser main thread context', () => {
    const env = detectCryptoEnv();

    // In Vitest, this runs in Node.js, but we can test the logic
    expect(env.context).toBeDefined();
    expect(['ssr', 'browser-main', 'worker', 'unknown']).toContain(env.context);
  });

  it('should detect crypto.subtle availability', () => {
    const env = detectCryptoEnv();

    if (env.cryptoRef && env.cryptoRef.subtle) {
      expect(env.hasSubtle).toBe(true);
    } else {
      expect(env.hasSubtle).toBe(false);
    }
  });

  it('should detect crypto.getRandomValues availability', () => {
    const env = detectCryptoEnv();

    if (env.cryptoRef && typeof env.cryptoRef.getRandomValues === 'function') {
      expect(env.hasGetRandomValues).toBe(true);
    } else {
      expect(env.hasGetRandomValues).toBe(false);
    }
  });

  it('should detect crypto.randomUUID availability', () => {
    const env = detectCryptoEnv();

    if (env.cryptoRef && typeof (env.cryptoRef as any).randomUUID === 'function') {
      expect(env.hasRandomUUID).toBe(true);
    } else {
      expect(env.hasRandomUUID).toBe(false);
    }
  });
});

describe('uuidv4_gRV', () => {
  it('should generate valid RFC4122 v4 UUIDs', () => {
    // Node.js 19+ has crypto in globalThis
    const crypto = globalThis.crypto as Crypto;
    if (!crypto || !crypto.getRandomValues) {
      console.warn('Skipping UUID test: crypto.getRandomValues not available');
      return;
    }

    const uuid = uuidv4_gRV(crypto);

    // Check format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    expect(uuid).toMatch(uuidRegex);
  });

  it('should generate unique UUIDs', () => {
    const crypto = globalThis.crypto as Crypto;
    if (!crypto || !crypto.getRandomValues) {
      return;
    }

    const uuid1 = uuidv4_gRV(crypto);
    const uuid2 = uuidv4_gRV(crypto);

    expect(uuid1).not.toBe(uuid2);
  });

  it('should set version bits correctly (4)', () => {
    const crypto = globalThis.crypto as Crypto;
    if (!crypto || !crypto.getRandomValues) {
      return;
    }

    const uuid = uuidv4_gRV(crypto);

    // Extract version field (13th character, 0-indexed position 14)
    const versionChar = uuid[14];
    expect(versionChar).toBe('4');
  });

  it('should set variant bits correctly (8, 9, a, or b)', () => {
    const crypto = globalThis.crypto as Crypto;
    if (!crypto || !crypto.getRandomValues) {
      return;
    }

    const uuid = uuidv4_gRV(crypto);

    // Extract variant field (17th character, 0-indexed position 19)
    const variantChar = uuid[19].toLowerCase();
    expect(['8', '9', 'a', 'b']).toContain(variantChar);
  });

  it('should throw error if crypto is null', () => {
    expect(() => uuidv4_gRV(null as any)).toThrow('getRandomValues');
  });

  it('should throw error if getRandomValues is missing', () => {
    const fakeCrypto = {} as Crypto;
    expect(() => uuidv4_gRV(fakeCrypto)).toThrow('getRandomValues');
  });

  it('should use cryptographically secure random values', () => {
    const crypto = globalThis.crypto as Crypto;
    if (!crypto || !crypto.getRandomValues) {
      return;
    }

    // Generate multiple UUIDs and check for randomness
    const uuids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      uuids.add(uuidv4_gRV(crypto));
    }

    // All should be unique (extremely high probability)
    expect(uuids.size).toBe(100);

    // Should not contain all zeros (not a proper random source)
    const allZeros = '00000000-0000-4000-8000-000000000000';
    expect(uuids.has(allZeros)).toBe(false);
  });
});

describe('randomUUID', () => {
  it('should use native randomUUID when available', () => {
    const crypto = globalThis.crypto as Crypto;
    if (!crypto || !crypto.getRandomValues) {
      return;
    }

    const env = detectCryptoEnv();

    // If native randomUUID exists, it should be used
    if (env.hasRandomUUID) {
      const uuid = randomUUID(env);
      expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    }
  });

  it('should use polyfill when native randomUUID is missing', () => {
    const crypto = globalThis.crypto as Crypto;
    if (!crypto || !crypto.getRandomValues) {
      return;
    }

    // Mock environment without native randomUUID
    const env: CryptoEnv = {
      hasWindow: true,
      hasSelf: true,
      isSecure: true,
      hasSubtle: true,
      hasGetRandomValues: true,
      hasRandomUUID: false, // Force polyfill
      cryptoRef: crypto,
      context: 'browser-main',
    };

    const uuid = randomUUID(env);
    expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  it('should throw error if cryptoRef is null', () => {
    const env: CryptoEnv = {
      hasWindow: false,
      hasSelf: false,
      isSecure: false,
      hasSubtle: false,
      hasGetRandomValues: false,
      hasRandomUUID: false,
      cryptoRef: null,
      context: 'ssr',
    };

    expect(() => randomUUID(env)).toThrow('No crypto available');
  });

  it('should throw error if getRandomValues is missing', () => {
    const env: CryptoEnv = {
      hasWindow: true,
      hasSelf: true,
      isSecure: true,
      hasSubtle: true,
      hasGetRandomValues: false,
      hasRandomUUID: false,
      cryptoRef: {} as Crypto,
      context: 'browser-main',
    };

    expect(() => randomUUID(env)).toThrow('getRandomValues');
  });
});

describe('validateCryptoEnvironment', () => {
  it('should throw on SSR context', () => {
    const env: CryptoEnv = {
      hasWindow: false,
      hasSelf: false,
      isSecure: false,
      hasSubtle: false,
      hasGetRandomValues: false,
      hasRandomUUID: false,
      cryptoRef: null,
      context: 'ssr',
    };

    expect(() => validateCryptoEnvironment(env)).toThrow('server-side rendering');
  });

  it('should throw on insecure context', () => {
    const env: CryptoEnv = {
      hasWindow: true,
      hasSelf: true,
      isSecure: false, // Not secure
      hasSubtle: false,
      hasGetRandomValues: false,
      hasRandomUUID: false,
      cryptoRef: null,
      context: 'browser-main',
    };

    expect(() => validateCryptoEnvironment(env)).toThrow('secure context');
  });

  it('should throw when crypto is missing', () => {
    const env: CryptoEnv = {
      hasWindow: true,
      hasSelf: true,
      isSecure: true,
      hasSubtle: false,
      hasGetRandomValues: false,
      hasRandomUUID: false,
      cryptoRef: null, // No crypto
      context: 'browser-main',
    };

    expect(() => validateCryptoEnvironment(env)).toThrow('not available in this environment');
  });

  it('should throw when subtle is missing', () => {
    const env: CryptoEnv = {
      hasWindow: true,
      hasSelf: true,
      isSecure: true,
      hasSubtle: false, // No subtle
      hasGetRandomValues: true,
      hasRandomUUID: false,
      cryptoRef: {} as Crypto,
      context: 'browser-main',
    };

    expect(() => validateCryptoEnvironment(env)).toThrow('subtle');
  });

  it('should throw when getRandomValues is missing', () => {
    const env: CryptoEnv = {
      hasWindow: true,
      hasSelf: true,
      isSecure: true,
      hasSubtle: true,
      hasGetRandomValues: false, // No getRandomValues
      hasRandomUUID: false,
      cryptoRef: { subtle: {} } as any,
      context: 'browser-main',
    };

    expect(() => validateCryptoEnvironment(env)).toThrow('getRandomValues');
  });

  it('should not throw when all requirements are met', () => {
    const crypto = globalThis.crypto as Crypto;
    if (!crypto || !crypto.getRandomValues) {
      return;
    }

    const env: CryptoEnv = {
      hasWindow: true,
      hasSelf: true,
      isSecure: true,
      hasSubtle: true,
      hasGetRandomValues: true,
      hasRandomUUID: false,
      cryptoRef: crypto,
      context: 'browser-main',
    };

    expect(() => validateCryptoEnvironment(env)).not.toThrow();
  });

  it('should provide helpful error message for Worker context', () => {
    const env: CryptoEnv = {
      hasWindow: false,
      hasSelf: true,
      isSecure: true,
      hasSubtle: false,
      hasGetRandomValues: true,
      hasRandomUUID: false,
      cryptoRef: {} as Crypto,
      context: 'worker',
    };

    expect(() => validateCryptoEnvironment(env)).toThrow('Worker context');
  });
});

describe('UUID format compliance', () => {
  it('should generate UUIDs with correct hyphen positions', () => {
    const crypto = globalThis.crypto as Crypto;
    if (!crypto || !crypto.getRandomValues) {
      return;
    }

    const uuid = uuidv4_gRV(crypto);

    // Check hyphen positions: 8-4-4-4-12
    expect(uuid[8]).toBe('-');
    expect(uuid[13]).toBe('-');
    expect(uuid[18]).toBe('-');
    expect(uuid[23]).toBe('-');
    expect(uuid.length).toBe(36);
  });

  it('should generate UUIDs with only valid hex characters', () => {
    const crypto = globalThis.crypto as Crypto;
    if (!crypto || !crypto.getRandomValues) {
      return;
    }

    const uuid = uuidv4_gRV(crypto);
    const withoutHyphens = uuid.replace(/-/g, '');

    // All characters should be valid hex
    expect(withoutHyphens).toMatch(/^[0-9a-f]+$/i);
  });

  it('should generate lowercase hex digits', () => {
    const crypto = globalThis.crypto as Crypto;
    if (!crypto || !crypto.getRandomValues) {
      return;
    }

    const uuid = uuidv4_gRV(crypto);

    // Should be lowercase
    expect(uuid).toBe(uuid.toLowerCase());
  });
});

describe('Security properties', () => {
  it('should not use Math.random', () => {
    const crypto = globalThis.crypto as Crypto;
    if (!crypto || !crypto.getRandomValues) {
      return;
    }

    // Mock Math.random to detect usage
    const originalRandom = Math.random;
    let mathRandomCalled = false;
    Math.random = () => {
      mathRandomCalled = true;
      return originalRandom();
    };

    try {
      uuidv4_gRV(crypto);
      expect(mathRandomCalled).toBe(false);
    } finally {
      Math.random = originalRandom;
    }
  });

  it('should produce statistically random output', () => {
    const crypto = globalThis.crypto as Crypto;
    if (!crypto || !crypto.getRandomValues) {
      return;
    }

    // Generate many UUIDs and check distribution of first character
    const firstChars = new Map<string, number>();
    const iterations = 1000;

    for (let i = 0; i < iterations; i++) {
      const uuid = uuidv4_gRV(crypto);
      const firstChar = uuid[0];
      firstChars.set(firstChar, (firstChars.get(firstChar) || 0) + 1);
    }

    // Should have multiple different first characters (not all the same)
    expect(firstChars.size).toBeGreaterThan(10);

    // No single character should dominate (rough check)
    for (const count of firstChars.values()) {
      expect(count).toBeLessThan(iterations * 0.2); // Less than 20% of total
    }
  });
});
