/**
 * Safe Crypto Interface
 *
 * Single import point for all WebCrypto operations in the web app.
 * Provides validated crypto objects and polyfilled APIs with comprehensive
 * error handling and diagnostics.
 *
 * Usage:
 *   import { getCryptoOrThrow } from '@/lib/runtime/crypto-safe';
 *   const { crypto, randomUUID } = getCryptoOrThrow();
 *   const id = randomUUID(); // Works everywhere, with polyfill fallback
 */

import {
  detectCryptoEnv,
  randomUUID as _randomUUID,
  validateCryptoEnvironment,
  type CryptoEnv,
} from './crypto-env';

export interface SafeCrypto {
  /** CryptoEnv diagnostics for debugging */
  ce: CryptoEnv;
  /** Validated Crypto object (guaranteed to exist) */
  crypto: Crypto;
  /** UUID v4 generator (native or polyfilled) */
  randomUUID: () => string;
  /** Get cryptographically secure random bytes */
  getRandomValues: <T extends ArrayBufferView | null>(array: T) => T;
  /** SubtleCrypto API for advanced operations */
  subtle: SubtleCrypto;
}

/**
 * Get a validated, safe crypto interface.
 *
 * This function:
 * 1. Detects the runtime environment (SSR, CSR, Worker)
 * 2. Validates that WebCrypto is available and usable
 * 3. Returns a safe interface with polyfilled randomUUID
 * 4. Throws descriptive errors if crypto is unavailable
 *
 * @returns SafeCrypto interface with validated crypto objects
 * @throws Error with actionable message if crypto is unavailable
 *
 * @example
 * ```typescript
 * // In a client-side component or hook
 * useEffect(() => {
 *   try {
 *     const { randomUUID } = getCryptoOrThrow();
 *     const id = randomUUID();
 *     console.log('Generated ID:', id);
 *   } catch (err) {
 *     console.error('Crypto unavailable:', err.message);
 *   }
 * }, []);
 * ```
 */
export function getCryptoOrThrow(): SafeCrypto {
  const ce = detectCryptoEnv();

  // Validate environment and throw descriptive errors
  validateCryptoEnvironment(ce);

  // At this point, crypto is guaranteed to be available
  const crypto = ce.cryptoRef!;

  return {
    ce,
    crypto,
    randomUUID: () => _randomUUID(ce),
    getRandomValues: crypto.getRandomValues.bind(crypto),
    subtle: crypto.subtle,
  };
}

/**
 * Check if WebCrypto is available without throwing.
 * Useful for conditional rendering or feature detection.
 *
 * @returns true if crypto is fully available, false otherwise
 *
 * @example
 * ```typescript
 * if (isCryptoAvailable()) {
 *   // Show encryption UI
 * } else {
 *   // Show "HTTPS required" message
 * }
 * ```
 */
export function isCryptoAvailable(): boolean {
  try {
    const ce = detectCryptoEnv();
    return (
      ce.isSecure &&
      ce.cryptoRef !== null &&
      ce.hasSubtle &&
      ce.hasGetRandomValues &&
      ce.context !== 'ssr'
    );
  } catch {
    return false;
  }
}

/**
 * Get detailed crypto availability status for diagnostics.
 * Does not throw; returns diagnostics even in unsupported environments.
 *
 * @returns CryptoEnv with full environment details
 *
 * @example
 * ```typescript
 * const status = getCryptoStatus();
 * console.log('Secure context:', status.isSecure);
 * console.log('Runtime context:', status.context);
 * console.log('Has randomUUID:', status.hasRandomUUID);
 * ```
 */
export function getCryptoStatus(): CryptoEnv {
  return detectCryptoEnv();
}

/**
 * Generate a UUID v4 in a try/catch wrapper for use in contexts
 * where you want to handle errors gracefully.
 *
 * @returns UUID v4 string on success, null on failure
 *
 * @example
 * ```typescript
 * const id = tryRandomUUID();
 * if (id) {
 *   // Use the ID
 * } else {
 *   // Handle the error case
 * }
 * ```
 */
export function tryRandomUUID(): string | null {
  try {
    const { randomUUID } = getCryptoOrThrow();
    return randomUUID();
  } catch {
    return null;
  }
}
