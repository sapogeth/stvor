/**
 * Argon2id Parameter Optimization for Browser Deployment
 *
 * SECURITY vs PERFORMANCE TRADEOFF:
 *
 * SENSITIVE (Current - TOO HEAVY):
 *   memoryLimit: 268,435,456 (256 MB)
 *   opsLimit: 4
 *   Time: 2-5 seconds ❌ Unacceptable for browser
 *   GPU resistance: Maximum
 *
 * MODERATE (Recommended):
 *   memoryLimit: 67,108,864 (64 MB) 
 *   opsLimit: 2
 *   Time: 500-1500 ms ✓ Acceptable UX
 *   GPU resistance: Excellent (still uses 2x ops, 4x memory)
 *   Threat model: Resists GPU-accelerated attacks
 *
 * INTERACTIVE (Fast, less secure):
 *   memoryLimit: 16,777,216 (16 MB)
 *   opsLimit: 1
 *   Time: 100-300 ms
 *   GPU resistance: Baseline (vulnerable to high-end GPUs)
 *
 * RECOMMENDATION FOR STVOR:
 * Use MODERATE as default. It maintains post-quantum security while
 * providing acceptable browser UX.
 *
 * References:
 * - Argon2 paper: https://github.com/P-H-C/phc-winner-argon2
 * - libsodium: https://doc.libsodium.org/password_hashing/the_argon2i_function
 */

export enum Argon2Mode {
  INTERACTIVE = 'INTERACTIVE',
  MODERATE = 'MODERATE',
  SENSITIVE = 'SENSITIVE',
}

export interface Argon2Params {
  memoryLimit: number; // in bytes
  opsLimit: number;
  mode: Argon2Mode;
  estimatedTimeMs: string;
}

/**
 * INTERACTIVE: Fast but less GPU-resistant
 * Use only for development/testing or non-critical operations
 */
export const ARGON2_INTERACTIVE: Argon2Params = {
  memoryLimit: 16_777_216, // 16 MB
  opsLimit: 1,
  mode: Argon2Mode.INTERACTIVE,
  estimatedTimeMs: '100-300ms',
};

/**
 * MODERATE: Balanced security and UX
 * RECOMMENDED for production browser deployment
 * Still resists GPU attacks while keeping <1.5s latency
 */
export const ARGON2_MODERATE: Argon2Params = {
  memoryLimit: 67_108_864, // 64 MB
  opsLimit: 2,
  mode: Argon2Mode.MODERATE,
  estimatedTimeMs: '500-1500ms',
};

/**
 * SENSITIVE: Maximum GPU resistance
 * Too slow for browser, suitable for server-side KDF only
 */
export const ARGON2_SENSITIVE: Argon2Params = {
  memoryLimit: 268_435_456, // 256 MB
  opsLimit: 4,
  mode: Argon2Mode.SENSITIVE,
  estimatedTimeMs: '2000-5000ms',
};

/**
 * Get Argon2 parameters for given mode
 */
export function getArgon2Params(mode: Argon2Mode): Argon2Params {
  switch (mode) {
    case Argon2Mode.INTERACTIVE:
      return ARGON2_INTERACTIVE;
    case Argon2Mode.MODERATE:
      return ARGON2_MODERATE;
    case Argon2Mode.SENSITIVE:
      return ARGON2_SENSITIVE;
    default:
      return ARGON2_MODERATE; // Safe default
  }
}

/**
 * Get recommended Argon2 mode for use case
 */
export function getRecommendedMode(context: 'browser' | 'server'): Argon2Mode {
  if (context === 'browser') {
    return Argon2Mode.MODERATE; // Trade off: some security for UX
  }
  return Argon2Mode.SENSITIVE; // Server can afford slower KDF
}

/**
 * Convert Argon2 params to libsodium constants
 * (if using @noble/hashes or libsodium.js)
 */
export function argon2ParamsToSodium(params: Argon2Params) {
  return {
    opsLimit: params.opsLimit,
    memoryLimit: params.memoryLimit,
    algorithm: 'argon2id13', // Argon2id variant for side-channel resistance
  };
}
