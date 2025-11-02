/**
 * E2E Security Configuration
 *
 * SECURITY: These settings control hardening measures against various attack vectors
 *
 * @module e2e-security-config
 */

/**
 * E2E Security Configuration
 *
 * THREAT MODEL & MITIGATIONS:
 *
 * 1. XSS Key Theft Protection:
 *    - requireLocalKeystorePassword: true
 *    - Even if attacker injects JS, they cannot read keys without password
 *
 * 2. Malicious Relay Protection:
 *    - allowInlineSessionAdoptionFromUnknownSenders: false
 *    - allowedSystemEntryTypes: whitelist only
 *    - Prevents relay from injecting fake sessions or malicious entries
 *
 * 3. Token Theft Protection:
 *    - persistRelayToken: false
 *    - Token in memory only, re-fetched on 401
 *    - XSS cannot steal token from localStorage
 *
 * 4. Account Takeover Protection:
 *    - requireExplicitReEnrollment: true
 *    - User must confirm before overwriting server identity
 *    - Prevents silent re-enrollment attacks
 */
export const E2E_SECURITY_CONFIG = {
  /**
   * SECURITY: Require password to unlock local keystore
   * Protects against: XSS key theft, malicious extensions, disk forensics
   * Default: true (recommended)
   */
  requireLocalKeystorePassword: true,

  /**
   * SECURITY: Persist relay JWT token to storage
   * When false: token kept in memory, re-fetched on 401
   * When true: token encrypted in keystore (requires password unlock)
   * Default: false (more secure, but requires re-auth on page refresh)
   */
  persistRelayToken: false,

  /**
   * SECURITY: Allow adopting inline sessions from unknown senders
   * When false: only accept sessions from established peers
   * Default: false (recommended - prevents session injection attacks)
   */
  allowInlineSessionAdoptionFromUnknownSenders: false,

  /**
   * SECURITY: Allowed system entry types from relay
   * Only these types can be processed if not encrypted chat messages
   * Default: handshake and prekey publish only
   */
  allowedSystemEntryTypes: [
    'handshake-init',
    'handshake-response',
    'prekey-publish',
  ] as const,

  /**
   * SECURITY: Require explicit user confirmation for re-enrollment
   * When true: show modal asking user to confirm
   * When false: silently re-enroll (dangerous - can be abused)
   * Default: true (recommended)
   */
  requireExplicitReEnrollment: true,

  /**
   * SECURITY: Exponential backoff for /register endpoint
   * Prevents rate-limit abuse and 429 errors
   */
  registerBackoff: {
    initialDelayMs: 1000,
    maxDelayMs: 30000,
    multiplier: 2,
    maxAttempts: 5,
  },

  /**
   * SECURITY: Auto-lock keystore after inactivity
   * 0 = never auto-lock
   * > 0 = lock after N milliseconds of inactivity
   * Default: 15 minutes (900000 ms)
   */
  autoLockAfterMs: 15 * 60 * 1000,

  /**
   * SECURITY: Minimum password length
   * Enforced when setting keystore password
   * Default: 12 characters (NIST recommendation)
   */
  minPasswordLength: 12,

  /**
   * SECURITY: Clear clipboard after copying safety number
   * Prevents accidental leakage via clipboard history
   * Default: 30 seconds
   */
  clearClipboardAfterMs: 30000,
} as const;

/**
 * Validate entry type against whitelist
 * SECURITY: Drop entries that don't match allowed types
 */
export function isAllowedSystemEntryType(type: string): boolean {
  return E2E_SECURITY_CONFIG.allowedSystemEntryTypes.includes(type as any);
}

/**
 * Get backoff delay for attempt number
 * SECURITY: Exponential backoff prevents rate-limit abuse
 */
export function getRegisterBackoffDelay(attemptNumber: number): number {
  const { initialDelayMs, maxDelayMs, multiplier } = E2E_SECURITY_CONFIG.registerBackoff;
  const delay = initialDelayMs * Math.pow(multiplier, attemptNumber - 1);
  return Math.min(delay, maxDelayMs);
}

/**
 * Check if max register attempts exceeded
 * SECURITY: Prevents infinite retry loops
 */
export function isMaxRegisterAttemptsExceeded(attemptNumber: number): boolean {
  return attemptNumber > E2E_SECURITY_CONFIG.registerBackoff.maxAttempts;
}

/**
 * Validate password strength
 * SECURITY: Enforce minimum password requirements
 */
export function validatePasswordStrength(password: string): { valid: boolean; error?: string } {
  if (password.length < E2E_SECURITY_CONFIG.minPasswordLength) {
    return {
      valid: false,
      error: `Password must be at least ${E2E_SECURITY_CONFIG.minPasswordLength} characters`,
    };
  }

  // Additional checks can be added here (uppercase, numbers, symbols, etc.)
  // For now, just length requirement

  return { valid: true };
}
