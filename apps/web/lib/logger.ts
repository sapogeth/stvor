/**
 * Production-Safe Centralized Logger
 *
 * Prevents sensitive data leakage in console logs.
 * Controlled by environment variables:
 * - NEXT_PUBLIC_DEBUG_GLOBAL: Enable all debugging (master flag)
 * - NEXT_PUBLIC_DEBUG_CRYPTO: Enable detailed crypto debugging
 * - NEXT_PUBLIC_DEBUG_AUTH: Enable auth token debugging
 * - NEXT_PUBLIC_DEBUG_SYNC: Enable sync loop debugging
 * - NEXT_PUBLIC_DEBUG_IDENTITY: Enable identity debugging
 *
 * SECURITY:
 * - Never logs full JWT tokens
 * - Never logs private keys
 * - Never logs decrypted plaintext (only length)
 * - Never logs full session state (only IDs + counters)
 */

// Debug flags - safe-by-default (all false in production)
const DEBUG_GLOBAL = typeof window !== 'undefined' && process.env.NEXT_PUBLIC_DEBUG_GLOBAL === '1';
const DEBUG_CRYPTO = typeof window !== 'undefined' && process.env.NEXT_PUBLIC_DEBUG_CRYPTO === '1';
const DEBUG_AUTH = typeof window !== 'undefined' && process.env.NEXT_PUBLIC_DEBUG_AUTH === '1';
const DEBUG_SYNC = typeof window !== 'undefined' && process.env.NEXT_PUBLIC_DEBUG_SYNC === '1';
const DEBUG_IDENTITY = typeof window !== 'undefined' && process.env.NEXT_PUBLIC_DEBUG_IDENTITY === '1';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogMetadata {
  [key: string]: any;
}

/**
 * Redact JWT token for security
 * Only shows prefix when DEBUG_AUTH=1
 */
export function redactToken(token: string): string {
  if (!token) return 'null';
  if (DEBUG_AUTH) {
    return `${token.substring(0, 20)}... (len=${token.length})`;
  }
  return '(redacted)';
}

/**
 * Redact session ID - show only first 16 hex chars
 */
export function redactSessionId(sessionId: Uint8Array | string): string {
  if (typeof sessionId === 'string') {
    return sessionId.slice(0, 16) + '...';
  }
  return Buffer.from(sessionId).toString('hex').slice(0, 16) + '...';
}

/**
 * Redact public key - show only first 16 hex chars
 */
export function redactPublicKey(publicKey: Uint8Array): string {
  return Buffer.from(publicKey).toString('hex').slice(0, 16) + '...';
}

/**
 * Redact plaintext message - only show length and optionally first 32 bytes as hex
 */
export function redactPlaintext(plaintext: Uint8Array | string): string {
  if (typeof plaintext === 'string') {
    if (DEBUG_CRYPTO) {
      return `(len=${plaintext.length}, preview="${plaintext.slice(0, 32)}...")`;
    }
    return `(len=${plaintext.length})`;
  }

  if (DEBUG_CRYPTO) {
    const hex = Buffer.from(plaintext.slice(0, Math.min(32, plaintext.length))).toString('hex');
    return `(len=${plaintext.length}, hex=${hex}...)`;
  }
  return `(len=${plaintext.length})`;
}

/**
 * Check if a scope should log based on debug flags
 */
function shouldLog(scope: string, level: LogLevel): boolean {
  // Always log errors and warnings
  if (level === 'error' || level === 'warn') return true;

  // Check scope-specific debug flags
  const normalizedScope = scope.toLowerCase();

  if (normalizedScope.includes('crypto') || normalizedScope.includes('handshake') ||
      normalizedScope.includes('ratchet') || normalizedScope.includes('message')) {
    return DEBUG_CRYPTO;
  }

  if (normalizedScope.includes('auth') || normalizedScope.includes('token')) {
    return DEBUG_AUTH;
  }

  if (normalizedScope.includes('sync')) {
    return DEBUG_SYNC;
  }

  if (normalizedScope.includes('identity') || normalizedScope.includes('keystore')) {
    return DEBUG_IDENTITY;
  }

  // Info level: log if DEBUG_GLOBAL or any specific debug flag is set
  if (level === 'info') {
    return DEBUG_GLOBAL || DEBUG_CRYPTO || DEBUG_AUTH || DEBUG_SYNC || DEBUG_IDENTITY;
  }

  // Debug level: require DEBUG_GLOBAL or specific scope flags
  return DEBUG_GLOBAL;
}

/**
 * Format log message with scope prefix
 */
function formatMessage(scope: string, message: string, metadata?: LogMetadata): (string | LogMetadata)[] {
  const prefix = `[${scope}]`;
  if (metadata && Object.keys(metadata).length > 0) {
    return [prefix, message, metadata];
  }
  return [prefix, message];
}

/**
 * Debug logging - only shows when specific debug flags are enabled
 */
export function logDebug(scope: string, message: string, metadata?: LogMetadata): void {
  if (!shouldLog(scope, 'debug')) return;
  const parts = formatMessage(scope, message, metadata);
  console.log(...parts);
}

/**
 * Info logging - shows high-level events when any debug flag is set
 */
export function logInfo(scope: string, message: string, metadata?: LogMetadata): void {
  if (!shouldLog(scope, 'info')) return;
  const parts = formatMessage(scope, message, metadata);
  console.log(...parts);
}

/**
 * Warning logging - always shown
 */
export function logWarn(scope: string, message: string, metadata?: LogMetadata): void {
  const parts = formatMessage(scope, message, metadata);
  console.warn(...parts);
}

/**
 * Error logging - always shown
 */
export function logError(scope: string, message: string, metadata?: LogMetadata): void {
  const parts = formatMessage(scope, message, metadata);
  console.error(...parts);
}

/**
 * Check if crypto debugging is enabled
 */
export function isCryptoDebugEnabled(): boolean {
  return DEBUG_CRYPTO;
}

/**
 * Check if auth debugging is enabled
 */
export function isAuthDebugEnabled(): boolean {
  return DEBUG_AUTH;
}

/**
 * Check if sync debugging is enabled
 */
export function isSyncDebugEnabled(): boolean {
  return DEBUG_SYNC;
}

/**
 * Check if identity debugging is enabled
 */
export function isIdentityDebugEnabled(): boolean {
  return DEBUG_IDENTITY;
}

/**
 * Check if global debugging is enabled
 */
export function isGlobalDebugEnabled(): boolean {
  return DEBUG_GLOBAL;
}
