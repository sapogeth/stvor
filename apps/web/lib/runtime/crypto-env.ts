/**
 * Crypto Environment Detection & Polyfills
 *
 * Provides runtime feature detection for WebCrypto APIs across browsers,
 * SSR/CSR contexts, and Web Workers. Includes RFC4122 v4 UUID polyfill
 * using crypto.getRandomValues (never Math.random).
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
 * @see https://www.rfc-editor.org/rfc/rfc4122.html#section-4.4
 */

export type CryptoEnv = {
  /** window object exists (browser main thread, not SSR) */
  hasWindow: boolean;
  /** self object exists (Worker or browser) */
  hasSelf: boolean;
  /** Running in secure context (https:// or localhost) */
  isSecure: boolean;
  /** crypto.subtle exists (SubtleCrypto API) */
  hasSubtle: boolean;
  /** crypto.getRandomValues exists (CSPRNG) */
  hasGetRandomValues: boolean;
  /** crypto.randomUUID exists (native UUID v4 generator) */
  hasRandomUUID: boolean;
  /** Reference to the Crypto object, if available */
  cryptoRef: Crypto | null;
  /** Additional context info for diagnostics */
  context: 'ssr' | 'browser-main' | 'worker' | 'unknown';
};

/**
 * Detects available crypto features in the current runtime environment.
 * Safe to call in SSR, CSR, Workers, and all browser contexts.
 */
export function detectCryptoEnv(): CryptoEnv {
  // Use globalThis for maximum compatibility (Node, Browser, Worker)
  const g: any = globalThis as any;

  // Attempt to locate the Crypto object
  const cryptoRef: Crypto | null = g?.crypto ?? null;

  // Environment detection
  const hasWindow = typeof window !== 'undefined';
  const hasSelf = typeof self !== 'undefined';

  // Secure context check (required for WebCrypto)
  // https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts
  const isSecure = (hasWindow || hasSelf) && (g?.isSecureContext === true);

  // Feature detection
  const hasSubtle = !!cryptoRef?.subtle;
  const hasGetRandomValues = typeof cryptoRef?.getRandomValues === 'function';
  const hasRandomUUID = typeof cryptoRef?.randomUUID === 'function';

  // Context classification for diagnostics
  let context: CryptoEnv['context'] = 'unknown';
  if (typeof window === 'undefined' && typeof process !== 'undefined') {
    context = 'ssr'; // Node.js server-side rendering
  } else if (hasWindow && hasSelf) {
    context = 'browser-main'; // Browser main thread
  } else if (!hasWindow && hasSelf) {
    context = 'worker'; // Web Worker or Service Worker
  }

  return {
    hasWindow,
    hasSelf,
    isSecure,
    hasSubtle,
    hasGetRandomValues,
    hasRandomUUID,
    cryptoRef,
    context,
  };
}

/**
 * RFC4122 v4 UUID generator using crypto.getRandomValues.
 *
 * Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
 * - x: random hex digit (0-f)
 * - 4: version 4 marker
 * - y: variant bits (8, 9, a, or b)
 *
 * @param cryptoRef - The Crypto object (must support getRandomValues)
 * @returns A valid UUID v4 string
 * @throws Error if cryptoRef is null or getRandomValues is missing
 *
 * @security This uses cryptographically secure random numbers (CSPRNG).
 *           Never uses Math.random() which is not suitable for security.
 */
export function uuidv4_gRV(cryptoRef: Crypto): string {
  if (!cryptoRef?.getRandomValues) {
    throw new Error('Crypto.getRandomValues is required for UUID generation');
  }

  // Generate 16 random bytes
  const bytes = new Uint8Array(16);
  cryptoRef.getRandomValues(bytes);

  // Set version bits (4 bits at byte 6, high nibble = 0100)
  bytes[6] = (bytes[6] & 0x0f) | 0x40;

  // Set variant bits (2 bits at byte 8, high 2 bits = 10)
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  // Convert to hex string with zero-padding
  const toHex = (n: number) => n.toString(16).padStart(2, '0');
  const hex = Array.from(bytes, toHex).join('');

  // Format as xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Generate a UUID v4 using native randomUUID or polyfill.
 * Prefers native implementation when available for better performance.
 *
 * @param ce - CryptoEnv from detectCryptoEnv()
 * @returns A valid UUID v4 string
 * @throws Error if crypto is not available or not in secure context
 */
export function randomUUID(ce: CryptoEnv): string {
  if (!ce.cryptoRef) {
    throw new Error('No crypto available - are you in a secure context (https)?');
  }

  // Prefer native implementation (faster, optimized by browser)
  if (ce.hasRandomUUID) {
    return (ce.cryptoRef as any).randomUUID();
  }

  // Fallback to polyfill (Safari < 15.4, old browsers)
  if (!ce.hasGetRandomValues) {
    throw new Error('crypto.getRandomValues is not available - cannot generate secure UUIDs');
  }

  return uuidv4_gRV(ce.cryptoRef);
}

/**
 * Validate that we're in a suitable environment for WebCrypto operations.
 * Throws descriptive errors to help users fix their environment.
 *
 * @param ce - CryptoEnv from detectCryptoEnv()
 * @throws Error with actionable message if crypto is unavailable
 */
export function validateCryptoEnvironment(ce: CryptoEnv): void {
  // SSR check
  if (ce.context === 'ssr') {
    throw new Error(
      'WebCrypto is not available during server-side rendering. ' +
      'This code must run client-side only (useEffect, event handlers, etc.)'
    );
  }

  // Secure context check
  if (!ce.isSecure) {
    throw new Error(
      'WebCrypto requires a secure context (https:// or localhost). ' +
      'Please access this application over HTTPS or from localhost.'
    );
  }

  // crypto object check
  if (!ce.cryptoRef) {
    throw new Error(
      'WebCrypto is not available in this environment. ' +
      'Please use a modern browser (Chrome 37+, Firefox 34+, Safari 11+, Edge 79+).'
    );
  }

  // SubtleCrypto check
  if (!ce.hasSubtle) {
    if (ce.context === 'worker') {
      throw new Error(
        'crypto.subtle is not available in this Worker context. ' +
        'This may occur on older Safari versions or in insecure contexts. ' +
        'Consider performing crypto operations on the main thread instead.'
      );
    }
    throw new Error(
      'crypto.subtle is not available. ' +
      'Ensure you are in a secure context and using a modern browser.'
    );
  }

  // CSPRNG check
  if (!ce.hasGetRandomValues) {
    throw new Error(
      'crypto.getRandomValues is not available. ' +
      'This API is required for secure random number generation. ' +
      'Please update your browser to a modern version.'
    );
  }
}
