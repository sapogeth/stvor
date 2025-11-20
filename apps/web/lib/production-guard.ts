/**
 * Production Guard
 * Prevents use of development credentials in production
 */

import { logError } from './logger';

export class ProductionGuardError extends Error {
  constructor(message: string) {
    super(`[ProductionGuard] CRITICAL: ${message}`);
    this.name = 'ProductionGuardError';
  }
}

/**
 * Check if Clerk is running in development mode
 */
export function isClerkDev(): boolean {
  // Clerk sets publishable key starting with 'pk_test' in dev mode
  const publishable = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY || '';
  return publishable.startsWith('pk_test_');
}

/**
 * Check if environment is production
 */
export function isProduction(): boolean {
  return process.env.NODE_ENV === 'production';
}

/**
 * CRITICAL: Block development credentials in production
 */
export function validateProductionEnvironment(): void {
  if (isProduction() && isClerkDev()) {
    const err = new ProductionGuardError(
      'Clerk development keys detected in PRODUCTION environment. ' +
      'This is a critical security violation. ' +
      'Development keys MUST NOT be used with production user data. ' +
      'Application MUST refuse to start. ' +
      'Set correct Clerk production publishable key in environment.'
    );
    logError('production-guard', err.message);
    throw err;
  }

  // Additional check: ensure relay public key is set in production
  if (isProduction()) {
    const relayKey = process.env.NEXT_PUBLIC_RELAY_PUBLIC_KEY;
    if (!relayKey) {
      const err = new ProductionGuardError(
        'Relay public key not set in production. ' +
        'Set NEXT_PUBLIC_RELAY_PUBLIC_KEY environment variable.'
      );
      logError('production-guard', err.message);
      throw err;
    }
  }
}

/**
 * Check if a key looks like a development stub key (starts with "dev-")
 */
export function isDevModeKey(key: Uint8Array): boolean {
  if (key.length < 4) return false;
  const prefix = String.fromCharCode(key[0], key[1], key[2], key[3]);
  return prefix === 'dev-';
}
