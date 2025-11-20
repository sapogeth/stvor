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
 * Check if this is a preview/staging environment (e.g., Vercel preview)
 * Preview deployments are allowed to use dev credentials for testing
 */
export function isPreviewEnvironment(): boolean {
  // Vercel sets VERCEL_ENV to "preview" for preview deployments
  const vercelEnv = process.env.VERCEL_ENV || '';
  const isVercelPreview = vercelEnv === 'preview' || vercelEnv === 'development';

  // Check for other preview indicators
  const isLocalhost = process.env.NEXT_PUBLIC_API_URL?.includes('localhost') || false;
  const hasPreviewUrl = process.env.VERCEL_URL?.includes('vercel.app') || false;

  return isVercelPreview || isLocalhost || hasPreviewUrl;
}

/**
 * CRITICAL: Block development credentials in ACTUAL production
 * Allow dev credentials in preview/staging environments for testing
 */
export function validateProductionEnvironment(): void {
  const isProd = isProduction();
  const isPreview = isPreviewEnvironment();
  const hasClerkDev = isClerkDev();

  // Only block if BOTH production AND dev credentials
  // If preview/staging, allow dev credentials
  if (isProd && !isPreview && hasClerkDev) {
    const err = new ProductionGuardError(
      'Clerk development keys detected in PRODUCTION environment. ' +
      'This is a critical security violation. ' +
      'Development keys MUST NOT be used with production user data. ' +
      'Application MUST refuse to start. ' +
      'Set correct Clerk production publishable key (pk_live_*) in environment.'
    );
    logError('production-guard', err.message);
    throw err;
  }

  // Additional check: ensure relay public key is set in actual production
  if (isProd && !isPreview) {
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

  // Log environment info for debugging
  if (isProd) {
    const clerkStatus = hasClerkDev ? 'dev keys (pk_test_*)' : 'production keys (pk_live_*)';
    const envType = isPreview ? 'preview/staging' : 'actual production';
    console.log(`[ProductionGuard] Environment: ${envType}, Clerk: ${clerkStatus}`);
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
