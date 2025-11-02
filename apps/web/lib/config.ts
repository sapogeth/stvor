/**
 * Configuration helpers for relay URL resolution
 * Centralizes relay base URL determination for client-side requests
 */

/**
 * Get the relay server base URL
 * Priority:
 * 1. In browser: ALWAYS use /api/relay proxy (NEVER direct http://localhost:3001)
 * 2. Server-side: RELAY_INTERNAL_URL for SSR
 * 3. Fallback: http://localhost:3001
 */
export function getRelayBaseUrl(): string {
  // In browser: ALWAYS use /api/relay proxy
  if (typeof window !== 'undefined') {
    return '/api/relay';
  }

  // Server-side: use internal URL
  return process.env.RELAY_INTERNAL_URL || 'http://localhost:3001';
}
