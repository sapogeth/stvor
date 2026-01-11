/**
 * Configuration helpers for relay URL resolution
 * Centralizes relay base URL determination for client-side requests
 */

/**
 * Get the relay server base URL
 * Priority:
 * 1. In browser: Use NEXT_PUBLIC_RELAY_URL (Fly.io relay directly, NOT /api/relay proxy)
 * 2. Server-side: RELAY_URL for server-to-server
 * 3. Fallback: http://localhost:3001
 */
export function getRelayBaseUrl(): string {
  // In browser: Use NEXT_PUBLIC_RELAY_URL to connect directly to relay
  // (not through Next.js /api/relay proxy - that has auth/intent overhead)
  if (typeof window !== 'undefined') {
    return process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';
  }

  // Server-side: use private RELAY_URL
  return process.env.RELAY_URL || 'http://localhost:3001';
}
