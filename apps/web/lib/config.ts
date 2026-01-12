/**
 * Configuration helpers for relay URL resolution
 * Centralizes relay base URL determination for client-side requests
 */

/**
 * Get the relay server base URL
 * Priority:
 * 1. In browser: ALWAYS use /api/relay proxy (NEVER direct relay access)
 * 2. Server-side: RELAY_URL for server-to-server with API key
 * 3. Fallback: http://localhost:3001
 * 
 * SECURITY: Browser NEVER accesses relay directly.
 * All browser requests go through Next.js /api/relay/* which:
 * - Adds RELAY_API_KEY server-side
 * - Enforces authentication
 * - Prevents enumeration attacks
 */
export function getRelayBaseUrl(): string {
  // In browser: ALWAYS use /api/relay proxy
  // Browser MUST NOT access relay directly (no API key, security boundary)
  if (typeof window !== 'undefined') {
    return '/api/relay';
  }

  // Server-side: use RELAY_URL with API key
  return process.env.RELAY_URL || process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';
}
