/**
 * Relay JWT Manager - Client-Side Authentication Token Management
 * 
 * CRITICAL: This module manages relay-specific JWTs (NOT Clerk JWTs).
 * 
 * Flow:
 * 1. Client authenticates with Clerk (httpOnly cookie)
 * 2. Client calls `/api/relay/session` to get relay JWT
 * 3. JWT cached in memory (NOT localStorage - XSS risk)
 * 4. ALL relay requests include: Authorization: Bearer <relay_jwt>
 * 5. JWT auto-refreshes when expired (1 minute before expiry)
 * 
 * Security:
 * - JWT stored in memory only (cleared on page reload)
 * - JWT auto-refreshes using Clerk httpOnly cookie
 * - If refresh fails (Clerk session expired), mark relay auth as FAILED
 * - NO localStorage (vulnerable to XSS)
 * - NO sessionStorage (vulnerable to XSS)
 * 
 * @see RELAY_AUTH_ROOT_CAUSE_ANALYSIS.md
 */

import { relayAuthController } from './relay-auth-controller';

interface RelayJWTCache {
  token: string;
  username: string;
  expiresAt: number;
}

// In-memory cache (cleared on page reload)
let cachedJWT: RelayJWTCache | null = null;

// Flag to prevent concurrent JWT refresh requests
let refreshInProgress: Promise<string> | null = null;

/**
 * Get relay JWT (auto-refreshes if expired)
 * 
 * @returns Relay JWT token
 * @throws Error if authentication fails
 */
export async function getRelayJWT(): Promise<string> {
  // Check cache (with 1-minute buffer before expiry)
  if (cachedJWT && Date.now() < cachedJWT.expiresAt - 60000) {
    return cachedJWT.token;
  }

  // If refresh already in progress, wait for it
  if (refreshInProgress) {
    return refreshInProgress;
  }

  // Start JWT refresh
  refreshInProgress = (async () => {
    try {
      console.log('[RelayJWT] Fetching relay JWT from /api/relay/session');
      
      const res = await fetch('/api/relay/session', {
        method: 'POST',
        credentials: 'include', // Send Clerk httpOnly cookie
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ error: 'Unknown error' }));
        console.error('[RelayJWT] Failed to obtain relay JWT', {
          status: res.status,
          error: errorData,
        });

        // Mark relay auth as FAILED
        relayAuthController.markFailed(
          `Cannot obtain relay JWT: ${errorData.error || 'HTTP ' + res.status}`,
          res.status as 401 | 403
        );

        throw new Error(
          `Relay authentication failed (${res.status}): ${errorData.error || 'Unknown error'}`
        );
      }

      const data = await res.json();
      const { relayJWT, username, expiresAt } = data;

      if (!relayJWT || !username || !expiresAt) {
        console.error('[RelayJWT] Invalid response from /api/relay/session', data);
        throw new Error('Invalid relay session response');
      }

      // Cache JWT
      cachedJWT = {
        token: relayJWT,
        username,
        expiresAt,
      };

      console.log('[RelayJWT] Successfully obtained relay JWT', {
        username,
        expiresAt: new Date(expiresAt).toISOString(),
      });

      // Mark relay auth as VERIFIED
      relayAuthController.markAuthenticated();

      return relayJWT;
    } finally {
      refreshInProgress = null;
    }
  })();

  return refreshInProgress;
}

/**
 * Get authenticated headers for relay requests
 * 
 * Includes:
 * - Authorization: Bearer <relay_jwt>
 * - Content-Type: application/json
 * 
 * @returns Headers for fetch requests
 * @throws Error if authentication fails
 */
export async function getRelayAuthHeaders(): Promise<HeadersInit> {
  const token = await getRelayJWT();
  
  return {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  };
}

/**
 * Get cached username (if JWT exists)
 * 
 * @returns Username or null if not authenticated
 */
export function getCachedUsername(): string | null {
  return cachedJWT?.username || null;
}

/**
 * Check if relay JWT is cached and valid
 * 
 * @returns true if JWT exists and not expired
 */
export function hasValidRelayJWT(): boolean {
  return cachedJWT !== null && Date.now() < cachedJWT.expiresAt;
}

/**
 * Clear cached JWT (called on logout)
 */
export function clearRelayJWT(): void {
  console.log('[RelayJWT] Clearing cached JWT');
  cachedJWT = null;
  refreshInProgress = null;
  relayAuthController.reset();
}

/**
 * Force JWT refresh (useful for testing or manual refresh)
 * 
 * @returns New JWT token
 */
export async function forceRefreshRelayJWT(): Promise<string> {
  cachedJWT = null;
  refreshInProgress = null;
  return getRelayJWT();
}
