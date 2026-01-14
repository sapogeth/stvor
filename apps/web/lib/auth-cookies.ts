/**
 * Secure Authentication Cookie Management
 * 
 * SECURITY ARCHITECTURE:
 * - JWT tokens NEVER exposed to JavaScript
 * - httpOnly: prevents XSS token theft
 * - secure: HTTPS-only in production
 * - sameSite=strict: prevents CSRF
 * - path=/api/relay: scoped to relay proxies only
 * 
 * CRITICAL: This is the ONLY way to store authentication tokens securely in browser.
 * Any storage accessible to JavaScript (localStorage, sessionStorage, IndexedDB) is vulnerable to XSS.
 */

import { cookies } from 'next/headers';

const COOKIE_NAME = 'ilyazh_relay_token';
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60; // 7 days
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

/**
 * Set authentication cookie (server-side only)
 * MUST be called from Server Component or Route Handler
 */
export async function setAuthCookie(username: string, token: string): Promise<void> {
  const cookieStore = await cookies();
  
  cookieStore.set(COOKIE_NAME, token, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'strict',
    path: '/api/relay',
    maxAge: COOKIE_MAX_AGE,
  });
  
  console.log(`[AuthCookies] Set httpOnly cookie for user: ${username}`);
}

/**
 * Get authentication token from cookie (server-side only)
 * Returns null if cookie not found
 */
export async function getAuthCookie(): Promise<string | null> {
  const cookieStore = await cookies();
  const cookie = cookieStore.get(COOKIE_NAME);
  return cookie?.value || null;
}

/**
 * Clear authentication cookie (logout)
 */
export async function clearAuthCookie(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete(COOKIE_NAME);
  console.log('[AuthCookies] Cleared httpOnly cookie');
}

/**
 * Extract JWT from request (prioritizes httpOnly cookie, fallback to header for compatibility)
 * SECURITY: Query parameter support REMOVED (too risky)
 */
export async function extractJWTFromRequest(req: Request): Promise<string | null> {
  // Priority 1: httpOnly cookie (XSS-resistant under documented assumptions - see ARCHITECTURAL_ASSUMPTIONS.md §A1)
  const cookieToken = await getAuthCookie();
  if (cookieToken) {
    console.log('[AuthCookies] Using JWT from httpOnly cookie');
    return cookieToken;
  }
  
  // Priority 2: Authorization header (for backwards compatibility during migration)
  const authHeader = req.headers.get('authorization');
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    console.warn('[AuthCookies] Using JWT from Authorization header (LEGACY - migrate to cookies)');
    return token;
  }
  
  console.warn('[AuthCookies] No JWT found in cookie or header');
  return null;
}
