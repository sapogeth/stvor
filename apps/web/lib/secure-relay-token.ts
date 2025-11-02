/**
 * Secure Relay Token Manager
 *
 * SECURITY:
 * - Keeps relay JWT in memory by default (not localStorage)
 * - Auto-refreshes on 401 from relay
 * - Optional: encrypt token in keystore if persistence needed
 * - Protects against XSS token theft
 *
 * THREAT MODEL:
 * - XSS trying to steal token from localStorage
 * - Token leakage via browser extensions
 * - Token persistence across sessions (optional)
 *
 * @module secure-relay-token
 */

import { E2E_SECURITY_CONFIG } from './e2e-security-config';
import { secureKeystore } from './secure-keystore';

/**
 * In-memory token storage
 * SECURITY: Cleared on page refresh unless persistence enabled
 */
class RelayTokenManager {
  private token: string | null = null;
  private tokenExpiry: number | null = null;

  /**
   * Get current relay token
   * SECURITY: Returns null if expired or not set
   */
  getToken(): string | null {
    if (!this.token) {
      return null;
    }

    // Check if expired
    if (this.tokenExpiry && Date.now() > this.tokenExpiry) {
      console.log('[RelayToken] Token expired, clearing');
      this.token = null;
      this.tokenExpiry = null;
      return null;
    }

    return this.token;
  }

  /**
   * Set relay token
   * SECURITY: Stores in memory only unless persistence enabled
   *
   * @param token - JWT token from relay
   * @param expiresIn - Optional: seconds until expiry (default: 1 hour)
   */
  setToken(token: string, expiresIn: number = 3600): void {
    this.token = token;
    this.tokenExpiry = Date.now() + expiresIn * 1000;

    console.log('[RelayToken] Token set (in-memory), expires in', expiresIn, 'seconds');

    // Optional: persist to encrypted keystore
    if (E2E_SECURITY_CONFIG.persistRelayToken) {
      this.persistToken(token).catch((err) => {
        console.error('[RelayToken] Failed to persist token to keystore:', err);
      });
    }
  }

  /**
   * Clear token from memory
   * SECURITY: Called on logout or token revocation
   */
  clearToken(): void {
    console.log('[RelayToken] Clearing token from memory');
    this.token = null;
    this.tokenExpiry = null;

    // Also clear from keystore if persisted
    if (E2E_SECURITY_CONFIG.persistRelayToken) {
      this.clearPersistedToken().catch((err) => {
        console.error('[RelayToken] Failed to clear persisted token:', err);
      });
    }
  }

  /**
   * Check if token is valid (not expired, not null)
   */
  isValid(): boolean {
    return this.getToken() !== null;
  }

  /**
   * Persist token to encrypted keystore
   * SECURITY: Only called if persistRelayToken is true
   * Requires keystore to be unlocked
   */
  private async persistToken(token: string): Promise<void> {
    if (!secureKeystore.isUnlocked()) {
      console.warn('[RelayToken] Cannot persist token - keystore is locked');
      return;
    }

    try {
      secureKeystore.updateRelayToken(token);
      console.log('[RelayToken] Token persisted to encrypted keystore');
    } catch (err) {
      console.error('[RelayToken] Failed to persist token:', err);
      throw err;
    }
  }

  /**
   * Load token from encrypted keystore
   * SECURITY: Only called if persistRelayToken is true
   * Requires keystore to be unlocked
   */
  async loadPersistedToken(): Promise<string | null> {
    if (!E2E_SECURITY_CONFIG.persistRelayToken) {
      return null;
    }

    if (!secureKeystore.isUnlocked()) {
      console.log('[RelayToken] Cannot load persisted token - keystore is locked');
      return null;
    }

    try {
      const keystore = secureKeystore.getKeystore();
      const token = keystore.relayToken || null;

      if (token) {
        console.log('[RelayToken] Loaded token from encrypted keystore');
        this.token = token;
        // Set expiry to 1 hour from now (conservative)
        this.tokenExpiry = Date.now() + 3600 * 1000;
      }

      return token;
    } catch (err) {
      console.error('[RelayToken] Failed to load persisted token:', err);
      return null;
    }
  }

  /**
   * Clear persisted token from keystore
   */
  private async clearPersistedToken(): Promise<void> {
    if (!secureKeystore.isUnlocked()) {
      return;
    }

    try {
      secureKeystore.updateRelayToken('');
      console.log('[RelayToken] Cleared persisted token from keystore');
    } catch (err) {
      console.error('[RelayToken] Failed to clear persisted token:', err);
    }
  }

  /**
   * Migrate token from localStorage to secure storage
   * SECURITY: One-time migration, then removes from localStorage
   */
  async migrateFromLocalStorage(userId: string): Promise<void> {
    const legacyKey = `jwt_token_${userId}`;
    const token = localStorage.getItem(legacyKey);

    if (token) {
      console.warn('[RelayToken] Migrating token from localStorage to secure storage');

      // Set in memory
      this.setToken(token);

      // Remove from localStorage (insecure)
      localStorage.removeItem(legacyKey);

      console.log('[RelayToken] Migration complete, localStorage cleared');
    }
  }
}

// Singleton instance
export const relayTokenManager = new RelayTokenManager();

/**
 * Fetch fresh relay token from server
 * SECURITY: Uses Clerk session to authenticate
 *
 * @param userId - User ID to fetch token for
 * @returns JWT token or null on error
 */
export async function fetchFreshRelayToken(userId: string): Promise<string | null> {
  try {
    console.log('[RelayToken] Fetching fresh token from server');

    // Call your API endpoint that issues relay tokens
    // This endpoint should verify Clerk session and return a JWT
    const response = await fetch('/api/auth/relay-token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId }),
    });

    if (!response.ok) {
      console.error('[RelayToken] Failed to fetch token:', response.status);
      return null;
    }

    const data = await response.json();
    const token = data.token;

    if (!token) {
      console.error('[RelayToken] No token in response');
      return null;
    }

    // Parse expiry from JWT (optional)
    const expiresIn = data.expiresIn || 3600;

    // Store token
    relayTokenManager.setToken(token, expiresIn);

    console.log('[RelayToken] Fresh token fetched and stored');
    return token;
  } catch (err) {
    console.error('[RelayToken] Error fetching fresh token:', err);
    return null;
  }
}

/**
 * Get relay token (from memory or fetch fresh)
 * SECURITY: Auto-refreshes on expiry
 *
 * @param userId - User ID
 * @returns Token or null
 */
export async function getRelayToken(userId: string): Promise<string | null> {
  // Try to get from memory
  let token = relayTokenManager.getToken();

  if (token) {
    return token;
  }

  // Try to load from persisted keystore
  token = await relayTokenManager.loadPersistedToken();

  if (token) {
    return token;
  }

  // Fetch fresh token
  return await fetchFreshRelayToken(userId);
}

/**
 * Handle 401 from relay - refresh token
 * SECURITY: Auto-refresh on auth failure
 *
 * @param userId - User ID
 * @returns New token or null
 */
export async function handleRelayUnauthorized(userId: string): Promise<string | null> {
  console.warn('[RelayToken] Received 401 from relay, refreshing token');

  // Clear old token
  relayTokenManager.clearToken();

  // Fetch fresh token
  return await fetchFreshRelayToken(userId);
}
