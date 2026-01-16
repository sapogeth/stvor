/**
 * RelayAuthController - Central Authority for Relay Authentication State
 * 
 * CRITICAL: This is the SINGLE SOURCE OF TRUTH for relay authentication.
 * 
 * ALL code must check isRelayAuthenticated() before:
 * - Creating identities
 * - Publishing prekey bundles
 * - Sending handshake messages
 * - Registering intents
 * - Polling sync endpoints
 * - Sending encrypted messages
 * 
 * RULE: If relay returns 401/403, we transition to FAILED state.
 * NO silent fallbacks. NO "DEV mode continue". NO retries without user action.
 * 
 * @see SECURITY_ARCHITECTURE_FINAL.md
 */

/**
 * Relay authentication states (finite state machine)
 */
export enum RelayAuthState {
  /** Initial state - auth not yet verified */
  UNVERIFIED = 'UNVERIFIED',
  
  /** Relay accepted our authentication (200 response from any protected endpoint) */
  VERIFIED = 'VERIFIED',
  
  /** Relay rejected our authentication (401/403 response) - TERMINAL STATE */
  FAILED = 'FAILED',
}

/**
 * Singleton controller for relay authentication state
 */
class RelayAuthController {
  private state: RelayAuthState = RelayAuthState.UNVERIFIED;
  private failureReason: string | null = null;
  private lastVerifiedAt: number | null = null;

  /**
   * Get current authentication state
   */
  getState(): RelayAuthState {
    return this.state;
  }

  /**
   * Check if relay is authenticated (safe to proceed with operations)
   */
  isRelayAuthenticated(): boolean {
    return this.state === RelayAuthState.VERIFIED;
  }

  /**
   * Check if relay authentication has failed (terminal state)
   */
  hasAuthFailed(): boolean {
    return this.state === RelayAuthState.FAILED;
  }

  /**
   * Get failure reason (if state is FAILED)
   */
  getFailureReason(): string | null {
    return this.failureReason;
  }

  /**
   * Mark relay as authenticated (called after successful 200 response)
   * CRITICAL: FAILED state is TERMINAL - cannot transition to VERIFIED
   */
  markAuthenticated(): void {
    if (this.state === RelayAuthState.FAILED) {
      const errorMsg = `[RelayAuth] TERMINAL STATE: Cannot transition from FAILED to VERIFIED. Reason: ${this.failureReason}`;
      console.error(errorMsg);
      throw new Error('Relay auth failed. Re-authentication required. Cannot proceed.');
    }

    this.state = RelayAuthState.VERIFIED;
    this.failureReason = null;
    this.lastVerifiedAt = Date.now();
    console.log('[RelayAuth] ✅ Relay authentication VERIFIED');
  }

  /**
   * Mark relay authentication as failed (called after 401/403 response)
   * 
   * CRITICAL: This is a TERMINAL STATE. Once failed, user must take action.
   */
  markFailed(reason: string, statusCode: 401 | 403): void {
    this.state = RelayAuthState.FAILED;
    this.failureReason = `HTTP ${statusCode}: ${reason}`;
    this.lastVerifiedAt = null;
    console.error(`[RelayAuth] ❌ Relay authentication FAILED: ${this.failureReason}`);
  }

  /**
   * Reset authentication state (used for logout or manual retry)
   * 
   * WARNING: Only call this when user explicitly logs out or requests retry.
   * Do NOT call this automatically on failures.
   */
  reset(): void {
    console.log('[RelayAuth] Resetting authentication state');
    this.state = RelayAuthState.UNVERIFIED;
    this.failureReason = null;
    this.lastVerifiedAt = null;
  }

  /**
   * Get time of last successful verification (milliseconds since epoch)
   */
  getLastVerifiedAt(): number | null {
    return this.lastVerifiedAt;
  }

  /**
   * Process HTTP response and update auth state accordingly
   * 
   * @param response - Fetch Response object
   * @param operation - Description of operation (for logging)
   * @returns true if response is OK, false if auth failed
   */
  processResponse(response: Response, operation: string): boolean {
    if (response.ok) {
      // Success - mark as authenticated
      if (this.state !== RelayAuthState.VERIFIED) {
        this.markAuthenticated();
      }
      return true;
    }

    // Auth failure - mark as failed
    if (response.status === 401 || response.status === 403) {
      const reason = response.status === 401 
        ? `Unauthorized during ${operation}`
        : `Forbidden during ${operation}`;
      this.markFailed(reason, response.status);
      return false;
    }

    // Other errors don't affect auth state
    return false;
  }
}

// Export singleton instance
export const relayAuthController = new RelayAuthController();

/**
 * Helper: Throw error if relay is not authenticated
 * 
 * Use this at the start of any function that requires relay access.
 */
export function requireRelayAuth(operation: string): void {
  if (relayAuthController.hasAuthFailed()) {
    throw new Error(
      `Cannot ${operation}: Relay authentication failed. ` +
      `Reason: ${relayAuthController.getFailureReason()}`
    );
  }

  if (!relayAuthController.isRelayAuthenticated()) {
    throw new Error(
      `Cannot ${operation}: Relay authentication not yet verified. ` +
      `Please wait for initial connection or refresh the page.`
    );
  }
}

/**
 * CRITICAL: Full reset when auth has FAILED
 * 
 * This clears ALL crypto state and forces full re-authentication.
 * Call this when user clicks "Re-authenticate" or "Reset Session".
 * 
 * NEVER call this automatically - user must explicitly request it.
 */
export async function performFullAuthReset(): Promise<void> {
  console.warn('[RelayAuth] ⚠️ Performing FULL authentication reset...');
  
  try {
    // 1. Clear identity from IndexedDB
    const { keystore } = await import('@/lib/keystore');
    await keystore.init();
    await keystore.deleteDatabase();
    console.log('[RelayAuth] ✅ Deleted keystore database (identity, sessions, prekeys)');
  } catch (err) {
    console.error('[RelayAuth] Failed to clear keystore:', err);
  }
  
  try {
    // 2. Clear relay JWT from memory cache
    const { clearRelayJWT } = await import('@/lib/relay-jwt-manager');
    clearRelayJWT();
    console.log('[RelayAuth] ✅ Cleared relay JWT cache');
  } catch (err) {
    console.error('[RelayAuth] Failed to clear JWT cache:', err);
  }
  
  try {
    // 3. Clear session storage
    sessionStorage.clear();
    console.log('[RelayAuth] ✅ Cleared session storage');
  } catch (err) {
    console.error('[RelayAuth] Failed to clear session storage:', err);
  }
  
  // 4. Reset the auth controller state (now safe to re-auth)
  relayAuthController.reset();
  console.log('[RelayAuth] ✅ Reset auth controller state');
  
  console.log('[RelayAuth] 🔄 Full reset complete. User must re-authenticate.');
}
