/**
 * Relay Register Backoff - Exponential backoff for /register endpoint
 *
 * SECURITY:
 * - Prevents rate-limit abuse (429 errors)
 * - Limits total retry attempts
 * - Exponential backoff prevents tight retry loops
 * - Handles 409 Conflict gracefully (user already registered)
 *
 * THREAT MODEL:
 * - Prevents: Accidental DoS of relay server
 * - Prevents: Rate-limit bans
 * - Prevents: Silent re-enrollment loops
 *
 * @module relay-register-backoff
 */

import {
  getRegisterBackoffDelay,
  isMaxRegisterAttemptsExceeded,
  E2E_SECURITY_CONFIG,
} from './e2e-security-config';
import { logWarn, logInfo } from './logger';

/**
 * Register attempt state
 */
interface RegisterAttemptState {
  attemptNumber: number;
  lastAttemptTime: number;
  totalAttempts: number;
}

/**
 * Per-user attempt tracking
 * SECURITY: Prevents infinite retry loops
 */
const attemptStates = new Map<string, RegisterAttemptState>();

/**
 * Reset attempt state for user
 * Called on successful registration
 */
export function resetRegisterAttempts(userId: string): void {
  attemptStates.delete(userId);
  logInfo('relay-register', 'Reset attempt counter for user', { userId });
}

/**
 * Get current attempt state for user
 */
function getAttemptState(userId: string): RegisterAttemptState {
  let state = attemptStates.get(userId);

  if (!state) {
    state = {
      attemptNumber: 0,
      lastAttemptTime: 0,
      totalAttempts: 0,
    };
    attemptStates.set(userId, state);
  }

  return state;
}

/**
 * Wait for backoff delay before next attempt
 * SECURITY: Exponential backoff prevents tight retry loops
 */
async function waitForBackoff(attemptNumber: number): Promise<void> {
  const delayMs = getRegisterBackoffDelay(attemptNumber);

  logInfo('relay-register', `Backing off before retry (attempt ${attemptNumber})`, {
    delayMs,
    delaySec: (delayMs / 1000).toFixed(1),
  });

  await new Promise((resolve) => setTimeout(resolve, delayMs));
}

/**
 * Register user with relay (with exponential backoff)
 * SECURITY: Handles 409/429 gracefully, prevents retry loops
 *
 * @param userId - User ID to register
 * @param registerFn - Function that performs the actual registration
 * @returns Success status and optional token
 */
export async function registerWithBackoff(
  userId: string,
  registerFn: () => Promise<{ success: boolean; token?: string; status?: number }>
): Promise<{ success: boolean; token?: string; reason?: string }> {
  const state = getAttemptState(userId);

  // Check if max attempts exceeded
  if (isMaxRegisterAttemptsExceeded(state.attemptNumber + 1)) {
    logWarn('relay-register', 'Max register attempts exceeded', {
      userId,
      attempts: state.totalAttempts,
      maxAttempts: E2E_SECURITY_CONFIG.registerBackoff.maxAttempts,
    });

    return {
      success: false,
      reason: `Maximum registration attempts exceeded (${E2E_SECURITY_CONFIG.registerBackoff.maxAttempts})`,
    };
  }

  // Increment attempt counter
  state.attemptNumber++;
  state.totalAttempts++;
  state.lastAttemptTime = Date.now();

  // Wait for backoff if this is not the first attempt
  if (state.attemptNumber > 1) {
    await waitForBackoff(state.attemptNumber);
  }

  logInfo('relay-register', 'Attempting registration', {
    userId,
    attemptNumber: state.attemptNumber,
    totalAttempts: state.totalAttempts,
  });

  try {
    const result = await registerFn();

    // Success - reset attempts
    if (result.success) {
      logInfo('relay-register', 'Registration successful', { userId });
      resetRegisterAttempts(userId);
      return result;
    }

    // Handle specific status codes
    if (result.status === 409) {
      // User already registered - this is actually OK
      logInfo('relay-register', 'User already registered (409 Conflict)', { userId });
      resetRegisterAttempts(userId);
      return {
        success: true,
        token: result.token,
        reason: 'User already registered',
      };
    }

    if (result.status === 429) {
      // Rate limited - back off more
      logWarn('relay-register', 'Rate limited by relay (429)', {
        userId,
        attemptNumber: state.attemptNumber,
      });

      // Don't retry immediately on 429 - let caller decide
      return {
        success: false,
        reason: 'Rate limited by relay server. Please wait and try again later.',
      };
    }

    // Other failure - retry with backoff
    logWarn('relay-register', 'Registration failed, will retry', {
      userId,
      status: result.status,
      attemptNumber: state.attemptNumber,
    });

    // Recursive retry
    return await registerWithBackoff(userId, registerFn);
  } catch (err) {
    logWarn('relay-register', 'Registration error', {
      userId,
      error: err instanceof Error ? err.message : String(err),
      attemptNumber: state.attemptNumber,
    });

    // Network error or other exception - retry with backoff
    if (state.attemptNumber < E2E_SECURITY_CONFIG.registerBackoff.maxAttempts) {
      return await registerWithBackoff(userId, registerFn);
    }

    return {
      success: false,
      reason: `Registration failed after ${state.attemptNumber} attempts: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * Check if user can attempt registration
 * SECURITY: Prevents retry spam
 */
export function canAttemptRegister(userId: string): boolean {
  const state = getAttemptState(userId);

  if (isMaxRegisterAttemptsExceeded(state.attemptNumber + 1)) {
    return false;
  }

  // Check if we're still in backoff period
  const minDelay = getRegisterBackoffDelay(state.attemptNumber);
  const timeSinceLastAttempt = Date.now() - state.lastAttemptTime;

  if (timeSinceLastAttempt < minDelay) {
    logInfo('relay-register', 'Still in backoff period', {
      userId,
      remainingMs: minDelay - timeSinceLastAttempt,
    });
    return false;
  }

  return true;
}

/**
 * Get remaining time until next attempt allowed (in ms)
 * Returns 0 if can attempt now
 */
export function getRemainingBackoffTime(userId: string): number {
  const state = getAttemptState(userId);

  if (state.attemptNumber === 0) {
    return 0;
  }

  const minDelay = getRegisterBackoffDelay(state.attemptNumber);
  const timeSinceLastAttempt = Date.now() - state.lastAttemptTime;

  if (timeSinceLastAttempt >= minDelay) {
    return 0;
  }

  return minDelay - timeSinceLastAttempt;
}
