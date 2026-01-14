'use client';

/**
 * RelayAuthWarning - Critical UI Component for Relay Authentication Failures
 * 
 * This component displays a BLOCKING ERROR when relay authentication fails.
 * User CANNOT proceed with messaging until auth is resolved.
 * 
 * Triggered when:
 * - Relay returns 401 Unauthorized
 * - Relay returns 403 Forbidden
 * - RelayAuthController.state === FAILED
 * 
 * @see relay-auth-controller.ts
 */

import { useEffect, useState } from 'react';
import { relayAuthController, RelayAuthState } from '@/lib/relay-auth-controller';

export function RelayAuthWarning() {
  const [authState, setAuthState] = useState<RelayAuthState>(RelayAuthState.UNVERIFIED);
  const [failureReason, setFailureReason] = useState<string | null>(null);

  useEffect(() => {
    // Poll auth state every second
    const interval = setInterval(() => {
      const state = relayAuthController.getState();
      setAuthState(state);
      
      if (state === RelayAuthState.FAILED) {
        setFailureReason(relayAuthController.getFailureReason());
      }
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  // Don't show warning if auth is OK or pending
  if (authState !== RelayAuthState.FAILED) {
    return null;
  }

  return (
    <div className="fixed top-0 left-0 right-0 z-50 bg-red-600 text-white px-6 py-4 shadow-lg">
      <div className="max-w-4xl mx-auto">
        <div className="flex items-start gap-4">
          {/* Error Icon */}
          <svg
            className="w-6 h-6 flex-shrink-0 mt-0.5"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
            />
          </svg>

          {/* Error Message */}
          <div className="flex-1">
            <h3 className="font-bold text-lg mb-1">
              🔒 Relay Authentication Failed
            </h3>
            <p className="text-sm opacity-95 mb-2">
              Cannot establish secure connection to relay server.
            </p>
            
            {failureReason && (
              <p className="text-xs font-mono bg-red-700 bg-opacity-50 px-3 py-2 rounded mb-3">
                {failureReason}
              </p>
            )}

            <div className="text-sm space-y-1 opacity-90">
              <p>⚠️ <strong>You cannot send or receive messages</strong> until this is resolved.</p>
              <p>🔄 Try the following:</p>
              <ul className="list-disc list-inside ml-4 space-y-0.5">
                <li>Refresh the page and sign in again</li>
                <li>Check your internet connection</li>
                <li>Clear browser cache and cookies</li>
                <li>Contact support if problem persists</li>
              </ul>
            </div>

            {/* Retry Button */}
            <button
              onClick={() => {
                relayAuthController.reset();
                window.location.reload();
              }}
              className="mt-4 px-4 py-2 bg-white text-red-600 font-semibold rounded hover:bg-red-50 transition-colors"
            >
              🔄 Retry Authentication
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * RelayAuthStatus - Subtle indicator for auth state (for debugging)
 * 
 * Shows small badge in corner indicating current relay auth state.
 * Only visible in development or when auth fails.
 */
export function RelayAuthStatus() {
  const [authState, setAuthState] = useState<RelayAuthState>(RelayAuthState.UNVERIFIED);

  useEffect(() => {
    const interval = setInterval(() => {
      setAuthState(relayAuthController.getState());
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  // Only show in dev or on failure
  if (process.env.NODE_ENV === 'production' && authState !== RelayAuthState.FAILED) {
    return null;
  }

  const stateColors = {
    [RelayAuthState.UNVERIFIED]: 'bg-yellow-500',
    [RelayAuthState.VERIFIED]: 'bg-green-500',
    [RelayAuthState.FAILED]: 'bg-red-500',
  };

  const stateLabels = {
    [RelayAuthState.UNVERIFIED]: '🟡 Unverified',
    [RelayAuthState.VERIFIED]: '🟢 Verified',
    [RelayAuthState.FAILED]: '🔴 Failed',
  };

  return (
    <div className="fixed bottom-4 right-4 z-40">
      <div
        className={`${stateColors[authState]} text-white text-xs font-mono px-3 py-1.5 rounded-full shadow-lg`}
      >
        {stateLabels[authState]}
      </div>
    </div>
  );
}
