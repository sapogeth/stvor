'use client';

import { useEffect, ReactNode } from 'react';
import { useRelayAuth } from '@/hooks/useRelayAuth';

interface RelayAuthGuardProps {
  children: ReactNode;
  fallback?: ReactNode;
  requireIdentity?: boolean;
}

export function RelayAuthGuard({
  children,
  fallback,
  requireIdentity = true,
}: RelayAuthGuardProps) {
  const {
    relayState,
    identityState,
    isLoading,
    error,
    authenticate,
    initializeIdentity,
  } = useRelayAuth();

  // Step 1: Authenticate with relay
  useEffect(() => {
    if (relayState.status === 'idle') {
      authenticate();
    }
  }, [relayState.status, authenticate]);

  // Step 2: Initialize identity after relay auth
  useEffect(() => {
    if (
      requireIdentity &&
      relayState.status === 'authenticated' &&
      identityState.status === 'uninitialized'
    ) {
      initializeIdentity();
    }
  }, [relayState.status, identityState.status, requireIdentity, initializeIdentity]);

  // Loading
  if (isLoading) {
    return fallback || (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-4" />
          <p className="text-gray-600">
            {relayState.status === 'authenticating' && 'Connecting to relay...'}
            {identityState.status === 'generating' && 'Generating cryptographic identity...'}
            {identityState.status === 'registering' && 'Registering with relay...'}
          </p>
        </div>
      </div>
    );
  }

  // FAIL-CLOSED: Any error blocks the app
  if (error || relayState.status === 'failed' || identityState.status === 'failed') {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center max-w-md p-6 border border-red-200 rounded-lg bg-red-50">
          <h2 className="text-xl font-semibold text-red-700 mb-2">
            Secure Connection Failed
          </h2>
          <p className="text-gray-700 mb-4">
            {error === 'RELAY_UNAVAILABLE' && 'Unable to connect to secure relay. Check your connection.'}
            {error === 'MISSING_AUTH' && 'Authentication required. Please sign in.'}
            {error === 'FORBIDDEN' && 'Access denied.'}
            {error === 'USERNAME_TAKEN' && 'Username is already in use.'}
            {error === 'IDENTITY_NOT_FOUND' && 'Identity verification failed.'}
            {!['RELAY_UNAVAILABLE', 'MISSING_AUTH', 'FORBIDDEN', 'USERNAME_TAKEN', 'IDENTITY_NOT_FOUND'].includes(error || '') && 
              `Error: ${error || 'Unknown error'}`}
          </p>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  // Not authenticated - block
  if (relayState.status !== 'authenticated') {
    return fallback || null;
  }

  // Identity required but not verified - block
  if (requireIdentity && identityState.status !== 'verified') {
    return fallback || null;
  }

  // All checks passed
  return <>{children}</>;
}
