'use client';

import { useEffect, ReactNode } from 'react';
import { useRelayAuth } from '@/hooks/use-relay-auth';

interface RelayAuthGuardProps {
  children: ReactNode;
  fallback?: ReactNode;
  requireIdentity?: boolean;
}

export function RelayAuthGuard({ 
  children, 
  fallback,
  requireIdentity = true 
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
    if (relayState.status === 'unauthenticated') {
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

  // Loading state
  if (isLoading) {
    return fallback || (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4" />
          <p className="text-muted-foreground">
            {relayState.status === 'authenticating' && 'Authenticating with relay...'}
            {identityState.status === 'generating' && 'Generating cryptographic identity...'}
            {identityState.status === 'registering' && 'Registering identity with relay...'}
          </p>
        </div>
      </div>
    );
  }

  // Error state - FAIL CLOSED
  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center max-w-md p-6 border rounded-lg bg-destructive/10">
          <h2 className="text-xl font-semibold text-destructive mb-2">
            Authentication Failed
          </h2>
          <p className="text-muted-foreground mb-4">
            {error === 'RELAY_AUTH_REQUIRED' && 'Unable to establish secure connection with relay.'}
            {error === 'NETWORK_ERROR' && 'Network error. Please check your connection.'}
            {error === 'REGISTRATION_FAILED' && 'Identity registration failed. Please try again.'}
            {error === 'EXCHANGE_FAILED' && 'Token exchange failed. Please sign in again.'}
            {!['RELAY_AUTH_REQUIRED', 'NETWORK_ERROR', 'REGISTRATION_FAILED', 'EXCHANGE_FAILED'].includes(error) && 
              `Error: ${error}`}
          </p>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-md"
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
