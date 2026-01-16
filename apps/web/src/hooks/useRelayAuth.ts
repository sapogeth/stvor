'use client';

import { useEffect, useState, useCallback } from 'react';
import { useAuth } from '@clerk/nextjs';
import { relayAuthClient, RelayAuthState } from '@/lib/client/relay-auth-client';
import { secureIdentityClient, IdentityState } from '@/lib/client/secure-identity-client';

export interface UseRelayAuthResult {
  relayState: RelayAuthState;
  identityState: IdentityState;
  isFullyReady: boolean;
  isLoading: boolean;
  error: string | null;
  authenticate: () => Promise<boolean>;
  initializeIdentity: () => Promise<boolean>;
  logout: () => void;
}

export function useRelayAuth(): UseRelayAuthResult {
  const { isSignedIn, isLoaded: clerkLoaded } = useAuth();
  const [relayState, setRelayState] = useState<RelayAuthState>(relayAuthClient.getState());
  const [identityState, setIdentityState] = useState<IdentityState>(secureIdentityClient.getState());

  // Subscribe to state changes
  useEffect(() => {
    const unsubRelay = relayAuthClient.subscribe(setRelayState);
    const unsubIdentity = secureIdentityClient.subscribe(setIdentityState);
    return () => {
      unsubRelay();
      unsubIdentity();
    };
  }, []);

  // Auto-authenticate when Clerk is ready
  useEffect(() => {
    if (clerkLoaded && isSignedIn && relayState.status === 'idle') {
      authenticate();
    }
  }, [clerkLoaded, isSignedIn, relayState.status]);

  // Auto-logout when Clerk signs out
  useEffect(() => {
    if (clerkLoaded && !isSignedIn && relayState.status === 'authenticated') {
      logout();
    }
  }, [clerkLoaded, isSignedIn, relayState.status]);

  const authenticate = useCallback(async (): Promise<boolean> => {
    return relayAuthClient.authenticate();
  }, []);

  const initializeIdentity = useCallback(async (): Promise<boolean> => {
    return secureIdentityClient.initialize();
  }, []);

  const logout = useCallback(() => {
    secureIdentityClient.clear();
    relayAuthClient.logout();
  }, []);

  const isFullyReady = 
    relayState.status === 'authenticated' &&
    identityState.status === 'verified' &&
    identityState.isRelayConfirmed;

  const isLoading =
    relayState.status === 'authenticating' ||
    identityState.status === 'generating' ||
    identityState.status === 'registering';

  const error = relayState.error || identityState.error;

  return {
    relayState,
    identityState,
    isFullyReady,
    isLoading,
    error,
    authenticate,
    initializeIdentity,
    logout,
  };
}
