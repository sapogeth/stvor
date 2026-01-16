'use client';

import { useEffect, useState, useCallback } from 'react';
import { useAuth } from '@clerk/nextjs';
import { relayAuthService, RelayAuthState } from '@/lib/client/relay-auth-service';
import { secureIdentityService, IdentityState } from '@/lib/client/secure-identity-service';

export interface UseRelayAuthResult {
  relayState: RelayAuthState;
  identityState: IdentityState;
  isFullyAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  authenticate: () => Promise<boolean>;
  initializeIdentity: () => Promise<boolean>;
  logout: () => void;
}

export function useRelayAuth(): UseRelayAuthResult {
  const { getToken, userId, isSignedIn } = useAuth();
  const [relayState, setRelayState] = useState<RelayAuthState>(relayAuthService.getState());
  const [identityState, setIdentityState] = useState<IdentityState>(secureIdentityService.getState());

  // Subscribe to state changes
  useEffect(() => {
    const unsubRelay = relayAuthService.subscribe(setRelayState);
    const unsubIdentity = secureIdentityService.subscribe(setIdentityState);
    return () => {
      unsubRelay();
      unsubIdentity();
    };
  }, []);

  // Auto-authenticate when Clerk session is ready
  useEffect(() => {
    if (isSignedIn && relayState.status === 'unauthenticated') {
      authenticate();
    }
  }, [isSignedIn]);

  // Auto-logout when Clerk session ends
  useEffect(() => {
    if (!isSignedIn && relayState.status === 'authenticated') {
      logout();
    }
  }, [isSignedIn]);

  const authenticate = useCallback(async (): Promise<boolean> => {
    if (!isSignedIn) {
      console.error('[USE_RELAY_AUTH] Not signed in to Clerk');
      return false;
    }

    return relayAuthService.authenticate(async () => {
      return getToken();
    });
  }, [isSignedIn, getToken]);

  const initializeIdentity = useCallback(async (): Promise<boolean> => {
    if (!userId) {
      console.error('[USE_RELAY_AUTH] No userId');
      return false;
    }

    if (!relayAuthService.isAuthenticated()) {
      console.error('[USE_RELAY_AUTH] Must authenticate with relay first');
      return false;
    }

    return secureIdentityService.initializeIdentity(userId);
  }, [userId]);

  const logout = useCallback(() => {
    secureIdentityService.clear();
    relayAuthService.logout();
  }, []);

  const isFullyAuthenticated = 
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
    isFullyAuthenticated,
    isLoading,
    error,
    authenticate,
    initializeIdentity,
    logout,
  };
}
