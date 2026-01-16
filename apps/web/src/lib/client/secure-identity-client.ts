import { relayAuthClient } from './relay-auth-client';
import type { AuthErrorCode } from '@/lib/relay/types';

export interface CryptoIdentity {
  publicKeys: {
    identity: string;
    signedPreKey: string;
    kyberPreKey: string;
  };
  // Private keys kept in memory only
  privateKeysAvailable: boolean;
}

export type IdentityStatus = 
  | 'uninitialized'
  | 'generating'
  | 'registering'
  | 'verified'
  | 'failed';

export interface IdentityState {
  status: IdentityStatus;
  identity: CryptoIdentity | null;
  error: AuthErrorCode | null;
  isRelayConfirmed: boolean;
}

class SecureIdentityClient {
  private state: IdentityState = {
    status: 'uninitialized',
    identity: null,
    error: null,
    isRelayConfirmed: false,
  };

  private listeners = new Set<(state: IdentityState) => void>();

  // Private keys stored separately, never serialized
  private privateKeys: {
    identityPrivate?: CryptoKey;
    signedPreKeyPrivate?: CryptoKey;
    kyberSecret?: Uint8Array;
  } = {};

  getState(): Readonly<IdentityState> {
    return { ...this.state };
  }

  subscribe(listener: (state: IdentityState) => void): () => void {
    this.listeners.add(listener);
    listener(this.getState());
    return () => this.listeners.delete(listener);
  }

  private setState(updates: Partial<IdentityState>): void {
    this.state = { ...this.state, ...updates };
    const snapshot = this.getState();
    this.listeners.forEach(l => l(snapshot));
  }

  /**
   * Initialize identity.
   * 
   * INVARIANT: Relay auth MUST be valid BEFORE calling this.
   * INVARIANT: If relay registration fails, identity is DISCARDED.
   * INVARIANT: NO LOCAL-ONLY MODE.
   */
  async initialize(): Promise<boolean> {
    // HARD FAIL if relay not authenticated
    if (!relayAuthClient.isAuthenticated()) {
      console.error('[IDENTITY] FATAL: Relay not authenticated');
      this.setState({
        status: 'failed',
        error: 'RELAY_UNAVAILABLE',
        isRelayConfirmed: false,
      });
      return false;
    }

    if (this.state.status === 'generating' || this.state.status === 'registering') {
      console.warn('[IDENTITY] Already initializing');
      return false;
    }

    const username = relayAuthClient.getUsername();
    if (!username) {
      console.error('[IDENTITY] FATAL: No username from relay');
      this.setState({
        status: 'failed',
        error: 'RELAY_UNAVAILABLE',
        isRelayConfirmed: false,
      });
      return false;
    }

    this.setState({ status: 'generating', error: null });

    try {
      // Step 1: Generate keys
      const { publicKeys, privateKeys } = await this.generateKeys();
      this.privateKeys = privateKeys;

      this.setState({
        status: 'registering',
        identity: { publicKeys, privateKeysAvailable: true },
      });

      // Step 2: Sign public keys
      const signature = await this.signPublicKeys(publicKeys, privateKeys.identityPrivate!);

      // Step 3: Register with relay (MUST succeed)
      const response = await fetch(`/api/relay/directory/${username}`, {
        method: 'POST',
        headers: {
          ...relayAuthClient.getAuthHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ publicKeys, signature }),
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        const errorCode = (data.error || 'INTERNAL_ERROR') as AuthErrorCode;
        
        console.error('[IDENTITY] Registration failed:', errorCode);
        
        // CRITICAL: Discard identity on failure
        this.clearPrivateKeys();
        this.setState({
          status: 'failed',
          identity: null,
          error: errorCode,
          isRelayConfirmed: false,
        });
        return false;
      }

      // Step 4: Verify registration
      const verifyResponse = await fetch(`/api/relay/directory/${username}`, {
        headers: relayAuthClient.getAuthHeaders(),
      });

      if (!verifyResponse.ok) {
        console.error('[IDENTITY] Verification failed');
        this.clearPrivateKeys();
        this.setState({
          status: 'failed',
          identity: null,
          error: 'IDENTITY_NOT_FOUND',
          isRelayConfirmed: false,
        });
        return false;
      }

      // SUCCESS
      this.setState({
        status: 'verified',
        identity: { publicKeys, privateKeysAvailable: true },
        error: null,
        isRelayConfirmed: true,
      });

      console.log('[IDENTITY] Initialized and verified:', username);
      return true;
    } catch (error) {
      console.error('[IDENTITY] Initialization error:', error);
      this.clearPrivateKeys();
      this.setState({
        status: 'failed',
        identity: null,
        error: 'INTERNAL_ERROR',
        isRelayConfirmed: false,
      });
      return false;
    }
  }

  private async generateKeys() {
    // Ed25519 identity key
    const identityKeyPair = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify']
    ) as CryptoKeyPair;

    // X25519 signed pre-key
    const signedPreKeyPair = await crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveBits']
    ) as CryptoKeyPair;

    // ML-KEM-768 (placeholder - use actual library)
    const kyberPublic = crypto.getRandomValues(new Uint8Array(1184));
    const kyberSecret = crypto.getRandomValues(new Uint8Array(2400));

    // Export public keys
    const identityPubRaw = await crypto.subtle.exportKey('raw', identityKeyPair.publicKey);
    const signedPreKeyPubRaw = await crypto.subtle.exportKey('raw', signedPreKeyPair.publicKey);

    return {
      publicKeys: {
        identity: this.bufferToBase64(identityPubRaw),
        signedPreKey: this.bufferToBase64(signedPreKeyPubRaw),
        kyberPreKey: this.uint8ToBase64(kyberPublic),
      },
      privateKeys: {
        identityPrivate: identityKeyPair.privateKey,
        signedPreKeyPrivate: signedPreKeyPair.privateKey,
        kyberSecret,
      },
    };
  }

  private async signPublicKeys(
    publicKeys: { identity: string; signedPreKey: string; kyberPreKey: string },
    privateKey: CryptoKey
  ): Promise<string> {
    const data = JSON.stringify(publicKeys);
    const encoded = new TextEncoder().encode(data);
    const signature = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, encoded);
    return this.bufferToBase64(signature);
  }

  private clearPrivateKeys(): void {
    if (this.privateKeys.kyberSecret) {
      this.privateKeys.kyberSecret.fill(0);
    }
    this.privateKeys = {};
  }

  private bufferToBase64(buffer: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  }

  private uint8ToBase64(arr: Uint8Array): string {
    return btoa(String.fromCharCode(...arr));
  }

  /**
   * Check if identity is usable for cryptographic operations.
   */
  isUsable(): boolean {
    return (
      this.state.status === 'verified' &&
      this.state.identity !== null &&
      this.state.isRelayConfirmed &&
      this.state.identity.privateKeysAvailable
    );
  }

  /**
   * INVARIANT: Require usable identity or throw.
   */
  requireUsable(): CryptoIdentity {
    if (!this.isUsable()) {
      throw new Error('IDENTITY_NOT_USABLE');
    }
    return this.state.identity!;
  }

  /**
   * Clear identity state.
   */
  clear(): void {
    this.clearPrivateKeys();
    this.setState({
      status: 'uninitialized',
      identity: null,
      error: null,
      isRelayConfirmed: false,
    });
  }
}

// Singleton
export const secureIdentityClient = new SecureIdentityClient();
