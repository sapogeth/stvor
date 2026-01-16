import { relayAuthService } from './relay-auth-service';

export interface CryptoIdentity {
  identityKeyPair: CryptoKeyPair;
  signedPreKeyPair: CryptoKeyPair;
  kyberKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
  publicKeys: {
    identity: string;
    signedPreKey: string;
    kyberPreKey: string;
  };
}

export type IdentityStatus = 
  | 'uninitialized'
  | 'generating'
  | 'registering'
  | 'verified'
  | 'error';

export interface IdentityState {
  status: IdentityStatus;
  identity: CryptoIdentity | null;
  error: string | null;
  isRelayConfirmed: boolean;
}

class SecureIdentityService {
  private state: IdentityState = {
    status: 'uninitialized',
    identity: null,
    error: null,
    isRelayConfirmed: false,
  };

  private listeners: Set<(state: IdentityState) => void> = new Set();

  getState(): IdentityState {
    return { ...this.state };
  }

  subscribe(listener: (state: IdentityState) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify(): void {
    const state = this.getState();
    this.listeners.forEach(listener => listener(state));
  }

  private setState(updates: Partial<IdentityState>): void {
    this.state = { ...this.state, ...updates };
    this.notify();
  }

  /**
   * CRITICAL INVARIANT:
   * Identity generation and registration MUST happen atomically with relay.
   * If relay registration fails, the identity is DISCARDED.
   * There is NO local-only mode.
   */
  async initializeIdentity(userId: string): Promise<boolean> {
    // INVARIANT: Must be authenticated with relay first
    if (!relayAuthService.isAuthenticated()) {
      console.error('[IDENTITY] Cannot initialize: relay not authenticated');
      this.setState({
        status: 'error',
        error: 'RELAY_AUTH_REQUIRED',
        isRelayConfirmed: false,
      });
      return false;
    }

    if (this.state.status === 'generating' || this.state.status === 'registering') {
      console.warn('[IDENTITY] Already initializing');
      return false;
    }

    this.setState({ status: 'generating', error: null });

    try {
      // Step 1: Generate cryptographic identity
      const identity = await this.generateCryptoIdentity();

      this.setState({ status: 'registering', identity });

      // Step 2: Register with relay (MUST succeed)
      const signature = await this.signPublicKeys(identity);
      
      const response = await fetch(`/api/relay/directory/${userId}`, {
        method: 'POST',
        headers: {
          ...relayAuthService.getAuthHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          publicKeys: identity.publicKeys,
          signature,
        }),
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'UNKNOWN' }));
        console.error('[IDENTITY] Registration failed:', error);
        
        // CRITICAL: Discard identity if relay registration fails
        this.setState({
          status: 'error',
          identity: null, // DISCARDED
          error: error.error || 'REGISTRATION_FAILED',
          isRelayConfirmed: false,
        });
        return false;
      }

      // Step 3: Verify registration
      const verifyResponse = await fetch(`/api/relay/directory/${userId}`, {
        headers: relayAuthService.getAuthHeaders(),
      });

      if (!verifyResponse.ok) {
        console.error('[IDENTITY] Verification failed');
        this.setState({
          status: 'error',
          identity: null,
          error: 'VERIFICATION_FAILED',
          isRelayConfirmed: false,
        });
        return false;
      }

      // SUCCESS: Identity is now relay-confirmed
      this.setState({
        status: 'verified',
        identity,
        error: null,
        isRelayConfirmed: true,
      });

      console.log('[IDENTITY] Successfully initialized and verified');
      return true;
    } catch (error) {
      console.error('[IDENTITY] Initialization error:', error);
      this.setState({
        status: 'error',
        identity: null,
        error: 'INITIALIZATION_FAILED',
        isRelayConfirmed: false,
      });
      return false;
    }
  }

  private async generateCryptoIdentity(): Promise<CryptoIdentity> {
    // Generate Ed25519 identity key pair
    const identityKeyPair = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify']
    ) as CryptoKeyPair;

    // Generate X25519 signed pre-key
    const signedPreKeyPair = await crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveBits']
    ) as CryptoKeyPair;

    // Generate ML-KEM-768 (Kyber) key pair
    // NOTE: This requires liboqs-js or similar library
    const kyberKeyPair = await this.generateKyberKeyPair();

    // Export public keys
    const identityPubRaw = await crypto.subtle.exportKey('raw', identityKeyPair.publicKey);
    const signedPreKeyPubRaw = await crypto.subtle.exportKey('raw', signedPreKeyPair.publicKey);

    const publicKeys = {
      identity: this.arrayBufferToBase64(identityPubRaw),
      signedPreKey: this.arrayBufferToBase64(signedPreKeyPubRaw),
      kyberPreKey: this.uint8ArrayToBase64(kyberKeyPair.publicKey),
    };

    return {
      identityKeyPair,
      signedPreKeyPair,
      kyberKeyPair,
      publicKeys,
    };
  }

  private async generateKyberKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    // Placeholder - integrate with actual ML-KEM implementation
    // In production, use liboqs-js or crystals-kyber
    const publicKey = crypto.getRandomValues(new Uint8Array(1184)); // ML-KEM-768 public key size
    const secretKey = crypto.getRandomValues(new Uint8Array(2400)); // ML-KEM-768 secret key size
    return { publicKey, secretKey };
  }

  private async signPublicKeys(identity: CryptoIdentity): Promise<string> {
    const dataToSign = JSON.stringify(identity.publicKeys);
    const encoder = new TextEncoder();
    const data = encoder.encode(dataToSign);

    const signature = await crypto.subtle.sign(
      { name: 'Ed25519' },
      identity.identityKeyPair.privateKey,
      data
    );

    return this.arrayBufferToBase64(signature);
  }

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  }

  private uint8ArrayToBase64(arr: Uint8Array): string {
    return btoa(String.fromCharCode(...arr));
  }

  /**
   * CRITICAL: Check if identity is usable
   * Identity is ONLY usable if relay-confirmed
   */
  isUsable(): boolean {
    return this.state.status === 'verified' && 
           this.state.identity !== null && 
           this.state.isRelayConfirmed;
  }

  requireUsableIdentity(): CryptoIdentity {
    if (!this.isUsable()) {
      throw new Error('IDENTITY_NOT_USABLE');
    }
    return this.state.identity!;
  }

  clear(): void {
    // Securely clear keys from memory
    if (this.state.identity?.kyberKeyPair) {
      this.state.identity.kyberKeyPair.secretKey.fill(0);
    }
    this.setState({
      status: 'uninitialized',
      identity: null,
      error: null,
      isRelayConfirmed: false,
    });
  }
}

export const secureIdentityService = new SecureIdentityService();
