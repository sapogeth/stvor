import type { AuthErrorCode } from '@/lib/relay/types';

export interface RelayAuthState {
  status: 'idle' | 'authenticating' | 'authenticated' | 'failed';
  relayToken: string | null;
  expiresAt: Date | null;
  sessionId: string | null;
  username: string | null;
  error: AuthErrorCode | null;
}

const REFRESH_BUFFER_MS = 5 * 60 * 1000; // 5 min before expiry

class RelayAuthClient {
  private state: RelayAuthState = {
    status: 'idle',
    relayToken: null,
    expiresAt: null,
    sessionId: null,
    username: null,
    error: null,
  };

  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private listeners = new Set<(state: RelayAuthState) => void>();

  getState(): Readonly<RelayAuthState> {
    return { ...this.state };
  }

  subscribe(listener: (state: RelayAuthState) => void): () => void {
    this.listeners.add(listener);
    listener(this.getState());
    return () => this.listeners.delete(listener);
  }

  private setState(updates: Partial<RelayAuthState>): void {
    this.state = { ...this.state, ...updates };
    const snapshot = this.getState();
    this.listeners.forEach(l => l(snapshot));
  }

  /**
   * Authenticate with relay.
   * Clerk auth is handled by Next.js middleware (httpOnly cookie).
   * We just call /api/relay/auth/exchange.
   */
  async authenticate(): Promise<boolean> {
    if (this.state.status === 'authenticating') {
      console.warn('[RELAY_AUTH] Already authenticating');
      return false;
    }

    this.setState({ status: 'authenticating', error: null });

    try {
      const response = await fetch('/api/relay/auth/exchange', {
        method: 'POST',
        credentials: 'include', // Include Clerk cookie
        headers: { 'Content-Type': 'application/json' },
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        const errorCode = (data.error || 'RELAY_UNAVAILABLE') as AuthErrorCode;
        
        console.error('[RELAY_AUTH] Exchange failed:', errorCode);
        this.setState({
          status: 'failed',
          error: errorCode,
          relayToken: null,
          sessionId: null,
          username: null,
          expiresAt: null,
        });
        return false;
      }

      const { relayToken, expiresAt, sessionId, username } = await response.json();

      this.setState({
        status: 'authenticated',
        relayToken,
        expiresAt: new Date(expiresAt),
        sessionId,
        username,
        error: null,
      });

      this.scheduleRefresh();

      console.log('[RELAY_AUTH] Authenticated:', { username, sessionId: sessionId?.slice(0, 8) });
      return true;
    } catch (error) {
      console.error('[RELAY_AUTH] Network error:', error);
      this.setState({
        status: 'failed',
        error: 'RELAY_UNAVAILABLE',
        relayToken: null,
        sessionId: null,
        username: null,
        expiresAt: null,
      });
      return false;
    }
  }

  private scheduleRefresh(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }

    if (!this.state.expiresAt) return;

    const refreshAt = this.state.expiresAt.getTime() - REFRESH_BUFFER_MS;
    const delay = Math.max(0, refreshAt - Date.now());

    this.refreshTimer = setTimeout(() => {
      console.log('[RELAY_AUTH] Auto-refresh triggered');
      this.authenticate();
    }, delay);
  }

  /**
   * Get auth headers for relay requests.
   * THROWS if not authenticated - fail-fast.
   */
  getAuthHeaders(): Record<string, string> {
    if (this.state.status !== 'authenticated' || !this.state.relayToken) {
      throw new Error('RELAY_NOT_AUTHENTICATED');
    }
    return {
      'Authorization': `Bearer ${this.state.relayToken}`,
    };
  }

  /**
   * Check if currently authenticated and token not expired.
   */
  isAuthenticated(): boolean {
    return (
      this.state.status === 'authenticated' &&
      this.state.relayToken !== null &&
      this.state.expiresAt !== null &&
      this.state.expiresAt > new Date()
    );
  }

  /**
   * INVARIANT: Require authentication or throw.
   * Use before any sensitive operation.
   */
  requireAuth(): void {
    if (!this.isAuthenticated()) {
      throw new Error('RELAY_AUTH_REQUIRED');
    }
  }

  /**
   * Logout and clear state.
   */
  logout(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    this.setState({
      status: 'idle',
      relayToken: null,
      expiresAt: null,
      sessionId: null,
      username: null,
      error: null,
    });
  }

  /**
   * Get current username (from relay session).
   */
  getUsername(): string | null {
    return this.state.username;
  }
}

// Singleton
export const relayAuthClient = new RelayAuthClient();
