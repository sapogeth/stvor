import { useAuth } from '@clerk/nextjs';

export interface RelayAuthState {
  status: 'unauthenticated' | 'authenticating' | 'authenticated' | 'error';
  relayToken: string | null;
  expiresAt: Date | null;
  sessionId: string | null;
  error: string | null;
}

const RELAY_TOKEN_REFRESH_BUFFER = 5 * 60 * 1000; // Refresh 5 min before expiry

class RelayAuthService {
  private state: RelayAuthState = {
    status: 'unauthenticated',
    relayToken: null,
    expiresAt: null,
    sessionId: null,
    error: null,
  };

  private refreshTimer: NodeJS.Timeout | null = null;
  private listeners: Set<(state: RelayAuthState) => void> = new Set();

  getState(): RelayAuthState {
    return { ...this.state };
  }

  subscribe(listener: (state: RelayAuthState) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify(): void {
    const state = this.getState();
    this.listeners.forEach(listener => listener(state));
  }

  private setState(updates: Partial<RelayAuthState>): void {
    this.state = { ...this.state, ...updates };
    this.notify();
  }

  async authenticate(getClerkToken: () => Promise<string | null>): Promise<boolean> {
    if (this.state.status === 'authenticating') {
      console.warn('[RELAY_AUTH] Already authenticating');
      return false;
    }

    this.setState({ status: 'authenticating', error: null });

    try {
      const clerkToken = await getClerkToken();
      if (!clerkToken) {
        this.setState({ 
          status: 'error', 
          error: 'CLERK_TOKEN_UNAVAILABLE',
          relayToken: null,
          sessionId: null,
          expiresAt: null,
        });
        return false;
      }

      const response = await fetch('/api/relay/auth/exchange', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${clerkToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'UNKNOWN' }));
        console.error('[RELAY_AUTH] Exchange failed:', error);
        this.setState({
          status: 'error',
          error: error.error || 'EXCHANGE_FAILED',
          relayToken: null,
          sessionId: null,
          expiresAt: null,
        });
        return false;
      }

      const { relayToken, expiresAt, sessionId } = await response.json();

      this.setState({
        status: 'authenticated',
        relayToken,
        expiresAt: new Date(expiresAt),
        sessionId,
        error: null,
      });

      // Schedule token refresh
      this.scheduleRefresh(getClerkToken);

      console.log('[RELAY_AUTH] Authenticated, sessionId:', sessionId);
      return true;
    } catch (error) {
      console.error('[RELAY_AUTH] Authentication error:', error);
      this.setState({
        status: 'error',
        error: 'NETWORK_ERROR',
        relayToken: null,
        sessionId: null,
        expiresAt: null,
      });
      return false;
    }
  }

  private scheduleRefresh(getClerkToken: () => Promise<string | null>): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }

    if (!this.state.expiresAt) return;

    const refreshAt = this.state.expiresAt.getTime() - RELAY_TOKEN_REFRESH_BUFFER;
    const delay = Math.max(0, refreshAt - Date.now());

    this.refreshTimer = setTimeout(async () => {
      console.log('[RELAY_AUTH] Token refresh triggered');
      await this.authenticate(getClerkToken);
    }, delay);
  }

  async verifySession(): Promise<boolean> {
    if (!this.state.relayToken) {
      return false;
    }

    try {
      const response = await fetch('/api/relay/session', {
        headers: {
          'Authorization': `Bearer ${this.state.relayToken}`,
        },
      });

      return response.ok;
    } catch {
      return false;
    }
  }

  getAuthHeaders(): Record<string, string> {
    if (!this.state.relayToken) {
      throw new Error('RELAY_NOT_AUTHENTICATED');
    }
    return {
      'Authorization': `Bearer ${this.state.relayToken}`,
    };
  }

  requireAuth(): void {
    if (this.state.status !== 'authenticated' || !this.state.relayToken) {
      throw new Error('RELAY_AUTH_REQUIRED');
    }
  }

  logout(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }
    this.setState({
      status: 'unauthenticated',
      relayToken: null,
      expiresAt: null,
      sessionId: null,
      error: null,
    });
  }

  isAuthenticated(): boolean {
    return this.state.status === 'authenticated' && 
           this.state.relayToken !== null &&
           this.state.expiresAt !== null &&
           this.state.expiresAt > new Date();
  }
}

// Singleton instance
export const relayAuthService = new RelayAuthService();
