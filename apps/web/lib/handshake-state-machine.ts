/**
 * Handshake State Machine
 * 
 * SECURITY-CRITICAL: Explicit finite state machine for handshake protocol
 * 
 * This module implements a formal state machine to prevent:
 * 1. Prekey regeneration during active handshake
 * 2. Duplicate/concurrent handshakes for same chat
 * 3. Race conditions in role determination
 * 4. Silent failures and undefined states
 * 
 * Protocol Safety Notes:
 * - State transitions are atomic and guarded
 * - Prekey mutation is BLOCKED while handshake is in progress
 * - Role (initiator/responder) is deterministic based on identity comparison
 * - Failed handshakes require explicit retry, no auto-healing
 * 
 * @module handshake-state-machine
 */

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/**
 * Handshake states
 * 
 * INVARIANTS:
 * - Only IDLE state allows prekey regeneration
 * - INITIATING and RESPONDING states MUST complete or fail
 * - No implicit state transitions
 */
export enum HandshakeState {
  /** No handshake in progress, prekey operations allowed */
  IDLE = 'IDLE',
  
  /** Intent registered with relay, waiting to initiate */
  INTENT_REGISTERED = 'INTENT_REGISTERED',
  
  /** Handshake message sent, waiting for response */
  INITIATING = 'INITIATING',
  
  /** Received handshake, processing as responder */
  RESPONDING = 'RESPONDING',
  
  /** Ratchet established, handshake complete */
  ESTABLISHED = 'ESTABLISHED',
  
  /** Handshake failed, requires explicit retry */
  FAILED = 'FAILED',
}

/**
 * Allowed state transitions
 * Security: Only explicit transitions are allowed
 */
const VALID_TRANSITIONS: Record<HandshakeState, HandshakeState[]> = {
  [HandshakeState.IDLE]: [
    HandshakeState.INTENT_REGISTERED,
    HandshakeState.RESPONDING,
  ],
  [HandshakeState.INTENT_REGISTERED]: [
    HandshakeState.INITIATING,
    HandshakeState.FAILED,
    HandshakeState.IDLE, // Cancel/timeout
  ],
  [HandshakeState.INITIATING]: [
    HandshakeState.ESTABLISHED,
    HandshakeState.FAILED,
  ],
  [HandshakeState.RESPONDING]: [
    HandshakeState.ESTABLISHED,
    HandshakeState.FAILED,
  ],
  [HandshakeState.ESTABLISHED]: [
    HandshakeState.IDLE, // Reset for new session
  ],
  [HandshakeState.FAILED]: [
    HandshakeState.IDLE, // Explicit retry
  ],
};

/**
 * Handshake session data
 */
export interface HandshakeSession {
  chatId: string;
  state: HandshakeState;
  role?: 'initiator' | 'responder';
  peerUsername?: string;
  
  /** Timestamp when state was entered */
  stateTimestamp: number;
  
  /** Pending ephemeral secrets (initiator only) */
  ephemeralX25519Secret?: Uint8Array;
  ephemeralMLKEMSecret?: Uint8Array;
  
  /** Prekey bundle ID used (for tracking) */
  prekeyBundleId?: string;
  
  /** Error message if FAILED */
  errorMessage?: string;
  errorCode?: HandshakeErrorCode;
  
  /** Number of retry attempts */
  retryCount: number;
}

/**
 * Typed error codes for handshake failures
 * Security: Explicit error types enable proper handling
 */
export enum HandshakeErrorCode {
  /** Prekey secrets missing and regeneration blocked */
  PREKEY_MISSING = 'PREKEY_MISSING',
  
  /** Prekey secrets incomplete (missing public key) */
  PREKEY_INCOMPLETE = 'PREKEY_INCOMPLETE',
  
  /** Signature verification failed */
  SIGNATURE_INVALID = 'SIGNATURE_INVALID',
  
  /** Peer identity mismatch */
  IDENTITY_MISMATCH = 'IDENTITY_MISMATCH',
  
  /** Handshake timeout */
  TIMEOUT = 'TIMEOUT',
  
  /** Relay communication error */
  RELAY_ERROR = 'RELAY_ERROR',
  
  /** Role conflict (both parties think they're initiator) */
  ROLE_CONFLICT = 'ROLE_CONFLICT',
  
  /** Duplicate handshake blocked */
  DUPLICATE_BLOCKED = 'DUPLICATE_BLOCKED',
  
  /** Invalid state transition attempted */
  INVALID_TRANSITION = 'INVALID_TRANSITION',
  
  /** PQ crypto unavailable */
  PQ_UNAVAILABLE = 'PQ_UNAVAILABLE',
  
  /** ML-KEM decapsulation failed */
  KEM_FAILED = 'KEM_FAILED',
}

/**
 * Custom error class for handshake failures
 */
export class HandshakeError extends Error {
  constructor(
    public readonly code: HandshakeErrorCode,
    message: string,
    public readonly chatId?: string,
    public readonly recoverable: boolean = false
  ) {
    super(`[Handshake/${code}] ${message}`);
    this.name = 'HandshakeError';
  }
}

// ============================================================================
// STATE MACHINE IMPLEMENTATION
// ============================================================================

/**
 * Handshake State Manager
 * 
 * SECURITY INVARIANTS:
 * 1. One session per chatId at a time
 * 2. State transitions are guarded
 * 3. Prekey mutation blocked during non-IDLE states
 */
class HandshakeStateManager {
  /** Active handshake sessions by chatId */
  private sessions: Map<string, HandshakeSession> = new Map();
  
  /** Global lock for prekey operations */
  private prekeyLocked: boolean = false;
  
  /** Timeout for stuck handshakes (5 minutes) */
  private readonly HANDSHAKE_TIMEOUT_MS = 5 * 60 * 1000;
  
  /**
   * Get current session for a chat
   */
  getSession(chatId: string): HandshakeSession | undefined {
    this.cleanupStaleHandshakes();
    return this.sessions.get(chatId);
  }
  
  /**
   * Check if a handshake is in progress for any chat
   * Used to block prekey operations
   */
  isAnyHandshakeActive(): boolean {
    this.cleanupStaleHandshakes();
    
    for (const session of this.sessions.values()) {
      if (session.state !== HandshakeState.IDLE &&
          session.state !== HandshakeState.ESTABLISHED &&
          session.state !== HandshakeState.FAILED) {
        return true;
      }
    }
    return false;
  }
  
  /**
   * Check if handshake is in progress for specific chat
   */
  isHandshakeActive(chatId: string): boolean {
    const session = this.getSession(chatId);
    if (!session) return false;
    
    return session.state !== HandshakeState.IDLE &&
           session.state !== HandshakeState.ESTABLISHED &&
           session.state !== HandshakeState.FAILED;
  }
  
  /**
   * Start a new handshake session
   * @throws HandshakeError if handshake already in progress
   */
  startSession(chatId: string, peerUsername: string): HandshakeSession {
    const existing = this.getSession(chatId);
    
    if (existing && this.isHandshakeActive(chatId)) {
      throw new HandshakeError(
        HandshakeErrorCode.DUPLICATE_BLOCKED,
        `Handshake already in progress for chat ${chatId.slice(0, 16)}...`,
        chatId
      );
    }
    
    const session: HandshakeSession = {
      chatId,
      state: HandshakeState.IDLE,
      peerUsername,
      stateTimestamp: Date.now(),
      retryCount: existing?.retryCount ?? 0,
    };
    
    this.sessions.set(chatId, session);
    console.log(`[HandshakeFSM] Session started for ${chatId.slice(0, 16)}...`);
    
    return session;
  }
  
  /**
   * Transition to a new state
   * @throws HandshakeError if transition is invalid
   */
  transition(
    chatId: string,
    newState: HandshakeState,
    updates?: Partial<HandshakeSession>
  ): HandshakeSession {
    const session = this.sessions.get(chatId);
    
    if (!session) {
      throw new HandshakeError(
        HandshakeErrorCode.INVALID_TRANSITION,
        `No session exists for chat ${chatId.slice(0, 16)}...`,
        chatId
      );
    }
    
    const validNextStates = VALID_TRANSITIONS[session.state];
    
    if (!validNextStates.includes(newState)) {
      throw new HandshakeError(
        HandshakeErrorCode.INVALID_TRANSITION,
        `Invalid transition ${session.state} -> ${newState}`,
        chatId
      );
    }
    
    const updatedSession: HandshakeSession = {
      ...session,
      ...updates,
      state: newState,
      stateTimestamp: Date.now(),
    };
    
    this.sessions.set(chatId, updatedSession);
    
    console.log(`[HandshakeFSM] ${chatId.slice(0, 16)}... : ${session.state} -> ${newState}`);
    
    // Update prekey lock based on active handshakes
    this.updatePrekeyLock();
    
    return updatedSession;
  }
  
  /**
   * Mark handshake as failed
   */
  fail(chatId: string, code: HandshakeErrorCode, message: string): HandshakeSession {
    const session = this.sessions.get(chatId);
    
    if (!session) {
      // Create failed session for tracking
      const failedSession: HandshakeSession = {
        chatId,
        state: HandshakeState.FAILED,
        stateTimestamp: Date.now(),
        errorCode: code,
        errorMessage: message,
        retryCount: 0,
      };
      this.sessions.set(chatId, failedSession);
      return failedSession;
    }
    
    return this.transition(chatId, HandshakeState.FAILED, {
      errorCode: code,
      errorMessage: message,
      retryCount: session.retryCount + 1,
    });
  }
  
  /**
   * Clear session (for established or after explicit reset)
   */
  clearSession(chatId: string): void {
    this.sessions.delete(chatId);
    this.updatePrekeyLock();
    console.log(`[HandshakeFSM] Session cleared for ${chatId.slice(0, 16)}...`);
  }
  
  /**
   * Check if prekey operations are allowed
   * SECURITY: Blocked during active handshakes
   */
  canMutatePrekeys(): boolean {
    return !this.prekeyLocked && !this.isAnyHandshakeActive();
  }
  
  /**
   * Assert prekey operations are allowed
   * @throws HandshakeError if prekey mutation is blocked
   */
  assertCanMutatePrekeys(): void {
    if (!this.canMutatePrekeys()) {
      throw new HandshakeError(
        HandshakeErrorCode.PREKEY_MISSING,
        'Prekey regeneration blocked: handshake in progress. ' +
        'Wait for handshake to complete or fail before regenerating keys.',
        undefined,
        false
      );
    }
  }
  
  /**
   * Cleanup stale handshakes that exceeded timeout
   */
  private cleanupStaleHandshakes(): void {
    const now = Date.now();
    
    for (const [chatId, session] of this.sessions) {
      if (session.state !== HandshakeState.IDLE &&
          session.state !== HandshakeState.ESTABLISHED &&
          now - session.stateTimestamp > this.HANDSHAKE_TIMEOUT_MS) {
        
        console.warn(`[HandshakeFSM] Timeout: ${chatId.slice(0, 16)}... in state ${session.state}`);
        
        this.fail(chatId, HandshakeErrorCode.TIMEOUT, 
          `Handshake timed out after ${this.HANDSHAKE_TIMEOUT_MS / 1000}s`);
      }
    }
  }
  
  /**
   * Update global prekey lock based on active sessions
   */
  private updatePrekeyLock(): void {
    this.prekeyLocked = this.isAnyHandshakeActive();
  }
}

// ============================================================================
// ROLE DETERMINATION
// ============================================================================

/**
 * Determine initiator/responder role deterministically
 * 
 * SECURITY: Uses lexicographic comparison of identity public keys
 * This ensures:
 * 1. Both parties agree on roles without communication
 * 2. No race conditions
 * 3. Consistent result regardless of timing
 * 
 * @param ourIdentityEd25519 - Our Ed25519 public key
 * @param peerIdentityEd25519 - Peer's Ed25519 public key
 * @returns 'initiator' if we should initiate, 'responder' otherwise
 */
export function determineRole(
  ourIdentityEd25519: Uint8Array,
  peerIdentityEd25519: Uint8Array
): 'initiator' | 'responder' {
  // Compare bytes lexicographically
  const minLen = Math.min(ourIdentityEd25519.length, peerIdentityEd25519.length);
  
  for (let i = 0; i < minLen; i++) {
    if (ourIdentityEd25519[i] < peerIdentityEd25519[i]) {
      return 'initiator';
    }
    if (ourIdentityEd25519[i] > peerIdentityEd25519[i]) {
      return 'responder';
    }
  }
  
  // If one is prefix of other, shorter one is initiator
  if (ourIdentityEd25519.length < peerIdentityEd25519.length) {
    return 'initiator';
  }
  if (ourIdentityEd25519.length > peerIdentityEd25519.length) {
    return 'responder';
  }
  
  // Keys are identical - this should NEVER happen (same user)
  throw new HandshakeError(
    HandshakeErrorCode.IDENTITY_MISMATCH,
    'Cannot determine role: identity keys are identical',
    undefined,
    false
  );
}

/**
 * Check if we should accept an incoming handshake based on role
 * 
 * SECURITY: Prevents race conditions where both parties send handshake
 * 
 * @returns true if we should accept (we are responder), false if we should ignore
 */
export function shouldAcceptIncomingHandshake(
  ourIdentityEd25519: Uint8Array,
  peerIdentityEd25519: Uint8Array,
  weAlreadySentHandshake: boolean
): boolean {
  const ourRole = determineRole(ourIdentityEd25519, peerIdentityEd25519);
  
  // If we're the designated responder, always accept
  if (ourRole === 'responder') {
    return true;
  }
  
  // If we're the designated initiator but already sent handshake, ignore incoming
  // (peer is violating protocol or there's network reordering)
  if (weAlreadySentHandshake) {
    console.warn('[HandshakeFSM] Ignoring incoming handshake: we are initiator and already sent');
    return false;
  }
  
  // If we're initiator but haven't sent yet, accept anyway
  // (peer sent faster, we become responder for this session)
  return true;
}

// ============================================================================
// SINGLETON EXPORT
// ============================================================================

/** Global handshake state manager */
export const handshakeManager = new HandshakeStateManager();

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Generate unique handshake ID for deduplication
 */
export function generateHandshakeId(chatId: string, timestamp: number): string {
  return `hs:${chatId}:${timestamp}`;
}

/**
 * Check if handshake is retryable based on error code
 */
export function isRetryableError(code: HandshakeErrorCode): boolean {
  switch (code) {
    case HandshakeErrorCode.RELAY_ERROR:
    case HandshakeErrorCode.TIMEOUT:
      return true;
    
    case HandshakeErrorCode.SIGNATURE_INVALID:
    case HandshakeErrorCode.IDENTITY_MISMATCH:
    case HandshakeErrorCode.PQ_UNAVAILABLE:
    case HandshakeErrorCode.KEM_FAILED:
      return false;
    
    default:
      return false;
  }
}

/**
 * Calculate retry delay with exponential backoff
 */
export function getRetryDelay(retryCount: number): number {
  const baseDelay = 1000; // 1 second
  const maxDelay = 30000; // 30 seconds
  
  const delay = Math.min(baseDelay * Math.pow(2, retryCount), maxDelay);
  
  // Add jitter (±10%)
  const jitter = delay * 0.1 * (Math.random() * 2 - 1);
  
  return Math.floor(delay + jitter);
}
