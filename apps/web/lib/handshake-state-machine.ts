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
 * 5. Confusion between HandshakeInit and HandshakeResponse
 * 
 * Protocol Safety Notes:
 * - State transitions are atomic and guarded
 * - Prekey mutation is BLOCKED while handshake is in progress
 * - Role (initiator/responder) is deterministic based on identity comparison
 * - Failed handshakes require explicit retry, no auto-healing
 * - HandshakeInit and HandshakeResponse are DISTINCT message types
 * 
 * ============================================================================
 * RACE CONDITION PROTOCOL (CRITICAL INVARIANTS)
 * ============================================================================
 * 
 * When both parties send HandshakeInit simultaneously:
 * 
 * 1. Both parties call determineRole(ourKey, peerKey)
 * 2. determineRole is ANTISYMMETRIC: if A→initiator, then B→responder
 * 
 * INITIATOR behavior:
 *   - IGNORES incoming init from peer (does NOT process it)
 *   - Waits for HandshakeResponse from RESPONDER
 *   - Creates the ONLY session when receiving response
 * 
 * RESPONDER behavior:
 *   - Cancels own pending init
 *   - Processes INITIATOR's init
 *   - Sends HandshakeResponse
 *   - Does NOT create a session
 * 
 * Result: Exactly ONE init processed, exactly ONE response, exactly ONE session.
 * 
 * ❌ FORBIDDEN:
 *   - Both parties processing each other's init (creates 4 keys)
 *   - Both parties sending response
 *   - INITIATOR creating "fallback" session from peer's init
 * ============================================================================
 * 
 * FSM TRANSITIONS:
 * 
 * Initiator flow:
 *   IDLE → INTENT_REGISTERED → INITIATING → (receive HandshakeResponse) → ESTABLISHED
 * 
 * Responder flow:
 *   IDLE → (receive HandshakeInit) → RESPONDING → (send HandshakeResponse) → ESTABLISHED
 * 
 * ATTACK PREVENTION:
 * - Duplicate HandshakeInit: Blocked if session exists (any state except IDLE)
 * - HandshakeResponse without INITIATING state: Rejected as invalid
 * - HandshakeResponse from wrong peer: Rejected as identity mismatch
 * - HandshakeInit when INITIATING: Race condition - use deterministic role
 * 
 * @module handshake-state-machine
 */

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/**
 * Handshake message types
 * 
 * CRITICAL: These MUST be distinguished by the FSM
 * - INIT: Sent by initiator to start handshake
 * - RESPONSE: Sent by responder to complete handshake
 * 
 * Mixing these up causes the "duplicate blocked" bug
 */
export enum HandshakeMessageType {
  /** Initial handshake message (from initiator) */
  INIT = 'handshake_init',
  
  /** Response handshake message (from responder) */
  RESPONSE = 'handshake_response',
}

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
  
  /** Received response when not in INITIATING state */
  UNEXPECTED_RESPONSE = 'UNEXPECTED_RESPONSE',
  
  /** Response from unexpected peer */
  WRONG_PEER = 'WRONG_PEER',
  
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
   * Start a new handshake session (for INITIATOR or RESPONDER starting fresh)
   * 
   * SECURITY: Only call this for NEW handshakes (HandshakeInit)
   * For HandshakeResponse, use receiveResponse() instead
   * 
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
   * Handle incoming HandshakeResponse message
   * 
   * SECURITY-CRITICAL: This method handles the "initiator receives response" case
   * 
   * PRECONDITIONS:
   * 1. Session MUST exist (we initiated the handshake)
   * 2. Session MUST be in INITIATING state
   * 3. Response MUST be from the expected peer
   * 
   * This is NOT a duplicate - it's the expected response to our init!
   * 
   * ATTACK PREVENTION:
   * - Replay: Response is only accepted once (INITIATING → ESTABLISHED)
   * - Reflection: Response must come from peerUsername we specified
   * - Race: If we're not INITIATING, we reject
   * 
   * @param chatId - Chat identifier
   * @param fromPeer - Username of the peer who sent the response
   * @returns true if response is valid and should be processed
   * @throws HandshakeError if response is invalid
   */
  receiveResponse(chatId: string, fromPeer: string): boolean {
    const session = this.sessions.get(chatId);
    
    // Case 1: No session exists - we never initiated
    if (!session) {
      console.warn(`[HandshakeFSM] receiveResponse: No session for ${chatId.slice(0, 16)}... - ignoring`);
      throw new HandshakeError(
        HandshakeErrorCode.UNEXPECTED_RESPONSE,
        `Received HandshakeResponse but no session exists for chat ${chatId.slice(0, 16)}...`,
        chatId,
        false
      );
    }
    
    // Case 2: Session exists but not in INITIATING state
    if (session.state !== HandshakeState.INITIATING) {
      console.warn(`[HandshakeFSM] receiveResponse: Session not in INITIATING state (${session.state})`);
      
      // Special case: If already ESTABLISHED, this is a duplicate response - ignore silently
      if (session.state === HandshakeState.ESTABLISHED) {
        console.log(`[HandshakeFSM] Ignoring duplicate HandshakeResponse (session already ESTABLISHED)`);
        return false; // Not an error, just ignore
      }
      
      throw new HandshakeError(
        HandshakeErrorCode.UNEXPECTED_RESPONSE,
        `Received HandshakeResponse but session is in ${session.state} state, not INITIATING`,
        chatId,
        false
      );
    }
    
    // Case 3: Response from unexpected peer (potential attack)
    if (session.peerUsername && session.peerUsername !== fromPeer) {
      console.error(`[HandshakeFSM] SECURITY: Response from wrong peer! Expected ${session.peerUsername}, got ${fromPeer}`);
      throw new HandshakeError(
        HandshakeErrorCode.WRONG_PEER,
        `HandshakeResponse from ${fromPeer} but expected from ${session.peerUsername}. Possible attack.`,
        chatId,
        false
      );
    }
    
    // Case 4: Valid response - log and return true
    console.log(`[HandshakeFSM] ✓ Valid HandshakeResponse from ${fromPeer} for ${chatId.slice(0, 16)}...`);
    return true;
  }
  
  /**
   * Check if we can accept a HandshakeInit message
   * 
   * SECURITY: Prevents duplicate/concurrent handshakes
   * 
   * @returns true if we can process the init, false if we should skip
   */
  canAcceptInit(chatId: string): boolean {
    const session = this.sessions.get(chatId);
    
    // No session - can accept
    if (!session) return true;
    
    // Session in terminal state - can accept (new handshake)
    if (session.state === HandshakeState.IDLE ||
        session.state === HandshakeState.ESTABLISHED ||
        session.state === HandshakeState.FAILED) {
      return true;
    }
    
    // Session active - cannot accept
    return false;
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
 * SECURITY-CRITICAL: This function resolves race conditions in handshake.
 * 
 * PROPERTIES:
 * 1. ANTISYMMETRIC: If A calls determineRole(A, B) = 'initiator',
 *    then B calls determineRole(B, A) = 'responder'
 * 2. DETERMINISTIC: Same inputs always produce same output
 * 3. NO COMMUNICATION NEEDED: Both parties compute locally
 * 
 * PROTOCOL BEHAVIOR:
 * - INITIATOR: Ignores incoming init, waits for response, creates session
 * - RESPONDER: Processes INITIATOR's init, sends response, NO session
 * 
 * Uses lexicographic comparison of Ed25519 identity public keys.
 * Lower key = INITIATOR.
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
 * SECURITY-CRITICAL: Implements correct race condition resolution.
 * 
 * RULE:
 * - RESPONDER (by determineRole): Accept incoming init, process it
 * - INITIATOR (by determineRole): IGNORE incoming init, wait for response
 * 
 * This ensures exactly ONE init is processed and exactly ONE session is created.
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
  
  // If we're the designated initiator:
  // - If we already sent handshake: IGNORE incoming (wait for response)
  // - If we haven't sent yet: Accept (peer was faster, we become responder)
  if (weAlreadySentHandshake) {
    // CRITICAL: We are INITIATOR in race condition.
    // We MUST ignore their init and wait for their response to our init.
    console.log('[HandshakeFSM] We are INITIATOR - ignoring incoming init, waiting for response');
    return false;
  }
  
  // We're initiator but haven't sent yet - peer was faster
  // Accept their init (we effectively become responder for this handshake)
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
