/**
 * Handshake State Machine - Explicit State Tracking for E2E Session Establishment
 * 
 * CRITICAL: This enforces a strict state machine for handshake flows.
 * Each state transition is EXPLICIT. NO skipping states.
 * 
 * State Progression (happy path):
 * IDLE → AUTH_VERIFIED → DIRECTORY_VERIFIED → PREKEY_PUBLISHED → 
 * INTENT_REGISTERED → HANDSHAKE_SENT → SESSION_ESTABLISHED
 * 
 * Failure path (ANY step fails):
 * ANY_STATE → FAILED (terminal)
 * 
 * RULES:
 * 1. Can only transition to next sequential state
 * 2. Cannot skip states (e.g., IDLE → PREKEY_PUBLISHED is FORBIDDEN)
 * 3. Once FAILED, cannot recover without full reset
 * 4. Each transition requires explicit validation
 * 
 * @see SECURITY_ARCHITECTURE_FINAL.md
 */

/**
 * Handshake state machine states
 */
export enum HandshakeState {
  /** Initial state - no handshake initiated */
  IDLE = 'IDLE',

  /** Relay authentication verified (relay accepted our JWT) */
  AUTH_VERIFIED = 'AUTH_VERIFIED',

  /** Our identity verified in relay directory (200 from /directory/:username) */
  DIRECTORY_VERIFIED = 'DIRECTORY_VERIFIED',

  /** Our prekey bundle published to relay (200 from POST /directory/:username) */
  PREKEY_PUBLISHED = 'PREKEY_PUBLISHED',

  /** Intent to initiate handshake registered with relay (200 from POST /message/:chatId) */
  INTENT_REGISTERED = 'INTENT_REGISTERED',

  /** Handshake message sent to peer via relay (200 from POST /message/:chatId) */
  HANDSHAKE_SENT = 'HANDSHAKE_SENT',

  /** Peer responded, session keys derived, ready for encrypted messaging */
  SESSION_ESTABLISHED = 'SESSION_ESTABLISHED',

  /** ANY step failed - TERMINAL STATE until manual retry */
  FAILED = 'FAILED',
}

/**
 * State transition validation rules
 */
const VALID_TRANSITIONS: Record<HandshakeState, HandshakeState[]> = {
  [HandshakeState.IDLE]: [
    HandshakeState.AUTH_VERIFIED,
    HandshakeState.FAILED,
  ],
  [HandshakeState.AUTH_VERIFIED]: [
    HandshakeState.DIRECTORY_VERIFIED,
    HandshakeState.FAILED,
  ],
  [HandshakeState.DIRECTORY_VERIFIED]: [
    HandshakeState.PREKEY_PUBLISHED,
    HandshakeState.FAILED,
  ],
  [HandshakeState.PREKEY_PUBLISHED]: [
    HandshakeState.INTENT_REGISTERED,
    HandshakeState.FAILED,
  ],
  [HandshakeState.INTENT_REGISTERED]: [
    HandshakeState.HANDSHAKE_SENT,
    HandshakeState.FAILED,
  ],
  [HandshakeState.HANDSHAKE_SENT]: [
    HandshakeState.SESSION_ESTABLISHED,
    HandshakeState.FAILED,
  ],
  [HandshakeState.SESSION_ESTABLISHED]: [
    HandshakeState.FAILED, // Session can still fail (e.g., ratchet desync)
  ],
  [HandshakeState.FAILED]: [
    // Terminal state - must reset to IDLE manually
  ],
};

/**
 * Handshake state machine tracker
 */
export class HandshakeStateMachine {
  private state: HandshakeState = HandshakeState.IDLE;
  private failureReason: string | null = null;
  private stateHistory: Array<{ state: HandshakeState; timestamp: number }> = [];

  constructor(private readonly chatId: string) {
    this.recordStateChange(HandshakeState.IDLE);
  }

  /**
   * Get current state
   */
  getState(): HandshakeState {
    return this.state;
  }

  /**
   * Get failure reason (if state is FAILED)
   */
  getFailureReason(): string | null {
    return this.failureReason;
  }

  /**
   * Get state transition history (for debugging)
   */
  getHistory(): Array<{ state: HandshakeState; timestamp: number }> {
    return [...this.stateHistory];
  }

  /**
   * Attempt to transition to a new state
   * 
   * @param newState - Target state
   * @param reason - Reason for transition (logged, and stored if transitioning to FAILED)
   * @throws Error if transition is invalid
   */
  transition(newState: HandshakeState, reason?: string): void {
    // Check if transition is valid
    const validTransitions = VALID_TRANSITIONS[this.state];
    if (!validTransitions.includes(newState)) {
      const error = `[HandshakeStateMachine] Invalid transition: ${this.state} → ${newState}. ` +
                    `Valid transitions from ${this.state}: ${validTransitions.join(', ')}`;
      console.error(error);
      throw new Error(error);
    }

    // Special case: transitioning to FAILED
    if (newState === HandshakeState.FAILED) {
      this.failureReason = reason || 'Unknown failure';
      console.error(
        `[HandshakeStateMachine] ${this.chatId}: ${this.state} → FAILED. ` +
        `Reason: ${this.failureReason}`
      );
    } else {
      console.log(
        `[HandshakeStateMachine] ${this.chatId}: ${this.state} → ${newState}` +
        (reason ? ` (${reason})` : '')
      );
    }

    this.state = newState;
    this.recordStateChange(newState);
  }

  /**
   * Check if handshake has completed successfully
   */
  isComplete(): boolean {
    return this.state === HandshakeState.SESSION_ESTABLISHED;
  }

  /**
   * Check if handshake has failed
   */
  hasFailed(): boolean {
    return this.state === HandshakeState.FAILED;
  }

  /**
   * Check if specific state has been reached
   */
  hasReachedState(targetState: HandshakeState): boolean {
    return this.stateHistory.some(entry => entry.state === targetState);
  }

  /**
   * Reset state machine to IDLE (for manual retry)
   * 
   * WARNING: Only call this when user explicitly requests retry.
   */
  reset(): void {
    console.log(`[HandshakeStateMachine] ${this.chatId}: Resetting to IDLE`);
    this.state = HandshakeState.IDLE;
    this.failureReason = null;
    this.stateHistory = [];
    this.recordStateChange(HandshakeState.IDLE);
  }

  /**
   * Record state change in history
   */
  private recordStateChange(state: HandshakeState): void {
    this.stateHistory.push({
      state,
      timestamp: Date.now(),
    });
  }
}

/**
 * Helper: Require handshake to be in specific state
 * 
 * @throws Error if current state doesn't match expected state
 */
export function requireHandshakeState(
  machine: HandshakeStateMachine,
  expectedState: HandshakeState,
  operation: string
): void {
  const currentState = machine.getState();
  
  if (currentState === HandshakeState.FAILED) {
    throw new Error(
      `Cannot ${operation}: Handshake failed. ` +
      `Reason: ${machine.getFailureReason()}`
    );
  }

  if (currentState !== expectedState) {
    throw new Error(
      `Cannot ${operation}: Expected handshake state ${expectedState}, ` +
      `but current state is ${currentState}`
    );
  }
}
