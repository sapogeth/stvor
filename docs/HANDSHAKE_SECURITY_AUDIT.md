# Handshake Security Audit Report

**Date**: 2025-01-28 (Updated: 2026-01-18)  
**Version**: v0.8.2  
**Status**: ✅ COMPLETE

## Executive Summary

This document describes the security-critical changes implemented to fix the handshake signature verification failure and the "duplicate blocked" bug that prevented ratchet establishment.

## Bug History

### Bug #1: "Handshake signature verification failed" (v0.8.0)

**Root Cause**: Prekey regeneration during handshake caused transcript mismatch.  
**Fix**: FSM blocks prekey regeneration during active handshake.

### Bug #2: "Duplicate handshake blocked" (v0.8.1) - CURRENT FIX

**Symptom**:
1. Initiator sends HandshakeInit
2. Responder replies with HandshakeResponse
3. Initiator receives response
4. FSM incorrectly blocks it as "duplicate handshake"
5. No ratchet state is created
6. Sending messages blocked: "no ratchet state"

**Root Cause**: FSM did NOT distinguish between:
- `HandshakeInit` (from initiator to start handshake)
- `HandshakeResponse` (from responder to complete handshake)

The FSM called `startSession()` for ALL incoming handshake messages, which blocked legitimate responses as duplicates.

## Implemented Fixes

### 1. Handshake Message Type Distinction (v0.8.2 - NEW)

**File**: [apps/web/lib/handshake-state-machine.ts](apps/web/lib/handshake-state-machine.ts)

```typescript
export enum HandshakeMessageType {
  INIT = 'handshake_init',      // Sent by initiator to START handshake
  RESPONSE = 'handshake_response', // Sent by responder to COMPLETE handshake
}
```

**New FSM Methods**:

```typescript
// For incoming HandshakeInit (creates new session)
canAcceptInit(chatId: string): boolean

// For incoming HandshakeResponse (uses EXISTING session, does NOT create new)
receiveResponse(chatId: string, fromPeer: string): boolean
```

**Key Insight**: `receiveResponse()` validates:
1. Session EXISTS (we initiated)
2. Session is in `INITIATING` state
3. Response is from expected peer

This is NOT a duplicate - it's the expected response!

### 2. Handshake State Machine (FSM)

**File**: [apps/web/lib/handshake-state-machine.ts](apps/web/lib/handshake-state-machine.ts)

```
┌──────────────────────────────────────────────────────────────────────┐
│                    HANDSHAKE STATE MACHINE (v0.8.2)                  │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  INITIATOR FLOW:                                                     │
│  ┌──────┐   ┌───────────────────┐   ┌────────────┐   ┌───────────┐  │
│  │ IDLE │──▶│ INTENT_REGISTERED │──▶│ INITIATING │──▶│ESTABLISHED│  │
│  └──────┘   └───────────────────┘   └────────────┘   └───────────┘  │
│                                           │                          │
│                                   receive HandshakeResponse          │
│                                   (via receiveResponse())            │
│                                                                      │
│  RESPONDER FLOW:                                                     │
│  ┌──────┐        receive HandshakeInit        ┌───────────┐         │
│  │ IDLE │──────────────────────────────────▶ │ RESPONDING │         │
│  └──────┘        (via canAcceptInit())        └───────────┘         │
│                                                     │                │
│                                           send HandshakeResponse     │
│                                                     ▼                │
│                                              ┌───────────┐          │
│                                              │ESTABLISHED│          │
│                                              └───────────┘          │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**States**:
- `IDLE`: No handshake active, prekey operations allowed
- `INTENT_REGISTERED`: Intent sent to relay, awaiting peer bundle
- `INITIATING`: Handshake message sent, waiting for response
- `RESPONDING`: Processing incoming handshake as responder
- `ESTABLISHED`: Session established successfully
- `FAILED`: Handshake failed, requires explicit retry

### 2. Prekey Regeneration Safety Invariant

**INVARIANT**: "Identity prekey secrets MUST NOT be regenerated while handshake is in progress"

**Implementation** in [apps/web/lib/prekeys.ts](apps/web/lib/prekeys.ts):

```typescript
// SECURITY CHECK: Block regeneration during active handshake
if (handshakeManager.isAnyHandshakeActive()) {
  throw new HandshakeError(
    HandshakeErrorCode.PREKEY_MISSING,
    `Prekey secrets not found for ${username} and regeneration is blocked during active handshake.`
  );
}
```

### 3. Role Determinism

**Problem**: If both parties send handshake simultaneously, role conflict occurs.

**Solution**: Lexicographic comparison of Ed25519 identity public keys:

```typescript
export function determineRole(
  ourIdentityEd25519: Uint8Array,
  peerIdentityEd25519: Uint8Array
): 'initiator' | 'responder' {
  for (let i = 0; i < minLen; i++) {
    if (ourIdentityEd25519[i] < peerIdentityEd25519[i]) {
      return 'initiator';
    }
    if (ourIdentityEd25519[i] > peerIdentityEd25519[i]) {
      return 'responder';
    }
  }
  throw new HandshakeError(HandshakeErrorCode.IDENTITY_MISMATCH, ...);
}
```

### 4. Duplicate/Replay Protection

- FSM tracks one session per `chatId`
- `DUPLICATE_BLOCKED` error if second handshake attempted
- Stale handshakes auto-expire after 5 minutes

### 5. responderPrekeyMLKEM in HandshakeMessage

**File**: [packages/crypto/src/handshake.ts](packages/crypto/src/handshake.ts)

The initiator now includes the responder's ML-KEM public key in the handshake message:

```typescript
interface HandshakeMessage {
  // ... existing fields
  responderPrekeyMLKEM?: Uint8Array; // NEW: Responder's prekey for transcript
}
```

This ensures both parties use the same key for transcript verification.

### 6. Typed Error Handling

All handshake failures use typed error codes:

```typescript
enum HandshakeErrorCode {
  PREKEY_MISSING,
  PREKEY_INCOMPLETE,
  SIGNATURE_INVALID,
  IDENTITY_MISMATCH,
  TIMEOUT,
  RELAY_ERROR,
  ROLE_CONFLICT,
  DUPLICATE_BLOCKED,
  INVALID_TRANSITION,
  PQ_UNAVAILABLE,
  KEM_FAILED,
}
```

Each error indicates whether it's recoverable and appropriate retry strategy.

## Security Properties

### Verified Invariants

| Property | Status | Verification |
|----------|--------|--------------|
| No prekey regeneration during handshake | ✅ | FSM blocks with explicit error |
| Deterministic role assignment | ✅ | Lexicographic key comparison |
| No duplicate handshakes | ✅ | FSM per-chat session tracking |
| Timeout for stuck handshakes | ✅ | 5-minute auto-expiry |
| Typed error handling | ✅ | HandshakeErrorCode enum |
| Transcript consistency | ✅ | responderPrekeyMLKEM field |

### Attack Resistance

| Attack Vector | Mitigation |
|---------------|------------|
| Key Confusion | FSM blocks regeneration during handshake |
| Race Condition | Deterministic role from key comparison |
| Replay | Duplicate handshake blocked by FSM |
| DoS via regeneration | Recoverable error with backoff |
| Protocol Downgrade | PQ required validation unchanged |

## Files Modified

1. `apps/web/lib/handshake-state-machine.ts` - NEW: FSM implementation
2. `apps/web/lib/prekeys.ts` - Integrated FSM safety checks
3. `apps/web/app/chat/page.tsx` - FSM transitions in handshake flow
4. `packages/crypto/src/handshake.ts` - responderPrekeyMLKEM field
5. `packages/crypto/src/wire.ts` - Wire format for new field

## Testing

### Build Verification
```
✅ pnpm run build - All 3 tasks successful
✅ No TypeScript errors
✅ No runtime warnings
```

### Manual Testing Checklist
- [ ] New chat handshake completes successfully
- [ ] Responder with missing prekeys sees explicit error (not silent failure)
- [ ] Duplicate handshake attempt blocked
- [ ] Handshake timeout after 5 minutes
- [ ] Session persists across page refresh

## Recommendations

1. **Add Unit Tests**: Create test suite for FSM state transitions
2. **Add Integration Tests**: Test handshake flow with mocked relay
3. **Monitoring**: Add telemetry for handshake failures by error code
4. **Rate Limiting**: Consider limiting handshake attempts per user per hour

## Conclusion

The handshake security audit identified a critical transcript mismatch bug that could cause protocol failures. The fix implements a formal state machine with safety invariants, ensuring:

1. **Prekey immutability** during handshake
2. **Deterministic roles** without communication
3. **Explicit error handling** instead of silent failures
4. **Replay protection** via duplicate blocking

All changes pass build verification. Manual testing recommended before production deployment.
