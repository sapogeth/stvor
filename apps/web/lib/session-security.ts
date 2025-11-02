/**
 * Session Security Management
 * - Skipped key storage for out-of-order messages
 * - Replay protection
 * - Session health monitoring
 */

import {
  HandshakeState,
  SkippedKeyStore,
  ReplayProtection,
  needsRekey,
  type RatchetState,
} from '@ilyazh/crypto';

export interface SessionSecurity {
  skippedKeys: SkippedKeyStore;
  replayProtection: ReplayProtection;
}

// Global stores per session
const sessionStores = new Map<string, SessionSecurity>();

/**
 * Get or create security context for session
 */
export function getSessionSecurity(sessionId: Uint8Array): SessionSecurity {
  const sid = Buffer.from(sessionId).toString('hex');

  let security = sessionStores.get(sid);
  if (!security) {
    security = {
      skippedKeys: new SkippedKeyStore(),
      replayProtection: new ReplayProtection(),
    };
    sessionStores.set(sid, security);
  }

  return security;
}

/**
 * Clear security context for session
 */
export function clearSessionSecurity(sessionId: Uint8Array): void {
  const sid = Buffer.from(sessionId).toString('hex');
  const security = sessionStores.get(sid);
  if (security) {
    security.skippedKeys.clear();
    security.replayProtection.clearSession(sessionId);
  }
  sessionStores.delete(sid);
}

/**
 * Check session health and return warnings/errors
 */
export interface SessionHealth {
  status: 'healthy' | 'warning' | 'critical';
  warnings: string[];
  needsRekey: boolean;
  rekeyReason?: string;
  canContinue: boolean;
}

export function checkSessionHealth(state: HandshakeState): SessionHealth {
  const warnings: string[] = [];
  let status: 'healthy' | 'warning' | 'critical' = 'healthy';
  let canContinue = true;

  const rekeyCheck = needsRekey(state as RatchetState);

  // Check rekey requirements
  if (rekeyCheck.required) {
    if (
      rekeyCheck.reason === 'session_cap_messages' ||
      rekeyCheck.reason === 'session_cap_time'
    ) {
      // Hard session caps - MUST NOT continue
      status = 'critical';
      canContinue = false;
      warnings.push(
        `Session expired (${rekeyCheck.reason}). You MUST start a new session.`
      );
    } else {
      // Epoch rekey needed
      status = 'warning';
      warnings.push(
        `Rekey required (${rekeyCheck.reason}). Session will expire soon.`
      );
    }
  }

  // Check approaching limits (soft warnings)
  const now = Date.now();
  const epochAge = now - state.epochStartTime;
  const sessionAge = now - state.sessionStartTime;

  // Warn at 90% of limits
  const EPOCH_MSG_WARNING = Math.floor((1 << 20) * 0.9); // 90% of 2^20
  const EPOCH_TIME_WARNING = Math.floor((24 * 60 * 60 * 1000) * 0.9); // 90% of 24h
  const SESSION_MSG_WARNING = Math.floor(Math.pow(2, 32) * 0.9); // 90% of 2^32
  const SESSION_TIME_WARNING = Math.floor((7 * 24 * 60 * 60 * 1000) * 0.9); // 90% of 7 days

  if (state.sendCounter >= EPOCH_MSG_WARNING && status === 'healthy') {
    status = 'warning';
    warnings.push(
      `Approaching epoch message limit (${state.sendCounter}/${1 << 20})`
    );
  }

  if (epochAge >= EPOCH_TIME_WARNING && status === 'healthy') {
    status = 'warning';
    const hoursLeft = Math.floor((24 * 60 * 60 * 1000 - epochAge) / (60 * 60 * 1000));
    warnings.push(`Epoch expiring in ~${hoursLeft} hours`);
  }

  if (state.totalMessages >= SESSION_MSG_WARNING && status === 'healthy') {
    status = 'warning';
    warnings.push(
      `Approaching session message cap (${state.totalMessages}/${Math.pow(2, 32)})`
    );
  }

  if (sessionAge >= SESSION_TIME_WARNING && status === 'healthy') {
    status = 'warning';
    const daysLeft = Math.floor((7 * 24 * 60 * 60 * 1000 - sessionAge) / (24 * 60 * 60 * 1000));
    warnings.push(`Session expiring in ~${daysLeft} days`);
  }

  return {
    status,
    warnings,
    needsRekey: rekeyCheck.required,
    rekeyReason: rekeyCheck.reason,
    canContinue,
  };
}

/**
 * Format session age for display
 */
export function formatAge(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ${hours % 24}h`;
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

/**
 * Derive safety number from identity keys (NOT sessionId)
 *
 * CRITICAL: Safety numbers MUST be based on long-term identity keys to detect MITM.
 * If we use sessionId, the number changes on every re-handshake, defeating the purpose.
 *
 * This function is SYMMETRICAL - both Alice and Bob will derive the SAME number
 * when verifying each other, regardless of who initiated the handshake.
 *
 * Format: 12 groups of 5 digits (60 digits total)
 *
 * @param ourIdentityEd25519 - Our Ed25519 public identity key
 * @param theirIdentityEd25519 - Peer's Ed25519 public identity key
 * @returns Safety number string
 */
export function deriveSafetyNumber(
  ourIdentityEd25519: Uint8Array,
  theirIdentityEd25519: Uint8Array
): string {
  const crypto = require('crypto');

  // CRITICAL: Sort identities lexicographically to ensure symmetry
  // Alice(A, B) must produce same result as Bob(B, A)
  const identities = [ourIdentityEd25519, theirIdentityEd25519];
  identities.sort((a, b) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  });

  // Concatenate sorted identities
  const combined = new Uint8Array(identities[0].length + identities[1].length);
  combined.set(identities[0], 0);
  combined.set(identities[1], identities[0].length);

  // Hash with SHA-256
  const hash = crypto.createHash('sha256').update(combined).digest();

  // Convert to decimal digits
  const digits: number[] = [];
  for (let i = 0; i < hash.length; i++) {
    const byte = hash[i];
    digits.push(Math.floor(byte / 100));
    digits.push(Math.floor((byte % 100) / 10));
    digits.push(byte % 10);
  }

  // Take first 60 digits and group into 12 blocks of 5
  const blocks: string[] = [];
  for (let i = 0; i < 60; i += 5) {
    blocks.push(digits.slice(i, i + 5).join(''));
  }

  return blocks.join(' ');
}

/**
 * Generate safety number from sessionId (DEPRECATED - use deriveSafetyNumber instead)
 *
 * This function is DEPRECATED because it derives the number from sessionId,
 * which changes on every re-handshake. Safety numbers should be based on
 * identity keys to detect MITM attacks.
 *
 * @deprecated Use deriveSafetyNumber(ourIdentity, theirIdentity) instead
 */
export function generateSafetyNumber(sessionId: Uint8Array): string {
  console.warn('[Security] DEPRECATED: generateSafetyNumber(sessionId) should use deriveSafetyNumber(ourIdentity, theirIdentity) instead');

  // Use SHA-256 of sessionId to get 32 bytes
  const crypto = require('crypto');
  const hash = crypto.createHash('sha256').update(sessionId).digest();

  // Convert to decimal digits
  const digits: number[] = [];
  for (let i = 0; i < hash.length; i++) {
    const byte = hash[i];
    digits.push(Math.floor(byte / 100));
    digits.push(Math.floor((byte % 100) / 10));
    digits.push(byte % 10);
  }

  // Take first 60 digits and group into 12 blocks of 5
  const blocks: string[] = [];
  for (let i = 0; i < 60; i += 5) {
    blocks.push(digits.slice(i, i + 5).join(''));
  }

  return blocks.join(' ');
}
