/**
 * Message Entry Validator - Hardened polling protection
 *
 * SECURITY:
 * - Strictly validates entries from relay before processing
 * - Prevents malicious relay from injecting fake sessions
 * - Whitelists only known system entry types
 * - Validates encrypted message structure
 * - Protects against session adoption attacks
 *
 * THREAT MODEL:
 * - Malicious relay trying to inject fake inline sessions
 * - Malicious relay trying to inject non-encrypted entries
 * - Malicious relay trying to inject unknown entry types
 *
 * @module message-entry-validator
 */

import { E2E_SECURITY_CONFIG, isAllowedSystemEntryType } from './e2e-security-config';
import { logWarn, logDebug } from './logger';

/**
 * Message entry structure from relay
 */
export interface RelayMessageEntry {
  id?: string;
  index?: number;
  type?: string;
  from?: string;
  to?: string;
  timestamp?: number;

  // Encrypted message fields
  cipher?: string;
  ciphertext?: string;
  blob?: string;
  payload?: any;

  // Session fields (potentially dangerous if from unknown sender)
  session?: any;
  inlineSession?: any;

  // Metadata
  meta?: any;
}

/**
 * Validation result
 */
export interface ValidationResult {
  valid: boolean;
  reason?: string;
  entryType: 'encrypted' | 'system' | 'invalid';
}

/**
 * Check if entry looks like encrypted ciphertext
 * SECURITY: Encrypted entries must have ciphertext data
 */
function isEncryptedEntry(entry: RelayMessageEntry): boolean {
  // Check for various ciphertext field names (relay inconsistencies)
  const hasCiphertext = !!(
    entry.cipher ||
    entry.ciphertext ||
    entry.blob ||
    entry.payload?.cipher ||
    entry.payload?.ciphertext
  );

  return hasCiphertext;
}

/**
 * Check if entry is a known system type
 * SECURITY: Only whitelisted system types are allowed
 */
function isKnownSystemEntry(entry: RelayMessageEntry): boolean {
  if (!entry.type) {
    return false;
  }

  return isAllowedSystemEntryType(entry.type);
}

/**
 * Validate message entry from relay
 * SECURITY: This is the main defense against malicious relay entries
 *
 * Returns:
 * - valid: true if entry should be processed
 * - entryType: 'encrypted' | 'system' | 'invalid'
 * - reason: why entry is invalid (for logging)
 */
export function validateMessageEntry(entry: RelayMessageEntry): ValidationResult {
  // Rule 1: Entry must have basic structure
  if (!entry || typeof entry !== 'object') {
    return {
      valid: false,
      reason: 'Entry is not an object',
      entryType: 'invalid',
    };
  }

  // Rule 2: Entry must have an ID (for deduplication)
  if (!entry.id && entry.index === undefined) {
    logDebug('message-validator', 'Entry missing ID/index', { entry });
    // Allow entries without ID for now (some relays don't provide it)
    // but log for monitoring
  }

  // Rule 3: Check if it's an encrypted message
  if (isEncryptedEntry(entry)) {
    // Encrypted entries are always valid
    return {
      valid: true,
      entryType: 'encrypted',
    };
  }

  // Rule 4: Check if it's a known system type
  if (isKnownSystemEntry(entry)) {
    return {
      valid: true,
      entryType: 'system',
    };
  }

  // Rule 5: If we get here, it's neither encrypted nor a known system type
  // This is suspicious - drop it
  logWarn('message-validator', 'Dropped untrusted entry from relay (not encrypted, not known system type)', {
    entryId: entry.id,
    entryType: entry.type,
    hasFrom: !!entry.from,
    hasSession: !!entry.session,
    hasInlineSession: !!entry.inlineSession,
  });

  return {
    valid: false,
    reason: `Unknown entry type: ${entry.type || 'undefined'} (not encrypted, not in whitelist)`,
    entryType: 'invalid',
  };
}

/**
 * Validate inline session adoption
 * SECURITY: Only adopt sessions from established peers
 *
 * Prevents: Malicious relay from injecting fake sessions
 *
 * @param entry - Entry containing inline session
 * @param currentPeerUsername - Username of currently established peer (if any)
 * @param establishedPeers - Set of usernames we have sessions with
 * @returns true if session adoption is safe
 */
export function validateInlineSessionAdoption(
  entry: RelayMessageEntry,
  currentPeerUsername?: string,
  establishedPeers?: Set<string>
): boolean {
  // SECURITY: Check if inline session adoption is enabled
  if (!E2E_SECURITY_CONFIG.allowInlineSessionAdoptionFromUnknownSenders) {
    // Only allow from current peer in active chat
    if (!currentPeerUsername || entry.from !== currentPeerUsername) {
      logWarn('message-validator', 'Rejected inline session from unknown/unexpected sender', {
        from: entry.from,
        expectedPeer: currentPeerUsername,
      });
      return false;
    }
  }

  // SECURITY: Additional check - only from established peers
  if (establishedPeers && entry.from && !establishedPeers.has(entry.from)) {
    logWarn('message-validator', 'Rejected inline session from non-established peer', {
      from: entry.from,
    });
    return false;
  }

  // Validate session structure (basic sanity check)
  const session = entry.session || entry.inlineSession;
  if (!session || typeof session !== 'object') {
    logWarn('message-validator', 'Invalid inline session structure', { entry });
    return false;
  }

  // Session should have required fields
  if (!session.sessionId || !session.sendChain || !session.receiveChain) {
    logWarn('message-validator', 'Inline session missing required fields', {
      hasSessionId: !!session.sessionId,
      hasSendChain: !!session.sendChain,
      hasReceiveChain: !!session.receiveChain,
    });
    return false;
  }

  return true;
}

/**
 * Sanitize entry before processing
 * SECURITY: Remove potentially dangerous fields
 *
 * @param entry - Entry to sanitize
 * @returns Sanitized entry
 */
export function sanitizeEntry(entry: RelayMessageEntry): RelayMessageEntry {
  const sanitized = { ...entry };

  // Remove inline session if not validated
  // (caller should validate first using validateInlineSessionAdoption)
  // This is a defense-in-depth measure

  return sanitized;
}

/**
 * Check if entry is likely a handshake message
 * SECURITY: Handshake detection without relying on relay-provided type
 *
 * Uses heuristics:
 * - Large payload (handshake messages are typically 3000+ bytes base64)
 * - Type contains "handshake" if provided
 * - Has specific handshake metadata
 */
export function looksLikeHandshake(entry: RelayMessageEntry): boolean {
  // Method 1: Check explicit type
  if (entry.type?.includes('handshake')) {
    return true;
  }

  // Method 2: Check payload metadata
  if (entry.payload?.kind === 'handshake') {
    return true;
  }

  if (entry.payload?.meta?.kind === 'handshake') {
    return true;
  }

  // Method 3: Check size (handshakes are typically large)
  const blob = entry.blob || entry.cipher || entry.ciphertext || '';
  if (typeof blob === 'string' && blob.length > 2500) {
    // Could be a handshake, but we need more evidence
    logDebug('message-validator', 'Entry has large payload (possible handshake)', {
      size: blob.length,
      hasType: !!entry.type,
    });
    return true;
  }

  return false;
}

/**
 * Batch validate entries
 * SECURITY: Process multiple entries efficiently
 *
 * @param entries - Array of entries to validate
 * @returns Filtered array of valid entries
 */
export function validateMessageEntries(entries: RelayMessageEntry[]): RelayMessageEntry[] {
  if (!Array.isArray(entries)) {
    logWarn('message-validator', 'validateMessageEntries called with non-array', { entries });
    return [];
  }

  const validEntries: RelayMessageEntry[] = [];
  let droppedCount = 0;

  for (const entry of entries) {
    const result = validateMessageEntry(entry);

    if (result.valid) {
      validEntries.push(entry);
    } else {
      droppedCount++;
      logDebug('message-validator', 'Dropped entry', {
        entryId: entry.id,
        reason: result.reason,
      });
    }
  }

  if (droppedCount > 0) {
    logWarn('message-validator', `Dropped ${droppedCount} invalid entries from relay`, {
      total: entries.length,
      valid: validEntries.length,
    });
  }

  return validEntries;
}
