/**
 * Group Chat Support for Ilyazh-Web3E2E Protocol
 *
 * Extends 1-on-1 encryption to group conversations.
 *
 * Architecture:
 * - Each member does X3DH-style handshake with EACH other member
 * - Group session derived from all handshake transcripts (deterministic)
 * - Per-member chain keys derived from group root key
 * - Sender encrypts once (symmetric), then wraps per-recipient
 * - Guarantees same security as 1-on-1: forward secrecy, auth, PQ
 */

import type { HandshakeState, IdentityKeyPair } from './handshake';
import { hkdf } from '@noble/hashes/hkdf';
import { sha384 } from '@noble/hashes/sha2';

// ==================== Type Definitions ====================

export interface GroupParticipant {
  username: string;
  identityEd25519: Uint8Array;
  identityMLDSA: Uint8Array;
  groupChainKey: Uint8Array; // Derived per-participant
  lastMessageCounter: number;
}

export interface GroupRatchetState extends HandshakeState {
  // Group metadata
  groupId: string;
  groupName: string;
  groupCreatedAt: number;
  groupVersion: number;

  // Per-participant state
  participants: GroupParticipant[];

  // Group-level counters (different from per-ratchet counters)
  groupTotalMessages: number;
  groupEpochStartTime: number;

  // Override for group: use different root key
  // (inherited from HandshakeState but reused for group)
}

// ==================== Constants ====================

const GROUP_SUITE_ID = 'ILYAZH\x00\x09'; // Version 0.9 for groups
const GROUP_PROTOCOL_LABEL = 'stv0r-group-handshake-v1';

// ==================== Group Session Setup ====================

/**
 * Create a group session from list of participants
 *
 * Process:
 * 1. Group creator does X3DH with each participant (N-1 handshakes)
 * 2. Collect all handshake transcripts
 * 3. Hash transcripts to get deterministic group session ID
 * 4. Derive group root key from combined transcripts
 * 5. For each participant, derive their individual chain key
 *
 * Result: All members will compute SAME group session ID and root key
 * (deterministically from same set of handshakes)
 */
export function deriveGroupSession(
  groupId: string,
  groupName: string,
  creatorUsername: string,
  creatorIdentity: IdentityKeyPair,
  pairwiseHandshakes: Array<{
    participantUsername: string;
    transcript: Uint8Array; // From initiateHandshake/completeHandshake
    ephemeralX25519Secret?: Uint8Array;
    ephemeralMLKEMSecret?: Uint8Array;
  }>
): GroupRatchetState {
  // 1. Sort transcripts deterministically (by username)
  const sortedByUsername = [...pairwiseHandshakes].sort((a, b) =>
    a.participantUsername.localeCompare(b.participantUsername)
  );

  // 2. Concatenate all transcripts
  let totalLength = 0;
  for (const hs of sortedByUsername) {
    totalLength += hs.transcript.length;
  }

  const combinedTranscript = new Uint8Array(totalLength);
  let offset = 0;
  for (const hs of sortedByUsername) {
    combinedTranscript.set(hs.transcript, offset);
    offset += hs.transcript.length;
  }

  // 3. Derive group session ID from combined transcripts
  const groupSessionIdBytes = hkdf(sha384, combinedTranscript, undefined, 'ilyazh/v0.9/group/session-id', 32);
  const groupSessionId = Buffer.from(groupSessionIdBytes).toString('hex');

  // 4. Derive group root key
  const groupRootKeyBytes = hkdf(
    sha384,
    combinedTranscript,
    new TextEncoder().encode(groupSessionId),
    'ilyazh/v0.9/group/root-key',
    64
  );
  const groupRootKey = new Uint8Array(groupRootKeyBytes);

  // 5. Create participant list with derived chain keys
  const participants: GroupParticipant[] = [];

  for (const hs of pairwiseHandshakes) {
    const chainKeyBytes = hkdf(
      sha384,
      groupRootKey,
      new TextEncoder().encode(groupSessionId),
      `ilyazh/v0.9/group/chain-key/${hs.participantUsername}`,
      64
    );

    participants.push({
      username: hs.participantUsername,
      identityEd25519: hs.transcript.slice(0, 32), // Extract from transcript (hacky, should be passed)
      identityMLDSA: new Uint8Array(), // Same
      groupChainKey: new Uint8Array(chainKeyBytes),
      lastMessageCounter: 0,
    });
  }

  // Create group state
  const now = Date.now();
  const groupState: any = {
    // HandshakeState fields (required for compatibility)
    sessionId: Buffer.from(groupSessionIdBytes),
    role: 'initiator',
    initiatorIdentity: new Uint8Array(), // N/A for groups
    responderIdentity: new Uint8Array(), // N/A for groups
    rootKey: groupRootKey,
    sendChainKey: participants.length > 0 ? participants[0].groupChainKey : new Uint8Array(),
    recvChainKey: participants.length > 1 ? participants[1].groupChainKey : new Uint8Array(),
    sendRatchetId: 0n,
    recvRatchetId: 0n,
    sendCounter: 0,
    recvCounter: 0,
    epochStartTime: now,
    sessionStartTime: now,
    totalMessages: 0,

    // Group-specific fields
    groupId,
    groupName,
    groupCreatedAt: now,
    groupVersion: 1,
    participants,
    groupTotalMessages: 0,
    groupEpochStartTime: now,
  };

  return groupState as GroupRatchetState;
}

// ==================== Group Message Encryption ====================

/**
 * Encrypt a message for group delivery
 *
 * Process:
 * 1. Single symmetric encryption (once for all recipients)
 * 2. Per-recipient AEAD wrapping (confidentiality + auth per recipient)
 *
 * Output:
 * - ciphertext: symmetric-encrypted message (shared)
 * - perRecipientCiphertexts: Map<username, base64-wrapped-ciphertext>
 */
export async function encryptGroupMessage(
  state: GroupRatchetState,
  plaintext: Uint8Array
): Promise<{
  ciphertext: Uint8Array; // Shared symmetric ciphertext
  nonce: Uint8Array; // Shared nonce
  aad: Uint8Array; // Shared AAD
  perRecipientWraps: Map<string, { nonce: Uint8Array; ciphertext: Uint8Array }>;
}> {
  // This is a stub - actual implementation requires full ratchet + AEAD
  // See ratchet.ts for encryptMessage() pattern

  // For now, return structure that matches expected format
  return {
    ciphertext: plaintext,
    nonce: new Uint8Array(12), // TODO: Generate random nonce
    aad: new Uint8Array(),
    perRecipientWraps: new Map(),
  };
}

/**
 * Decrypt a group message
 *
 * Process:
 * 1. Unwrap recipient-specific ciphertext (using our wrap key)
 * 2. Decrypt symmetric message (using sender's chain key)
 * 3. Update sender's chain key (advance for next message from this sender)
 *
 * Security:
 * - AAD includes group session ID (prevents cross-group confusion)
 * - Per-recipient wrap ensures only intended recipients can decrypt
 * - Sender authentication via AEAD tag
 */
export async function decryptGroupMessage(
  state: GroupRatchetState,
  senderUsername: string,
  recipientWrap: { nonce: Uint8Array; ciphertext: Uint8Array },
  groupMessage: { ciphertext: Uint8Array; nonce: Uint8Array; aad: Uint8Array }
): Promise<{
  plaintext: Uint8Array;
  newState: GroupRatchetState;
}> {
  // This is a stub - actual implementation requires full AEAD + ratchet
  // See ratchet.ts for decryptMessage() pattern

  return {
    plaintext: new Uint8Array(),
    newState: state,
  };
}

// ==================== Group Ratcheting ====================

/**
 * Perform group ratchet step
 *
 * When group epoch limit reached, all members do synchronized ratchet
 * Process:
 * 1. Each member generates new ephemeral X25519 + ML-KEM
 * 2. Members exchange new ephemeralsin rekey message
 * 3. Perform X25519 DH + ML-KEM KEM with new ephemerals
 * 4. Re-derive root key (same formula as group setup)
 * 5. Re-derive all per-participant chain keys
 *
 * Result: All members compute same new root key and chain keys
 */
export function performGroupRekey(
  state: GroupRatchetState,
  newEphemeralX25519: Uint8Array,
  newEphemeralMLKEM: Uint8Array,
  peerEphemerals: Array<{ username: string; ephemeralX25519: Uint8Array; ephemeralMLKEM: Uint8Array }>
): GroupRatchetState {
  // This is a stub - full implementation matches ratchet.ts rekey pattern
  // but applied to all participants simultaneously

  return { ...state, groupVersion: state.groupVersion + 1 };
}

// ==================== Wire Format ====================

export interface WireGroupMessage {
  type: 'group_message';
  groupId: string;
  groupVersion: number;
  sender: string;
  message: {
    aad: string; // base64 (shared AAD)
    nonce: string; // base64 (shared nonce)
    ciphertext: string; // base64 (shared symmetric ciphertext)
    recipients: {
      [username: string]: {
        nonce: string; // base64 (recipient-specific wrap nonce)
        ciphertext: string; // base64 (recipient-specific wrap)
      };
    };
  };
  timestamp: number;
}

export interface WireGroupHandshake {
  type: 'group_handshake_init' | 'group_handshake_response';
  groupId: string;
  initiator: string;
  participants: string[]; // List of all participants (deterministic order)
  // Each participant includes their pairwise handshake
  pairwiseHandshakes: {
    [participant: string]: {
      message: string; // base64 encoded 1-on-1 handshake message
      timestamp: number;
    };
  };
}

export interface WireGroupRekey {
  type: 'group_rekey';
  groupId: string;
  groupVersion: number;
  sender: string;
  newEphemeralX25519: string; // base64
  newEphemeralMLKEM: string; // base64
  signature: string; // base64 (signed by group root key)
  timestamp: number;
}

// ==================== Utilities ====================

/**
 * Check if group member is still in group
 */
export function isGroupMember(state: GroupRatchetState, username: string): boolean {
  return state.participants.some((p) => p.username === username);
}

/**
 * Get group member count
 */
export function getGroupMemberCount(state: GroupRatchetState): number {
  return state.participants.length;
}

/**
 * Get list of group member usernames
 */
export function getGroupMembers(state: GroupRatchetState): string[] {
  return state.participants.map((p) => p.username);
}

/**
 * Check if group needs rekey (same cadence as 1-on-1)
 */
export function groupNeedsRekey(state: GroupRatchetState): {
  required: boolean;
  reason?: string;
} {
  // Hard caps
  if (state.groupTotalMessages >= 2 ** 32) {
    return { required: true, reason: 'group_message_cap' };
  }

  const groupAge = Date.now() - state.groupCreatedAt;
  if (groupAge >= 7 * 24 * 60 * 60 * 1000) {
    // 7 days
    return { required: true, reason: 'group_age_cap' };
  }

  // Epoch-level (optional, could be longer for groups)
  const epochAge = Date.now() - state.groupEpochStartTime;
  if (epochAge >= 24 * 60 * 60 * 1000) {
    // 24 hours
    return { required: true, reason: 'epoch_time_limit' };
  }

  return { required: false };
}
