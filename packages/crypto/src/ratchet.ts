/**
 * Double Ratchet with Mandated Re-encapsulation Cadence
 * Enforces: rekey every 2^20 messages or 24h (per epoch)
 * Session cap: 2^32 messages or 7 days
 * Nonce: R64 || C32 (ratchet ID || counter)
 */

import * as prim from './primitives.js';
import * as constants from './constants.js';
import { HandshakeState } from './handshake.js';

export interface EncryptedRecord {
  aad: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export interface RatchetState extends HandshakeState {
  // Inherited from HandshakeState
}

/**
 * Check if rekey is required based on cadence limits
 */
export function needsRekey(state: RatchetState): {
  required: boolean;
  reason?: 'message_limit' | 'time_limit' | 'session_cap_messages' | 'session_cap_time';
} {
  const now = Date.now();
  const epochAge = now - state.epochStartTime;
  const sessionAge = now - state.sessionStartTime;

  // Hard session caps (MUST NOT exceed)
  if (state.totalMessages >= constants.SESSION_MESSAGE_CAP) {
    return { required: true, reason: 'session_cap_messages' };
  }
  if (sessionAge >= constants.SESSION_TIME_CAP_MS) {
    return { required: true, reason: 'session_cap_time' };
  }

  // Epoch rekey cadence
  const epochMessages = state.sendCounter; // messages in current epoch
  if (epochMessages >= constants.REKEY_MESSAGE_LIMIT) {
    return { required: true, reason: 'message_limit' };
  }
  if (epochAge >= constants.REKEY_TIME_LIMIT_MS) {
    return { required: true, reason: 'time_limit' };
  }

  return { required: false };
}

/**
 * Build AAD for record
 * Format: Version(1) || SuiteID(8) || sid(32) || Seq(8) || Epoch(8) || Flags(1)
 */
export function buildAAD(
  sessionId: Uint8Array,
  sequence: bigint,
  ratchetId: bigint,
  flags: number = 0
): Uint8Array {
  const aad = new Uint8Array(1 + 8 + 32 + 8 + 8 + 1);
  let offset = 0;

  // Version
  aad[offset++] = constants.PROTOCOL_VERSION;

  // Suite ID
  aad.set(constants.SUITE_ID, offset);
  offset += constants.SUITE_ID.length;

  // Session ID (sid in AAD - normative requirement)
  aad.set(sessionId, offset);
  offset += constants.SESSION_ID_LENGTH;

  // Sequence (8 bytes, big-endian)
  const seqView = new DataView(aad.buffer, offset, 8);
  seqView.setBigUint64(0, sequence, false);
  offset += 8;

  // Ratchet epoch (8 bytes, big-endian)
  const epochView = new DataView(aad.buffer, offset, 8);
  epochView.setBigUint64(0, ratchetId, false);
  offset += 8;

  // Flags
  aad[offset] = flags;

  return aad;
}

/**
 * Build nonce: R64 || C32
 * R64 = ratchet ID (big-endian)
 * C32 = counter (big-endian)
 */
export function buildNonce(ratchetId: bigint, counter: number): Uint8Array {
  if (counter >= 0xFFFFFFFF) {
    throw new Error('Counter overflow - rekey required');
  }

  const nonce = new Uint8Array(constants.AEAD_NONCE_LENGTH);

  // R64 (first 8 bytes)
  const ratchetView = new DataView(nonce.buffer, 0, 8);
  ratchetView.setBigUint64(0, ratchetId, false);

  // C32 (next 4 bytes)
  const counterView = new DataView(nonce.buffer, 8, 4);
  counterView.setUint32(0, counter, false);

  return nonce;
}

/**
 * Derive message key from chain key
 * mk = HKDF(ck, "mk", 32)
 * ck_next = HKDF(ck, "ck", 64)
 */
function deriveMessageKey(
  chainKey: Uint8Array,
  sessionId: Uint8Array
): { messageKey: Uint8Array; nextChainKey: Uint8Array } {
  const messageKey = prim.hkdfSHA384(
    chainKey,
    constants.LABEL_MESSAGE_KEY,
    constants.MESSAGE_KEY_LENGTH,
    sessionId
  );

  const nextChainKey = prim.hkdfSHA384(
    chainKey,
    constants.LABEL_CHAIN_KEY,
    constants.CHAIN_KEY_LENGTH,
    sessionId
  );

  // Zeroize old chain key
  prim.zeroize(chainKey);

  return { messageKey, nextChainKey };
}

/**
 * Encrypt a message
 */
export async function encryptMessage(
  state: RatchetState,
  plaintext: Uint8Array
): Promise<{ record: EncryptedRecord; newState: RatchetState }> {
  await prim.initCrypto();

  // Check cadence limits
  const rekeyCheck = needsRekey(state);
  if (rekeyCheck.required) {
    throw new Error(`Rekey required: ${rekeyCheck.reason}`);
  }

  // Derive message key
  const { messageKey, nextChainKey } = deriveMessageKey(state.sendChainKey, state.sessionId);

  // Build nonce
  const nonce = buildNonce(state.sendRatchetId, state.sendCounter);

  // Build AAD with sid
  const sequence = BigInt(state.totalMessages);
  const aad = buildAAD(state.sessionId, sequence, state.sendRatchetId);

  // Encrypt
  const ciphertext = prim.aeadEncrypt(messageKey, nonce, plaintext, aad);

  // Zeroize message key
  prim.zeroize(messageKey);

  // Update state
  const newState: RatchetState = {
    ...state,
    sendChainKey: nextChainKey,
    sendCounter: state.sendCounter + 1,
    totalMessages: state.totalMessages + 1,
  };

  return {
    record: { aad, nonce, ciphertext },
    newState,
  };
}

/**
 * Decrypt a message
 */
export async function decryptMessage(
  state: RatchetState,
  record: EncryptedRecord
): Promise<{ plaintext: Uint8Array; newState: RatchetState }> {
  await prim.initCrypto();

  // Verify AAD structure and sid
  if (record.aad.length < constants.AAD_MIN_LENGTH) {
    throw new Error('Invalid AAD length');
  }

  // Extract sid from AAD (offset 9, length 32)
  const aadSid = record.aad.slice(9, 9 + constants.SESSION_ID_LENGTH);
  if (!prim.constantTimeEqual(aadSid, state.sessionId)) {
    throw new Error('AAD session ID mismatch');
  }

  // Derive message key
  const { messageKey, nextChainKey } = deriveMessageKey(state.recvChainKey, state.sessionId);

  // Decrypt
  const plaintext = prim.aeadDecrypt(messageKey, record.nonce, record.ciphertext, record.aad);

  // Zeroize message key
  prim.zeroize(messageKey);

  // Update state
  const newState: RatchetState = {
    ...state,
    recvChainKey: nextChainKey,
    recvCounter: state.recvCounter + 1,
    totalMessages: state.totalMessages + 1,
  };

  return { plaintext, newState };
}

/**
 * Perform ratchet step (re-encapsulation)
 * Generate new ephemeral keys, perform DH + KEM, derive new chain keys
 */
export async function performRekey(
  state: RatchetState,
  peerEphemeralX25519: Uint8Array,
  peerEphemeralMLKEM: Uint8Array
): Promise<RatchetState> {
  await prim.initCrypto();

  // Generate new ephemeral keys
  const newX25519 = prim.generateX25519KeyPair();
  const newMLKEM = prim.generateMLKEMKeyPair();

  // Perform DH
  const dhSecret = prim.x25519(newX25519.secretKey, peerEphemeralX25519);

  // Perform KEM encapsulation
  const kemResult = prim.mlkemEncapsulate(peerEphemeralMLKEM);
  const kemSecret = kemResult.sharedSecret;

  // Combine
  const combined = new Uint8Array(dhSecret.length + kemSecret.length);
  combined.set(dhSecret);
  combined.set(kemSecret, dhSecret.length);

  // Derive new root key
  const newRootKey = prim.hkdfSHA384(
    combined,
    constants.LABEL_ROOT_KEY,
    constants.ROOT_KEY_LENGTH,
    state.sessionId
  );

  // Derive new chain keys
  const newSendChainKey = prim.hkdfSHA384(
    newRootKey,
    constants.LABEL_CHAIN_KEYS + '/send',
    constants.CHAIN_KEY_LENGTH,
    state.sessionId
  );

  const newRecvChainKey = prim.hkdfSHA384(
    newRootKey,
    constants.LABEL_CHAIN_KEYS + '/recv',
    constants.CHAIN_KEY_LENGTH,
    state.sessionId
  );

  // Zeroize secrets
  prim.zeroize(dhSecret);
  prim.zeroize(kemSecret);
  prim.zeroize(combined);
  prim.zeroize(state.rootKey);
  prim.zeroize(state.sendChainKey);
  prim.zeroize(state.recvChainKey);

  const now = Date.now();
  return {
    ...state,
    rootKey: newRootKey,
    sendChainKey: newSendChainKey,
    recvChainKey: newRecvChainKey,
    sendRatchetId: state.sendRatchetId + 1n,
    recvRatchetId: state.recvRatchetId + 1n,
    sendCounter: 0,
    recvCounter: 0,
    epochStartTime: now,
  };
}

/**
 * Serialize state for persistence (excluding secrets)
 */
export function serializeStatePublic(state: RatchetState): string {
  return JSON.stringify({
    role: state.role,
    sessionId: Buffer.from(state.sessionId).toString('base64'),
    sendRatchetId: state.sendRatchetId.toString(),
    recvRatchetId: state.recvRatchetId.toString(),
    sendCounter: state.sendCounter,
    recvCounter: state.recvCounter,
    epochStartTime: state.epochStartTime,
    sessionStartTime: state.sessionStartTime,
    totalMessages: state.totalMessages,
  });
}
