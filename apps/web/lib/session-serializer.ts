/**
 * Session Serialization Helper
 *
 * Converts HandshakeState to/from JSON-serializable format for relay storage.
 * This ensures consistent serialization across all parts of the app.
 */

import { type HandshakeState } from '@ilyazh/crypto';

/**
 * Serialized session format for JSON transport to relay
 */
export interface SerializedSession {
  role: 'initiator' | 'responder';
  sessionId: string; // hex
  rootKey: string; // base64
  sendChainKey: string; // base64
  recvChainKey: string; // base64
  sendRatchetId: string; // bigint as string
  recvRatchetId: string; // bigint as string
  sendCounter: number;
  recvCounter: number;
  epochStartTime: number;
  sessionStartTime: number;
  totalMessages: number;
  devMode?: boolean;
  pqEnabled?: boolean;
  version: number; // timestamp for conflict resolution
  participants?: Array<{
    username: string;
    identityEd25519: string;
  }>;
  createdAt?: number;
  lastUpdated: number;
}

/**
 * Convert Uint8Array to base64 (Node + Browser compatible)
 */
function u8ToBase64(u8: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(u8).toString('base64');
  }
  // Browser fallback
  const binString = Array.from(u8, (byte) => String.fromCodePoint(byte)).join('');
  return btoa(binString);
}

/**
 * Convert base64 to Uint8Array (Node + Browser compatible)
 */
function base64ToU8(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(b64, 'base64');
  }
  // Browser fallback
  const binString = atob(b64);
  return Uint8Array.from(binString, (m) => m.codePointAt(0)!);
}

/**
 * Serialize HandshakeState to JSON-compatible format
 * Converts Uint8Arrays to base64, bigints to strings
 */
export function serializeSession(
  session: HandshakeState,
  participants?: Array<{ username: string; identityEd25519: string }>
): SerializedSession {
  return {
    role: session.role,
    sessionId: Buffer.from(session.sessionId).toString('hex'),
    rootKey: u8ToBase64(session.rootKey),
    sendChainKey: u8ToBase64(session.sendChainKey),
    recvChainKey: u8ToBase64(session.recvChainKey),
    sendRatchetId: session.sendRatchetId.toString(),
    recvRatchetId: session.recvRatchetId.toString(),
    sendCounter: session.sendCounter,
    recvCounter: session.recvCounter,
    epochStartTime: session.epochStartTime,
    sessionStartTime: session.sessionStartTime,
    totalMessages: session.totalMessages,
    devMode: session.devMode,
    pqEnabled: session.pqEnabled,
    version: Date.now(), // Use current timestamp as version
    participants,
    createdAt: session.sessionStartTime,
    lastUpdated: Date.now(),
  };
}

/**
 * Deserialize from JSON format back to HandshakeState
 * Converts base64 to Uint8Arrays, strings to bigints
 */
export function deserializeSession(serialized: any): HandshakeState {
  return {
    role: serialized.role || 'responder',
    sessionId: typeof serialized.sessionId === 'string' && serialized.sessionId.length > 0
      ? (typeof Buffer !== 'undefined' ? Buffer.from(serialized.sessionId, 'hex') : base64ToU8(serialized.sessionId))
      : new Uint8Array(32),
    rootKey: base64ToU8(serialized.rootKey),
    sendChainKey: base64ToU8(serialized.sendChainKey),
    recvChainKey: base64ToU8(serialized.recvChainKey),
    sendRatchetId: BigInt(serialized.sendRatchetId || '0'),
    recvRatchetId: BigInt(serialized.recvRatchetId || '0'),
    sendCounter: serialized.sendCounter || 0,
    recvCounter: serialized.recvCounter || 0,
    epochStartTime: serialized.epochStartTime || Date.now(),
    sessionStartTime: serialized.sessionStartTime || Date.now(),
    totalMessages: serialized.totalMessages || 0,
    devMode: serialized.devMode,
    pqEnabled: serialized.pqEnabled,
  };
}

/**
 * Push updated session to relay (call after every encrypt/decrypt)
 */
export async function pushSessionToRelay(
  chatId: string,
  session: HandshakeState,
  relayUrl: string,
  participants?: Array<{ username: string; identityEd25519: string }>
): Promise<boolean> {
  try {
    const serialized = serializeSession(session, participants);

    console.log('[SessionSync] Pushing updated session to relay');
    console.log('[SessionSync] - sessionId:', serialized.sessionId.slice(0, 16) + '...');
    console.log('[SessionSync] - sendCounter:', serialized.sendCounter);
    console.log('[SessionSync] - recvCounter:', serialized.recvCounter);
    console.log('[SessionSync] - version:', serialized.version);

    const res = await fetch(`${relayUrl}/chat/${chatId}/session`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(serialized),
    });

    if (res.ok) {
      console.log('[SessionSync] ✅ Session pushed to relay');
      return true;
    } else if (res.status === 409) {
      const conflict = await res.json();
      console.warn('[SessionSync] ⚠️  Version conflict - relay has newer:', conflict.current);
      return false;
    } else {
      console.warn('[SessionSync] Failed to push session:', res.status);
      return false;
    }
  } catch (err) {
    console.error('[SessionSync] Error pushing session to relay:', err);
    return false;
  }
}
