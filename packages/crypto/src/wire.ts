/**
 * Wire format encoding/decoding
 * CBOR-based message structure
 */

import { encode, decode } from 'cbor-x';
import { EncryptedRecord } from './ratchet.js';
import { HandshakeMessage } from './handshake.js';

export interface WireHandshakeMessage {
  type: 'handshake';
  role: 'initiator' | 'responder';
  identityEd25519: string; // base64
  identityMLDSA: string;
  ephemeralX25519: string;
  ephemeralMLKEM?: string;
  kemCiphertext?: string;
  ed25519Sig: string;
  mldsaSig: string;
}

export interface WireEncryptedMessage {
  type: 'message';
  aad: string; // base64
  nonce: string;
  ciphertext: string;
}

export interface WireRekeyMessage {
  type: 'rekey';
  ephemeralX25519: string;
  ephemeralMLKEM: string;
  signature: string; // signed by current session keys
}

export type WireMessage = WireHandshakeMessage | WireEncryptedMessage | WireRekeyMessage;

/**
 * Encode handshake message to wire format
 */
export function encodeHandshakeMessage(msg: HandshakeMessage): Uint8Array {
  const wire: WireHandshakeMessage = {
    type: 'handshake',
    role: msg.role,
    identityEd25519: Buffer.from(msg.identityPublicEd25519).toString('base64'),
    identityMLDSA: Buffer.from(msg.identityPublicMLDSA).toString('base64'),
    ephemeralX25519: Buffer.from(msg.ephemeralX25519).toString('base64'),
    ephemeralMLKEM: msg.ephemeralMLKEM
      ? Buffer.from(msg.ephemeralMLKEM).toString('base64')
      : undefined,
    kemCiphertext: msg.kemCiphertext
      ? Buffer.from(msg.kemCiphertext).toString('base64')
      : undefined,
    ed25519Sig: Buffer.from(msg.ed25519Signature).toString('base64'),
    mldsaSig: Buffer.from(msg.mldsaSignature).toString('base64'),
  };

  return encode(wire);
}

/**
 * Decode handshake message from wire format
 */
export function decodeHandshakeMessage(data: Uint8Array): HandshakeMessage {
  const wire = decode(data) as WireHandshakeMessage;

  if (wire.type !== 'handshake') {
    throw new Error('Invalid message type');
  }

  return {
    role: wire.role,
    identityPublicEd25519: Buffer.from(wire.identityEd25519, 'base64'),
    identityPublicMLDSA: Buffer.from(wire.identityMLDSA, 'base64'),
    ephemeralX25519: Buffer.from(wire.ephemeralX25519, 'base64'),
    ephemeralMLKEM: wire.ephemeralMLKEM
      ? Buffer.from(wire.ephemeralMLKEM, 'base64')
      : undefined,
    kemCiphertext: wire.kemCiphertext
      ? Buffer.from(wire.kemCiphertext, 'base64')
      : undefined,
    ed25519Signature: Buffer.from(wire.ed25519Sig, 'base64'),
    mldsaSignature: Buffer.from(wire.mldsaSig, 'base64'),
  };
}

/**
 * Encode encrypted record to wire format
 */
export function encodeEncryptedMessage(record: EncryptedRecord): Uint8Array {
  const wire: WireEncryptedMessage = {
    type: 'message',
    aad: Buffer.from(record.aad).toString('base64'),
    nonce: Buffer.from(record.nonce).toString('base64'),
    ciphertext: Buffer.from(record.ciphertext).toString('base64'),
  };

  return encode(wire);
}

/**
 * Minimum wire message length (CBOR overhead + minimal fields)
 * A CBOR map with type + aad + nonce + ciphertext is at least ~40 bytes
 */
const MIN_WIRE_MESSAGE_LENGTH = 24;

/**
 * Decode encrypted record from wire format
 * Validates structure and length before attempting CBOR decode
 */
export function decodeEncryptedMessage(data: Uint8Array): EncryptedRecord {
  // Validate input is a Uint8Array
  if (!(data instanceof Uint8Array)) {
    throw new Error(`Wire data must be Uint8Array, got: ${typeof data}`);
  }

  // Validate minimum length
  if (!data || data.byteLength < MIN_WIRE_MESSAGE_LENGTH) {
    throw new Error(`Wire message too short: ${data?.byteLength ?? 0} bytes (minimum ${MIN_WIRE_MESSAGE_LENGTH})`);
  }

  // Attempt CBOR decode with better error handling
  let wire: any;
  try {
    wire = decode(data);
  } catch (err) {
    throw new Error(`CBOR decode failed: ${err instanceof Error ? err.message : 'Unknown error'}. Data length: ${data.byteLength} bytes`);
  }

  // Validate decoded structure
  if (!wire || typeof wire !== 'object') {
    throw new Error(`Wire message is not a CBOR map, got: ${typeof wire}`);
  }

  // Validate message type
  if (wire.type !== 'message') {
    throw new Error(`Invalid message type: "${wire.type}" (expected "message"). This might be a handshake or rekey message.`);
  }

  // Validate required fields exist
  if (!wire.aad || !wire.nonce || !wire.ciphertext) {
    throw new Error(`Missing required fields in wire message. Has: {type: ${wire.type}, aad: ${!!wire.aad}, nonce: ${!!wire.nonce}, ciphertext: ${!!wire.ciphertext}}`);
  }

  return {
    aad: Buffer.from(wire.aad, 'base64'),
    nonce: Buffer.from(wire.nonce, 'base64'),
    ciphertext: Buffer.from(wire.ciphertext, 'base64'),
  };
}

/**
 * Encode rekey message
 */
export function encodeRekeyMessage(
  ephemeralX25519: Uint8Array,
  ephemeralMLKEM: Uint8Array,
  signature: Uint8Array
): Uint8Array {
  const wire: WireRekeyMessage = {
    type: 'rekey',
    ephemeralX25519: Buffer.from(ephemeralX25519).toString('base64'),
    ephemeralMLKEM: Buffer.from(ephemeralMLKEM).toString('base64'),
    signature: Buffer.from(signature).toString('base64'),
  };

  return encode(wire);
}

/**
 * Decode rekey message
 */
export function decodeRekeyMessage(data: Uint8Array): {
  ephemeralX25519: Uint8Array;
  ephemeralMLKEM: Uint8Array;
  signature: Uint8Array;
} {
  const wire = decode(data) as WireRekeyMessage;

  if (wire.type !== 'rekey') {
    throw new Error('Invalid message type');
  }

  return {
    ephemeralX25519: Buffer.from(wire.ephemeralX25519, 'base64'),
    ephemeralMLKEM: Buffer.from(wire.ephemeralMLKEM, 'base64'),
    signature: Buffer.from(wire.signature, 'base64'),
  };
}

/**
 * Serialize prekey bundle to canonical byte array
 * CRITICAL: Must be 100% deterministic
 * Used for signing by identity private key
 */
export function serializePrekeyBundle(bundle: {
  x25519Pub: Uint8Array;
  pqKemPub?: Uint8Array;
  pqSigPub?: Uint8Array;
}): Uint8Array {
  // IMPORTANT: order and empties must be deterministic
  // Use empty arrays for missing PQ fields
  const empty = new Uint8Array(0);

  const parts: Uint8Array[] = [
    bundle.x25519Pub || empty,
    bundle.pqKemPub || empty,
    bundle.pqSigPub || empty,
  ];

  // Validate all parts are Uint8Array
  for (let i = 0; i < parts.length; i++) {
    if (!(parts[i] instanceof Uint8Array)) {
      parts[i] = empty;
    }
  }

  // Simple format: [len1(1byte)|data1|len2(1byte)|data2|len3(1byte)|data3]
  // For keys > 255 bytes, we use 4-byte length prefix
  let totalLength = 0;
  for (const p of parts) {
    // Length prefix: 1 byte for < 256, or 4 bytes for >= 256
    totalLength += (p.length < 256 ? 1 : 4) + p.length;
  }

  const out = new Uint8Array(totalLength);
  let offset = 0;

  for (const p of parts) {
    if (p.length < 256) {
      // 1-byte length prefix
      out[offset++] = p.length;
    } else {
      // 4-byte length prefix (big-endian)
      out[offset++] = 0xFF; // marker for 4-byte length
      out[offset++] = (p.length >> 16) & 0xFF;
      out[offset++] = (p.length >> 8) & 0xFF;
      out[offset++] = p.length & 0xFF;
    }
    out.set(p, offset);
    offset += p.length;
  }

  return out;
}

/**
 * Base64 encoding (standard, not URL-safe)
 * CRITICAL: Must use same encoding everywhere
 */
export function toBase64(u8: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    // Node.js
    return Buffer.from(u8).toString('base64');
  } else {
    // Browser
    return btoa(String.fromCharCode(...u8));
  }
}

/**
 * Base64 decoding (standard, not URL-safe)
 * CRITICAL: Must use same decoding everywhere
 */
export function fromBase64(s: string): Uint8Array {
  if (!s) return new Uint8Array(0);

  if (typeof Buffer !== 'undefined') {
    // Node.js
    return new Uint8Array(Buffer.from(s, 'base64'));
  } else {
    // Browser
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }
}

/**
 * Normalize wire data from various formats to Uint8Array
 * Handles: base64 string, ArrayBuffer, Uint8Array, Buffer
 */
export function normalizeWireData(data: any): Uint8Array {
  // Already Uint8Array
  if (data instanceof Uint8Array) {
    return data;
  }

  // Base64 string
  if (typeof data === 'string') {
    return fromBase64(data);
  }

  // ArrayBuffer
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }

  // Node.js Buffer
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(data)) {
    return new Uint8Array(data);
  }

  // Fallback: try to treat as array-like
  if (data && typeof data.length === 'number' && typeof data[0] === 'number') {
    return new Uint8Array(data);
  }

  throw new Error(`Cannot normalize wire data: unsupported type ${typeof data}`);
}

/**
 * Check if data looks like an encrypted blob (pre-decode validation)
 * Helps avoid CBOR decode errors on non-message entries
 */
export function isLikelyEncryptedBlob(data: any): boolean {
  try {
    // Normalize to Uint8Array
    const normalized = normalizeWireData(data);

    // Must have minimum length
    if (!normalized || normalized.byteLength < MIN_WIRE_MESSAGE_LENGTH) {
      return false;
    }

    // CBOR map starts with major type 5 (0b101xxxxx)
    // First byte should be 0xA0-0xBF for a map
    const firstByte = normalized[0];
    const isCBORMap = (firstByte >= 0xA0 && firstByte <= 0xBF);

    if (!isCBORMap) {
      return false;
    }

    // Optionally: Quick peek into CBOR to check for "type" field
    // But this is complex, so we rely on length + map marker for now

    return true;
  } catch {
    return false;
  }
}
