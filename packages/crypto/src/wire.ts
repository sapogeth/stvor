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
 * Decode encrypted record from wire format
 */
export function decodeEncryptedMessage(data: Uint8Array): EncryptedRecord {
  const wire = decode(data) as WireEncryptedMessage;

  if (wire.type !== 'message') {
    throw new Error('Invalid message type');
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
