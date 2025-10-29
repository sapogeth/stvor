/**
 * Ilyazh-Web3E2E Handshake (Hybrid AKE)
 * X25519 + ML-KEM-768 key exchange
 * Dual signatures: Ed25519 + ML-DSA-65 over transcript
 * sid derivation and key confirmation
 */

import * as prim from './primitives.js';
import * as constants from './constants.js';
import { encode } from 'cbor-x';

export interface IdentityKeyPair {
  ed25519: prim.Ed25519KeyPair;
  mldsa: prim.MLDSAKeyPair;
}

export interface PrekeyBundle {
  // Ephemeral keys for this bundle
  x25519Ephemeral: Uint8Array; // public
  mlkemPublicKey: Uint8Array;

  // Dual signatures over bundle (signed by identity keys)
  ed25519Signature: Uint8Array;
  mldsaSignature: Uint8Array;

  // Metadata
  bundleId: string;
  timestamp: number;
}

export interface PrekeyBundleWithSecrets extends PrekeyBundle {
  // Secret keys (must be stored securely by caller)
  x25519SecretKey: Uint8Array;
  mlkemSecretKey: Uint8Array;
}

export interface HandshakeState {
  role: 'initiator' | 'responder';
  sessionId: Uint8Array;
  rootKey: Uint8Array;
  sendChainKey: Uint8Array;
  recvChainKey: Uint8Array;
  sendRatchetId: bigint;
  recvRatchetId: bigint;
  sendCounter: number;
  recvCounter: number;
  epochStartTime: number;
  sessionStartTime: number;
  totalMessages: number;
}

export interface HandshakeMessage {
  role: 'initiator' | 'responder';
  identityPublicEd25519: Uint8Array;
  identityPublicMLDSA: Uint8Array;
  ephemeralX25519: Uint8Array;
  ephemeralMLKEM?: Uint8Array; // initiator sends; responder omits
  kemCiphertext?: Uint8Array; // responder sends; initiator omits
  ed25519Signature: Uint8Array;
  mldsaSignature: Uint8Array;
}

/**
 * Generate long-term identity keypair
 */
export async function generateIdentity(): Promise<IdentityKeyPair> {
  await prim.initCrypto();
  return {
    ed25519: prim.generateEd25519KeyPair(),
    mldsa: prim.generateMLDSAKeyPair(),
  };
}

/**
 * Generate signed prekey bundle
 * Returns both public bundle and secret keys
 */
export async function generatePrekeyBundle(
  identity: IdentityKeyPair,
  bundleId: string
): Promise<PrekeyBundleWithSecrets> {
  await prim.initCrypto();

  const x25519KeyPair = prim.generateX25519KeyPair();
  const mlkemKeyPair = prim.generateMLKEMKeyPair();

  // Sign bundle contents with both identity keys
  const bundleData = encode({
    bundleId,
    x25519: x25519KeyPair.publicKey,
    mlkem: mlkemKeyPair.publicKey,
    timestamp: Date.now(),
  });

  const ed25519Signature = prim.ed25519Sign(bundleData, identity.ed25519.secretKey);
  const mldsaSignature = prim.mldsaSign(bundleData, identity.mldsa.secretKey);

  return {
    x25519Ephemeral: x25519KeyPair.publicKey,
    mlkemPublicKey: mlkemKeyPair.publicKey,
    ed25519Signature,
    mldsaSignature,
    bundleId,
    timestamp: Date.now(),
    // Include secret keys for caller to store securely
    x25519SecretKey: x25519KeyPair.secretKey,
    mlkemSecretKey: mlkemKeyPair.secretKey,
  };
}

/**
 * Build handshake transcript for hashing
 * Order: suite || caps || identities || ephemerals || kem_cts || roles
 */
function buildTranscript(
  initiatorMsg: HandshakeMessage,
  responderMsg: HandshakeMessage
): Uint8Array {
  const parts: Uint8Array[] = [
    constants.SUITE_ID,
    // Capabilities (default dual-sig mode)
    new Uint8Array([0x01]), // dual-sig enabled

    // Identities
    initiatorMsg.identityPublicEd25519,
    initiatorMsg.identityPublicMLDSA,
    responderMsg.identityPublicEd25519,
    responderMsg.identityPublicMLDSA,

    // Ephemerals
    initiatorMsg.ephemeralX25519,
    initiatorMsg.ephemeralMLKEM!,
    responderMsg.ephemeralX25519,

    // KEM ciphertext
    responderMsg.kemCiphertext!,

    // Roles
    new TextEncoder().encode('initiator'),
    new TextEncoder().encode('responder'),
  ];

  const totalLength = parts.reduce((sum, p) => sum + p.length, 0);
  const transcript = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    transcript.set(part, offset);
    offset += part.length;
  }

  return transcript;
}

/**
 * Hybrid key combiner: X25519 DH || ML-KEM shared secret
 */
function hybridCombine(dhSecret: Uint8Array, kemSecret: Uint8Array): Uint8Array {
  const combined = new Uint8Array(dhSecret.length + kemSecret.length);
  combined.set(dhSecret);
  combined.set(kemSecret, dhSecret.length);
  return combined;
}

/**
 * Initiator: start handshake
 */
export async function initiateHandshake(
  initiatorIdentity: IdentityKeyPair,
  responderIdentityPubEd25519: Uint8Array,
  responderIdentityPubMLDSA: Uint8Array,
  responderPrekey: PrekeyBundle
): Promise<{ message: HandshakeMessage; ephemeralX25519Secret: Uint8Array }> {
  await prim.initCrypto();

  // Generate ephemeral keys
  const ephemeralX25519 = prim.generateX25519KeyPair();
  const ephemeralMLKEM = prim.generateMLKEMKeyPair();

  const message: HandshakeMessage = {
    role: 'initiator',
    identityPublicEd25519: initiatorIdentity.ed25519.publicKey,
    identityPublicMLDSA: initiatorIdentity.mldsa.publicKey,
    ephemeralX25519: ephemeralX25519.publicKey,
    ephemeralMLKEM: ephemeralMLKEM.publicKey,
    ed25519Signature: new Uint8Array(0), // placeholder
    mldsaSignature: new Uint8Array(0),
  };

  // Build partial transcript for signature (without responder message yet)
  const partialTranscript = encode({
    suite: constants.SUITE_ID,
    initiator: {
      identityEd: message.identityPublicEd25519,
      identityML: message.identityPublicMLDSA,
      ephX: message.ephemeralX25519,
      ephML: message.ephemeralMLKEM,
    },
    responder: {
      identityEd: responderIdentityPubEd25519,
      identityML: responderIdentityPubMLDSA,
      prekeyX: responderPrekey.x25519Ephemeral,
      prekeyML: responderPrekey.mlkemPublicKey,
    },
  });

  message.ed25519Signature = prim.ed25519Sign(partialTranscript, initiatorIdentity.ed25519.secretKey);
  message.mldsaSignature = prim.mldsaSign(partialTranscript, initiatorIdentity.mldsa.secretKey);

  return {
    message,
    ephemeralX25519Secret: ephemeralX25519.secretKey,
  };
}

/**
 * Responder: complete handshake and derive session keys
 */
export async function completeHandshake(
  responderIdentity: IdentityKeyPair,
  responderPrekeyX25519Secret: Uint8Array,
  responderPrekeyMLKEMSecret: Uint8Array,
  initiatorMsg: HandshakeMessage
): Promise<{ message: HandshakeMessage; state: HandshakeState }> {
  await prim.initCrypto();

  // Verify initiator signatures
  const partialTranscript = encode({
    suite: constants.SUITE_ID,
    initiator: {
      identityEd: initiatorMsg.identityPublicEd25519,
      identityML: initiatorMsg.identityPublicMLDSA,
      ephX: initiatorMsg.ephemeralX25519,
      ephML: initiatorMsg.ephemeralMLKEM,
    },
    responder: {
      identityEd: responderIdentity.ed25519.publicKey,
      identityML: responderIdentity.mldsa.publicKey,
    },
  });

  const ed25519Valid = prim.ed25519Verify(
    initiatorMsg.ed25519Signature,
    partialTranscript,
    initiatorMsg.identityPublicEd25519
  );

  const mldsaValid = prim.mldsaVerify(
    initiatorMsg.mldsaSignature,
    partialTranscript,
    initiatorMsg.identityPublicMLDSA
  );

  // Dual-signature mode: both must pass
  if (!ed25519Valid || !mldsaValid) {
    throw new Error('Handshake signature verification failed');
  }

  // Perform X25519 DH
  const dhSecret = prim.x25519(responderPrekeyX25519Secret, initiatorMsg.ephemeralX25519);

  // Encapsulate ML-KEM
  const kemResult = prim.mlkemEncapsulate(initiatorMsg.ephemeralMLKEM!);
  const kemSecret = kemResult.sharedSecret;

  // Combine secrets
  const combinedSecret = hybridCombine(dhSecret, kemSecret);

  // Generate responder ephemeral for ratchet
  const responderEphemeralX25519 = prim.generateX25519KeyPair();

  const responderMsg: HandshakeMessage = {
    role: 'responder',
    identityPublicEd25519: responderIdentity.ed25519.publicKey,
    identityPublicMLDSA: responderIdentity.mldsa.publicKey,
    ephemeralX25519: responderEphemeralX25519.publicKey,
    kemCiphertext: kemResult.ciphertext,
    ed25519Signature: new Uint8Array(0),
    mldsaSignature: new Uint8Array(0),
  };

  // Build full transcript
  const transcript = buildTranscript(initiatorMsg, responderMsg);
  const transcriptHash = prim.hashTranscript(transcript);

  // Sign transcript
  responderMsg.ed25519Signature = prim.ed25519Sign(transcriptHash, responderIdentity.ed25519.secretKey);
  responderMsg.mldsaSignature = prim.mldsaSign(transcriptHash, responderIdentity.mldsa.secretKey);

  // Derive session ID and root key
  const sessionId = prim.hkdfSHA384(
    combinedSecret,
    constants.LABEL_SESSION_ID,
    constants.SESSION_ID_LENGTH,
    constants.SUITE_ID
  );

  const rootKey = prim.hkdfSHA384(
    combinedSecret,
    constants.LABEL_ROOT_KEY,
    constants.ROOT_KEY_LENGTH,
    sessionId
  );

  // Derive initial chain keys (responder sends, initiator receives)
  const sendChainKey = prim.hkdfSHA384(
    rootKey,
    constants.LABEL_CHAIN_KEYS + '/send',
    constants.CHAIN_KEY_LENGTH,
    sessionId
  );

  const recvChainKey = prim.hkdfSHA384(
    rootKey,
    constants.LABEL_CHAIN_KEYS + '/recv',
    constants.CHAIN_KEY_LENGTH,
    sessionId
  );

  // Zeroize secrets
  prim.zeroize(dhSecret);
  prim.zeroize(kemSecret);
  prim.zeroize(combinedSecret);

  const now = Date.now();
  const state: HandshakeState = {
    role: 'responder',
    sessionId,
    rootKey,
    sendChainKey,
    recvChainKey,
    sendRatchetId: 0n,
    recvRatchetId: 0n,
    sendCounter: 0,
    recvCounter: 0,
    epochStartTime: now,
    sessionStartTime: now,
    totalMessages: 0,
  };

  return { message: responderMsg, state };
}

/**
 * Initiator: finalize handshake with responder's message
 */
export async function finalizeHandshake(
  ephemeralX25519Secret: Uint8Array,
  ephemeralMLKEMSecret: Uint8Array,
  initiatorMsg: HandshakeMessage,
  responderMsg: HandshakeMessage
): Promise<HandshakeState> {
  await prim.initCrypto();

  // Build full transcript
  const transcript = buildTranscript(initiatorMsg, responderMsg);
  const transcriptHash = prim.hashTranscript(transcript);

  // Verify responder signatures
  const ed25519Valid = prim.ed25519Verify(
    responderMsg.ed25519Signature,
    transcriptHash,
    responderMsg.identityPublicEd25519
  );

  const mldsaValid = prim.mldsaVerify(
    responderMsg.mldsaSignature,
    transcriptHash,
    responderMsg.identityPublicMLDSA
  );

  if (!ed25519Valid || !mldsaValid) {
    throw new Error('Responder signature verification failed');
  }

  // Perform X25519 DH
  const dhSecret = prim.x25519(ephemeralX25519Secret, responderMsg.ephemeralX25519);

  // Decapsulate ML-KEM
  const kemSecret = prim.mlkemDecapsulate(responderMsg.kemCiphertext!, ephemeralMLKEMSecret);

  // Combine secrets
  const combinedSecret = hybridCombine(dhSecret, kemSecret);

  // Derive session ID and root key (same as responder)
  const sessionId = prim.hkdfSHA384(
    combinedSecret,
    constants.LABEL_SESSION_ID,
    constants.SESSION_ID_LENGTH,
    constants.SUITE_ID
  );

  const rootKey = prim.hkdfSHA384(
    combinedSecret,
    constants.LABEL_ROOT_KEY,
    constants.ROOT_KEY_LENGTH,
    sessionId
  );

  // Derive initial chain keys (initiator receives responder's send, sends to responder's recv)
  const recvChainKey = prim.hkdfSHA384(
    rootKey,
    constants.LABEL_CHAIN_KEYS + '/send', // responder's send = initiator's recv
    constants.CHAIN_KEY_LENGTH,
    sessionId
  );

  const sendChainKey = prim.hkdfSHA384(
    rootKey,
    constants.LABEL_CHAIN_KEYS + '/recv', // responder's recv = initiator's send
    constants.CHAIN_KEY_LENGTH,
    sessionId
  );

  // Zeroize secrets
  prim.zeroize(dhSecret);
  prim.zeroize(kemSecret);
  prim.zeroize(combinedSecret);
  prim.zeroize(ephemeralX25519Secret);
  prim.zeroize(ephemeralMLKEMSecret);

  const now = Date.now();
  const state: HandshakeState = {
    role: 'initiator',
    sessionId,
    rootKey,
    sendChainKey,
    recvChainKey,
    sendRatchetId: 0n,
    recvRatchetId: 0n,
    sendCounter: 0,
    recvCounter: 0,
    epochStartTime: now,
    sessionStartTime: now,
    totalMessages: 0,
  };

  return state;
}
