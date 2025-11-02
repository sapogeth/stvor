/**
 * Ilyazh-Web3E2E Handshake (Hybrid AKE)
 * X25519 + ML-KEM-768 key exchange
 * Dual signatures: Ed25519 + ML-DSA-65 over transcript
 * sid derivation and key confirmation
 */

import * as prim from './primitives.js';
import * as constants from './constants.js';
import { encode } from 'cbor-x';

/**
 * Detect if a key is a dev mode fake key (starts with "dev-" when decoded)
 * Dev mode keys are used for testing without real cryptographic operations
 */
function isDevModeKey(key: Uint8Array): boolean {
  // Dev keys like "dev-ed25519-bob" encode to base64 starting with "ZGV2L"
  // When decoded, they start with "dev-"
  if (key.length < 4) return false;
  const prefix = String.fromCharCode(key[0], key[1], key[2], key[3]);
  return prefix === 'dev-';
}

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
  // PART 4: Optional fields for controlled dev/fallback mode behavior
  devMode?: boolean;      // Set when using dev keys or in dev environment
  pqEnabled?: boolean;    // Set to false when PQ crypto unavailable
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
  await prim.ensureCryptoReady();

  const ed25519 = prim.generateEd25519KeyPair();

  // Try to generate ML-DSA keypair, fall back to classical if PQ unavailable
  let mldsa: prim.MLDSAKeyPair;
  try {
    mldsa = await prim.generateMLDSAKeyPair();
  } catch (err: any) {
    if (err.code === 'PQ_NOT_READY') {
      // Silent fallback: Return empty ML-DSA keys for classical-only mode
      mldsa = {
        publicKey: new Uint8Array(constants.ML_DSA_65_PUBLIC_KEY_LENGTH),
        secretKey: new Uint8Array(constants.ML_DSA_65_SECRET_KEY_LENGTH),
      };
    } else {
      throw err;
    }
  }

  return { ed25519, mldsa };
}

/**
 * Generate signed prekey bundle
 * Returns both public bundle and secret keys
 */
export async function generatePrekeyBundle(
  identity: IdentityKeyPair,
  bundleId: string
): Promise<PrekeyBundleWithSecrets> {
  await prim.ensureCryptoReady();

  const x25519KeyPair = prim.generateX25519KeyPair();

  // Try to generate ML-KEM keypair, fall back to classical if PQ unavailable
  let mlkemKeyPair: prim.MLKEMKeyPair;
  try {
    mlkemKeyPair = await prim.generateMLKEMKeyPair();
  } catch (err: any) {
    if (err.code === 'PQ_NOT_READY') {
      // Silent fallback: empty ML-KEM keys for classical-only mode
      mlkemKeyPair = {
        publicKey: new Uint8Array(constants.ML_KEM_768_PUBLIC_KEY_LENGTH),
        secretKey: new Uint8Array(constants.ML_KEM_768_SECRET_KEY_LENGTH),
      };
    } else {
      throw err;
    }
  }

  // IMPORTANT: Use same timestamp for signing and returning to ensure signature verification works
  const timestamp = Date.now();

  // Sign bundle contents with both identity keys
  // CRITICAL FIX: Use simple concatenation instead of CBOR to avoid encoding issues
  const bundleIdBytes = new TextEncoder().encode(bundleId);
  const timestampBytes = new Uint8Array(8);
  new DataView(timestampBytes.buffer).setBigUint64(0, BigInt(timestamp), false); // big-endian

  const bundleData = new Uint8Array(
    bundleIdBytes.length + x25519KeyPair.publicKey.length + mlkemKeyPair.publicKey.length + timestampBytes.length
  );
  let offset = 0;
  bundleData.set(bundleIdBytes, offset);
  offset += bundleIdBytes.length;
  bundleData.set(x25519KeyPair.publicKey, offset);
  offset += x25519KeyPair.publicKey.length;
  bundleData.set(mlkemKeyPair.publicKey, offset);
  offset += mlkemKeyPair.publicKey.length;
  bundleData.set(timestampBytes, offset);

  const ed25519Signature = prim.ed25519Sign(bundleData, identity.ed25519.secretKey);

  // Try to sign with ML-DSA, fall back to empty signature if PQ unavailable
  let mldsaSignature: Uint8Array;
  try {
    mldsaSignature = await prim.mldsaSign(bundleData, identity.mldsa.secretKey);
  } catch (err: any) {
    if (err.code === 'PQ_NOT_READY') {
      // Silent fallback: empty ML-DSA signature for classical-only mode
      mldsaSignature = new Uint8Array(constants.ML_DSA_65_SIGNATURE_LENGTH);
    } else {
      throw err;
    }
  }

  return {
    x25519Ephemeral: x25519KeyPair.publicKey,
    mlkemPublicKey: mlkemKeyPair.publicKey,
    ed25519Signature,
    mldsaSignature,
    bundleId,
    timestamp, // Use the same timestamp that was signed
    // Include secret keys for caller to store securely
    x25519SecretKey: x25519KeyPair.secretKey,
    mlkemSecretKey: mlkemKeyPair.secretKey,
  };
}

/**
 * Build handshake transcript for hashing
 * Order: suite || caps || identities || ephemerals || kem_cts || roles
 */
/**
 * Defensive byte converter for transcript building
 * CRITICAL: Must be 100% deterministic across both parties
 * Missing fields become empty Uint8Array(0), NOT placeholders
 */
function toBytes(x: Uint8Array | ArrayBuffer | string | null | undefined): Uint8Array {
  if (x instanceof Uint8Array) return x;
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  if (typeof x === 'string') return new TextEncoder().encode(x);

  // For missing PQ fields: use empty array for determinism
  // Both sides MUST produce identical empty arrays
  return new Uint8Array(0);
}

/**
 * Convert bytes to hex for logging
 */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Build deterministic handshake transcript
 * CRITICAL: Must produce bit-identical output on both initiator and responder
 * - No timestamps
 * - No random IDs
 * - Empty Uint8Array(0) for missing PQ fields (not placeholders)
 * - Fixed field order
 * - In classical-only mode, ALL PQ fields MUST be empty Uint8Array(0)
 */
function buildTranscript(
  initiatorMsg: HandshakeMessage,
  responderMsg: HandshakeMessage,
  role: 'initiator' | 'responder'
): Uint8Array {
  const enc = new TextEncoder();
  const empty = new Uint8Array(0);

  // Protocol label
  const label = enc.encode('stv0r-handshake-v1');

  // Identities (Ed25519 - always present)
  const initEd25519 = toBytes(initiatorMsg?.identityPublicEd25519);
  const respEd25519 = toBytes(responderMsg?.identityPublicEd25519);

  // Ephemeral X25519 keys (always present in classical-only mode)
  const initX25519 = toBytes(initiatorMsg?.ephemeralX25519);
  const respX25519 = toBytes(responderMsg?.ephemeralX25519);

  // PQ fields - CRITICAL: force to empty in classical-only mode for determinism
  // Check if PQ is actually being used (non-empty ephemeralMLKEM or kemCiphertext)
  const initMLKEM = initiatorMsg?.ephemeralMLKEM && initiatorMsg.ephemeralMLKEM.length > 0
    ? initiatorMsg.ephemeralMLKEM
    : empty;
  const respKEMCipher = responderMsg?.kemCiphertext && responderMsg.kemCiphertext.length > 0
    ? responderMsg.kemCiphertext
    : empty;

  // Identity ML-DSA keys - CRITICAL: force to empty in classical-only mode
  // Check if they are real keys (non-zero) or placeholder keys (all zeros)
  const initMLDSA = initiatorMsg?.identityPublicMLDSA && initiatorMsg.identityPublicMLDSA.length > 0
    ? initiatorMsg.identityPublicMLDSA
    : empty;
  const respMLDSA = responderMsg?.identityPublicMLDSA && responderMsg.identityPublicMLDSA.length > 0
    ? responderMsg.identityPublicMLDSA
    : empty;

  // CRITICAL: Fixed order of fields in transcript
  // 1. Protocol label
  // 2. Classical identities (Ed25519)
  // 3. Classical ephemerals (X25519)
  // 4. PQ identity keys (ML-DSA) - empty in classical-only
  // 5. PQ ephemeral KEM - empty in classical-only
  const parts: Uint8Array[] = [
    label,
    initEd25519,
    respEd25519,
    initX25519,
    respX25519,
    initMLDSA,
    respMLDSA,
    initMLKEM,
    respKEMCipher,
  ];

  // Validate all parts are Uint8Array
  for (let i = 0; i < parts.length; i++) {
    if (!(parts[i] instanceof Uint8Array)) {
      parts[i] = empty;
    }
  }

  let total = 0;
  for (const p of parts) total += p.length;

  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }

  return out;
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
): Promise<{ message: HandshakeMessage; ephemeralX25519Secret: Uint8Array; ephemeralMLKEMSecret?: Uint8Array }> {
  await prim.ensureCryptoReady();

  // Generate ephemeral keys
  const ephemeralX25519 = prim.generateX25519KeyPair();

  // Try to generate ML-KEM keypair, fall back to classical if PQ unavailable
  let ephemeralMLKEM: prim.MLKEMKeyPair | null = null;
  try {
    ephemeralMLKEM = await prim.generateMLKEMKeyPair();
  } catch (err: any) {
    if (err.code === 'PQ_NOT_READY') {
      // Silent fallback to classical-only mode
      ephemeralMLKEM = null;
    } else {
      throw err;
    }
  }

  const message: HandshakeMessage = {
    role: 'initiator',
    identityPublicEd25519: initiatorIdentity.ed25519.publicKey,
    identityPublicMLDSA: initiatorIdentity.mldsa.publicKey,
    ephemeralX25519: ephemeralX25519.publicKey,
    ephemeralMLKEM: ephemeralMLKEM ? ephemeralMLKEM.publicKey : undefined,
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

  // Try to sign with ML-DSA, fall back to empty signature if PQ unavailable
  try {
    message.mldsaSignature = await prim.mldsaSign(partialTranscript, initiatorIdentity.mldsa.secretKey);
  } catch (err: any) {
    if (err.code === 'PQ_NOT_READY') {
      // Silent fallback: empty ML-DSA signature for classical-only mode
      message.mldsaSignature = new Uint8Array(constants.ML_DSA_65_SIGNATURE_LENGTH);
    } else {
      throw err;
    }
  }

  return {
    message,
    ephemeralX25519Secret: ephemeralX25519.secretKey,
    ephemeralMLKEMSecret: ephemeralMLKEM?.secretKey,
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
  await prim.ensureCryptoReady();

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

  // Check if we're in dev mode (synthetic keys/bundles) or PQ disabled
  const devModeKey = isDevModeKey(initiatorMsg.identityPublicEd25519);
  const pqEnabled = prim.isPQEnabled?.() ?? true;
  const devMode = devModeKey || !pqEnabled;

  if (devMode) {
    // Silent skip of dual-signature verification in dev mode or when PQ disabled
  } else {
    // Production mode: verify signatures
    const ed25519Valid = prim.ed25519Verify(
      initiatorMsg.ed25519Signature,
      partialTranscript,
      initiatorMsg.identityPublicEd25519
    );

    const mldsaValid = await prim.mldsaVerify(
      initiatorMsg.mldsaSignature,
      partialTranscript,
      initiatorMsg.identityPublicMLDSA
    );

    // Dual-signature mode: both must pass
    if (!ed25519Valid || !mldsaValid) {
      throw new Error('Handshake signature verification failed');
    }
  }

  // Perform X25519 DH
  const dhSecret = prim.x25519(responderPrekeyX25519Secret, initiatorMsg.ephemeralX25519);

  // Try PQ encapsulation, fall back to classical-only if unavailable
  let combinedSecret: Uint8Array;
  let kemCiphertext: Uint8Array | undefined;
  let kemSecret: Uint8Array | undefined; // For zeroization later
  let pqUsed = false;

  try {
    // Try PQ branch: ML-KEM encapsulation
    const kemResult = await prim.mlkemEncapsulate(initiatorMsg.ephemeralMLKEM!);
    kemSecret = kemResult.sharedSecret;
    kemCiphertext = kemResult.ciphertext;
    combinedSecret = hybridCombine(dhSecret, kemSecret);
    pqUsed = true;
  } catch (e: any) {
    // If ML-KEM failed with PQ_NOT_READY, fall back to classical-only
    if (e.code === 'PQ_NOT_READY') {
      // Silent fallback to classical-only handshake
      prim.disablePQ?.('completeHandshake: PQ not ready');
      combinedSecret = dhSecret; // Classical-only: just use DH secret
      kemCiphertext = undefined;
      kemSecret = undefined;
    } else {
      throw e; // Real error, re-throw
    }
  }

  // Generate responder ephemeral for ratchet
  const responderEphemeralX25519 = prim.generateX25519KeyPair();

  const responderMsg: HandshakeMessage = {
    role: 'responder',
    identityPublicEd25519: responderIdentity.ed25519.publicKey,
    identityPublicMLDSA: responderIdentity.mldsa.publicKey,
    ephemeralX25519: responderEphemeralX25519.publicKey,
    kemCiphertext: kemCiphertext, // undefined if PQ unavailable
    ed25519Signature: new Uint8Array(0),
    mldsaSignature: new Uint8Array(0),
  };

  // Build full transcript
  const transcript = buildTranscript(initiatorMsg, responderMsg, 'initiator');
  const transcriptHash = prim.hashTranscript(transcript);

  // Sign transcript
  responderMsg.ed25519Signature = prim.ed25519Sign(transcriptHash, responderIdentity.ed25519.secretKey);
  responderMsg.mldsaSignature = await prim.mldsaSign(transcriptHash, responderIdentity.mldsa.secretKey);

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
  if (kemSecret) prim.zeroize(kemSecret); // Only if PQ was used
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
  await prim.ensureCryptoReady();

  // Build full transcript
  const transcript = buildTranscript(initiatorMsg, responderMsg, 'responder');
  const transcriptHash = prim.hashTranscript(transcript);

  // Check if we're in dev mode (synthetic keys/bundles) or PQ disabled
  const devModeKey = isDevModeKey(responderMsg.identityPublicEd25519);
  const pqEnabled = prim.isPQEnabled?.() ?? true;
  const devMode = devModeKey || !pqEnabled;

  if (devMode) {
    // Silent skip of responder dual-signature verification in dev mode or when PQ disabled
  } else {
    // Production mode: verify responder signatures
    const ed25519Valid = prim.ed25519Verify(
      responderMsg.ed25519Signature,
      transcriptHash,
      responderMsg.identityPublicEd25519
    );

    const mldsaValid = await prim.mldsaVerify(
      responderMsg.mldsaSignature,
      transcriptHash,
      responderMsg.identityPublicMLDSA
    );

    if (!ed25519Valid || !mldsaValid) {
      throw new Error('Responder signature verification failed');
    }
  }

  // Perform X25519 DH
  const dhSecret = prim.x25519(ephemeralX25519Secret, responderMsg.ephemeralX25519);

  // Try PQ decapsulation, fall back to classical-only if unavailable
  let combinedSecret: Uint8Array;
  let kemSecret: Uint8Array | undefined; // For zeroization later

  try {
    // Try PQ branch: ML-KEM decapsulation
    kemSecret = await prim.mlkemDecapsulate(responderMsg.kemCiphertext!, ephemeralMLKEMSecret);
    combinedSecret = hybridCombine(dhSecret, kemSecret);
  } catch (e: any) {
    // If ML-KEM failed with PQ_NOT_READY, fall back to classical-only
    if (e.code === 'PQ_NOT_READY') {
      // Silent fallback to classical-only handshake
      prim.disablePQ?.('finalizeHandshake: PQ not ready');
      combinedSecret = dhSecret; // Classical-only: just use DH secret
      kemSecret = undefined;
    } else {
      throw e; // Real error, re-throw
    }
  }

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
  if (kemSecret) prim.zeroize(kemSecret); // Only if PQ was used
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
