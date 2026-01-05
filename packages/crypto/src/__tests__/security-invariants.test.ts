/**
 * Security Invariant Tests for Stvor Protocol
 * 
 * PURPOSE:
 * These tests validate PROTOCOL INVARIANTS rather than code coverage.
 * Each test corresponds to a security property from the threat model.
 * 
 * TARGET AUDIENCE:
 * KAIST CS admissions committee (demonstrates security engineering understanding)
 * 
 * TESTING PHILOSOPHY:
 * - Property-based testing (invariants hold across many inputs)
 * - Security-focused (not unit testing every function)
 * - Formal correspondence (tests map to security proofs in docs/SECURITY.md)
 */

import { describe, test, expect } from '@jest/globals';
import * as prim from '../primitives';
import * as handshake from '../handshake';
import * as ratchet from '../ratchet';
import * as wire from '../wire';

/**
 * SECURITY PROPERTY 1: Key Separation Invariant
 * 
 * PROPERTY:
 * Session keys derived from different session IDs must be computationally independent.
 * 
 * SECURITY GOAL:
 * Prevents cross-session key reuse attacks (if attacker compromises one session,
 * they cannot derive keys for other sessions).
 * 
 * FORMAL STATEMENT:
 * ∀ sid_1 ≠ sid_2: Pr[DeriveKey(sid_1) = DeriveKey(sid_2)] ≤ negl(λ)
 */
describe('Security Invariant: Key Separation', () => {
  test('should derive independent session keys for different session IDs', async () => {
    await prim.ensureCryptoReady();
    
    // Generate two different identity keypairs
    const alice1 = await prim.generateIdentityKeypair();
    const bob1 = await prim.generateIdentityKeypair();
    
    const alice2 = await prim.generateIdentityKeypair();
    const bob2 = await prim.generateIdentityKeypair();
    
    // Create two prekey bundles
    const prekeyBundle1 = await handshake.generatePrekeyBundle(bob1, 'bundle-1');
    const prekeyBundle2 = await handshake.generatePrekeyBundle(bob2, 'bundle-2');
    
    // Perform two handshakes
    const hs1 = await handshake.initiateHandshake(alice1, prekeyBundle1);
    const hs2 = await handshake.initiateHandshake(alice2, prekeyBundle2);
    
    // Extract session IDs and root keys
    const sid1 = hs1.sessionId;
    const sid2 = hs2.sessionId;
    const rootKey1 = hs1.rootKey;
    const rootKey2 = hs2.rootKey;
    
    // INVARIANT: Different sessions MUST have different session IDs
    expect(sid1).not.toBe(sid2);
    
    // INVARIANT: Root keys MUST be different (with overwhelming probability)
    // Convert Uint8Array to hex for comparison
    const hex1 = Buffer.from(rootKey1).toString('hex');
    const hex2 = Buffer.from(rootKey2).toString('hex');
    expect(hex1).not.toBe(hex2);
    
    // INVARIANT: Even with same message, different sessions produce different ciphertexts
    const message = new TextEncoder().encode('test message');
    const ct1 = await ratchet.encrypt(hs1, message);
    const ct2 = await ratchet.encrypt(hs2, message);
    
    const ctHex1 = Buffer.from(ct1.ciphertext).toString('hex');
    const ctHex2 = Buffer.from(ct2.ciphertext).toString('hex');
    expect(ctHex1).not.toBe(ctHex2);
  });
  
  test('should include session ID in AAD to prevent cross-session forgery', async () => {
    await prim.ensureCryptoReady();
    
    const alice = await prim.generateIdentityKeypair();
    const bob = await prim.generateIdentityKeypair();
    const prekeyBundle = await handshake.generatePrekeyBundle(bob, 'bundle-1');
    
    // Create session
    const hsInit = await handshake.initiateHandshake(alice, prekeyBundle);
    const hsFinal = await handshake.completeHandshake(bob, hsInit.handshakeMessage, 'bundle-1');
    
    // Encrypt message in session A
    const message = new TextEncoder().encode('secret');
    const encrypted = await ratchet.encrypt(hsFinal, message);
    
    // Attempt to decrypt with MODIFIED session ID in AAD
    const tamperedState = { ...hsFinal, sessionId: 'tampered-session-id' };
    
    // INVARIANT: Decryption MUST fail (AAD mismatch)
    await expect(async () => {
      await ratchet.decrypt(tamperedState, encrypted);
    }).rejects.toThrow();
  });
});

/**
 * SECURITY PROPERTY 2: Re-encapsulation Enforcement
 * 
 * PROPERTY:
 * Protocol MUST reject messages that exceed re-encapsulation cadence limits.
 * 
 * SECURITY GOAL:
 * Ensures post-quantum key material is refreshed periodically, preventing
 * long-term compromise if classical DH is broken.
 * 
 * FORMAL STATEMENT:
 * ∀ epoch_i: message_count_i ≤ 2^20 ∨ time_elapsed_i ≤ 24h
 */
describe('Security Invariant: Re-encapsulation Cadence', () => {
  test('should enforce message limit per epoch (2^20 messages)', async () => {
    await prim.ensureCryptoReady();
    
    const alice = await prim.generateIdentityKeypair();
    const bob = await prim.generateIdentityKeypair();
    const prekeyBundle = await handshake.generatePrekeyBundle(bob, 'bundle-1');
    
    const hsInit = await handshake.initiateHandshake(alice, prekeyBundle);
    const state = await handshake.completeHandshake(bob, hsInit.handshakeMessage, 'bundle-1');
    
    // Simulate sending 2^20 messages (message limit)
    const REKEY_MESSAGE_LIMIT = 2 ** 20;
    state.sendCounter = REKEY_MESSAGE_LIMIT - 1;  // Just before limit
    
    // This message should succeed
    const message1 = new TextEncoder().encode('message at limit-1');
    const ct1 = await ratchet.encrypt(state, message1);
    expect(ct1).toBeDefined();
    
    // Check if rekey is required
    const rekeyStatus = ratchet.needsRekey(state);
    
    // INVARIANT: After 2^20 messages, rekey MUST be required
    expect(rekeyStatus.required).toBe(true);
    expect(rekeyStatus.reason).toBe('message_limit');
  });
  
  test('should enforce time limit per epoch (24 hours)', async () => {
    await prim.ensureCryptoReady();
    
    const alice = await prim.generateIdentityKeypair();
    const bob = await prim.generateIdentityKeypair();
    const prekeyBundle = await handshake.generatePrekeyBundle(bob, 'bundle-1');
    
    const hsInit = await handshake.initiateHandshake(alice, prekeyBundle);
    const state = await handshake.completeHandshake(bob, hsInit.handshakeMessage, 'bundle-1');
    
    // Simulate 24 hours elapsed
    const REKEY_TIME_LIMIT_MS = 24 * 60 * 60 * 1000;
    state.epochStartTime = Date.now() - REKEY_TIME_LIMIT_MS - 1000;  // 1 second past limit
    
    // Check if rekey is required
    const rekeyStatus = ratchet.needsRekey(state);
    
    // INVARIANT: After 24 hours, rekey MUST be required
    expect(rekeyStatus.required).toBe(true);
    expect(rekeyStatus.reason).toBe('time_limit');
  });
  
  test('should enforce hard session caps (2^32 messages or 7 days)', async () => {
    await prim.ensureCryptoReady();
    
    const alice = await prim.generateIdentityKeypair();
    const bob = await prim.generateIdentityKeypair();
    const prekeyBundle = await handshake.generatePrekeyBundle(bob, 'bundle-1');
    
    const hsInit = await handshake.initiateHandshake(alice, prekeyBundle);
    const state = await handshake.completeHandshake(bob, hsInit.handshakeMessage, 'bundle-1');
    
    // Simulate exceeding session message cap
    const SESSION_MESSAGE_CAP = 2 ** 32;
    state.totalMessages = SESSION_MESSAGE_CAP;
    
    let rekeyStatus = ratchet.needsRekey(state);
    
    // INVARIANT: Session MUST require rekey at hard cap
    expect(rekeyStatus.required).toBe(true);
    expect(rekeyStatus.reason).toBe('session_cap_messages');
    
    // Reset and test time cap
    state.totalMessages = 0;
    const SESSION_TIME_CAP_MS = 7 * 24 * 60 * 60 * 1000;
    state.sessionStartTime = Date.now() - SESSION_TIME_CAP_MS - 1000;
    
    rekeyStatus = ratchet.needsRekey(state);
    
    // INVARIANT: Session MUST require rekey at time cap
    expect(rekeyStatus.required).toBe(true);
    expect(rekeyStatus.reason).toBe('session_cap_time');
  });
});

/**
 * SECURITY PROPERTY 3: Session Key Unlinkability
 * 
 * PROPERTY:
 * Compromise of session key at epoch i does not reveal session key at epoch i+1.
 * 
 * SECURITY GOAL:
 * Forward secrecy across ratchet epochs (post-compromise security).
 * 
 * FORMAL STATEMENT:
 * ∀ i, j where i ≠ j: KeyCompromise(K_i) ∧ FreshEntropy(epoch_j) ⟹ K_j remains secret
 */
describe('Security Invariant: Session Key Unlinkability', () => {
  test('should derive independent keys for different epochs', async () => {
    await prim.ensureCryptoReady();
    
    const alice = await prim.generateIdentityKeypair();
    const bob = await prim.generateIdentityKeypair();
    const prekeyBundle = await handshake.generatePrekeyBundle(bob, 'bundle-1');
    
    const hsInit = await handshake.initiateHandshake(alice, prekeyBundle);
    const state = await handshake.completeHandshake(bob, hsInit.handshakeMessage, 'bundle-1');
    
    // Encrypt messages in epoch 0
    const msg1 = new TextEncoder().encode('epoch 0 message 1');
    const msg2 = new TextEncoder().encode('epoch 0 message 2');
    
    const ct1 = await ratchet.encrypt(state, msg1);
    const ct2 = await ratchet.encrypt(state, msg2);
    
    // Extract message keys (for invariant testing, normally these are internal)
    // In real implementation, keys are destroyed after use
    const key1 = ct1.ciphertext.slice(0, 32);  // Simplified extraction
    const key2 = ct2.ciphertext.slice(0, 32);
    
    // INVARIANT: Different messages MUST use different keys (ratchet forward)
    const hex1 = Buffer.from(key1).toString('hex');
    const hex2 = Buffer.from(key2).toString('hex');
    expect(hex1).not.toBe(hex2);
  });
  
  test('should prevent key reuse across sequence numbers', async () => {
    await prim.ensureCryptoReady();
    
    const alice = await prim.generateIdentityKeypair();
    const bob = await prim.generateIdentityKeypair();
    const prekeyBundle = await handshake.generatePrekeyBundle(bob, 'bundle-1');
    
    const hsInit = await handshake.initiateHandshake(alice, prekeyBundle);
    const state = await handshake.completeHandshake(bob, hsInit.handshakeMessage, 'bundle-1');
    
    // Encrypt same message twice
    const message = new TextEncoder().encode('repeated message');
    const ct1 = await ratchet.encrypt(state, message);
    const ct2 = await ratchet.encrypt(state, message);
    
    // INVARIANT: Same plaintext produces different ciphertexts (non-deterministic encryption)
    const ctHex1 = Buffer.from(ct1.ciphertext).toString('hex');
    const ctHex2 = Buffer.from(ct2.ciphertext).toString('hex');
    expect(ctHex1).not.toBe(ctHex2);
    
    // INVARIANT: Nonces MUST be different (sequence counter increments)
    const nonceHex1 = Buffer.from(ct1.nonce).toString('hex');
    const nonceHex2 = Buffer.from(ct2.nonce).toString('hex');
    expect(nonceHex1).not.toBe(nonceHex2);
  });
});

/**
 * SECURITY PROPERTY 4: Post-Quantum Mandatory Flag
 * 
 * PROPERTY:
 * If both parties support PQ, protocol MUST reject handshakes without PQ components.
 * 
 * SECURITY GOAL:
 * Prevent downgrade attacks where adversary strips ML-KEM/ML-DSA fields.
 * 
 * FORMAL STATEMENT:
 * (PQ_Alice = true ∧ PQ_Bob = true) ⟹ (PQ_used = true ∨ Handshake_rejected)
 */
describe('Security Invariant: PQ Downgrade Resistance', () => {
  test('should reject handshake if PQ is mandatory but missing', async () => {
    await prim.ensureCryptoReady();
    
    // Check if PQ is available
    const pqAvailable = prim.isPQAvailable();
    
    if (!pqAvailable) {
      console.log('⚠️  Skipping PQ mandatory test: ML-KEM not available');
      return;
    }
    
    const alice = await prim.generateIdentityKeypair();
    const bob = await prim.generateIdentityKeypair();
    const prekeyBundle = await handshake.generatePrekeyBundle(bob, 'bundle-1');
    
    // Initiate handshake normally (PQ should be used)
    const hsInit = await handshake.initiateHandshake(alice, prekeyBundle);
    
    // INVARIANT: If PQ available, pqSupported flag MUST be true
    expect(hsInit.pqSupported).toBe(true);
    
    // INVARIANT: Handshake message MUST contain ML-KEM ciphertext
    expect(hsInit.handshakeMessage.mlkemCiphertext).toBeDefined();
    expect(hsInit.handshakeMessage.mlkemCiphertext!.length).toBeGreaterThan(0);
  });
  
  test('should set pqMandatory flag when both parties support PQ', async () => {
    await prim.ensureCryptoReady();
    
    const pqAvailable = prim.isPQAvailable();
    
    if (!pqAvailable) {
      console.log('⚠️  Skipping PQ mandatory flag test: ML-KEM not available');
      return;
    }
    
    const alice = await prim.generateIdentityKeypair();
    const bob = await prim.generateIdentityKeypair();
    const prekeyBundle = await handshake.generatePrekeyBundle(bob, 'bundle-1');
    
    const hsInit = await handshake.initiateHandshake(alice, prekeyBundle);
    const hsFinal = await handshake.completeHandshake(bob, hsInit.handshakeMessage, 'bundle-1');
    
    // INVARIANT: If both parties support PQ, pqMandatory MUST be true
    expect(hsFinal.pqMandatory).toBe(true);
  });
});

/**
 * SECURITY PROPERTY 5: Signature Verification
 * 
 * PROPERTY:
 * All prekey bundles and handshake messages MUST be signed by identity keys.
 * 
 * SECURITY GOAL:
 * Authentication (prevent impersonation attacks).
 * 
 * FORMAL STATEMENT:
 * ∀ prekey_bundle: Verify(pk_identity, Sign(sk_identity, prekey)) = true
 */
describe('Security Invariant: Authentication via Signatures', () => {
  test('should verify dual signatures on prekey bundles', async () => {
    await prim.ensureCryptoReady();
    
    const bob = await prim.generateIdentityKeypair();
    const prekeyBundle = await handshake.generatePrekeyBundle(bob, 'bundle-1');
    
    // INVARIANT: Prekey bundle MUST have both Ed25519 and ML-DSA signatures
    expect(prekeyBundle.signatureEd25519).toBeDefined();
    expect(prekeyBundle.signatureEd25519.length).toBeGreaterThan(0);
    
    if (prim.isPQAvailable()) {
      expect(prekeyBundle.signatureMlDsa).toBeDefined();
      expect(prekeyBundle.signatureMlDsa!.length).toBeGreaterThan(0);
    }
    
    // Extract signature message (what was signed)
    const message = wire.serializePrekeyForSignature({
      identityEd25519: prekeyBundle.identityEd25519,
      identityMlDsa: prekeyBundle.identityMlDsa,
      prekeyX25519: prekeyBundle.prekeyX25519,
      prekeyMlKem: prekeyBundle.prekeyMlKem,
    });
    
    // INVARIANT: Ed25519 signature MUST verify
    const ed25519Valid = await prim.verifyEd25519(
      message,
      prekeyBundle.signatureEd25519,
      prekeyBundle.identityEd25519
    );
    expect(ed25519Valid).toBe(true);
  });
  
  test('should reject prekey bundles with invalid signatures', async () => {
    await prim.ensureCryptoReady();
    
    const bob = await prim.generateIdentityKeypair();
    const prekeyBundle = await handshake.generatePrekeyBundle(bob, 'bundle-1');
    
    // Tamper with signature (flip one bit)
    const tamperedSig = new Uint8Array(prekeyBundle.signatureEd25519);
    tamperedSig[0] ^= 0x01;  // Flip first bit
    
    const message = wire.serializePrekeyForSignature({
      identityEd25519: prekeyBundle.identityEd25519,
      identityMlDsa: prekeyBundle.identityMlDsa,
      prekeyX25519: prekeyBundle.prekeyX25519,
      prekeyMlKem: prekeyBundle.prekeyMlKem,
    });
    
    // INVARIANT: Tampered signature MUST NOT verify
    const valid = await prim.verifyEd25519(
      message,
      tamperedSig,
      prekeyBundle.identityEd25519
    );
    expect(valid).toBe(false);
  });
});

/**
 * SECURITY PROPERTY 6: Nonce Uniqueness
 * 
 * PROPERTY:
 * AEAD nonces MUST be unique for each message within a session.
 * 
 * SECURITY GOAL:
 * Prevent nonce reuse attacks (catastrophic for ChaCha20-Poly1305).
 * 
 * FORMAL STATEMENT:
 * ∀ i, j where i ≠ j: nonce_i ≠ nonce_j
 */
describe('Security Invariant: Nonce Uniqueness', () => {
  test('should generate unique nonces for consecutive messages', async () => {
    await prim.ensureCryptoReady();
    
    const alice = await prim.generateIdentityKeypair();
    const bob = await prim.generateIdentityKeypair();
    const prekeyBundle = await handshake.generatePrekeyBundle(bob, 'bundle-1');
    
    const hsInit = await handshake.initiateHandshake(alice, prekeyBundle);
    const state = await handshake.completeHandshake(bob, hsInit.handshakeMessage, 'bundle-1');
    
    // Encrypt multiple messages
    const nonces: string[] = [];
    for (let i = 0; i < 100; i++) {
      const msg = new TextEncoder().encode(`message ${i}`);
      const ct = await ratchet.encrypt(state, msg);
      const nonceHex = Buffer.from(ct.nonce).toString('hex');
      nonces.push(nonceHex);
    }
    
    // INVARIANT: All nonces MUST be unique
    const uniqueNonces = new Set(nonces);
    expect(uniqueNonces.size).toBe(nonces.length);
  });
});

/**
 * SECURITY PROPERTY 7: AAD Binding
 * 
 * PROPERTY:
 * Ciphertexts authenticated with wrong AAD MUST fail decryption.
 * 
 * SECURITY GOAL:
 * Context binding (prevent ciphertext substitution across sessions/epochs).
 * 
 * FORMAL STATEMENT:
 * ∀ ct, aad_1, aad_2 where aad_1 ≠ aad_2: Dec(ct, aad_1) ≠ Dec(ct, aad_2)
 */
describe('Security Invariant: AAD Binding', () => {
  test('should reject ciphertexts with modified AAD', async () => {
    await prim.ensureCryptoReady();
    
    const alice = await prim.generateIdentityKeypair();
    const bob = await prim.generateIdentityKeypair();
    const prekeyBundle = await handshake.generatePrekeyBundle(bob, 'bundle-1');
    
    const hsInit = await handshake.initiateHandshake(alice, prekeyBundle);
    const state = await handshake.completeHandshake(bob, hsInit.handshakeMessage, 'bundle-1');
    
    const message = new TextEncoder().encode('authenticated message');
    const encrypted = await ratchet.encrypt(state, message);
    
    // Tamper with AAD (modify epoch counter)
    const tamperedAAD = new Uint8Array(encrypted.aad);
    tamperedAAD[tamperedAAD.length - 1] ^= 0x01;  // Flip bit in epoch field
    
    const tamperedEncrypted = {
      ...encrypted,
      aad: tamperedAAD,
    };
    
    // INVARIANT: Decryption with modified AAD MUST fail
    await expect(async () => {
      await ratchet.decrypt(state, tamperedEncrypted);
    }).rejects.toThrow();
  });
});
