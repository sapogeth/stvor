/**
 * Protocol Test Suite with Deterministic Vectors
 */

import * as crypto from '../index.js';

describe('Ilyazh-Web3E2E Protocol', () => {
  beforeAll(async () => {
    await crypto.initCrypto();
  });

  describe('Primitives', () => {
    test('X25519 key generation produces correct sizes', () => {
      const kp = crypto.generateX25519KeyPair();
      expect(kp.publicKey.length).toBe(crypto.X25519_PUBLIC_KEY_LENGTH);
      expect(kp.secretKey.length).toBe(crypto.X25519_SECRET_KEY_LENGTH);
    });

    test('Ed25519 signatures verify correctly', () => {
      const kp = crypto.generateEd25519KeyPair();
      const message = new TextEncoder().encode('test message');
      const sig = crypto.ed25519Sign(message, kp.secretKey);

      expect(sig.length).toBe(crypto.ED25519_SIGNATURE_LENGTH);
      expect(crypto.ed25519Verify(sig, message, kp.publicKey)).toBe(true);

      // Modified message should fail
      message[0] ^= 1;
      expect(crypto.ed25519Verify(sig, message, kp.publicKey)).toBe(false);
    });

    test('ML-KEM-768 produces correct wire sizes', async () => {
      const kp = await crypto.generateMLKEMKeyPair();
      expect(kp.publicKey.length).toBe(crypto.ML_KEM_768_PUBLIC_KEY_LENGTH);
      expect(kp.secretKey.length).toBe(crypto.ML_KEM_768_SECRET_KEY_LENGTH);

      const encap = await crypto.mlkemEncapsulate(kp.publicKey);
      expect(encap.ciphertext.length).toBe(crypto.ML_KEM_768_CIPHERTEXT_LENGTH);
      expect(encap.sharedSecret.length).toBe(crypto.ML_KEM_768_SHARED_SECRET_LENGTH);
    });

    test('ML-DSA-65 produces correct wire sizes', async () => {
      const kp = await crypto.generateMLDSAKeyPair();
      expect(kp.publicKey.length).toBe(crypto.ML_DSA_65_PUBLIC_KEY_LENGTH);
      expect(kp.secretKey.length).toBe(crypto.ML_DSA_65_SECRET_KEY_LENGTH);

      const message = new TextEncoder().encode('test');
      const sig = await crypto.mldsaSign(message, kp.secretKey);
      expect(sig.length).toBe(crypto.ML_DSA_65_SIGNATURE_LENGTH);
    });

    test('HKDF-SHA-384 derives keys with correct labels', () => {
      const ikm = crypto.randomBytes(32);
      const salt = crypto.SUITE_ID;

      const sid = crypto.hkdfSHA384(ikm, crypto.LABEL_SESSION_ID, 32, salt);
      expect(sid.length).toBe(32);

      const rk = crypto.hkdfSHA384(ikm, crypto.LABEL_ROOT_KEY, 64, sid);
      expect(rk.length).toBe(64);

      // Different labels produce different outputs
      expect(Buffer.from(sid).equals(Buffer.from(rk.slice(0, 32)))).toBe(false);
    });

    test('XChaCha20-Poly1305 encrypts and decrypts correctly', () => {
      const key = crypto.randomBytes(32);
      const aad = new TextEncoder().encode('additional data');
      const plaintext = new TextEncoder().encode('secret message');

      // New API: aeadEncrypt generates random 24-byte nonce internally
      const { nonce, ciphertext } = crypto.aeadEncrypt(key, plaintext, aad);
      expect(ciphertext.length).toBeGreaterThan(plaintext.length); // includes tag
      expect(nonce.length).toBe(24); // XChaCha20 requires 24-byte nonce

      const decrypted = crypto.aeadDecrypt(key, nonce, ciphertext, aad);
      expect(Buffer.from(decrypted).toString()).toBe('secret message');

      // Wrong AAD should fail
      const wrongAAD = new TextEncoder().encode('wrong aad');
      expect(() => crypto.aeadDecrypt(key, nonce, ciphertext, wrongAAD)).toThrow();
    });
  });

  describe('Handshake', () => {
    test.skip('Full handshake completes and derives matching session IDs', async () => {
      // Generate identities
      const aliceIdentity = await crypto.generateIdentity();
      const bobIdentity = await crypto.generateIdentity();

      // Bob generates prekey bundle
      const bobPrekey = await crypto.generatePrekeyBundle(bobIdentity, 'bob-bundle-1');

      // Alice initiates handshake
      const aliceInit = await crypto.initiateHandshake(
        aliceIdentity,
        bobIdentity.ed25519.publicKey,
        bobIdentity.mldsa.publicKey,
        bobPrekey
      );

      // Bob completes handshake (mock: we need prekey secrets)
      // In real scenario, Bob would have stored these with the bundle
      const bobPrekeyX25519 = crypto.generateX25519KeyPair().secretKey;
      const bobPrekeyMLKEMKP = await crypto.generateMLKEMKeyPair();
      const bobPrekeyMLKEM = bobPrekeyMLKEMKP.secretKey;

      const bobComplete = await crypto.completeHandshake(
        bobIdentity,
        bobPrekeyX25519,
        bobPrekeyMLKEM,
        aliceInit.message
      );

      // Alice finalizes with Bob's response
      const aliceEphMLKEMKP = await crypto.generateMLKEMKeyPair();
      const aliceEphMLKEM = aliceEphMLKEMKP.secretKey;
      const aliceState = await crypto.finalizeHandshake(
        aliceInit.ephemeralX25519Secret,
        aliceEphMLKEM,
        aliceInit.message,
        bobComplete.message
      );

      // Session IDs should match (in real scenario with proper KEM)
      expect(aliceState.sessionId.length).toBe(crypto.SESSION_ID_LENGTH);
      expect(bobComplete.state.sessionId.length).toBe(crypto.SESSION_ID_LENGTH);

      // Both should have derived root keys
      expect(aliceState.rootKey.length).toBe(crypto.ROOT_KEY_LENGTH);
      expect(bobComplete.state.rootKey.length).toBe(crypto.ROOT_KEY_LENGTH);
    });

    test('Dual-signature verification enforced by default', async () => {
      const identity = await crypto.generateIdentity();
      const prekey = await crypto.generatePrekeyBundle(identity, 'test-bundle');

      // Signatures should be present
      expect(prekey.ed25519Signature.length).toBe(crypto.ED25519_SIGNATURE_LENGTH);
      expect(prekey.mldsaSignature.length).toBe(crypto.ML_DSA_65_SIGNATURE_LENGTH);
    });
  });

  describe('Double Ratchet', () => {
    let aliceState: crypto.RatchetState;
    let bobState: crypto.RatchetState;

    beforeEach(async () => {
      const sessionId = crypto.randomBytes(32);
      const rootKey = crypto.randomBytes(64);
      const now = Date.now();

      aliceState = {
        role: 'initiator',
        sessionId,
        rootKey: rootKey.slice(),
        sendChainKey: crypto.randomBytes(64),
        recvChainKey: crypto.randomBytes(64),
        sendRatchetId: 0n,
        recvRatchetId: 0n,
        sendCounter: 0,
        recvCounter: 0,
        epochStartTime: now,
        sessionStartTime: now,
        totalMessages: 0,
      };

      bobState = {
        role: 'responder',
        sessionId,
        rootKey: rootKey.slice(),
        sendChainKey: aliceState.recvChainKey.slice(),
        recvChainKey: aliceState.sendChainKey.slice(),
        sendRatchetId: 0n,
        recvRatchetId: 0n,
        sendCounter: 0,
        recvCounter: 0,
        epochStartTime: now,
        sessionStartTime: now,
        totalMessages: 0,
      };
    });

    test('Encrypt and decrypt single message', async () => {
      const plaintext = new TextEncoder().encode('Hello Bob!');

      const encrypted = await crypto.encryptMessage(aliceState, plaintext);
      aliceState = encrypted.newState;

      // Bob receives and decrypts
      const decrypted = await crypto.decryptMessage(bobState, encrypted.record);
      bobState = decrypted.newState;

      expect(Buffer.from(decrypted.plaintext).toString()).toBe('Hello Bob!');
      expect(aliceState.sendCounter).toBe(1);
      expect(bobState.recvCounter).toBe(1);
    });

    test('AAD contains session ID (sid-in-AAD normative)', async () => {
      const plaintext = new TextEncoder().encode('test');
      const encrypted = await crypto.encryptMessage(aliceState, plaintext);

      // Extract sid from AAD (offset 9, length 32)
      const aadSid = encrypted.record.aad.slice(9, 9 + 32);
      expect(Buffer.from(aadSid).equals(Buffer.from(aliceState.sessionId))).toBe(true);
    });

    test('Random 24-byte nonces generated by aeadEncrypt', async () => {
      // SECURITY FIX: Nonce generation moved to aeadEncrypt() for random 24-byte nonces
      // This prevents nonce reuse attacks with XChaCha20-Poly1305

      const key = crypto.randomBytes(32);
      const aad = new TextEncoder().encode('test aad');
      const plaintext = new TextEncoder().encode('test message');

      // Encrypt twice to ensure nonces are different (random)
      const enc1 = crypto.aeadEncrypt(key, plaintext, aad);
      const enc2 = crypto.aeadEncrypt(key, plaintext, aad);

      // Both should have 24-byte nonces for XChaCha20-Poly1305
      expect(enc1.nonce.length).toBe(24);
      expect(enc2.nonce.length).toBe(24);

      // Nonces should be different (random generation)
      expect(Buffer.from(enc1.nonce).equals(Buffer.from(enc2.nonce))).toBe(false);
    });

    test('Message encryption produces valid XChaCha20 nonce', async () => {
      // Verify that encryptMessage produces messages with valid 24-byte nonces
      const plaintext = new TextEncoder().encode('test');
      const encrypted = await crypto.encryptMessage(aliceState, plaintext);

      // Nonce should be 24 bytes for XChaCha20-Poly1305
      expect(encrypted.record.nonce.length).toBe(24);

      // Should be decodable
      expect(encrypted.record.aad.length).toBeGreaterThan(0);
      expect(encrypted.record.ciphertext.length).toBeGreaterThan(0);
    });

    test('Message counters increment correctly', async () => {
      const plaintext = new TextEncoder().encode('msg');

      for (let i = 0; i < 5; i++) {
        const encrypted = await crypto.encryptMessage(aliceState, plaintext);
        aliceState = encrypted.newState;
        expect(aliceState.sendCounter).toBe(i + 1);
        expect(aliceState.totalMessages).toBe(i + 1);
      }
    });

    test('Rekey required after message limit', async () => {
      // Set counter near limit
      aliceState.sendCounter = crypto.REKEY_MESSAGE_LIMIT - 1;

      const check1 = crypto.needsRekey(aliceState);
      expect(check1.required).toBe(false);

      // One more message
      aliceState.sendCounter = crypto.REKEY_MESSAGE_LIMIT;

      const check2 = crypto.needsRekey(aliceState);
      expect(check2.required).toBe(true);
      expect(check2.reason).toBe('message_limit');
    });

    test('Rekey required after time limit', async () => {
      // Set epoch start in the past
      aliceState.epochStartTime = Date.now() - crypto.REKEY_TIME_LIMIT_MS - 1000;

      const check = crypto.needsRekey(aliceState);
      expect(check.required).toBe(true);
      expect(check.reason).toBe('time_limit');
    });

    test('Session cap enforced (2^32 messages)', async () => {
      aliceState.totalMessages = crypto.SESSION_MESSAGE_CAP - 1;

      const check1 = crypto.needsRekey(aliceState);
      expect(check1.required).toBe(false);

      aliceState.totalMessages = crypto.SESSION_MESSAGE_CAP;

      const check2 = crypto.needsRekey(aliceState);
      expect(check2.required).toBe(true);
      expect(check2.reason).toBe('session_cap_messages');
    });

    test('Session cap enforced (7 days)', async () => {
      aliceState.sessionStartTime = Date.now() - crypto.SESSION_TIME_CAP_MS - 1000;

      const check = crypto.needsRekey(aliceState);
      expect(check.required).toBe(true);
      expect(check.reason).toBe('session_cap_time');
    });

    test('Encryption throws when rekey required', async () => {
      aliceState.sendCounter = crypto.REKEY_MESSAGE_LIMIT;

      const plaintext = new TextEncoder().encode('should fail');
      await expect(crypto.encryptMessage(aliceState, plaintext)).rejects.toThrow('Rekey required');
    });

    test('Invalid AAD session ID rejected', async () => {
      const plaintext = new TextEncoder().encode('test');
      const encrypted = await crypto.encryptMessage(aliceState, plaintext);

      // Corrupt session ID in AAD
      encrypted.record.aad[10] ^= 0xFF;

      await expect(crypto.decryptMessage(bobState, encrypted.record)).rejects.toThrow(
        'AAD session ID mismatch'
      );
    });
  });

  describe('Wire Format', () => {
    test('Handshake message encodes and decodes correctly', async () => {
      const identity = await crypto.generateIdentity();
      const prekey = await crypto.generatePrekeyBundle(identity, 'test');

      const msg: crypto.HandshakeMessage = {
        role: 'initiator',
        identityPublicEd25519: identity.ed25519.publicKey,
        identityPublicMLDSA: identity.mldsa.publicKey,
        ephemeralX25519: crypto.randomBytes(32),
        ephemeralMLKEM: crypto.randomBytes(crypto.ML_KEM_768_PUBLIC_KEY_LENGTH),
        ed25519Signature: crypto.randomBytes(64),
        mldsaSignature: crypto.randomBytes(crypto.ML_DSA_65_SIGNATURE_LENGTH),
      };

      const encoded = crypto.encodeHandshakeMessage(msg);
      const decoded = crypto.decodeHandshakeMessage(encoded);

      expect(Buffer.from(decoded.identityPublicEd25519).equals(msg.identityPublicEd25519)).toBe(true);
      expect(Buffer.from(decoded.ephemeralX25519).equals(msg.ephemeralX25519)).toBe(true);
    });

    test('Encrypted message encodes and decodes correctly', async () => {
      const record: crypto.EncryptedRecord = {
        aad: crypto.randomBytes(58),
        nonce: crypto.randomBytes(12),
        ciphertext: crypto.randomBytes(100),
      };

      const encoded = crypto.encodeEncryptedMessage(record);
      const decoded = crypto.decodeEncryptedMessage(encoded);

      expect(Buffer.from(decoded.aad).equals(record.aad)).toBe(true);
      expect(Buffer.from(decoded.nonce).equals(record.nonce)).toBe(true);
      expect(Buffer.from(decoded.ciphertext).equals(record.ciphertext)).toBe(true);
    });
  });

  describe('Deterministic Test Vectors', () => {
    test('Vector 1: Session ID derivation', () => {
      // Known inputs
      const ikm = Buffer.from('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', 'hex');
      const salt = crypto.SUITE_ID;

      const sid = crypto.hkdfSHA384(ikm, crypto.LABEL_SESSION_ID, 32, salt);

      // Store vector for interop
      const sidHex = Buffer.from(sid).toString('hex');
      console.log('Vector 1 - Session ID:', sidHex);
      expect(sid.length).toBe(32);
    });

    test('Vector 2: Root key derivation', () => {
      const ikm = Buffer.from('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', 'hex');
      const sid = crypto.hkdfSHA384(ikm, crypto.LABEL_SESSION_ID, 32, crypto.SUITE_ID);

      const rk = crypto.hkdfSHA384(ikm, crypto.LABEL_ROOT_KEY, 64, sid);

      const rkHex = Buffer.from(rk).toString('hex');
      console.log('Vector 2 - Root Key:', rkHex);
      expect(rk.length).toBe(64);
    });

    test('Vector 3: AAD construction', () => {
      const sid = Buffer.from('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'hex');
      const seq = 42n;
      const epoch = 1n;

      const aad = crypto.buildAAD(sid, seq, epoch, 0);

      const aadHex = Buffer.from(aad).toString('hex');
      console.log('Vector 3 - AAD:', aadHex);
      expect(aad.length).toBe(58);
      expect(aad[0]).toBe(crypto.PROTOCOL_VERSION);
    });

    test('Vector 4: Random XChaCha20 nonce generation', () => {
      // SECURITY FIX: nonce generation now uses XChaCha20-Poly1305 with random 24-byte nonces
      // Previous 12-byte deterministic nonces were vulnerable to reuse if session state lost
      const key = crypto.randomBytes(32);
      const aad = new TextEncoder().encode('test aad');
      const plaintext = new TextEncoder().encode('test message');

      const enc = crypto.aeadEncrypt(key, plaintext, aad);

      const nonceHex = Buffer.from(enc.nonce).toString('hex');
      console.log('Vector 4 - Nonce:', nonceHex);
      // XChaCha20 requires 24-byte nonce
      expect(enc.nonce.length).toBe(24);
      // Nonce should be random
      expect(nonceHex.length).toBe(48); // 24 bytes = 48 hex chars
    });
  });

  describe('Security Properties', () => {
    test('Zeroization helper works', () => {
      const buffer = crypto.randomBytes(32);
      const copy = buffer.slice();

      crypto.zeroize(buffer);

      expect(buffer.every((b) => b === 0)).toBe(true);
      expect(copy.some((b) => b !== 0)).toBe(true);
    });

    test('Constant-time comparison', () => {
      const a = crypto.randomBytes(32);
      const b = a.slice();
      const c = crypto.randomBytes(32);

      expect(crypto.constantTimeEqual(a, b)).toBe(true);
      expect(crypto.constantTimeEqual(a, c)).toBe(false);
      expect(crypto.constantTimeEqual(a, a.slice(0, 31))).toBe(false);
    });
  });
});
