# STVOR Security Documentation

**Version**: 1.0  
**Last Updated**: 2026-01-14  
**Classification**: PUBLIC

---

## 1. EXECUTIVE SUMMARY

STVOR is an end-to-end encrypted messenger implementing hybrid post-quantum cryptography. This document provides a comprehensive threat model, security guarantees, and explicitly documented limitations.

**Security Posture**: Production-capable with documented residual risks (see [ARCHITECTURAL_ASSUMPTIONS.md](ARCHITECTURAL_ASSUMPTIONS.md))  
**Cryptographic Strength**: Post-quantum secure (ML-KEM-768, ML-DSA-65)  
**Verified By**: Internal security audit (2026-01-14)

---

## 2. THREAT MODEL

### 2.1 Adversary Capabilities

**IN SCOPE (Protected Against):**
- **Network Adversary**: Eavesdropping, MITM attacks on network traffic
- **Malicious Relay**: Impersonation, message injection, replay attacks
- **Quantum Computer**: Harvest-now-decrypt-later attacks (Shor's algorithm)
- **XSS Attacks**: JavaScript-based token theft (httpOnly cookies)
- **Replay Attacks**: Message duplication, out-of-order delivery
- **Unauthorized Access**: Non-participants reading chat messages

**OUT OF SCOPE (NOT Protected Against):**
- **Compromised Client Device**: Malware, keyloggers, screen capture
- **Physical Device Access**: Unencrypted IndexedDB extraction
- **Metadata Leakage**: Who talks to whom, when, message sizes
- **Relay DoS**: Resource exhaustion, distributed denial of service
- **Side-Channel Attacks**: Timing, cache, power analysis
- **Traffic Analysis**: Correlation attacks, network fingerprinting

### 2.2 Trust Model

**TRUSTED:**
- Client code (served via HTTPS)
- Cryptographic primitives (libsodium, liboqs)
- User's device security (no malware)

**NOT TRUSTED:**
- Relay server (untrusted infrastructure)
- Network infrastructure (ISP, CDN)
- Third-party dependencies (after verification)

**PARTIALLY TRUSTED:**
- Browser security (XSS mitigation via CSP)
- Next.js server (session management only)

---

## 3. CRYPTOGRAPHIC GUARANTEES

### 3.1 Core Primitives

| Primitive | Algorithm | Purpose | Post-Quantum |
|-----------|-----------|---------|--------------|
| **Key Exchange** | X25519 + ML-KEM-768 | Hybrid KEM | ✅ Yes |
| **Signatures** | Ed25519 + ML-DSA-65 | Hybrid dual signatures | ✅ Yes |
| **AEAD** | XChaCha20-Poly1305 | Message encryption | ❌ No (not needed) |
| **KDF** | HKDF-SHA384 | Key derivation | ❌ No (not needed) |
| **Password KDF** | Argon2id SENSITIVE | Keystore encryption | ❌ No (not needed) |

### 3.2 Security Properties

**Confidentiality**: ✅ Forward secrecy (ephemeral keys)  
**Authenticity**: ✅ Dual signatures (prevents impersonation)  
**Integrity**: ✅ AEAD with AAD binding (tampering detected)  
**Post-Quantum Security**: ✅ Hybrid X25519+ML-KEM-768 (no silent downgrade)  
**Deniability**: ❌ Not implemented (signatures are non-repudiable)  

### 3.3 Key Lifecycle

| Key Type | Lifetime | Storage | Rotation |
|----------|----------|---------|----------|
| **Identity Keys** | Long-term | IndexedDB (encrypted) | Never |
| **Prekeys** | One-time | Relay (untrusted) | On consumption |
| **Session Keys** | Per-session | Memory only | Every 2^20 messages or 24h |
| **Message Keys** | Per-message | Ephemeral (not stored) | Every message |

---

## 4. AUTHENTICATION & AUTHORIZATION

### 4.1 Authentication Chain

```
User → Identity Generation → Relay Registration → JWT Token → httpOnly Cookie
```

**JWT Storage**: httpOnly, secure, sameSite=strict cookies  
**XSS Protection**: JWT NOT accessible to JavaScript  
**CSRF Protection**: sameSite=strict prevents cross-site requests  
**Token Lifetime**: 7 days (automatically refreshed)

### 4.2 Authorization Model

**Chat Membership**: Stored in `chat_participants` table (relay DB)  
**Access Control**: `/sync/:chatId` verifies membership via `isParticipant(chatId, userId)`  
**Error Codes**:
- `401 Unauthorized`: JWT invalid or missing
- `403 Forbidden`: Authenticated but not participant
- `404 Not Found`: Chat does not exist

### 4.3 Relay Identity Verification

**Production**: Relay identity key MANDATORY (`RELAY_IDENTITY_KEY` env var)  
**Failure Mode**: `process.exit(1)` if missing (fail-closed)  
**Verification**: Client verifies Ed25519 signature on directory responses  
**Pinning**: Relay public key hardcoded in client (prevents EREBUS attacks)

---

## 5. KNOWN LIMITATIONS

### 5.1 CRITICAL (Cannot Be Fixed Without Redesign)

**L1: Metadata Leakage**
- **What**: Relay sees who talks to whom, when, message sizes
- **Impact**: Traffic analysis, social graph reconstruction
- **Mitigation**: None (requires mixnet)
- **Risk**: HIGH

**L2: Device Loss = Key Loss**
- **What**: Losing device = losing all message history
- **Impact**: No key backup, no multi-device sync
- **Mitigation**: User must manually backup keystore seed
- **Risk**: MEDIUM (usability issue, not security)

**L3: No Perfect Forward Secrecy for Handshake**
- **What**: Long-term identity keys used in handshake
- **Impact**: Compromised identity key = compromised handshakes
- **Mitigation**: None (Signal X3DH limitation)
- **Risk**: LOW (requires long-term key compromise)

### 5.2 MEDIUM (Fixable with Effort)

**L4: No Message Padding**
- **What**: Message lengths leak information
- **Impact**: Adversary can guess message type (short = emoji, long = paragraph)
- **Mitigation**: PKCS#7 padding applied, but lengths still visible to relay
- **Risk**: LOW

**L5: No Multi-Device Support**
- **What**: One identity per device
- **Impact**: Cannot use same account on phone + desktop
- **Mitigation**: None (requires Sesame protocol redesign)
- **Risk**: MEDIUM (usability issue)

### 5.3 LOW (Acceptable Trade-offs)

**L6: Relay Availability Dependency**
- **What**: If relay is down, no message delivery
- **Impact**: Centralized infrastructure (not p2p)
- **Mitigation**: Deploy multiple relay instances
- **Risk**: LOW (operational issue)

**L7: No Disappearing Messages**
- **What**: Messages stored until manually deleted
- **Impact**: Forensic recovery possible from device
- **Mitigation**: User can manually clear chats
- **Risk**: LOW

---

## 6. SECURITY ASSUMPTIONS

**A1**: User's device is not compromised by malware  
**A2**: Browser enforces Content Security Policy correctly  
**A3**: Cryptographic primitives (libsodium, liboqs) are implemented correctly  
**A4**: Next.js server is not compromised  
**A5**: HTTPS/TLS provides secure transport layer  
**A6**: Argon2id KDF makes brute-force infeasible  

**If any assumption breaks**: Security degrades gracefully (e.g., XSS steals session, not long-term keys)

---

## 7. OPERATIONAL SECURITY

### 7.1 Production Checklist

- [x] Relay identity key configured (`RELAY_IDENTITY_KEY`)
- [x] JWT secret is cryptographically random (≥64 characters)
- [x] Database credentials use strong passwords
- [x] HTTPS enforced (no HTTP fallback)
- [x] CSP headers deployed
- [x] Rate limiting enabled
- [x] Structured logging (no sensitive data)

### 7.2 Incident Response

**Security Breach**: Immediately rotate `RELAY_IDENTITY_KEY` and `JWT_SECRET`  
**Key Compromise**: User must re-enroll device (no recovery possible)  
**XSS Vulnerability**: httpOnly cookies limit damage to current session  

### 7.3 Vulnerability Disclosure

**Contact**: security@stvor.xyz  
**Response Time**: 48 hours  
**Disclosure Policy**: Coordinated disclosure (90 days)  

---

## 8. COMPLIANCE & AUDITING

**GDPR**: End-to-end encryption = user controls data  
**Export Control**: Post-quantum crypto not restricted (open-source)  
**Audit Trail**: Relay logs authentication attempts (no message content)  

**Independent Audit**: Not yet performed (recommended before 1.0 GA)  
**Penetration Testing**: Not yet performed (recommended)  

---

## 9. FINAL SECURITY STATEMENT

**What STVOR Protects**:
- ✅ Message content (E2E encrypted with PQ security)
- ✅ Sender authenticity (dual signatures)
- ✅ Replay attacks (blob deduplication)
- ✅ Unauthorized chat access (membership verification)
- ✅ XSS token theft (httpOnly cookies)

**What STVOR Does NOT Protect**:
- ❌ Metadata (who, when, how much)
- ❌ Device compromise (malware wins)
- ❌ Physical device access (keystore extractable)
- ❌ Multi-device sync (one device only)
- ❌ Key recovery (backup is user's responsibility)

**Honest Assessment**:
STVOR is suitable for **confidential communication** where message content must be protected from network adversaries and quantum computers. It is NOT suitable for **anonymous communication** or scenarios where metadata leakage is unacceptable.

**Use Cases**:
- ✅ Private conversations (personal, business)
- ✅ Whistleblowing (content protected, not identity)
- ❌ Journalism in oppressive regimes (metadata leakage risk)
- ❌ Tor-level anonymity (no mixnet)

---

## 10. FURTHER READING

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System design
- [CRYPTO_QUICK_REFERENCE.md](./apps/web/CRYPTO_QUICK_REFERENCE.md) - Crypto implementation
- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Signal Protocol](https://signal.org/docs/)

---

**Document Version**: 1.0  
**Next Review**: 2026-04-14 (quarterly)  
**Maintainer**: Security Team <security@stvor.xyz>
