# Stvor Messenger - System Architecture

**Version**: 0.8.0  
**Last Updated**: 2026-01-15  
**Status**: Production

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Component Architecture](#component-architecture)
3. [Authentication Architecture](#authentication-architecture)
4. [E2E Encryption Protocol](#e2e-encryption-protocol)
5. [Message Flow](#message-flow)
6. [Data Flow Diagrams](#data-flow-diagrams)
7. [Deployment Architecture](#deployment-architecture)
8. [Security Model](#security-model)
9. [Technology Stack](#technology-stack)

---

## System Overview

Stvor is an end-to-end encrypted messenger with **post-quantum cryptography** (PQC), designed for maximum security and privacy. The system uses a hybrid approach combining classical cryptography (X25519, Ed25519) with post-quantum algorithms (ML-KEM-768, ML-DSA-65).

### Key Features

- **Hybrid PQC**: X25519 + ML-KEM-768 key exchange
- **Signal Protocol**: X3DH handshake + Double Ratchet
- **Zero Trust**: Server cannot read messages or keys
- **Prekey Bundles**: Asynchronous messaging support
- **Session Management**: Automatic key rotation and forward secrecy
- **Clerk Authentication**: Production-grade identity provider
- **Relay-based Delivery**: Stateless message relay

### Design Principles

1. **End-to-End Encryption**: Only sender and recipient can decrypt messages
2. **Forward Secrecy**: Past messages remain secure even if keys are compromised
3. **Post-Quantum Security**: Protection against quantum computer attacks
4. **Zero Knowledge**: Server learns nothing about message content
5. **Fail-Fast**: Authentication errors cause immediate abort (no fallbacks)

---

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT (Browser)                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   UI Layer   │  │  Auth Layer  │  │ Crypto Layer │         │
│  │              │  │              │  │              │         │
│  │ - Chat UI    │  │ - Clerk SDK  │  │ - libsodium  │         │
│  │ - Messages   │  │ - JWT Cache  │  │ - ML-KEM     │         │
│  │ - Sessions   │  │ - Auth State │  │ - ML-DSA     │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│         │                  │                  │                 │
│  ┌──────────────────────────────────────────────────┐          │
│  │            State Management (Zustand)            │          │
│  └──────────────────────────────────────────────────┘          │
│         │                  │                  │                 │
│  ┌──────────────────────────────────────────────────┐          │
│  │         Storage Layer (IndexedDB)                │          │
│  │  - Identity Keys   - Sessions   - Messages       │          │
│  └──────────────────────────────────────────────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    NEXT.JS BACKEND (Vercel)                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐      │
│  │           API Routes (/app/api/)                     │      │
│  │                                                      │      │
│  │  ┌────────────────┐  ┌────────────────┐            │      │
│  │  │ /relay/session │  │ /relay/proxy   │            │      │
│  │  │                │  │                │            │      │
│  │  │ - Issue relay  │  │ - Forward to   │            │      │
│  │  │   JWT          │  │   relay server │            │      │
│  │  │ - Verify Clerk │  │ - Transparent  │            │      │
│  │  └────────────────┘  └────────────────┘            │      │
│  │                                                      │      │
│  └──────────────────────────────────────────────────────┘      │
│         │                                                       │
│  ┌──────────────────────────────────────────────────────┐      │
│  │         Clerk Authentication Integration             │      │
│  │  - Session verification  - JWT validation            │      │
│  └──────────────────────────────────────────────────────┘      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS (relay JWT)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    RELAY SERVER (Railway)                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐      │
│  │           Authentication Middleware                  │      │
│  │                                                      │      │
│  │  requireWebAuth  →  Verify relay JWT                │      │
│  │  requireParticipant  →  Check chat membership       │      │
│  └──────────────────────────────────────────────────────┘      │
│         │                                                       │
│  ┌──────────────────────────────────────────────────────┐      │
│  │                Relay Endpoints                       │      │
│  │                                                      │      │
│  │  POST /directory/:username  - Register identity     │      │
│  │  GET  /directory/:username  - Fetch identity        │      │
│  │  POST /prekeys/:username    - Publish prekey bundle │      │
│  │  GET  /prekeys/:username    - Fetch prekey bundle   │      │
│  │  POST /message/:chatId      - Store encrypted msg   │      │
│  │  GET  /sync/:chatId         - Sync messages         │      │
│  │  POST /intent/:username     - Register chat intent  │      │
│  └──────────────────────────────────────────────────────┘      │
│         │                                                       │
│  ┌──────────────────────────────────────────────────────┐      │
│  │              Storage Adapter                         │      │
│  │                                                      │      │
│  │  - PostgreSQL (production)                          │      │
│  │  - Memory (development)                             │      │
│  └──────────────────────────────────────────────────────┘      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Authentication Architecture

### Three-Layer Authentication Model

Stvor uses a **hybrid authentication model** with three distinct layers:

1. **User Authentication (Clerk)**: Verifies user identity
2. **Relay JWT**: Authorizes client → relay communication
3. **Backend API Key**: Authorizes Next.js → relay communication

### Authentication Flow

```
┌─────────────────────────────────────────────────────────────┐
│ PHASE 1: User Authentication (Clerk)                       │
└─────────────────────────────────────────────────────────────┘
    
    User enters credentials
          ↓
    Clerk verifies identity
          ↓
    httpOnly cookie set (auth.clerk.io)
          ↓
    Client obtains Clerk session

┌─────────────────────────────────────────────────────────────┐
│ PHASE 2: Relay JWT Acquisition                             │
└─────────────────────────────────────────────────────────────┘

    Client → POST /api/relay/session
          ↓ (includes Clerk httpOnly cookie)
    Next.js verifies Clerk session
          ↓
    Signs relay JWT with RELAY_JWT_SECRET
          ↓
    Returns { relayJWT, username, expiresAt }
          ↓
    Client caches JWT in memory (24h TTL)

┌─────────────────────────────────────────────────────────────┐
│ PHASE 3: Identity Registration (Bootstrap)                 │
└─────────────────────────────────────────────────────────────┘

    Client → POST /api/relay/directory
          ↓ (includes Clerk httpOnly cookie)
    Next.js verifies Clerk session
          ↓
    Forwards to relay with RELAY_API_KEY
          ↓
    Relay verifies API key (backend-to-backend trust)
          ↓
    Stores identity → 200 OK

┌─────────────────────────────────────────────────────────────┐
│ PHASE 4: Messaging (Post-Bootstrap)                        │
└─────────────────────────────────────────────────────────────┘

    Client → POST /api/relay/message/:chatId
          ↓ Authorization: Bearer <relay_jwt>
    Next.js proxy forwards header
          ↓
    Relay requireWebAuth middleware:
      - Extracts JWT from Authorization header
      - Verifies HMAC-SHA256 signature
      - Validates aud, iss, exp
      - Attaches request.user = { username }
          ↓
    Relay requireParticipant middleware:
      - Checks chat membership
      - Returns 403 if not participant
          ↓
    Processes message → 200 OK
```

### JWT Structure

**Relay JWT Payload**:
```json
{
  "username": "alice",
  "userId": "user_abc123",
  "iss": "ilyazh-web",
  "aud": "ilyazh-relay",
  "iat": 1736889600,
  "exp": 1736976000
}
```

**Signing Algorithm**: HS256 (HMAC-SHA256)  
**Secret**: `RELAY_JWT_SECRET` (shared between Next.js and Relay)  
**TTL**: 24 hours  
**Storage**: In-memory only (cleared on page reload)

### Endpoint Authentication Matrix

| Endpoint | Auth Method | Credential | Error Behavior |
|----------|-------------|------------|----------------|
| `POST /api/relay/session` | Clerk httpOnly cookie | Clerk session | 401 → ABORT |
| `POST /api/relay/directory` | Clerk httpOnly cookie | Clerk session → API key | 401 → ABORT |
| `GET /directory/:username` | None (public) | - | - |
| `POST /directory/:username` | API Key | RELAY_API_KEY | 401 → ABORT |
| `POST /message/:chatId` | Relay JWT | Authorization header | 401 → ABORT |
| `GET /sync/:chatId` | Relay JWT | Authorization header | 401/403 → ABORT (stop sync) |
| `POST /prekeys/:username` | Relay JWT | Authorization header | 401 → ABORT |

---

## E2E Encryption Protocol

### Cryptographic Primitives

**Classical Cryptography**:
- **X25519**: Elliptic curve Diffie-Hellman (ECDH)
- **Ed25519**: EdDSA signatures
- **ChaCha20-Poly1305**: Authenticated encryption (AEAD)

**Post-Quantum Cryptography**:
- **ML-KEM-768** (Kyber): Post-quantum key encapsulation
- **ML-DSA-65** (Dilithium): Post-quantum signatures

### Identity Keys (Long-term)

Each user has a permanent identity keypair:

```typescript
IdentityKeyPair {
  ed25519: {
    publicKey: Uint8Array(32),   // Classical signature
    secretKey: Uint8Array(64)
  },
  mldsa: {
    publicKey: Uint8Array(1952),  // PQ signature (ML-DSA-65)
    secretKey: Uint8Array(4032)
  }
}
```

**Storage**: IndexedDB (client-side only, never sent to server)  
**Lifetime**: Permanent (unless device re-enrollment)

### Prekey Bundles (One-time)

For asynchronous messaging, each user publishes prekey bundles:

```typescript
PrekeyBundle {
  bundleId: string,              // UUID
  x25519Ephemeral: Uint8Array(32),     // Classical prekey
  mlkemPublicKey: Uint8Array(1184),    // PQ KEM (ML-KEM-768)
  ed25519Signature: Uint8Array(64),    // Signature over bundle
  mldsaSignature: Uint8Array(3293),    // PQ signature over bundle
  timestamp: number
}
```

**Storage**: Relay server (public, readable by anyone)  
**Lifetime**: Single use (deleted after handshake)  
**Regeneration**: Automatic after each use

### X3DH Handshake (Initiator = Alice, Responder = Bob)

**Phase 1: Alice initiates**

1. Alice fetches Bob's identity keys from relay
2. Alice fetches Bob's prekey bundle from relay
3. Alice verifies signatures on Bob's prekey bundle
4. Alice generates ephemeral keypairs:
   - Ephemeral X25519 (EK_A)
   - Ephemeral ML-KEM keypair
5. Alice performs hybrid key exchange:
   ```
   Classical: DH1 = ECDH(IK_A, SPK_B)
              DH2 = ECDH(EK_A, IK_B)
              DH3 = ECDH(EK_A, SPK_B)
   PQ:        KEM = ML-KEM-Encap(mlkem_pub_B)
   
   SK = KDF(DH1 || DH2 || DH3 || KEM_shared_secret)
   ```
6. Alice creates handshake message:
   ```typescript
   HandshakeMessage {
     role: 'initiator',
     ephemeralX25519: EK_A.publicKey,
     ephemeralMLKEM: mlkem_ciphertext,
     identityPublicEd25519: IK_A.ed25519.publicKey,
     identityPublicMLDSA: IK_A.mldsa.publicKey,
     ed25519Signature: sig_ed25519(handshake_data),
     mldsaSignature: sig_mldsa(handshake_data)
   }
   ```
7. Alice sends handshake to relay: `POST /message/:chatId`

**Phase 2: Bob completes**

1. Bob receives handshake from relay via sync
2. Bob verifies Alice's signatures
3. Bob performs hybrid key exchange:
   ```
   Classical: DH1 = ECDH(SPK_B, IK_A)
              DH2 = ECDH(IK_B, EK_A)
              DH3 = ECDH(SPK_B, EK_A)
   PQ:        KEM = ML-KEM-Decap(mlkem_ciphertext, mlkem_secret_B)
   
   SK = KDF(DH1 || DH2 || DH3 || KEM_shared_secret)
   ```
4. Bob initializes Double Ratchet with SK
5. Bob creates response handshake
6. Bob sends response to relay: `POST /message/:chatId`
7. Bob deletes used prekey bundle
8. Bob generates new prekey bundle

**Phase 3: Alice finalizes**

1. Alice receives Bob's response via sync
2. Alice verifies Bob's signatures
3. Alice initializes Double Ratchet with SK
4. **Session established** ✅

### Double Ratchet

After handshake, all messages use the Double Ratchet:

```typescript
RatchetState {
  sessionId: string,           // Chat ID
  role: 'initiator' | 'responder',
  rootKey: Uint8Array(32),     // Root key (never used directly)
  sendingChainKey: Uint8Array(32),
  receivingChainKey: Uint8Array(32),
  sendingRatchetKey: { x25519, mlkem },
  receivingRatchetKey: { x25519, mlkem },
  messageCounter: number,
  receivedMessages: Set<number>
}
```

**Per-Message Encryption**:
1. Derive message key from chain key: `MK = KDF(CK)`
2. Encrypt with ChaCha20-Poly1305:
   ```
   ciphertext = ChaCha20-Poly1305-Encrypt(
     key: MK,
     nonce: counter,
     plaintext: message,
     aad: (sessionId || sender || recipient)
   )
   ```
3. Advance chain key: `CK' = KDF(CK)`
4. Send encrypted message to relay

**Ratchet Advancement**:
- **Symmetric ratchet**: Every message advances chain key
- **DH ratchet**: Every round-trip advances root key
- **Forward secrecy**: Old keys deleted immediately after use

---

## Message Flow

### 1. Send Message

```
┌──────────────────────────────────────────────────────────┐
│ Client A: Send "Hello"                                   │
└──────────────────────────────────────────────────────────┘
    
    1. Check ratchetState.status === 'established'
       ↓
    2. Encrypt with Double Ratchet:
       plaintext = "Hello"
       ciphertext = ratchet.encrypt(plaintext)
       ↓
    3. Create encrypted blob:
       {
         nonce: base64(random(24)),
         ciphertext: base64(ciphertext),
         aad: base64(sessionId || sender || recipient)
       }
       ↓
    4. Obtain relay JWT:
       headers = await createAuthHeaders(username)
       ↓
    5. Send to relay:
       POST /api/relay/message/:chatId
       Authorization: Bearer <relay_jwt>
       {
         type: 'message',
         from: 'alice',
         blob: base64(encrypted_blob)
       }
       ↓
    6. Relay verifies JWT → stores blob → 200 OK
       ↓
    7. Update local state:
       - Save message to IndexedDB
       - Advance ratchet
       - Update UI

┌──────────────────────────────────────────────────────────┐
│ Client B: Receive "Hello"                                │
└──────────────────────────────────────────────────────────┘

    1. Sync polling (every 2s):
       GET /api/relay/sync/:chatId?since=<cursor>
       Authorization: Bearer <relay_jwt>
       ↓
    2. Relay returns:
       {
         messages: [
           {
             blobRef: "msg_123",
             encryptedBlob: base64(...),
             senderId: "alice",
             sequence: 5
           }
         ]
       }
       ↓
    3. Decrypt message:
       blob = base64_decode(encryptedBlob)
       plaintext = ratchet.decrypt(blob)
       ↓
    4. Verify sender identity
       ↓
    5. Store decrypted message in IndexedDB
       ↓
    6. Update UI with "Hello"
```

### 2. Sync Protocol

**Polling Strategy**:
- Interval: 2 seconds (configurable)
- Cursor-based: `GET /sync/:chatId?since=<last_sequence>`
- Deduplication: Client-side seen set

**Sync Response**:
```json
{
  "chatId": "abc123",
  "since": 5,
  "messages": [
    {
      "blobRef": "msg_6",
      "encryptedBlob": "base64...",
      "senderId": "alice",
      "sequence": 6,
      "createdAt": 1736889600000
    }
  ],
  "participants": [
    {
      "username": "alice",
      "identityEd25519": "base64...",
      "identityMLDSA": "base64..."
    }
  ]
}
```

**Error Handling**:
- 401 Unauthorized → Stop sync, mark auth FAILED
- 403 Forbidden → Stop sync, user not in chat
- 404 Not Found → Chat doesn't exist, abort
- 500 Server Error → Retry with exponential backoff

### 3. Chat Initialization

```
1. User A clicks "Start Chat with B"
   ↓
2. POST /api/relay/chat/init
   { participants: ["alice", "bob"] }
   ↓
3. Relay generates canonical chatId:
   chatId = SHA256(sort(["alice", "bob"]))
   ↓
4. Register both users as participants
   ↓
5. Return { chatId }
   ↓
6. Client stores chatId
   ↓
7. Initiate handshake (see X3DH above)
```

---

## Data Flow Diagrams

### User Registration Flow

```
User → Clerk Sign-Up
  ↓
Clerk verifies email/phone
  ↓
Clerk creates user account
  ↓
Client receives Clerk session (httpOnly cookie)
  ↓
Client generates identity keypair:
  - Ed25519 + ML-DSA-65
  ↓
Client → POST /api/relay/directory
  Body: { username, identityEd25519, identityMLDSA }
  Cookie: Clerk session
  ↓
Next.js verifies Clerk session
  ↓
Next.js → Relay
  POST /directory/:username
  Authorization: Bearer <RELAY_API_KEY>
  ↓
Relay stores identity → 200 OK
  ↓
Client generates prekey bundle
  ↓
Client → POST /api/relay/prekeys/:username
  Authorization: Bearer <relay_jwt>
  ↓
Relay stores prekey bundle → 200 OK
  ↓
✅ User ready to chat
```

### Message Delivery Flow (E2E)

```
┌─────────┐                                    ┌─────────┐
│ Alice   │                                    │   Bob   │
└────┬────┘                                    └────┬────┘
     │                                              │
     │ 1. Type "Hello"                              │
     ├─────────────────────────────────────────────┤
     │ 2. Encrypt with ratchet                      │
     │    ciphertext = ratchet.encrypt("Hello")     │
     ├─────────────────────────────────────────────┤
     │                                              │
     │ 3. POST /message/:chatId                     │
     │    { blob: base64(ciphertext) }              │
     ├────────────────────────────▶                 │
     │                              Relay Server    │
     │ 4. Store encrypted blob      (cannot read)   │
     │                                              │
     │                              ◀───────────────┤
     │                                              │ 5. Poll: GET /sync/:chatId
     │                                              │    ?since=0
     │                              ─────────────▶  │
     │                              Relay Server    │
     │                              (returns blob)  │
     │                              ◀───────────────┤
     │                                              │
     │                                              │ 6. Decrypt: plaintext =
     │                                              │    ratchet.decrypt(blob)
     │                                              │
     │                                              │ 7. Display "Hello"
     └──────────────────────────────────────────────┘
```

---

## Deployment Architecture

### Production Environment

```
┌─────────────────────────────────────────────────────────────┐
│                      VERCEL (Next.js)                       │
│  Region: Global (Edge Functions)                            │
│  Domain: stvor.xyz                                          │
├─────────────────────────────────────────────────────────────┤
│  - Serverless Functions (API routes)                        │
│  - Static Site Generation (SSG)                             │
│  - Edge Middleware                                          │
│  - CDN (Vercel Edge Network)                                │
└─────────────────────────────────────────────────────────────┘
                         │
                         │ HTTPS
                         │
┌─────────────────────────────────────────────────────────────┐
│                    RAILWAY (Relay Server)                   │
│  Region: US East                                            │
│  URL: ilyazhrelay-production.up.railway.app                 │
├─────────────────────────────────────────────────────────────┤
│  - Fastify HTTP Server                                      │
│  - PostgreSQL Database                                      │
│  - WebSocket Support (planned)                              │
│  - Auto-scaling (Railway handles)                           │
└─────────────────────────────────────────────────────────────┘
```

### Environment Variables

**Vercel (Next.js)**:
```bash
# Clerk
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_...
CLERK_SECRET_KEY=sk_live_...
CLERK_JWT_ISSUER=https://clerk.stvor.xyz

# Relay
NEXT_PUBLIC_RELAY_URL=https://ilyazhrelay-production.up.railway.app
RELAY_API_KEY=<secret>        # Backend-to-backend auth
RELAY_JWT_SECRET=<secret>     # JWT signing (MUST match Railway)
```

**Railway (Relay)**:
```bash
# Database
DATABASE_URL=postgresql://...

# Auth
RELAY_API_KEY=<secret>        # Backend-to-backend auth
RELAY_JWT_SECRET=<secret>     # JWT verification (MUST match Vercel)

# CORS
ALLOWED_ORIGINS=https://stvor.xyz,https://www.stvor.xyz

# Storage
STORAGE_TYPE=postgres         # or 'memory' for dev
```

### Scaling Strategy

**Horizontal Scaling**:
- Next.js: Automatic (Vercel handles)
- Relay: Manual (Railway deployment settings)
- Database: Vertical scaling (increase RAM/CPU)

**Performance Optimizations**:
- CDN caching for static assets
- Edge functions for auth endpoints
- Database connection pooling (pg)
- In-memory caching (relay rate limits)

---

## Security Model

### Threat Model

**Adversaries**:
1. **Passive Network Attacker**: Can observe traffic but not modify
2. **Active Network Attacker**: Can intercept and modify traffic
3. **Compromised Server**: Relay server is malicious or hacked
4. **Quantum Computer**: Future quantum adversary (post-quantum protection)

**Security Properties**:
1. **Confidentiality**: Only sender and recipient can read messages
2. **Integrity**: Messages cannot be tampered without detection
3. **Authenticity**: Recipients can verify sender identity
4. **Forward Secrecy**: Past messages remain secure if keys compromised
5. **Post-Compromise Security**: Security recovers after key compromise

### Attack Mitigations

| Attack | Mitigation |
|--------|-----------|
| **Man-in-the-Middle** | Identity verification, signature checks |
| **Replay Attack** | Message counters, nonce validation |
| **Message Tampering** | AEAD (ChaCha20-Poly1305) |
| **Quantum Attack** | ML-KEM-768, ML-DSA-65 (PQC) |
| **Server Compromise** | E2E encryption (server can't read) |
| **Key Compromise** | Forward secrecy (Double Ratchet) |
| **Session Hijacking** | JWT expiry, signature verification |
| **XSS Attack** | httpOnly cookies, CSP headers |
| **CSRF Attack** | SameSite cookies, origin checks |

### Security Boundaries

```
┌──────────────────────────────────────────────────────┐
│ TRUSTED ZONE: Client Browser                         │
│                                                      │
│ - Identity keys (never leave device)                │
│ - Session keys (never leave device)                 │
│ - Plaintext messages (never sent to server)         │
│ - Ratchet state (never sent to server)              │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│ SEMI-TRUSTED ZONE: Next.js Backend                  │
│                                                      │
│ - Clerk session validation (sees user identity)     │
│ - Relay JWT signing (knows username)                │
│ - Cannot read messages (encrypted)                  │
│ - Cannot read keys (never sent)                     │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│ UNTRUSTED ZONE: Relay Server                        │
│                                                      │
│ - Stores encrypted messages (cannot decrypt)        │
│ - Stores identity public keys (already public)      │
│ - Stores prekey bundles (already public)            │
│ - Cannot impersonate users (no private keys)        │
│ - Cannot read messages (E2E encrypted)              │
└──────────────────────────────────────────────────────┘
```

---

## Technology Stack

### Frontend (Client)

| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | Next.js | 14.2.35 |
| UI | React | 18.2.0 |
| Styling | Tailwind CSS | 3.4.17 |
| State | Zustand | 5.0.2 |
| Storage | IndexedDB | Native |
| Auth | Clerk | 6.34.1 |

### Cryptography

| Component | Technology | Key Size |
|-----------|-----------|----------|
| Classical KEM | X25519 | 32 bytes |
| PQ KEM | ML-KEM-768 | 1184 bytes (pk) |
| Classical Signature | Ed25519 | 32 bytes (pk) |
| PQ Signature | ML-DSA-65 | 1952 bytes (pk) |
| AEAD | ChaCha20-Poly1305 | 32 bytes (key) |
| Hash | SHA-256 | 32 bytes |

### Backend (Next.js)

| Component | Technology | Version |
|-----------|-----------|---------|
| Runtime | Node.js | 22.x |
| Framework | Next.js | 14.2.35 |
| Auth | Clerk SDK | 6.34.1 |
| JWT | jsonwebtoken | 9.0.3 |
| Deployment | Vercel | - |

### Relay Server

| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | Fastify | 5.x |
| Database | PostgreSQL | 16.x |
| ORM | Raw SQL | - |
| Auth | JWT (jsonwebtoken) | 9.0.3 |
| Deployment | Railway | - |

### Development Tools

| Tool | Purpose |
|------|---------|
| pnpm | Package manager |
| Turbo | Monorepo build system |
| TypeScript | Type safety |
| ESLint | Code linting |
| Git | Version control |

---

## Appendix: Key Rotation & Session Recovery

### Prekey Bundle Rotation

```
Trigger: After each use (handshake completion)
Process:
  1. Bob receives Alice's handshake
  2. Bob uses his prekey bundle to complete handshake
  3. Bob deletes used prekey bundle
  4. Bob generates new prekey bundle
  5. Bob publishes new bundle: POST /prekeys/:username
```

### Session Recovery

```
Scenario: Lost session (browser cleared, device changed)
Process:
  1. Client detects missing session with peer
  2. Client initiates new handshake (X3DH)
  3. Previous session keys lost (forward secrecy)
  4. Old messages cannot be decrypted
  5. New session starts from scratch
```

### Device Re-enrollment

```
Scenario: User signs in on new device
Process:
  1. User signs in with Clerk
  2. Client checks for local identity keys
  3. If missing → generate NEW identity keypair
  4. Register new identity: POST /directory/:username
  5. Relay allows identity update (with Clerk auth)
  6. Inform contacts: "Alice changed device"
  7. Re-establish sessions with all contacts
```

---

## Version History

- **v0.8.0** (2026-01-15): Relay JWT authentication architecture
- **v0.7.0** (2026-01-10): Post-quantum cryptography integration
- **v0.6.0** (2025-12-20): Double Ratchet implementation
- **v0.5.0** (2025-12-01): X3DH handshake protocol
- **v0.1.0** (2025-11-01): Initial prototype

---

**End of Architecture Document**
