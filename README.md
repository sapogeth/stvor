# Ilyazh Messenger - Post-Quantum E2E Encrypted Chat

A web-based end-to-end encrypted messenger with post-quantum cryptography support.

## 🚀 Quick Start

### Prerequisites
- Node.js 20+
- pnpm (or npm)

### Start Development Servers

```bash
# Terminal 1: Relay Server
cd apps/relay
STORAGE_TYPE=memory JWT_SECRET=QPjWOdcqY4r7Atj0rcEYdk8PrjwNxJFrUmijeir5QsQaatJwzicSyBPvStnj9NfA pnpm run dev

# Terminal 2: Web Client
cd apps/web
pnpm run dev
```

### Access the Application

- **Web Client**: http://localhost:3002
- **Relay API**: http://localhost:3001

## ✅ Current Status

**All major bugs fixed!** See [COMPLETE_FIX_SUMMARY.md](COMPLETE_FIX_SUMMARY.md) for details.

✅ Handshake type detection working
✅ CORS configured correctly
✅ Session restore fixed
✅ Wire/ratchet layer validation working
✅ Both servers running successfully

## 🔐 Security Features

- **End-to-End Encryption**: Messages encrypted on client, server cannot read
- **Post-Quantum**: Hybrid classical + ML-KEM-768 key exchange
- **Forward Secrecy**: Double ratchet protocol
- **AAD Validation**: Session ID binding prevents replay attacks
- **Signature Verification**: ML-DSA + Ed25519 dual signatures
- **Type Validation**: Wire format CBOR structure validation

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [COMPLETE_FIX_SUMMARY.md](COMPLETE_FIX_SUMMARY.md) | Overview of all fixes applied |
| [QUICK_START.md](QUICK_START.md) | Detailed startup instructions |
| [HANDSHAKE_TYPE_FIX.md](HANDSHAKE_TYPE_FIX.md) | Relay message type detection fix |
| [CORS_FIX_IDENTITY_REGISTRATION.md](CORS_FIX_IDENTITY_REGISTRATION.md) | CORS configuration fix |
| [HANDSHAKE_RESTORE_FIX_COMPLETE.md](HANDSHAKE_RESTORE_FIX_COMPLETE.md) | Session restore fix |
| [WIRE_RATCHET_LAYER_FIX.md](WIRE_RATCHET_LAYER_FIX.md) | Wire/ratchet validation fixes |
| [VERIFICATION_CHECKLIST.md](VERIFICATION_CHECKLIST.md) | Testing checklist |

## 🧪 Testing

### E2E Test Flow

1. **Create Users**
   - Browser 1: http://localhost:3002 → Create "alice"
   - Browser 2 (incognito): http://localhost:3002 → Create "bob"

2. **Start Chat**
   - Alice: Navigate to `/chat` → Enter "bob" → "Start Encrypted Chat"
   - Wait for handshake to complete
   - Both should show "🔒 E2E Encrypted (Active)"

3. **Send Messages**
   - Alice: Type "Hello Bob!" → Send
   - Bob: Should see decrypted message

### Health Check

```bash
curl http://localhost:3001/healthz
# {"status":"ok","storage":"memory","version":"0.8.0"}
```

## 🏗️ Architecture

```
Browser (Alice) ←→ Relay Server ←→ Browser (Bob)
     ↓                                    ↓
 IndexedDB                            IndexedDB
 (sessions,                          (sessions,
  identity,                           identity,
  prekeys)                            prekeys)
```

**Relay Server**: Routes encrypted messages, stores prekey bundles, provides identity directory
**Web Client**: Generates keys, performs handshakes, encrypts/decrypts messages

## 📦 Project Structure

```
ilyazh-messenger/
├── apps/
│   ├── relay/          # Relay server (Fastify)
│   │   ├── src/
│   │   │   ├── index.ts
│   │   │   └── storage/
│   │   └── .env
│   └── web/            # Web client (Next.js 15)
│       ├── app/
│       │   ├── chat/page.tsx
│       │   └── page.tsx
│       └── lib/
│           ├── crypto/
│           ├── identity.ts
│           ├── keystore.ts
│           └── prekeys.ts
└── packages/
    └── crypto/         # Crypto primitives
        └── src/
            ├── handshake.ts
            ├── ratchet.ts
            ├── wire.ts
            └── primitives.ts
```

## 🔧 Configuration

### Relay (.env)
```env
PORT=3001
STORAGE_TYPE=memory
JWT_SECRET=<generate-with-openssl-rand-base64-48>
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3002
```

### Web Client (.env.local)
```env
NEXT_PUBLIC_RELAY_URL=http://localhost:3001
```

## 🛠️ Development Commands

| Command | Description |
|---------|-------------|
| `pnpm install` | Install dependencies |
| `pnpm --filter @ilyazh/relay run dev` | Start relay |
| `pnpm --filter @ilyazh/web run dev` | Start web client |
| `pnpm --filter @ilyazh/crypto run build` | Build crypto package |
| `pnpm run build` | Build all packages |

## 🐛 Known Issues / TODOs

- [ ] Implement automatic session refresh on AAD mismatch
- [ ] Add persistent storage (PostgreSQL) for production relay
- [ ] Add rate limiting enforcement
- [ ] Add authentication verification in relay
- [ ] Add typing indicators
- [ ] Add read receipts
- [ ] Add message retry on failure

## 🔒 Security Notes

**Development Mode**:
- Relay uses in-memory storage (data lost on restart)
- CORS allows localhost origins
- Authentication checks disabled

**Production Recommendations**:
- Use PostgreSQL for relay storage
- Enable authentication verification
- Use HTTPS only
- Restrict CORS to actual domains
- Enable rate limiting
- Use secure JWT secret (not in git)

## 📝 License

MIT License

## 🙏 Acknowledgments

- **ML-KEM-768**: NIST Post-Quantum KEM
- **ML-DSA**: NIST Post-Quantum Signature
- **X25519/Ed25519**: Classical elliptic curve crypto
- **Double Ratchet**: Signal Protocol

---

**Last Updated**: 2025-11-01
**Version**: 0.8.0
**Status**: ✅ All major bugs fixed, ready for testing
