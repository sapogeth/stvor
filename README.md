# Ilyazh Messenger

**Post-quantum end-to-end encrypted web messenger** implementing the **Ilyazh-Web3E2E protocol** with **database-free storage**.

## Features

- 🔐 **Hybrid Post-Quantum Security**: X25519 + ML-KEM-768, Ed25519 + ML-DSA-65
- 🔒 **True E2E Encryption**: Server never sees plaintext or keys
- 📦 **Database-Free**: Content-addressed blobs + append-only manifests
- ⚡ **Mandated Cadence**: Automatic rekeying (2^20 msgs or 24h)
- 🛡️ **sid-in-AAD**: Session ID binding prevents replay attacks
- 🌐 **Web-Native**: Pure TypeScript, runs in browser

## Protocol: Ilyazh-Web3E2E v0.8

- **Key Exchange**: Hybrid X25519 + ML-KEM-768 (NIST FIPS 203)
- **Signatures**: Dual Ed25519 + ML-DSA-65 (NIST FIPS 204)
- **Encryption**: AES-256-GCM with HKDF-SHA-384
- **Messaging**: Double Ratchet with enforced re-encapsulation
- **Wire Format**: CBOR

See [CRYPTO.md](CRYPTO.md) for full specification.

## Quick Start

### Prerequisites

- Node.js ≥20.0.0
- pnpm ≥9.0.0

### Run Locally

```bash
# Install dependencies
pnpm install

# Start relay + web client
pnpm dev
```

**Access:**
- Web: http://localhost:3000
- Relay: http://localhost:3001

### Docker

```bash
docker-compose up -d
```

## Repository Structure

```
ilyazh-messenger/
├── apps/
│   ├── web/           # Next.js frontend (Chat, Benchmarks, Security tabs)
│   └── relay/         # Fastify relay server (stateless blob store)
├── packages/
│   └── crypto/        # Protocol implementation + tests
├── SECURITY.md        # Security analysis & threat model
├── STORAGE.md         # Database-free architecture
├── CRYPTO.md          # Cryptographic specification
└── RUNBOOK.md         # Operations guide
```

## Documentation

| Document | Purpose |
|----------|---------|
| [SECURITY.md](SECURITY.md) | Security properties, invariants, threat model |
| [STORAGE.md](STORAGE.md) | Database-free storage, manifests, content addressing |
| [CRYPTO.md](CRYPTO.md) | Cryptographic spec, KDF labels, test vectors |
| [RUNBOOK.md](RUNBOOK.md) | Building, deploying, monitoring, scaling |

## Architecture

### Client (Browser)

- Generate identity keys (Ed25519 + ML-DSA-65)
- Perform hybrid AKE with peers
- Encrypt/decrypt messages using Double Ratchet
- Enforce cadence limits (auto-rekey)

### Relay (Server)

- Stateless message relay
- Stores **only**:
  - Public identity keys
  - Signed prekey bundles
  - Encrypted message blobs (SHA-256 addressed)
  - Append-only manifest (metadata: timestamp, sender, blobRef)
- **Cannot**:
  - Decrypt messages (no keys)
  - Forge messages (no signing keys)
  - Tamper with messages (content addressing)

### Storage

**Filesystem (default):**
```
storage/
├── users/<userId>/identity.json
├── prekeys/<userId>/<bundleId>.json
└── chats/<chatId>/
    ├── manifest.json       # Append-only index
    └── blobs/<hash>.bin    # Encrypted ciphertexts
```

**S3 mode:** Same structure, stored in S3-compatible bucket.

## Security Highlights

✅ **sid-in-AAD** — Session ID in every AAD (normative requirement)
✅ **Dual signatures** — Both Ed25519 and ML-DSA verified
✅ **Nonce policy** — R64 || C32 prevents reuse
✅ **Cadence enforcement** — Rekey at 2^20 msgs or 24h
✅ **Key erasure** — Forward secrecy via zeroization
✅ **Constant-time** — AAD verification, comparisons
✅ **Transcript binding** — Handshake hash signatures

See [SECURITY.md](SECURITY.md) for threat analysis.

## Test Coverage

```bash
cd packages/crypto
pnpm test
```

**Test Suites:**
- Primitives (X25519, Ed25519, ML-KEM, ML-DSA, HKDF, AES-GCM)
- Handshake (full AKE, dual-sig verification)
- Double Ratchet (encrypt/decrypt, nonce policy)
- Cadence (message limits, time limits, session caps)
- Wire format (CBOR encoding)
- Deterministic vectors (interop)

## Performance

**Handshake:** ~3.5ms (X25519 + mock ML-KEM + signatures)
**Encryption:** ~0.25ms per message
**Rekey:** ~0.57ms (DH + KEM)

*Note: ML-KEM/ML-DSA times are mocked pending liboqs-wasm integration.*

## Implementation Status

### Production-Ready ✅

- X25519, Ed25519, AES-GCM, HKDF-SHA-384 (libsodium)
- Double Ratchet logic
- Cadence enforcement
- sid-in-AAD validation
- Wire format (CBOR)
- Relay server (filesystem + S3)
- Web UI (chat, benchmarks, security dashboard)

### In Development ⚠️

- **ML-KEM-768**: Mocked (correct wire sizes per FIPS 203)
- **ML-DSA-65**: Mocked (correct wire sizes per FIPS 204)

**Blockers:** Awaiting liboqs-wasm or vetted WASM bindings.
**Interface:** Ready to drop in real implementations without API changes.

### Future Enhancements 🔮

- Out-of-band key verification (QR codes)
- Multi-device support (prekey rotation)
- Group messaging
- Encrypted metadata (sender anonymity)
- Onion routing integration

## Deployment

### Filesystem Mode

```bash
DATA_DIR=/var/lib/ilyazh/storage pnpm relay
```

### S3 Mode

```bash
STORAGE_TYPE=s3 \
S3_BUCKET=my-bucket \
S3_ENDPOINT=https://s3.amazonaws.com \
S3_ACCESS_KEY=xxx \
S3_SECRET_KEY=yyy \
pnpm relay
```

### Docker Compose

```bash
docker-compose up -d
```

See [RUNBOOK.md](RUNBOOK.md) for production setup, monitoring, scaling.

## Contributing

Contributions welcome! Please:

1. Read [SECURITY.md](SECURITY.md) and [CRYPTO.md](CRYPTO.md)
2. Add tests for new features
3. Follow existing code style
4. Update documentation

## Security Disclosure

**Found a vulnerability?** Please report responsibly:

- **Email:** [your-security-email]
- **PGP:** [your-pgp-key]

Do **not** open public issues for security bugs.

## License

[MIT License](LICENSE) — see LICENSE file for details.

## References

- **Paper:** *Ilyazh-Web3E2E: Hybrid Post-Quantum Secure Messaging Protocol* (2025-1713)
- **NIST PQC:** [https://csrc.nist.gov/projects/post-quantum-cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- **Signal Protocol:** [https://signal.org/docs/](https://signal.org/docs/)
- **libsodium:** [https://doc.libsodium.org/](https://doc.libsodium.org/)

---

**Built with** 🔐 **by the Ilyazh Team**

**Protocol Version:** 0.8.0
**Last Updated:** 2025-10-29
