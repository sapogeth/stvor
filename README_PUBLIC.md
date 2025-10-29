# 🔐 Stv0r - Quantum-Resistant Encrypted Messenger

**Stv0r** is a modern end-to-end encrypted messenger built with **post-quantum cryptography**, ensuring your conversations remain private even against future quantum computers.

[![Security Grade](https://img.shields.io/badge/Security-B+-green)](SECURITY_COMPLETED.md)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-15.5-black)](https://nextjs.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## ✨ Features

### 🛡️ Military-Grade Security
- **Post-Quantum Cryptography**: ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204)
- **Double Ratchet Protocol**: Perfect forward secrecy for every message
- **Authenticated Encryption**: ChaCha20-Poly1305-IETF AEAD
- **Password-Protected Keys**: Optional Argon2id encryption for stored keys
- **JWT Authentication**: Token-based authorization for all operations

### 🚀 Modern Technology Stack
- **Frontend**: Next.js 15 + React 18 + TypeScript
- **Backend**: Fastify (stateless relay server)
- **Cryptography**: libsodium + liboqs (NIST-standardized PQC)
- **Storage**: IndexedDB (client-side) + Filesystem/S3 (relay)

### 🔒 Privacy-First Design
- **Zero-Knowledge Server**: Relay server cannot decrypt messages
- **Metadata Protection**: SHA256-hashed chat IDs
- **No Phone Numbers**: Username-based registration
- **Rate Limited**: DoS protection (100 req/min)

---

## 🎯 Quick Start

### Prerequisites
- Node.js 18+
- pnpm 8+

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/Stv0r.git
cd Stv0r

# Install dependencies
pnpm install

# Start development servers
pnpm dev
```

This starts:
- **Web UI**: http://localhost:3002
- **Relay Server**: http://localhost:3001

### First Steps

1. **Open the app**: Visit http://localhost:3002
2. **Create account**: Enter a username (no password needed)
3. **Start chatting**: Enter recipient's username and send encrypted messages!

---

## 🏗️ Architecture

```
┌─────────────────┐                  ┌─────────────────┐
│   Web Client    │                  │   Web Client    │
│   (Next.js)     │                  │   (Next.js)     │
└────────┬────────┘                  └────────┬────────┘
         │                                     │
         │  Encrypted Messages                 │
         │  (E2E Encrypted)                    │
         │                                     │
         └──────────┬──────────────────────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │   Relay Server       │
         │   (Fastify)          │
         │   • JWT Auth         │
         │   • Rate Limiting    │
         │   • Zero Knowledge   │
         └──────────────────────┘
```

**Key Points**:
- All encryption happens **client-side**
- Server only relays **encrypted blobs**
- No user data stored on server (only public keys)

---

## 🔐 Cryptographic Protocol

### Ilyazh-Web3E2E v0.8

**Key Exchange**:
- X25519 (classical ECDH)
- ML-KEM-768 (post-quantum KEM)
- Hybrid: `sharedSecret = X25519_secret || ML-KEM_secret`

**Signatures**:
- Ed25519 (classical signatures)
- ML-DSA-65 (post-quantum signatures)
- Dual verification for security

**Message Encryption**:
- ChaCha20-Poly1305-IETF (AEAD)
- Double ratchet with HKDF-SHA-384
- 32-byte authentication tags

**Key Derivation**:
- HKDF-SHA-384 for ratchet
- Argon2id for password-based encryption
- Unique nonces per message

For technical details, see [CRYPTO.md](CRYPTO.md)

---

## 📚 Documentation

- **[Installation Guide](INSTALL.md)** - Detailed setup instructions
- **[Quick Start](QUICKSTART.md)** - Get running in 5 minutes
- **[Crypto Spec](CRYPTO.md)** - Full cryptographic protocol
- **[Security Audit](SECURITY_COMPLETED.md)** - Recent security improvements
- **[Migration Guide](MIGRATION_GUIDE.md)** - Upgrade from older versions

---

## 🌐 Deployment

### Production Deployment

1. **Set environment variables**:
```bash
# Server (.env)
JWT_SECRET=your-random-secret-here
NODE_ENV=production
PORT=3001

# Client (.env.local)
NEXT_PUBLIC_RELAY_URL=https://your-relay-domain.com
```

2. **Build for production**:
```bash
pnpm build
```

3. **Deploy**:
- **Client**: Deploy `apps/web` to Vercel/Netlify/AWS
- **Relay**: Deploy `apps/relay` to any Node.js host
- **HTTPS Required**: WebCrypto only works over HTTPS

### Cloud Providers

**Recommended**:
- Vercel (web client)
- Railway/Fly.io (relay server)
- Cloudflare Workers (alternative relay)

See [deployment docs](INSTALL.md#production-deployment) for details.

---

## 🔧 Development

### Project Structure
```
Stv0r/
├── apps/
│   ├── web/          # Next.js web client
│   └── relay/        # Fastify relay server
├── packages/
│   └── crypto/       # Shared crypto library
├── SECURITY_COMPLETED.md
└── README.md
```

### Running Tests
```bash
# Run all tests
pnpm test

# Type checking
pnpm typecheck

# Linting
pnpm lint
```

### Development Mode
```bash
# Start with hot reload
pnpm dev

# Build packages
pnpm build

# Clean build artifacts
pnpm clean
```

---

## 🛡️ Security

### Recent Improvements (v0.8)

✅ **Replaced mocked PQC** with real NIST-standardized algorithms
✅ **Added JWT authentication** to prevent impersonation
✅ **Implemented key encryption** with password-based storage

**Security Grade**: B+ (Production Ready)

### Reporting Vulnerabilities

Found a security issue? Please email: **security@your-domain.com**

**DO NOT** create public GitHub issues for security vulnerabilities.

### Threat Model

**Protected Against**:
- ✅ Man-in-the-middle attacks
- ✅ Message replay attacks
- ✅ Future quantum computers
- ✅ Server compromise (zero-knowledge)
- ✅ Key theft via XSS (with password encryption)

**Not Protected Against**:
- ❌ Endpoint compromise (malware on device)
- ❌ Weak passwords (user responsibility)
- ❌ Physical device access

---

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Contribution Guidelines

- Write tests for new features
- Follow TypeScript best practices
- Update documentation
- Run `pnpm lint` before committing

---

## 📜 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **libsodium** - Cryptographic primitives
- **liboqs** - Post-quantum cryptography (NIST standards)
- **Signal Protocol** - Inspiration for double ratchet
- **NIST** - Standardizing post-quantum algorithms

---

## 📞 Support

- **Documentation**: [Read the docs](INSTALL.md)
- **Issues**: [GitHub Issues](https://github.com/yourusername/Stv0r/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/Stv0r/discussions)

---

## 🚀 Roadmap

- [ ] Mobile apps (React Native)
- [ ] Group chats
- [ ] File/image sharing
- [ ] Voice/video calls
- [ ] Desktop apps (Electron)
- [ ] Federation support

---

## ⚠️ Disclaimer

This software is provided as-is for educational and personal use. While we implement industry-standard cryptography, **no software is 100% secure**. Use at your own risk for sensitive communications.

For maximum security:
- Enable password-based key encryption
- Use strong, unique passwords
- Keep software up to date
- Review security audit reports

---

**Built with ❤️ and 🔐 by the Stv0r team**

*Making quantum-safe communication accessible to everyone*
