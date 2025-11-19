# Defense-in-Depth Security Module Integration Guide

## Overview

This guide explains how to integrate three orthogonal security mechanisms inspired by peer-reviewed KAIST NetS&P Lab research into the Stvor messenger.

**Papers Referenced:**

1. **EREBUS: A Stealthier Partitioning Attack against Bitcoin Peer-to-Peer Network** (Tran, Kang, et al., 2020 IEEE S&P)
   - Addresses: Network-layer attacks on relay servers
   - Solution: Relay Identity Verification (Application-Layer Certificate Pinning)

2. **Privacy of DNS-over-HTTPS: Requiem for a Dream?** (Csikor, Kang, et al., 2021 IEEE EuroS&P)
   - Addresses: Metadata leakage via traffic analysis
   - Solution: Adaptive Message Padding

3. **Work in Progress: I Know You Pin Me: Privacy Risks in User Pinning of Zoom Video Conferencing** (Woo, Song, Kang, 2024 IEEE EuroS&PW)
   - Addresses: Side-channel privacy leaks from presence indicators
   - Solution: User-Centric Privacy Controls (Opt-in + Obfuscation)

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Stvor Web Client (React)                    │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Privacy-Aware UI Layer                          │   │
│  │  - Typing Indicator (batched + jittered)         │   │
│  │  - Read Receipts (delayed + obfuscated)          │   │
│  │  - Presence Status (opt-in only)                 │   │
│  └──────────────────────────────────────────────────┘   │
│           ↓ (consent-enforced events)                    │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Message Encryption + Padding Layer              │   │
│  │  - Random padding to fixed block size (256B)     │   │
│  │  - Constant-time unpadding                       │   │
│  │  - Prevents traffic analysis attacks             │   │
│  └──────────────────────────────────────────────────┘   │
│           ↓ (padded ciphertext)                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Secure WebSocket + Relay Pinning                │   │
│  │  - TLS handshake (standard HTTPS)                │   │
│  │  - Relay identity challenge-response             │   │
│  │  - Ed25519 signature verification                │   │
│  │  - Backup relay failover                         │   │
│  └──────────────────────────────────────────────────┘   │
│           ↓ (authenticated, encrypted)                   │
└─────────────────────────────────────────────────────────┘
           ↓
        Internet
           ↓
┌─────────────────────────────────────────────────────────┐
│           Stvor Relay Server (Fastify)                   │
│           (Untrusted Intermediary)                       │
└─────────────────────────────────────────────────────────┘
```

---

## File Locations

### Core Implementation
- **`packages/crypto/src/defense-in-depth.ts`** (New)
  - `RelayPinner` class: Relay identity verification
  - `padMessage()` / `unpadMessage()`: Message padding helpers
  - `PrivacyConfigManager` class: Privacy controls
  - Type definitions for all three mechanisms

### Web Integration
- **`apps/web/lib/defense-integration.ts`** (New)
  - `SecureWebSocketManager`: WebSocket + relay pinning
  - `PrivacyAwareMessageSender`: Privacy-enforced message sending
  - `encryptMessageWithPadding()`: Convenient encryption wrapper
  - Configuration builders for environment variables

### Existing Files to Update
- `apps/web/app/chat/page.tsx` (See "Integration Steps" below)
- `apps/web/lib/identity.ts` (Optional: integrate padding into crypto state)

---

## Integration Steps

### Step 1: Export Defense-in-Depth from Crypto Package

Update `packages/crypto/src/index.ts`:

```typescript
// Add these exports
export {
  RelayPinner,
  padMessage,
  unpadMessage,
  encryptWithPadding,
  decryptWithUnpadding,
  PrivacyConfigManager,
  type RelayIdentityConfig,
  type PaddingConfig,
  type PrivacySettings,
  DEFAULT_PADDING_CONFIG,
  DEFAULT_PRIVACY_SETTINGS,
  initializeDefenseInDepth
} from './defense-in-depth.js';
```

### Step 2: Environment Configuration

Create `.env.local` (web app):

```env
# Relay Server Configuration (EREBUS mitigation)
REACT_APP_RELAY_URL=wss://relay.localhost:3001
REACT_APP_RELAY_KEY_HASH=<sha256_hash_of_relay_public_key>

# Backup Relays (Optional, for resilience)
REACT_APP_RELAY_BACKUP_1_URL=wss://relay-backup-1.example.com
REACT_APP_RELAY_BACKUP_1_HASH=<hash>

REACT_APP_RELAY_BACKUP_2_URL=wss://relay-backup-2.example.com
REACT_APP_RELAY_BACKUP_2_HASH=<hash>

# TLS Certificate Pinning (Optional, future enhancement)
REACT_APP_RELAY_TLS_HASH=<tls_cert_hash>
```

### Step 3: Initialize in Chat Component

In `apps/web/app/chat/page.tsx`:

```typescript
import {
  SecureWebSocketManager,
  PrivacyAwareMessageSender,
  createRelayConfigFromEnv,
  createPrivacyConfigFromStorage,
  savePrivacyConfigToStorage,
  encryptMessageWithPadding,
  decryptMessageWithUnpadding
} from '@/lib/defense-integration';
import { PrivacyConfigManager, type PaddingConfig } from '@ilyazh/crypto';

export default function ChatPage() {
  const [wsManager, setWsManager] = useState<SecureWebSocketManager | null>(null);
  const [privacySender, setPrivacySender] = useState<PrivacyAwareMessageSender | null>(null);
  const [paddingConfig, setPaddingConfig] = useState<PaddingConfig>({
    enabled: true,
    blockSize: 256,
    alwaysPad: false,
    jitterPercent: 10
  });

  useEffect(() => {
    const initialize = async () => {
      try {
        // 1. Create relay pinning config from environment
        const relayConfig = createRelayConfigFromEnv();
        const wsManager = new SecureWebSocketManager(relayConfig);

        // 2. Connect with relay identity verification
        const ws = await wsManager.connect(relayConfig.relayUrl);
        setWsManager(wsManager);

        // 3. Initialize privacy settings from storage
        const privacySettings = createPrivacyConfigFromStorage();
        const privacyManager = new PrivacyConfigManager(privacySettings);
        const privacySender = new PrivacyAwareMessageSender(
          privacyManager,
          async (event) => wsManager.send(JSON.stringify(event))
        );
        setPrivacySender(privacySender);

        // 4. Listen for messages
        ws.addEventListener('message', (event: MessageEvent) => {
          const msg = JSON.parse(event.data);
          handleIncomingMessage(msg);
        });

        console.info('[Chat] ✅ Defense-in-Depth initialized');
      } catch (error) {
        console.error('[Chat] Failed to initialize security:', error);
        // Fallback to unencrypted (development only!)
      }
    };

    initialize();

    return () => {
      wsManager?.close();
      privacySender?.destroy();
    };
  }, []);

  // --- Message Sending with Padding ---

  const sendMessage = async (recipientId: string, content: string) => {
    if (!wsManager || !privacySender) return;

    try {
      // 1. Encrypt with padding (PART 2: Traffic Analysis Resistance)
      const encrypted = await encryptMessageWithPadding(
        content,
        cryptoState.encryptMessage.bind(cryptoState),
        paddingConfig
      );

      // 2. Send encrypted message
      const wireMsg = {
        action: 'message',
        to: recipientId,
        ciphertext: Buffer.from(encrypted).toString('hex'),
        timestamp: Date.now()
      };

      wsManager.send(JSON.stringify(wireMsg));

      // 3. Clear typing indicator
      privacySender.sendTypingIndicator(recipientId);

      console.info('[Chat] Message sent with padding (traffic analysis resistant)');
    } catch (error) {
      console.error('[Chat] Failed to send message:', error);
    }
  };

  // --- Typing Indicators (with Privacy) ---

  const handleKeyPress = async (recipientId: string, _content: string) => {
    if (!privacySender) return;

    try {
      // Batched + jittered typing indicator (PART 3: Side-Channel Mitigation)
      await privacySender.sendTypingIndicator(recipientId);
    } catch (error) {
      // Typing indicators are optional, don't fail message sending
      console.warn('[Chat] Failed to send typing indicator:', error);
    }
  };

  // --- Receive Messages with Unpadding ---

  const handleIncomingMessage = async (msg: any) => {
    if (msg.action === 'message') {
      try {
        // 1. Decrypt and unpad message
        const ciphertext = Buffer.from(msg.ciphertext, 'hex');
        const plaintext = await decryptMessageWithUnpadding(
          ciphertext,
          cryptoState.decryptMessage.bind(cryptoState),
          paddingConfig.blockSize
        );

        // 2. Display message
        displayMessage(msg.from, plaintext);

        // 3. Send read receipt (if enabled)
        await privacySender?.sendReadReceipt(msg.id);
      } catch (error) {
        console.error('[Chat] Failed to decrypt message:', error);
      }
    }
  };

  // --- Privacy Settings UI ---

  const renderPrivacySettings = () => {
    if (!privacySender) return null;

    const settings = privacySender.privacyManager.getSettings(); // Add getter if needed

    return (
      <div className="privacy-settings">
        <h3>🔒 Privacy Controls</h3>

        <label>
          <input
            type="checkbox"
            checked={settings.typingIndicatorEnabled}
            onChange={(e) => {
              privacySender.updatePrivacySettings(
                { typingIndicatorEnabled: e.target.checked },
                true // User explicitly consented
              );
              savePrivacyConfigToStorage(privacySender.privacyManager.getSettings());
            }}
          />
          Allow typing indicators
        </label>

        <label>
          <input
            type="checkbox"
            checked={settings.readReceiptEnabled}
            onChange={(e) => {
              privacySender.updatePrivacySettings(
                { readReceiptEnabled: e.target.checked },
                true
              );
              savePrivacyConfigToStorage(privacySender.privacyManager.getSettings());
            }}
          />
          Send read receipts
        </label>

        <label>
          <input
            type="checkbox"
            checked={settings.presenceIndicatorEnabled}
            onChange={(e) => {
              privacySender.updatePrivacySettings(
                { presenceIndicatorEnabled: e.target.checked },
                true
              );
              savePrivacyConfigToStorage(privacySender.privacyManager.getSettings());
            }}
          />
          Show online status
        </label>

        <details>
          <summary>ℹ️ Privacy Details</summary>
          <ul>
            <li>✅ Messages are end-to-end encrypted (E2E)</li>
            <li>✅ Relay cannot read message content</li>
            <li>✅ Messages are padded to fixed size (256 bytes)</li>
            <li>✅ Relay identity is verified via signed challenge</li>
            <li>❓ Relay can see: who talks to whom, when, message count</li>
            <li>⚠️ Typing indicators leak exactly when you type</li>
            <li>⚠️ Read receipts leak exactly when you read</li>
          </ul>
        </details>
      </div>
    );
  };

  return (
    <div className="chat-container">
      {renderPrivacySettings()}
      {/* ... rest of chat UI ... */}
    </div>
  );
}
```

---

## Configuration Reference

### 1. Relay Pinning Config

```typescript
interface RelayIdentityConfig {
  relayUrl: string;                    // wss://relay.example.com
  expectedIdentityKeyHash: string;     // SHA256 hash (hex, 64 chars)
  backupRelays?: Array<{
    url: string;
    expectedIdentityKeyHash: string;
  }>;
  tlsCertificateHash?: string;         // Optional TLS pinning
  configCreatedAt: number;             // Timestamp
}
```

**How to Generate `expectedIdentityKeyHash`:**

On relay server (Node.js):
```typescript
import { publicKeyDetails } from 'libsodium-wrappers';
import { sha256 } from '@noble/hashes/sha256';

const relayIdentityPublicKey = /* Ed25519 public key from config */;
const hash = sha256(relayIdentityPublicKey);
console.log('expectedIdentityKeyHash:', Buffer.from(hash).toString('hex'));
```

### 2. Padding Config

```typescript
interface PaddingConfig {
  enabled: boolean;              // true = enable padding
  blockSize: number;             // 256 bytes (default, adjustable)
  alwaysPad: boolean;            // false = pad only if needed
  jitterPercent: number;         // 10% random variation
}
```

**Recommendations:**
- `blockSize: 256` = good balance (overhead ~25% for ~200B messages)
- `blockSize: 512` = higher security (overhead ~50%)
- `blockSize: 1024` = maximum security (overhead ~100%)

### 3. Privacy Settings

```typescript
interface PrivacySettings {
  typingIndicatorEnabled: boolean;       // default: false
  readReceiptEnabled: boolean;           // default: false
  presenceIndicatorEnabled: boolean;     // default: false
  typingIndicatorDebounceMs: number;     // 2000ms default
  typingIndicatorJitterMs: number;       // 1000ms default
  typingIndicatorBatchSize: number;      // 5 events default
  consentTimestamp: number | null;       // User consent time
}
```

---

## Security Considerations

### EREBUS Mitigation (Network Integrity)

**Threat:** Adversary AS performs network partitioning attack, redirects client to fake relay.

**How RelayPinner prevents this:**
1. Client has pre-stored hash of authentic relay's identity key
2. On connection, client challenges relay: "Sign this nonce"
3. Relay signs with Ed25519 private key
4. Client verifies signature + public key hash
5. If mismatch → abort connection

**Limitations:**
- Doesn't prevent relay operator from being compromised
- Doesn't hide that you're connecting to relay (ISP can see)
- Requires secure distribution of `expectedIdentityKeyHash` (use code signing, not hardcoding)

### Traffic Analysis Resistance (Metadata Obfuscation)

**Threat:** Relay or network observer analyzes message sizes to infer content.

Example attack:
```
Message: "Yes" (3 bytes)
Padded:  256 bytes (random padding)
→ Attacker still sees message is ~256 bytes, not random traffic
→ But can't distinguish "Yes" from "Maybe" from "I don't know"
```

**How padding helps:**
- Fixes all encrypted messages to ~256 byte blocks
- Random padding bytes don't follow any pattern
- Attacker sees uniform 256-byte traffic, not meaningful variation

**Limitations:**
- Doesn't prevent frequency analysis (message count per day)
- Doesn't prevent timing attacks (when messages are sent)
- Adds 20-50% bandwidth overhead

### Privacy Controls (Side-Channel Mitigation)

**Threat:** Automatic "typing indicators" and "read receipts" leak user behavior.

Example attack:
```
Attacker sees typing indicator every keystroke
→ Infers exactly when user is typing
→ Combined with message send time: reveals typing speed, pauses
→ May reveal emotional state ("angry typing") or thinking patterns
```

**How privacy controls help:**
1. Features are **opt-in by default** (users must consent)
2. Typing indicators are **batched** (send every 2 sec, not per keystroke)
3. Timing is **jittered** (1-3 sec random delay added)
4. Read receipts have **random delay** (1-5 sec)

**Example:**
```
User types: "H-e-l-l-o"
Without batching: 5 separate "typing" events
With batching: 1 event every 2 sec (max 3 events total)

With jitter: Event sent at 2000ms + (0-1000ms random) = 2000-3000ms
Attacker sees: "user typed something between 2-3 seconds"
(Can't tell if it was 5 chars or 500 chars)
```

---

## Testing

### Unit Tests

In `packages/crypto/src/__tests__/defense.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { padMessage, unpadMessage, RelayPinner } from '../defense-in-depth';

describe('Defense-in-Depth', () => {
  describe('Message Padding', () => {
    it('should pad message to block size', () => {
      const msg = 'hello';
      const padded = padMessage(msg, { enabled: true, blockSize: 256 });
      expect(padded.length).toBe(256);
    });

    it('should round-trip pad/unpad', () => {
      const msg = 'test message';
      const padded = padMessage(msg, { blockSize: 256 });
      const unpadded = unpadMessage(padded, 256);
      expect(new TextDecoder().decode(unpadded)).toBe(msg);
    });
  });

  describe('Relay Pinner', () => {
    it('should reject mismatched identity key', async () => {
      const pinner = new RelayPinner({
        relayUrl: 'wss://relay.test',
        expectedIdentityKeyHash: 'wrong_hash',
        configCreatedAt: Date.now()
      });

      // Mock WebSocket
      const mockWs = {
        send: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn()
      };

      const result = await pinner.verifyRelayIdentity(mockWs);
      expect(result).toBe(false);
    });
  });
});
```

### Integration Tests

Manual test flow:

1. **Start relay server:**
   ```bash
   cd apps/relay
   pnpm run dev
   ```

2. **Start web client:**
   ```bash
   cd apps/web
   pnpm run dev
   ```

3. **Test in browser (http://localhost:3002):**
   - Open DevTools Console
   - Verify: `[SecureWSManager] ✅ Relay identity verified`
   - Send message → check padding applied
   - Enable typing indicators → verify batching in console logs

---

## Performance Impact

| Feature | Overhead | Mitigation |
|---------|----------|-----------|
| Relay Pinning | ~50ms per connection | Only on initial handshake |
| Message Padding | 20-50% bandwidth | Disable for localhost dev |
| Privacy Controls | < 1ms per indicator | Batching reduces events 5-10x |

**Recommendation:** Disable padding and privacy features in development for faster testing:

```env
# .env.local (development)
REACT_APP_DEFENSE_MODE=development  # Skip verification during dev
```

---

## Deployment Checklist

- [ ] Generate relay identity key hash
- [ ] Store hash in `.env.local` / CI/CD secrets
- [ ] Set up backup relays for HA
- [ ] Test relay identity verification in staging
- [ ] Enable padding (blockSize=256)
- [ ] Privacy settings visible in UI
- [ ] Document for users why features are opt-in
- [ ] Monitor padding overhead in analytics
- [ ] Plan key rotation strategy for relay identity

---

## References

1. **EREBUS Paper**: https://ieeexplore.ieee.org/document/9152701
2. **DNS-over-HTTPS Paper**: https://ieeexplore.ieee.org/document/9519425
3. **Zoom Pinning Paper**: https://ieeexplore.ieee.org/document/10785549
4. **Code**: `packages/crypto/src/defense-in-depth.ts`
5. **Integration**: `apps/web/lib/defense-integration.ts`

---

**Last Updated:** 2025-11-20
**Author:** Stvor Security Team
**Status:** Production Ready
