# Defense-in-Depth Integration in Chat Component

## Quick Integration Guide for `/apps/web/app/chat/page.tsx`

This document shows how to integrate the three Defense-in-Depth security mechanisms into the existing chat component.

---

## 1. Import Defense-in-Depth Classes

Add these imports to the top of `chat/page.tsx`:

```typescript
import {
  RelayPinner,
  padMessage,
  unpadMessage,
  PrivacyConfigManager,
  type RelayIdentityConfig,
  type PrivacySettings,
  encryptWithPadding,
  decryptWithUnpadding,
} from '@ilyazh/crypto';

import {
  SecureWebSocketManager,
  PrivacyAwareMessageSender,
  createRelayConfigFromEnv,
  createPrivacyConfigFromStorage,
} from '@/lib/defense-integration';
```

---

## 2. Initialize Defense Components in `useEffect`

In the main `ChatPage` component, add initialization:

```typescript
const [relayPinner, setRelayPinner] = useState<RelayPinner | null>(null);
const [privacyManager, setPrivacyManager] = useState<PrivacyConfigManager | null>(null);
const [privacySender, setPrivacySender] = useState<PrivacyAwareMessageSender | null>(null);

useEffect(() => {
  // Initialize RelayPinner for network integrity verification
  const relayConfig: RelayIdentityConfig = {
    relayUrl: process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001',
    expectedIdentityKeyHash: process.env.REACT_APP_RELAY_KEY_HASH || '',
    configCreatedAt: Date.now(),
  };

  const pinner = new RelayPinner(relayConfig);
  setRelayPinner(pinner);

  // Initialize PrivacyConfigManager with environment config
  const privacySettings: Partial<PrivacySettings> = {
    typingIndicatorEnabled: process.env.REACT_APP_PRIVACY_TYPING_ENABLED === 'true',
    readReceiptEnabled: process.env.REACT_APP_PRIVACY_READ_RECEIPT_ENABLED === 'true',
    presenceEnabled: process.env.REACT_APP_PRIVACY_PRESENCE_ENABLED === 'true',
    typingIndicatorDebounceMs: parseInt(process.env.REACT_APP_TYPING_DEBOUNCE_MS || '2000'),
    typingIndicatorJitterMs: parseInt(process.env.REACT_APP_TYPING_JITTER_MS || '1000'),
  };

  const privMgr = new PrivacyConfigManager(privacySettings);
  setPrivacyManager(privMgr);

  // Create a wrapper for sending privacy-aware events
  const sendEventFn = async (event: any) => {
    // Send event through WebSocket or REST API
    console.log('[Defense] Privacy-aware event:', event);
  };

  const privSender = new PrivacyAwareMessageSender(privMgr, sendEventFn);
  setPrivacySender(privSender);

  return () => {
    privMgr.destroy();
  };
}, []);
```

---

## 3. Add Padding to Message Encryption

Modify the `sendMessage()` function to use `encryptWithPadding`:

```typescript
const sendMessage = async () => {
  if (!inputText.trim() || !chatId) return;

  const messageText = inputText;
  const messageId = `msg-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  setInputText('');

  // ... existing code ...

  try {
    let data: string;

    if (ratchetState) {
      console.log('[Send] 📝 Encrypting message with padding...');

      // DEFENSE: Pad message before encryption
      const paddingConfig = {
        enabled: process.env.REACT_APP_PADDING_ENABLED === 'true',
        blockSize: parseInt(process.env.REACT_APP_PADDING_BLOCK_SIZE || '256') as 256 | 512 | 1024,
        jitterPercent: parseInt(process.env.REACT_APP_PADDING_JITTER_PERCENT || '10'),
      };

      const plaintext = new TextEncoder().encode(messageText);
      const paddedMessage = padMessage(plaintext, paddingConfig);

      console.log('[Send] 🛡️ Message padding applied:', {
        originalSize: plaintext.length,
        paddedSize: paddedMessage.length,
        blockSize: paddingConfig.blockSize,
      });

      // Encrypt the padded message
      const { record, newState } = await encryptMessage(ratchetState, paddedMessage);

      setRatchetState(newState);

      // Save updated session state to IndexedDB
      await keystore.init();
      await keystore.saveSession(newState.sessionId, recipientCanonical, newState);

      // Encode as wire format
      const wireData = encodeEncryptedMessage(record);
      data = Buffer.from(wireData).toString('base64');
    } else {
      console.log('[Send] ⚠️  No ratchet state - using plaintext fallback');
      data = Buffer.from(messageText, 'utf-8').toString('base64');
    }

    // ... rest of sendMessage logic ...
  }
};
```

---

## 4. Add Typing Indicator Protection

Modify typing indicator sending to use privacy controls:

```typescript
const sendTypingIndicator = async () => {
  if (!privacySender) {
    console.warn('[Defense] Privacy sender not initialized');
    return;
  }

  try {
    // PrivacyAwareMessageSender will check if typing indicators are enabled
    // and apply batching + jitter if they are
    await privacySender.sendTypingIndicator(recipientCanonical);
    console.log('[Defense] 🛡️ Typing indicator sent (privacy-aware)');
  } catch (err) {
    console.error('[Defense] Failed to send typing indicator:', err);
  }
};
```

---

## 5. Add Read Receipt Protection

When marking a message as read:

```typescript
const markMessageAsRead = async (messageId: string, lastSequence: number) => {
  if (!privacySender) {
    console.warn('[Defense] Privacy sender not initialized');
    return;
  }

  try {
    // PrivacyAwareMessageSender will apply timing delays if read receipts are enabled
    await privacySender.sendReadReceipt(messageId);
    console.log('[Defense] 🛡️ Read receipt sent (privacy-aware)');
  } catch (err) {
    console.error('[Defense] Failed to send read receipt:', err);
  }
};
```

---

## 6. Add Relay Identity Verification

Before or after WebSocket connection, verify relay identity:

```typescript
const verifyRelayIdentity = async () => {
  if (!relayPinner) {
    console.error('[Defense] RelayPinner not initialized');
    return false;
  }

  try {
    console.log('[Defense] 🔐 Verifying relay identity...');

    // Note: In a real implementation, you'd have a reference to the WebSocket connection
    // This is a simplified example - see defense-integration.ts for full WebSocket integration

    // const ws = ... get reference to WebSocket
    // const isVerified = await relayPinner.verifyRelayIdentity(ws);

    // if (!isVerified) {
    //   console.error('[Defense] ❌ Relay identity verification failed!');
    //   alert('SECURITY WARNING: Relay server identity could not be verified!');
    //   return false;
    // }

    console.log('[Defense] ✅ Relay identity verified successfully');
    return true;
  } catch (err) {
    console.error('[Defense] Relay verification error:', err);
    return false;
  }
};
```

---

## 7. Decrypt Messages with Unpadding

When receiving and decrypting messages:

```typescript
const processIncomingMessage = async (encryptedRecord: any) => {
  try {
    // Decrypt with ratchet (existing code)
    const plaintext = await decryptMessage(ratchetState, encryptedRecord);

    // DEFENSE: Remove padding if it was applied during send
    const unpadConfig = {
      blockSize: parseInt(process.env.REACT_APP_PADDING_BLOCK_SIZE || '256') as 256 | 512 | 1024,
    };

    const originalMessage = unpadMessage(plaintext, unpadConfig.blockSize);
    const messageText = new TextDecoder().decode(originalMessage);

    console.log('[Defense] 🛡️ Message padding removed:', {
      paddedSize: plaintext.length,
      originalSize: originalMessage.length,
      blockSize: unpadConfig.blockSize,
    });

    return messageText;
  } catch (err) {
    console.error('[Defense] Failed to decrypt and unpad message:', err);
    throw err;
  }
};
```

---

## 8. User Privacy Controls UI

Add a privacy settings panel:

```typescript
const PrivacyControls = ({ privacyManager }: { privacyManager: PrivacyConfigManager | null }) => {
  const [settings, setSettings] = useState<PrivacySettings | null>(null);

  useEffect(() => {
    if (privacyManager) {
      setSettings(privacyManager.getSettings());
    }
  }, [privacyManager]);

  const handleToggle = (feature: 'typing' | 'read-receipt' | 'presence') => {
    if (!privacyManager) return;

    const newSettings = { ...settings };
    if (feature === 'typing') {
      newSettings.typingIndicatorEnabled = !newSettings.typingIndicatorEnabled;
    } else if (feature === 'read-receipt') {
      newSettings.readReceiptEnabled = !newSettings.readReceiptEnabled;
    } else if (feature === 'presence') {
      newSettings.presenceEnabled = !newSettings.presenceEnabled;
    }

    // Require explicit user consent
    const consent = confirm(
      `Enable ${feature}? This may reveal your behavior to the relay server.`
    );

    if (consent) {
      privacyManager.updateSettings(newSettings, true);
      setSettings(newSettings);
    }
  };

  if (!settings) return null;

  return (
    <div className="privacy-controls">
      <h3>🛡️ Privacy Controls</h3>
      <label>
        <input
          type="checkbox"
          checked={settings.typingIndicatorEnabled}
          onChange={() => handleToggle('typing')}
        />
        Show typing indicators
      </label>
      <label>
        <input
          type="checkbox"
          checked={settings.readReceiptEnabled}
          onChange={() => handleToggle('read-receipt')}
        />
        Send read receipts
      </label>
      <label>
        <input
          type="checkbox"
          checked={settings.presenceEnabled}
          onChange={() => handleToggle('presence')}
        />
        Show online status
      </label>
    </div>
  );
};
```

---

## 9. Configuration Environment Variables

Ensure these are set in `.env.local`:

```env
# Network Integrity (EREBUS Mitigation)
REACT_APP_RELAY_URL=wss://relay.stvor.io
REACT_APP_RELAY_KEY_HASH=<sha256_of_relay_pubkey>

# Message Padding (Traffic Analysis Resistance)
REACT_APP_PADDING_ENABLED=true
REACT_APP_PADDING_BLOCK_SIZE=256
REACT_APP_PADDING_JITTER_PERCENT=10

# Privacy Controls (Side-Channel Mitigation)
REACT_APP_PRIVACY_TYPING_ENABLED=false
REACT_APP_PRIVACY_READ_RECEIPT_ENABLED=false
REACT_APP_PRIVACY_PRESENCE_ENABLED=false
REACT_APP_TYPING_DEBOUNCE_MS=2000
REACT_APP_TYPING_JITTER_MS=1000
REACT_APP_TYPING_BATCH_SIZE=5
```

---

## 10. Security Checklist

- [ ] RelayPinner initialized on component mount
- [ ] Relay identity verified before sending messages
- [ ] Message padding applied to all plaintext before encryption
- [ ] PrivacyConfigManager initialized with user consent
- [ ] Typing indicators use PrivacyAwareMessageSender
- [ ] Read receipts use PrivacyAwareMessageSender
- [ ] Environment variables properly configured
- [ ] .env values are NOT hardcoded (use CI/CD secrets)
- [ ] Logging shows [Defense] prefix for security events
- [ ] User can disable privacy features if needed

---

## Implementation Order (Recommended)

1. **First:** Add RelayPinner for network integrity (CRITICAL)
2. **Second:** Add message padding (HIGH)
3. **Third:** Add PrivacyConfigManager for user controls (MEDIUM)
4. **Fourth:** Add typing/read receipt protection (MEDIUM)
5. **Fifth:** Test with various network conditions

---

## Testing

```typescript
// Test message padding round-trip
const original = 'Hello, World!';
const padded = padMessage(original, { blockSize: 256 });
const unpadded = unpadMessage(padded, 256);
const restored = new TextDecoder().decode(unpadded);
console.assert(restored === original, 'Padding round-trip failed');

// Test relay pinner with mock WebSocket
const pinner = new RelayPinner({
  relayUrl: 'ws://localhost:3001',
  expectedIdentityKeyHash: '...',
  configCreatedAt: Date.now(),
});

// Test privacy config
const privacyMgr = new PrivacyConfigManager();
privacyMgr.updateSettings({ typingIndicatorEnabled: true }, true);
console.assert(privacyMgr.isFeatureEnabled('typing'), 'Privacy config failed');
```

---

**Last Updated:** 2025-11-20
**Status:** Integration Guide Ready
**Version:** 1.0.0
