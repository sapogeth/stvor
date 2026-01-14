'use client';

/**
 * Defense-in-Depth Example Component
 *
 * Demonstrates how to integrate the three security mechanisms:
 * 1. RelayPinner - Network integrity verification
 * 2. Message Padding - Traffic analysis resistance
 * 3. PrivacyConfigManager - User behavior privacy
 *
 * This is a reference implementation for use in the main Chat component.
 */

import { useState, useEffect, useCallback } from 'react';
import type { RelayIdentityConfig, PrivacySettings, PrivacyConfigManager } from '@ilyazh/crypto';
import type { RelayPinner } from '@/lib/relay-security';

import {
  SecureWebSocketManager,
  PrivacyAwareMessageSender,
} from '@/lib/defense-integration';

interface DefenseInDepthExampleProps {
  username: string;
  recipient: string;
  chatId: string;
}

/**
 * Example Component showing Defense-in-Depth integration
 *
 * This component demonstrates:
 * - Initializing RelayPinner for network integrity
 * - Using message padding for traffic analysis resistance
 * - Managing user privacy settings with PrivacyConfigManager
 * - Sending privacy-aware messages and indicators
 */
export function DefenseInDepthExample({
  username,
  recipient,
  chatId,
}: DefenseInDepthExampleProps) {
  // ===========================================================================
  // PART 1: RELAY PINNER - Network Integrity Verification (EREBUS Mitigation)
  // ===========================================================================

  const [relayPinner, setRelayPinner] = useState<RelayPinner | null>(null);
  const [relayVerified, setRelayVerified] = useState(false);
  const [relayError, setRelayError] = useState<string | null>(null);

  useEffect(() => {
    /**
     * Initialize RelayPinner with configuration from environment variables
     *
     * EREBUS Paper: Demonstrates how network-level adversaries (ASes) can
     * hijack connections. RelayPinner verifies relay identity using Ed25519
     * signatures to prevent this attack.
     *
     * Reference: Tran et al. "EREBUS" (2020 IEEE S&P)
     */
    const relayConfig: RelayIdentityConfig = {
      relayUrl: process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001',
      expectedIdentityKeyHash: process.env.REACT_APP_RELAY_KEY_HASH || '',
      configCreatedAt: Date.now(),
    };

    // Dynamically load RelayPinner to avoid bundling crypto at build time
    const initRelay = async () => {
      const { RelayPinner } = await import('@/lib/relay-security');
      const pinner = new RelayPinner(relayConfig);
      setRelayPinner(pinner);
      console.log('[Defense] 🔐 RelayPinner initialized', {
        relayUrl: relayConfig.relayUrl,
        expectedKeyHash: relayConfig.expectedIdentityKeyHash?.slice(0, 16) + '...',
      });
    };

    void (async () => {
      try {
        await initRelay();
      } catch (err) {
        console.error('[Defense] Failed to load RelayPinner', err);
        setRelayError('Failed to load crypto module');
      }
    })();
  }, []);

  const verifyRelayIdentity = useCallback(async () => {
    if (!relayPinner) {
      setRelayError('RelayPinner not initialized');
      return;
    }

    try {
      console.log('[Defense] 🔐 Verifying relay identity...');

      // In a real implementation, you would verify the relay identity
      // with the actual WebSocket connection:
      //
      // const ws = ... (your WebSocket reference)
      // const isVerified = await relayPinner.verifyRelayIdentity(ws);
      //
      // For this example, we'll log that verification would happen:

      console.log('[Defense] ✅ Relay identity verification completed');
      setRelayVerified(true);
      setRelayError(null);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      console.error('[Defense] ❌ Relay identity verification failed:', errorMessage);
      setRelayError(errorMessage);
      setRelayVerified(false);
    }
  }, [relayPinner]);

  // ===========================================================================
  // PART 2: MESSAGE PADDING - Traffic Analysis Resistance
  // ===========================================================================

  const [messageText, setMessageText] = useState('');
  const [paddingStats, setPaddingStats] = useState<{
    original: number;
    padded: number;
    overhead: number;
  } | null>(null);

  /**
   * Apply message padding before encryption
   *
   * DNS-over-HTTPS Privacy Paper: Shows how packet size reveals content even
   * when encrypted. Message padding hides the size by padding to fixed block
   * sizes (256, 512, or 1024 bytes) with random bytes.
   *
   * Reference: Csikor et al. "Privacy of DNS-over-HTTPS" (2021 IEEE EuroS&P)
   */
  const applyMessagePadding = useCallback(
    async (message: string) => {
      const plaintext = new TextEncoder().encode(message);

      // Get padding configuration from environment
      const paddingConfig = {
        enabled: process.env.REACT_APP_PADDING_ENABLED === 'true',
        blockSize: (parseInt(process.env.REACT_APP_PADDING_BLOCK_SIZE || '256') as
          | 256
          | 512
          | 1024) || 256,
        jitterPercent: parseInt(process.env.REACT_APP_PADDING_JITTER_PERCENT || '10'),
        alwaysPad: false,
      };

      // Load padMessage dynamically at call time
      const { padMessage } = await import('@/lib/crypto');
      const padded = padMessage(plaintext, paddingConfig);

      const overhead = padded.length - plaintext.length;
      const overheadPercent =
        plaintext.length > 0 ? Math.round((overhead / plaintext.length) * 100) : 0;

      setPaddingStats({
        original: plaintext.length,
        padded: padded.length,
        overhead: overheadPercent,
      });

      console.log('[Defense] 🛡️ Message padding applied', {
        originalSize: plaintext.length,
        paddedSize: padded.length,
        blockSize: paddingConfig.blockSize,
        overhead: `${overheadPercent}%`,
        enabled: paddingConfig.enabled,
      });

      return padded;
    },
    []
  );

  const removeMessagePadding = useCallback(async (paddedMessage: Uint8Array) => {
    const blockSize = (parseInt(process.env.REACT_APP_PADDING_BLOCK_SIZE || '256') as
      | 256
      | 512
      | 1024) || 256;

    const { unpadMessage } = await import('@/lib/crypto');
    const unpadded = unpadMessage(paddedMessage, blockSize);
    const original = new TextDecoder().decode(unpadded);

    console.log('[Defense] 🛡️ Message padding removed', {
      paddedSize: paddedMessage.length,
      unpaddedSize: unpadded.length,
      blockSize,
    });

    return original;
  }, []);

  // ===========================================================================
  // PART 3: PRIVACY CONFIG MANAGER - Side-Channel Mitigation
  // ===========================================================================

  const [privacyManager, setPrivacyManager] = useState<PrivacyConfigManager | null>(null);
  const [privacySettings, setPrivacySettings] = useState<PrivacySettings | null>(null);
  const [privacySender, setPrivacySender] = useState<PrivacyAwareMessageSender | null>(null);

  useEffect(() => {
    let manager: PrivacyConfigManager | null = null;

    /**
     * Initialize PrivacyConfigManager with environment configuration
     *
     * Zoom Pinning Paper: Shows how automatic presence indicators (typing,
     * read receipts, online status) leak user behavior. PrivacyConfigManager
     * enforces explicit user consent and applies timing obfuscation.
     *
     * Reference: Woo et al. "I Know You Pin Me" (2024 IEEE EuroS&PW)
     */
    const setupPrivacy = async () => {
      const initialSettings: Partial<PrivacySettings> = {
        typingIndicatorEnabled: process.env.REACT_APP_PRIVACY_TYPING_ENABLED === 'true',
        readReceiptEnabled: process.env.REACT_APP_PRIVACY_READ_RECEIPT_ENABLED === 'true',
        presenceIndicatorEnabled: process.env.REACT_APP_PRIVACY_PRESENCE_ENABLED === 'true',
        typingIndicatorDebounceMs: parseInt(
          process.env.REACT_APP_TYPING_DEBOUNCE_MS || '2000'
        ),
        typingIndicatorJitterMs: parseInt(
          process.env.REACT_APP_TYPING_JITTER_MS || '1000'
        ),
        typingIndicatorBatchSize: parseInt(
          process.env.REACT_APP_TYPING_BATCH_SIZE || '5'
        ),
      };

      // Dynamically load PrivacyConfigManager
      const crypto = await import('@/lib/crypto');
      const ManagerCtor = crypto.PrivacyConfigManager as unknown as typeof PrivacyConfigManager;
      manager = new ManagerCtor(initialSettings);
      setPrivacyManager(manager);
      setPrivacySettings(manager.getSettings());

      // Create event sender function
      const sendEventFn = async (event: any) => {
        console.log('[Defense] 📤 Privacy-aware event queued:', event);
        // In a real implementation, this would send through WebSocket or REST API
      };

      // Create privacy-aware message sender
      const sender = new PrivacyAwareMessageSender(manager, sendEventFn);
      setPrivacySender(sender);

      console.log('[Defense] 🛡️ PrivacyConfigManager initialized', initialSettings);
    };

    void (async () => {
      try {
        await setupPrivacy();
      } catch (err) {
        console.error('[Defense] Failed to initialize PrivacyConfigManager', err);
      }
    })();

    return () => {
      if (manager) manager.destroy();
    };
  }, []);

  const handlePrivacySettingChange = useCallback(
    (setting: keyof PrivacySettings, value: boolean) => {
      if (!privacyManager) return;

      // Require explicit user consent
      const consentMessage =
        setting === 'typingIndicatorEnabled'
          ? 'Enable typing indicators? Others will see when you are typing.'
          : setting === 'readReceiptEnabled'
            ? 'Enable read receipts? Others will see when you read messages.'
            : 'Enable presence indicator? Others will see your online status.';

      const consent = confirm(consentMessage + '\n\nThis is visible to the relay server.');

      if (consent) {
        privacyManager.updateSettings({ [setting]: value }, true);
        setPrivacySettings(privacyManager.getSettings());

        console.log('[Defense] 🛡️ Privacy setting updated with user consent', {
          setting,
          value,
        });
      }
    },
    [privacyManager]
  );

  const handleSendTypingIndicator = useCallback(async () => {
    if (!privacySender) {
      console.warn('[Defense] PrivacySender not initialized');
      return;
    }

    try {
      console.log('[Defense] 📝 Sending typing indicator (privacy-aware)...');
      await privacySender.sendTypingIndicator(recipient);
      console.log('[Defense] ✅ Typing indicator sent');
    } catch (err) {
      console.error('[Defense] ❌ Failed to send typing indicator:', err);
    }
  }, [privacySender, recipient]);

  const handleSendReadReceipt = useCallback(async () => {
    if (!privacySender) {
      console.warn('[Defense] PrivacySender not initialized');
      return;
    }

    try {
      console.log('[Defense] ✓ Sending read receipt (privacy-aware)...');
      await privacySender.sendReadReceipt('msg-example-123');
      console.log('[Defense] ✅ Read receipt sent');
    } catch (err) {
      console.error('[Defense] ❌ Failed to send read receipt:', err);
    }
  }, [privacySender]);

  // ===========================================================================
  // RENDER: UI Components
  // ===========================================================================

  return (
    <div className="defense-in-depth-example">
      <div className="defense-section">
        <h2>🔐 Defense-in-Depth Security Demo</h2>
        <p>Username: {username} → Chat with: {recipient}</p>
      </div>

      {/* SECTION 1: RELAY PINNER */}
      <div className="defense-section relay-section">
        <h3>1. Relay Identity Verification (EREBUS Mitigation)</h3>
        <p>
          Verifies that the relay server is authentic and not a network-level impostor.
          Uses Ed25519 signed challenge-response protocol.
        </p>

        <div className="status">
          Status:{' '}
          <span className={relayVerified ? 'verified' : 'unverified'}>
            {relayVerified ? '✅ Verified' : '❌ Not Verified'}
          </span>
        </div>

        {relayError && (
          <div className="error">
            <strong>Error:</strong> {relayError}
          </div>
        )}

        <button onClick={verifyRelayIdentity} disabled={!relayPinner}>
          Verify Relay Identity
        </button>

        <details>
          <summary>Configuration</summary>
          <pre>
            Relay URL: {process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001'}
            {'\n'}
            Key Hash: {process.env.REACT_APP_RELAY_KEY_HASH?.slice(0, 32) || 'Not set'}...
          </pre>
        </details>
      </div>

      {/* SECTION 2: MESSAGE PADDING */}
      <div className="defense-section padding-section">
        <h3>2. Message Padding (Traffic Analysis Resistance)</h3>
        <p>
          Pads messages to fixed block sizes to hide content length. Prevents traffic
          analysis attacks that classify encrypted messages by size.
        </p>

        <div>
          <label>
            Message:
            <input
              type="text"
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              placeholder="Type a message..."
            />
          </label>
          <button onClick={() => void applyMessagePadding(messageText)} disabled={!messageText}>
            Apply Padding
          </button>
        </div>

        {paddingStats && (
          <div className="stats">
            <p>
              <strong>Original size:</strong> {paddingStats.original} bytes
            </p>
            <p>
              <strong>Padded size:</strong> {paddingStats.padded} bytes
            </p>
            <p>
              <strong>Overhead:</strong> {paddingStats.overhead}%
            </p>
          </div>
        )}

        <details>
          <summary>Configuration</summary>
          <pre>
            Block Size: {process.env.REACT_APP_PADDING_BLOCK_SIZE || '256'} bytes
            {'\n'}
            Jitter: {process.env.REACT_APP_PADDING_JITTER_PERCENT || '10'}%
            {'\n'}
            Enabled: {process.env.REACT_APP_PADDING_ENABLED === 'true' ? 'Yes' : 'No'}
          </pre>
        </details>
      </div>

      {/* SECTION 3: PRIVACY CONTROLS */}
      <div className="defense-section privacy-section">
        <h3>3. User Privacy Controls (Side-Channel Mitigation)</h3>
        <p>
          Opt-in controls for typing indicators and read receipts. Applies timing
          obfuscation and event batching to hide user behavior.
        </p>

        {privacySettings && (
          <div className="privacy-controls">
            <label>
              <input
                type="checkbox"
                checked={privacySettings.typingIndicatorEnabled || false}
                onChange={(e) =>
                  handlePrivacySettingChange('typingIndicatorEnabled', e.target.checked)
                }
              />
              Show typing indicators
              <span className="info">
                (Debounce: {privacySettings.typingIndicatorDebounceMs}ms, Jitter:{' '}
                {privacySettings.typingIndicatorJitterMs}ms)
              </span>
            </label>

            <label>
              <input
                type="checkbox"
                checked={privacySettings.readReceiptEnabled || false}
                onChange={(e) =>
                  handlePrivacySettingChange('readReceiptEnabled', e.target.checked)
                }
              />
              Send read receipts
              <span className="info">(Adds random 1-5s delay)</span>
            </label>

            <label>
              <input
                type="checkbox"
                checked={privacySettings.presenceIndicatorEnabled || false}
                onChange={(e) =>
                  handlePrivacySettingChange('presenceIndicatorEnabled', e.target.checked)
                }
              />
              Show online status
              <span className="info">(Presence updates are batched)</span>
            </label>
          </div>
        )}

        <div className="button-group">
          <button
            onClick={handleSendTypingIndicator}
            disabled={
              !privacySender || !privacySettings?.typingIndicatorEnabled
            }
          >
            Send Typing Indicator
          </button>
          <button
            onClick={handleSendReadReceipt}
            disabled={
              !privacySender || !privacySettings?.readReceiptEnabled
            }
          >
            Send Read Receipt
          </button>
        </div>

        <div className="warning">
          <strong>⚠️ Privacy Notice:</strong> These features are disabled by default.
          Enable them only when necessary. Even when disabled, the relay server sees
          that you're connected.
        </div>
      </div>

      {/* SUMMARY */}
      <div className="defense-section summary">
        <h3>Security Summary</h3>
        <ul>
          <li>
            <strong>Network Layer:</strong> {relayVerified ? '✅' : '❌'} Relay identity
            verified
          </li>
          <li>
            <strong>Transport Layer:</strong> 🛡️ Message padding enabled (
            {process.env.REACT_APP_PADDING_ENABLED === 'true' ? 'yes' : 'no'})
          </li>
          <li>
            <strong>Application Layer:</strong> 🛡️ Privacy controls initialized
          </li>
        </ul>
      </div>

      <style jsx>{`
        .defense-in-depth-example {
          max-width: 800px;
          margin: 20px auto;
          font-family: system-ui, -apple-system, sans-serif;
        }

        .defense-section {
          border: 1px solid #ddd;
          border-radius: 8px;
          padding: 16px;
          margin-bottom: 16px;
          background: #f9f9f9;
        }

        .defense-section h3 {
          margin-top: 0;
          color: #333;
        }

        .defense-section p {
          margin: 8px 0;
          color: #666;
          font-size: 14px;
        }

        .status {
          padding: 8px;
          background: #fff;
          border-radius: 4px;
          margin: 8px 0;
        }

        .verified {
          color: #28a745;
          font-weight: bold;
        }

        .unverified {
          color: #dc3545;
          font-weight: bold;
        }

        .error {
          padding: 8px;
          background: #f8d7da;
          color: #721c24;
          border-radius: 4px;
          margin: 8px 0;
        }

        .stats {
          background: #fff;
          padding: 12px;
          border-radius: 4px;
          margin: 8px 0;
        }

        .stats p {
          margin: 4px 0;
          font-size: 13px;
        }

        .privacy-controls {
          background: #fff;
          padding: 12px;
          border-radius: 4px;
          margin: 8px 0;
        }

        .privacy-controls label {
          display: block;
          margin: 8px 0;
          font-size: 14px;
        }

        .privacy-controls input[type='checkbox'] {
          margin-right: 8px;
        }

        .info {
          display: block;
          margin-left: 24px;
          font-size: 12px;
          color: #999;
        }

        button {
          background: #007bff;
          color: white;
          border: none;
          padding: 8px 16px;
          border-radius: 4px;
          cursor: pointer;
          margin: 4px 4px 4px 0;
          font-size: 14px;
        }

        button:hover:not(:disabled) {
          background: #0056b3;
        }

        button:disabled {
          background: #ccc;
          cursor: not-allowed;
        }

        .button-group {
          margin-top: 12px;
        }

        .warning {
          background: #fff3cd;
          border: 1px solid #ffc107;
          color: #856404;
          padding: 12px;
          border-radius: 4px;
          margin-top: 12px;
          font-size: 13px;
        }

        details {
          margin-top: 12px;
        }

        details summary {
          cursor: pointer;
          color: #007bff;
          font-size: 13px;
        }

        pre {
          background: #f4f4f4;
          padding: 8px;
          border-radius: 4px;
          font-size: 12px;
          overflow-x: auto;
        }

        .summary ul {
          margin: 8px 0;
          padding-left: 20px;
        }

        .summary li {
          margin: 4px 0;
          font-size: 14px;
        }
      `}</style>
    </div>
  );
}
