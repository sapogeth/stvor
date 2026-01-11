/**
 * Defense-in-Depth Integration Layer for Web Client
 *
 * This file demonstrates how to integrate the three security mechanisms
 * into the existing Stvor web application.
 *
 * Integration Points:
 * 1. RelayPinner: On WebSocket connection establishment
 * 2. Message Padding: In crypto layer before encryption
 * 3. PrivacySettings: In message sending and UI state management
 *
 * @see packages/crypto/src/defense-in-depth.ts for implementation details
 */

import type { RelayIdentityConfig, PaddingConfig, PrivacySettings } from '@/lib/crypto';
import * as crypto from '@/lib/crypto';

// ============================================================================
// WebSocket Connection Manager (with Relay Pinning)
// ============================================================================

/**
 * Enhanced WebSocket Manager with Relay Identity Verification
 *
 * Usage:
 * ```typescript
 * const wsManager = new SecureWebSocketManager({
 *   relayUrl: 'wss://relay.example.com',
 *   expectedIdentityKeyHash: 'sha256_hash_of_relay_pubkey...',
 *   configCreatedAt: Date.now()
 * });
 *
 * const ws = await wsManager.connect();
 * // Connection is now verified to be authentic relay
 * ```
 *
 * @see EREBUS (Kang et al., 2020): Network partitioning attacks
 */
export class SecureWebSocketManager {
  private relayPinner: any | null = null;
  private relayConfig: RelayIdentityConfig;
  private ws: WebSocket | null = null;
  private isConnected: boolean = false;
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;
  private reconnectDelayMs: number = 1000;

  constructor(relayConfig: RelayIdentityConfig) {
    this.relayConfig = relayConfig;
  }

  /**
   * Establish secure connection to relay with identity verification
   *
   * @param url - WebSocket URL
   * @returns Promise<WebSocket> - Verified and authenticated connection
   * @throws Error if relay identity verification fails or connection times out
   */
  async connect(url: string): Promise<WebSocket> {
    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(url);

        this.ws.onopen = async () => {
          console.info('[SecureWSManager] WebSocket connected, verifying relay identity...');

          try {
            if (!this.relayPinner) {
              this.relayPinner = new crypto.RelayPinner(this.relayConfig);
            }
            // Verify relay identity
            const isVerified = await this.relayPinner.verifyRelayIdentity(this.ws!);

            if (!isVerified) {
              this.ws?.close();
              reject(new Error('[SecureWSManager] Relay identity verification failed'));
              return;
            }

            console.info('[SecureWSManager] ✅ Relay identity verified, connection secure');
            this.isConnected = true;
            this.reconnectAttempts = 0;
            resolve(this.ws!);
          } catch (error) {
            this.ws?.close();
            reject(new Error(`[SecureWSManager] Verification error: ${String(error)}`));
          }
        };

        this.ws.onerror = (event) => {
          console.error('[SecureWSManager] WebSocket error:', event);
          reject(new Error('[SecureWSManager] WebSocket connection failed'));
        };

        this.ws.onclose = () => {
          console.warn('[SecureWSManager] WebSocket closed');
          this.isConnected = false;
        };
      } catch (error) {
        reject(new Error(`[SecureWSManager] Connection error: ${String(error)}`));
      }
    });
  }

  /**
   * Reconnect with exponential backoff
   */
  async reconnect(url: string): Promise<WebSocket | null> {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('[SecureWSManager] Max reconnect attempts reached');
      return null;
    }

    const delayMs = this.reconnectDelayMs * Math.pow(2, this.reconnectAttempts);
    console.info(`[SecureWSManager] Reconnecting in ${delayMs}ms...`);

    await new Promise(resolve => setTimeout(resolve, delayMs));

    this.reconnectAttempts++;

    try {
      return await this.connect(url);
    } catch (error) {
      console.error('[SecureWSManager] Reconnection failed:', error);
      return this.reconnect(url);
    }
  }

  /**
   * Send message through secure WebSocket
   */
  send(data: string | ArrayBufferLike): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('[SecureWSManager] WebSocket not connected');
    }
    this.ws.send(data);
  }

  /**
   * Close connection
   */
  close(): void {
    if (this.ws) {
      this.ws.close();
      this.isConnected = false;
    }
  }

  /**
   * Check connection status
   */
  isConnectedSecure(): boolean {
    return this.isConnected && this.ws?.readyState === WebSocket.OPEN;
  }

  /**
   * Update relay identity key (e.g., after key rotation)
   */
  updateRelayKey(newKeyHash: string): void {
    this.relayPinner.updateIdentityKey(newKeyHash);
  }
}

// ============================================================================
// Encrypted Message Layer (with Padding)
// ============================================================================

/**
 * Message encryption helper with automatic padding
 *
 * Usage:
 * ```typescript
 * const encryptedMsg = await encryptMessageWithPadding(
 *   'Hello Alice!',
 *   cryptoState,
 *   { enabled: true, blockSize: 256 }
 * );
 * ```
 *
 * @see DNS-over-HTTPS Privacy (Kang et al., 2021): Traffic analysis resistance
 */
export async function encryptMessageWithPadding(
  message: string,
  encryptFn: (data: Uint8Array) => Promise<Uint8Array>,
  paddingConfig?: PaddingConfig
): Promise<Uint8Array> {
  const effectiveConfig: PaddingConfig =
    paddingConfig ?? (crypto.DEFAULT_PADDING_CONFIG as PaddingConfig);
  const paddedMessage = crypto.padMessage(message, effectiveConfig);
  return encryptFn(paddedMessage);
}

/**
 * Message decryption helper with automatic unpadding
 *
 * Usage:
 * ```typescript
 * const plaintext = await decryptMessageWithUnpadding(
 *   ciphertext,
 *   cryptoState
 * );
 * ```
 */
export async function decryptMessageWithUnpadding(
  ciphertext: Uint8Array,
  decryptFn: (data: Uint8Array) => Promise<Uint8Array>,
  blockSize?: number
): Promise<string> {
  const effectiveBlockSize = blockSize ?? crypto.DEFAULT_PADDING_CONFIG.blockSize;
  const plaintext = await decryptFn(ciphertext);
  const unpadded = crypto.unpadMessage(plaintext, effectiveBlockSize);
  return new TextDecoder().decode(unpadded);
}

// ============================================================================
// Privacy Controls Integration
// ============================================================================

/**
 * Privacy-Aware Message Sender
 *
 * Enforces privacy settings before sending messages with presence indicators.
 *
 * Usage:
 * ```typescript
 * const privacySender = new PrivacyAwareMessageSender(
 *   privacyManager,
 *   async (event) => relay.send(JSON.stringify(event))
 * );
 *
 * // User types in message box
 * privacySender.onKeypress('alice', (event) => {
 *   privacySender.sendTypingIndicator(event);
 * });
 *
 * // User clicks "Mark as Read"
 * privacySender.onMessageRead('msg-123', (event) => {
 *   privacySender.sendReadReceipt(event);
 * });
 * ```
 *
 * @see I Know You Pin Me (Woo, Song, Kang, 2024): Privacy-invasive indicators
 */
export class PrivacyAwareMessageSender {
  private privacyManager: any;
  private sendEventFn: (event: any) => Promise<void>;

  constructor(
    privacyManager: any,
    sendEventFn: (event: any) => Promise<void>
  ) {
    this.privacyManager = privacyManager;
    this.sendEventFn = sendEventFn;
  }

  /**
   * Send typing indicator (with user consent and obfuscation)
   *
   * @param recipientId - User being typed to
   * @throws Error if typing indicators are disabled
   */
  async sendTypingIndicator(recipientId: string): Promise<void> {
    await this.privacyManager.sendTypingIndicator(
      recipientId,
      this.sendEventFn
    );
  }

  /**
   * Send read receipt (with timing obfuscation)
   *
   * @param messageId - Message that was read
   * @param additionalDelayMs - Extra delay to add (default: random 1-5s)
   */
  async sendReadReceipt(messageId: string, additionalDelayMs?: number): Promise<void> {
    await this.privacyManager.sendReadReceipt(
      messageId,
      this.sendEventFn,
      additionalDelayMs
    );
  }

  /**
   * Send presence indicator
   *
   * @param status - 'online' | 'away' | 'offline'
   */
  async sendPresenceUpdate(status: 'online' | 'away' | 'offline'): Promise<void> {
    await this.privacyManager.sendPresenceIndicator(status, this.sendEventFn);
  }

  /**
   * Check if typing indicators are enabled
   */
  isTypingIndicatorEnabled(): boolean {
    return this.privacyManager.isFeatureEnabled('typing');
  }

  /**
   * Check if read receipts are enabled
   */
  isReadReceiptEnabled(): boolean {
    return this.privacyManager.isFeatureEnabled('read-receipt');
  }

  /**
   * Update privacy settings with consent
   */
  updatePrivacySettings(
    updates: Partial<PrivacySettings>,
    userConsented: boolean
  ): void {
    this.privacyManager.updateSettings(updates, userConsented);
  }

  /**
   * Cleanup
   */
  destroy(): void {
    this.privacyManager.destroy();
  }
}

// ============================================================================
// Integration Example: Full Chat Message Flow
// ============================================================================

/**
 * Complete example of integrating all three mechanisms
 *
 * @example
 * ```typescript
 * // 1. Initialize secure WebSocket connection
 * const wsManager = new SecureWebSocketManager({
 *   relayUrl: 'wss://relay.stvor.io',
 *   expectedIdentityKeyHash: process.env.REACT_APP_RELAY_KEY_HASH!,
 *   configCreatedAt: Date.now()
 * });
 *
 * const ws = await wsManager.connect('wss://relay.stvor.io/ws');
 *
 * // 2. Initialize privacy settings
 * const privacyManager = new PrivacyConfigManager({
 *   typingIndicatorEnabled: false,
 *   readReceiptEnabled: false,
 *   consentTimestamp: null
 * });
 *
 * const privacySender = new PrivacyAwareMessageSender(
 *   privacyManager,
 *   async (event) => wsManager.send(JSON.stringify(event))
 * );
 *
 * // 3. User enables typing indicators (explicit consent)
 * privacySender.updatePrivacySettings(
 *   { typingIndicatorEnabled: true },
 *   true // User clicked "Allow" button
 * );
 *
 * // 4. User types a message
 * onKeydown = async (e: KeyboardEvent) => {
 *   const messageInput = (e.target as HTMLInputElement).value;
 *   // Send typing indicator (batched + jittered)
 *   await privacySender.sendTypingIndicator('alice');
 *
 *   // Encrypt with padding before sending
 *   const padded = padMessage(messageInput, { blockSize: 256 });
 *   const encrypted = await cryptoState.encryptMessage(padded);
 *   // ... prepare wire message ...
 * };
 *
 * // 5. User clicks "Send"
 * onSendClick = async () => {
 *   const message = messageInput.value;
 *   const paddingConfig: PaddingConfig = {
 *     enabled: true,
 *     blockSize: 256,
 *     alwaysPad: false,
 *     jitterPercent: 10
 *   };
 *
 *   const encrypted = await encryptMessageWithPadding(
 *     message,
 *     cryptoState.encryptMessage,
 *     paddingConfig
 *   );
 *
 *   const wireMsg = {
 *     action: 'message',
 *     to: 'alice',
 *     ciphertext: Buffer.from(encrypted).toString('hex'),
 *     timestamp: Date.now()
 *   };
 *
 *   wsManager.send(JSON.stringify(wireMsg));
 *   privacySender.sendTypingIndicator('alice'); // Stop typing
 * };
 *
 * // 6. Receive message and decrypt
 * ws.onmessage = async (event: MessageEvent) => {
 *   const msg = JSON.parse(event.data);
 *
 *   if (msg.action === 'message') {
 *     const ciphertext = Buffer.from(msg.ciphertext, 'hex');
 *
 *     // Decrypt and unpad
 *     const plaintext = await decryptMessageWithUnpadding(
 *       ciphertext,
 *       cryptoState.decryptMessage,
 *       256
 *     );
 *
 *     displayMessage(msg.from, plaintext);
 *
 *     // Send read receipt (if enabled)
 *     await privacySender.sendReadReceipt(msg.id);
 *   }
 * };
 * ```
 */
export async function exampleFullIntegration() {
  // Placeholder for documentation
  console.info('[DefenseIntegration] See TSDoc example above for full integration pattern');
}

// ============================================================================
// Configuration Builders (for easy setup)
// ============================================================================

/**
 * Create relay pinning config from environment variables
 *
 * @example
 * ```typescript
 * // .env.local
 * REACT_APP_RELAY_URL=wss://relay.stvor.io
 * REACT_APP_RELAY_KEY_HASH=abc123...
 * REACT_APP_RELAY_BACKUP_1_URL=wss://relay-backup.stvor.io
 * REACT_APP_RELAY_BACKUP_1_HASH=def456...
 * ```
 */
export function createRelayConfigFromEnv(): RelayIdentityConfig {
  const relayUrl = process.env.REACT_APP_RELAY_URL;
  const expectedHash = process.env.REACT_APP_RELAY_KEY_HASH;

  if (!relayUrl || !expectedHash) {
    throw new Error(
      '[DefenseIntegration] Missing REACT_APP_RELAY_URL or REACT_APP_RELAY_KEY_HASH'
    );
  }

  const backupRelays = [];
  for (let i = 1; i <= 3; i++) {
    const backupUrl = process.env[`REACT_APP_RELAY_BACKUP_${i}_URL`];
    const backupHash = process.env[`REACT_APP_RELAY_BACKUP_${i}_HASH`];
    if (backupUrl && backupHash) {
      backupRelays.push({ url: backupUrl, expectedIdentityKeyHash: backupHash });
    }
  }

  return {
    relayUrl,
    expectedIdentityKeyHash: expectedHash,
    backupRelays: backupRelays.length > 0 ? backupRelays : undefined,
    tlsCertificateHash: process.env.REACT_APP_RELAY_TLS_HASH,
    configCreatedAt: Date.now()
  };
}

/**
 * Create privacy settings from localStorage
 *
 * @example
 * ```typescript
 * const privacySettings = createPrivacyConfigFromStorage();
 * const manager = new PrivacyConfigManager(privacySettings);
 * ```
 */
export function createPrivacyConfigFromStorage(): PrivacySettings {
  const stored = localStorage.getItem('stvor_privacy_settings');
  if (stored) {
    try {
      return JSON.parse(stored);
    } catch (error) {
      console.warn('[DefenseIntegration] Failed to parse stored privacy settings');
    }
  }
  return {
    typingIndicatorEnabled: false,
    readReceiptEnabled: false,
    presenceIndicatorEnabled: false,
    consentTimestamp: null,
  } as PrivacySettings;
}

/**
 * Save privacy settings to localStorage
 *
 * @example
 * ```typescript
 * privacyManager.updateSettings({ typingIndicatorEnabled: true }, true);
 * savePrivacyConfigToStorage(privacyManager.getSettings());
 * ```
 */
export function savePrivacyConfigToStorage(settings: PrivacySettings): void {
  localStorage.setItem('stvor_privacy_settings', JSON.stringify(settings));
}

// ============================================================================
// Export Summary
// ============================================================================

/**
 * All exports from this integration layer
 */
export const DefenseIntegration = {
  SecureWebSocketManager,
  PrivacyAwareMessageSender,
  encryptMessageWithPadding,
  decryptMessageWithUnpadding,
  createRelayConfigFromEnv,
  createPrivacyConfigFromStorage,
  savePrivacyConfigToStorage
};
