/**
 * Ilyazh-Web3E2E Protocol Implementation
 * Export public API
 */

export * from './constants.js';
export * from './primitives.js';
export * from './handshake.js';
export * from './ratchet.js';
export * from './wire.js';
export * from './skipped-keys.js';
export * from './group-chat.js';

// ============================================================================
// Security Detection Functions (Defense-in-Depth)
// ============================================================================

export { isPQReallyUnavailable } from './primitives.js';

// ============================================================================
// Defense-in-Depth Security Module (KAIST NetS&P Lab)
// @see https://ieeexplore.ieee.org/document/9152701 (EREBUS)
// @see https://ieeexplore.ieee.org/document/9519425 (DNS-over-HTTPS Privacy)
// @see Zoom Pinning (2024 IEEE EuroS&PW)
// ============================================================================

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
  initializeDefenseInDepth,
  type DefenseInDepthConfig
} from './defense-in-depth.js';

// Version
export const PROTOCOL_VERSION_STRING = '0.9.0-beta';
export const PROTOCOL_NAME = 'Ilyazh-Web3E2E';
export const SUPPORTS_GROUP_CHAT = true;
