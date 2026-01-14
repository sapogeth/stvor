/**
 * Relay Security Module - Network Integrity & Identity Verification
 * 
 * This module provides relay server authentication and network integrity
 * verification, preventing man-in-the-middle and network partitioning attacks.
 * 
 * ARCHITECTURE:
 * - Re-exports RelayPinner from @ilyazh/crypto package
 * - Provides clear namespace separation from Web Crypto API
 * - No confusion with globalThis.crypto or require('crypto')
 * 
 * @see EREBUS (Kang et al., 2020): Network partitioning attacks
 * @see packages/crypto/src/defense-in-depth.ts for implementation
 */

// Re-export RelayPinner and related types from crypto package
export {
  RelayPinner,
  type RelayIdentityConfig,
  type PaddingConfig,
  type PrivacySettings,
  type PrivacyConfigManager,
  DEFAULT_PADDING_CONFIG,
  DEFAULT_PRIVACY_SETTINGS,
  padMessage,
  unpadMessage,
  encryptWithPadding,
  decryptWithUnpadding,
  initializeDefenseInDepth,
  type DefenseInDepthConfig,
} from '@ilyazh/crypto';
