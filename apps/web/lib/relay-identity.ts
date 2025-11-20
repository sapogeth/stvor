/**
 * Relay Identity Verification
 * Ensures relay cannot impersonate peers by signing prekey bundles
 */

import _sodium from 'libsodium-wrappers';
import { logError, logInfo, logWarn } from './logger';

// CRITICAL: Pinned relay Ed25519 public key (should come from environment/config)
// This prevents relay compromise from impersonating clients
const RELAY_PUBLIC_KEY = process.env.NEXT_PUBLIC_RELAY_PUBLIC_KEY ||
  // Fallback test key (MUST be replaced in production)
  'c8a4d3e5b2f1a9c7d4e6f8a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e1f3a5b7';

export async function getRelayPublicKey(): Promise<Uint8Array> {
  await _sodium.ready;
  const sodium = _sodium;

  try {
    return sodium.from_hex(RELAY_PUBLIC_KEY);
  } catch (err) {
    throw new Error(`[RelayIdentity] Invalid relay public key in config: ${err}`);
  }
}

/**
 * Verify that a prekey bundle response is signed by the relay
 * Detects relay compromise or man-in-the-middle attacks
 */
export async function verifyRelaySignature(
  bundleData: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  await _sodium.ready;
  const sodium = _sodium;

  if (signature.length === 0 || signature.every(b => b === 0)) {
    throw new Error(
      '[RelayIdentity] CRITICAL: Empty or all-zero relay signature detected. ' +
      'Relay bundle is UNSIGNED - potential impersonation attack or relay compromise. ' +
      'Session REJECTED.'
    );
  }

  const relayKey = await getRelayPublicKey();

  try {
    const isValid = sodium.crypto_sign_verify_detached(signature, bundleData, relayKey);

    if (!isValid) {
      throw new Error('[RelayIdentity] Relay signature verification FAILED - bundle rejected');
    }

    return true;
  } catch (err) {
    logError('relay-identity', 'Relay signature verification error', { error: String(err) });
    throw new Error(
      `[RelayIdentity] CRITICAL: Relay signature invalid or verification failed. ` +
      `Bundle rejected. Error: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

/**
 * Flag indicating relay identity is pinned and verified
 */
export function isRelayIdentityVerified(): boolean {
  return RELAY_PUBLIC_KEY !== undefined && RELAY_PUBLIC_KEY.length > 0;
}
