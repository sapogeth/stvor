/**
 * Relay Identity Verification
 * Ensures relay cannot impersonate peers by signing prekey bundles
 */

import { logError, logInfo, logWarn } from './logger';

async function sodiumMod() {
  // Use eval-based dynamic import to prevent bundlers from statically analyzing
  // and pulling libsodium into client bundles.
  const mod = (await (0, eval)(`import('libsodium-wrappers')`)).default as any;
  await mod.ready;
  return mod as any;
}

// CRITICAL SECURITY: Pinned relay Ed25519 public key (MANDATORY from environment)
// This prevents EREBUS/MITM attacks where attacker impersonates the relay
// WITHOUT this key, attacker can substitute arbitrary prekey bundles
const RELAY_PUBLIC_KEY = process.env.NEXT_PUBLIC_RELAY_PUBLIC_KEY;

// SECURITY: FAIL-CLOSED - Relay public key is MANDATORY
// Missing key means we cannot verify relay authenticity
if (!RELAY_PUBLIC_KEY) {
  console.error('[RelayIdentity] ❌ CRITICAL: NEXT_PUBLIC_RELAY_PUBLIC_KEY is not configured');
  console.error('[RelayIdentity]    This must be set in .env.local or environment variables');
  console.error('[RelayIdentity]    The relay public key is essential for EREBUS/MITM attack prevention');
  console.error('[RelayIdentity]    Without it, attacker can impersonate the relay');
  console.error('[RelayIdentity]    Application will REJECT all prekey bundles as untrusted');
}

export async function getRelayPublicKey(): Promise<Uint8Array> {
  const sodium = await sodiumMod();

  // CRITICAL SECURITY: Relay public key is MANDATORY
  // If not configured, verification will always fail (fail-closed)
  if (!RELAY_PUBLIC_KEY) {
    throw new Error(
      '[RelayIdentity] CRITICAL: Relay public key not configured. ' +
      'Set NEXT_PUBLIC_RELAY_PUBLIC_KEY in environment variables. ' +
      'Without this key, relay signature verification is impossible. ' +
      'All prekey bundles will be rejected as unverifiable.'
    );
  }

  try {
    return sodium.from_hex(RELAY_PUBLIC_KEY);
  } catch (err) {
    throw new Error(
      `[RelayIdentity] CRITICAL: Invalid relay public key in config. ` +
      `Must be 64 hex characters (32 bytes). Error: ${err}`
    );
  }
}

/**
 * CRITICAL: Verify that a prekey bundle response is signed by the relay
 * This is MANDATORY for EREBUS/MITM attack prevention
 * If verification fails, bundle is REJECTED (fail-closed)
 *
 * Attack scenario without verification:
 * 1. Attacker intercepts relay response for "bob"
 * 2. Attacker substitutes bob's prekey with attacker's prekey
 * 3. Alice establishes session with attacker (thinking it's bob)
 * 4. Attacker reads all messages between alice and bob
 *
 * With relay signature verification:
 * 1. Alice verifies bundle is signed by relay (using RELAY_PUBLIC_KEY)
 * 2. If signature invalid, bundle is REJECTED
 * 3. Session cannot be established with fake prekeys
 */
export async function verifyRelaySignature(
  bundleData: Uint8Array,
  signature: Uint8Array | undefined
): Promise<boolean> {
  const sodium = await sodiumMod();

  // CRITICAL SECURITY: Check for missing or invalid signature
  if (!signature || signature.length === 0) {
    throw new Error(
      '[RelayIdentity] CRITICAL: Relay signature is missing or empty. ' +
      'Prekey bundle is UNSIGNED - cannot verify relay authenticity. ' +
      'This indicates either relay compromise or EREBUS attack. ' +
      'Bundle REJECTED for security.'
    );
  }

  // Check for all-zero signature (stub/placeholder)
  if (signature.every(b => b === 0)) {
    throw new Error(
      '[RelayIdentity] CRITICAL: Relay signature is all zeros (stub/placeholder). ' +
      'Relay did not sign this bundle properly. ' +
      'This indicates relay misconfiguration or compromise. ' +
      'Bundle REJECTED.'
    );
  }

  // Verify signature length (Ed25519 signatures are 64 bytes)
  if (signature.length !== 64) {
    throw new Error(
      `[RelayIdentity] CRITICAL: Relay signature has invalid length ${signature.length}, expected 64 bytes. ` +
      'Bundle REJECTED.'
    );
  }

  const relayKey = await getRelayPublicKey();

  try {
    const isValid = sodium.crypto_sign_verify_detached(signature, bundleData, relayKey);

    if (!isValid) {
      logError('relay-identity', 'Relay signature verification FAILED', {
        bundleLength: bundleData.length,
        signatureLength: signature.length,
      });
      throw new Error(
        '[RelayIdentity] CRITICAL: Relay signature verification FAILED. ' +
        'Signature does not match bundle content. ' +
        'This is an EREBUS/MITM attack indicator. ' +
        'Bundle REJECTED.'
      );
    }

    logInfo('relay-identity', 'Relay signature verified successfully');
    return true;
  } catch (err) {
    // If verification throws, it's a critical error (not just invalid signature)
    logError('relay-identity', 'Relay signature verification error', {
      error: err instanceof Error ? err.message : String(err),
      bundleLength: bundleData.length,
      signatureLength: signature.length,
    });
    throw new Error(
      `[RelayIdentity] CRITICAL: Relay signature verification error. ` +
      `Bundle REJECTED for security. Error: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

/**
 * Check if relay identity is properly configured for verification
 * CRITICAL: Returns false if relay public key is not configured
 * (meaning all prekey bundles will be rejected)
 */
export function isRelayIdentityVerified(): boolean {
  const configured = RELAY_PUBLIC_KEY !== undefined && RELAY_PUBLIC_KEY.length > 0;

  if (!configured) {
    logWarn(
      'relay-identity',
      'Relay identity NOT verified - public key not configured. ' +
      'All prekey bundles will be rejected as unverifiable.'
    );
  }

  return configured;
}
