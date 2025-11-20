/**
 * Browser-safe PQ loader (npm-first, hard-fail on unavailable)
 * NO ../../../../dist references, NO import.meta, NO HTTP imports
 * NO inline stubs - stubs are cryptographically worthless
 */

import type { MLKEM768, MLDSA65 } from '@openforge-sh/liboqs';

let mlkem768Instance: MLKEM768 | null = null;
let mldsa65Instance: MLDSA65 | null = null;
let ML_KEM_768_INFO_INSTANCE: any = null;
let ML_DSA_65_INFO_INSTANCE: any = null;
let pqAvailable = false;
let pqReallyUnavailable = false; // CRITICAL: true if using inline stubs OR real PQ failed to load

export async function initPQBrowser(): Promise<{ pqAvailable: boolean; pqReallyUnavailable: boolean }> {
  if (pqAvailable && mlkem768Instance && mldsa65Instance && !pqReallyUnavailable) {
    return { pqAvailable: true, pqReallyUnavailable: false };
  }

  // Strategy 1: Try npm-installed @openforge-sh/liboqs (REAL PQ CRYPTO)
  try {
    console.log('[PQ Browser] Attempting npm module load...');
    const { createMLKEM768, ML_KEM_768_INFO, createMLDSA65, ML_DSA_65_INFO } = await import('@openforge-sh/liboqs');

    mlkem768Instance = await createMLKEM768();
    mldsa65Instance = await createMLDSA65();
    ML_KEM_768_INFO_INSTANCE = ML_KEM_768_INFO;
    ML_DSA_65_INFO_INSTANCE = ML_DSA_65_INFO;

    // CRITICAL: Validate that keys are NOT all zeros (stub detection)
    const testKeyPair = await mlkem768Instance.generateKeyPair();
    const isZeros = testKeyPair.publicKey.every((b: number) => b === 0);

    if (isZeros) {
      console.error('[PQ Browser] 🚨 SECURITY: ML-KEM public key is all zeros - stub detected, rejecting');
      throw new Error('ML-KEM stub detected (all-zero key)');
    }

    pqAvailable = true;
    pqReallyUnavailable = false;

    console.log('[PQ Browser] ✅ Loaded REAL PQ from npm (@openforge-sh/liboqs)');
    return { pqAvailable: true, pqReallyUnavailable: false };
  } catch (npmError) {
    console.error('[PQ Browser] npm load failed or stub detected:', npmError);

    // DO NOT try inline fallback - inline stubs are cryptographically worthless
    // Hard-fail instead
    pqAvailable = false;
    pqReallyUnavailable = true; // CRITICAL: Mark as unusable

    console.error('[PQ Browser] 🚨 CRITICAL: PQ cryptography is UNAVAILABLE');
    console.error('[PQ Browser] 🚨 Post-quantum protection FAILED - application must refuse to create sessions');
    console.error('[PQ Browser] Error details:', npmError);

    return { pqAvailable: false, pqReallyUnavailable: true };
  }
}

export function getPQ(): { mlkem768: MLKEM768 | null; mldsa65: MLDSA65 | null; mlkemInfo: any; mldsaInfo: any } {
  return {
    mlkem768: mlkem768Instance,
    mldsa65: mldsa65Instance,
    mlkemInfo: ML_KEM_768_INFO_INSTANCE,
    mldsaInfo: ML_DSA_65_INFO_INSTANCE
  };
}

export function isPQAvailable(): boolean {
  return pqAvailable;
}

export function isPQReallyUnavailable(): boolean {
  return pqReallyUnavailable;
}
