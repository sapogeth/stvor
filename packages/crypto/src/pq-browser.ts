/**
 * Browser-safe PQ loader (npm-first, inline-second)
 * NO ../../../../dist references, NO import.meta, NO HTTP imports
 */

import type { MLKEM768, MLDSA65 } from '@openforge-sh/liboqs';

let mlkem768Instance: MLKEM768 | null = null;
let mldsa65Instance: MLDSA65 | null = null;
let ML_KEM_768_INFO_INSTANCE: any = null;
let ML_DSA_65_INFO_INSTANCE: any = null;
let pqAvailable = false;
let pqReallyUnavailable = false; // CRITICAL: true if using inline stubs (not real PQ crypto)

export async function initPQBrowser(): Promise<{ pqAvailable: boolean; pqReallyUnavailable: boolean }> {
  if (pqAvailable && mlkem768Instance && mldsa65Instance) {
    return { pqAvailable: true, pqReallyUnavailable };
  }

  // Strategy 1: Try npm-installed @openforge-sh/liboqs (REAL PQ CRYPTO)
  try {
    console.log('[PQ Browser] Attempting npm module load...');
    const { createMLKEM768, ML_KEM_768_INFO, createMLDSA65, ML_DSA_65_INFO } = await import('@openforge-sh/liboqs');

    mlkem768Instance = await createMLKEM768();
    mldsa65Instance = await createMLDSA65();
    ML_KEM_768_INFO_INSTANCE = ML_KEM_768_INFO;
    ML_DSA_65_INFO_INSTANCE = ML_DSA_65_INFO;
    pqAvailable = true;
    pqReallyUnavailable = false; // Real PQ crypto loaded

    console.log('[PQ Browser] ✅ Loaded REAL PQ from npm (@openforge-sh/liboqs)');
    return { pqAvailable: true, pqReallyUnavailable: false };
  } catch (npmError) {
    console.warn('[PQ Browser] npm load failed (real PQ unavailable):', npmError);

    // Strategy 2: Use inline TypeScript stubs (deterministic but NOT cryptographically secure)
    try {
      console.log('[PQ Browser] Attempting inline fallback (stubs only)...');
      const inline = await import('./pq-inline.js');

      mlkem768Instance = await inline.createInlineMLKEM768() as any;
      mldsa65Instance = await inline.createInlineMLDSA65() as any;
      ML_KEM_768_INFO_INSTANCE = inline.ML_KEM_768_INFO;
      ML_DSA_65_INFO_INSTANCE = inline.ML_DSA_65_INFO;
      pqAvailable = true;
      pqReallyUnavailable = true; // Using STUB PQ (NOT REAL CRYPTO)

      console.warn('[PQ Browser] ⚠️  Loaded STUB PQ (NOT cryptographically secure)');
      console.warn('[PQ Browser] ⚠️  Post-quantum protection is UNAVAILABLE');
      console.warn('[PQ Browser] ⚠️  Messages vulnerable to harvest-now-decrypt-later attacks');
      console.warn('[PQ Browser] ⚠️  Consider using application-level PQ-wrapper');
      return { pqAvailable: true, pqReallyUnavailable: true };
    } catch (inlineError) {
      console.error('[PQ Browser] All strategies failed:', inlineError);
      pqAvailable = false;
      pqReallyUnavailable = true;
      return { pqAvailable: false, pqReallyUnavailable: true };
    }
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
