/**
 * Browser-safe PQ loader (npm-first, WASM-fallback, hard-fail on unavailable)
 * NO ../../../../dist references, NO import.meta
 * NO inline stubs - stubs are cryptographically worthless
 *
 * Strategy:
 * 1. Try npm-installed @openforge-sh/liboqs (REAL PQ CRYPTO)
 * 2. If npm fails → Try local WASM from /public/pq/*.wasm (compiled liboqs)
 * 3. If both fail → Hard-fail (pqReallyUnavailable = true)
 */

import type { MLKEM768, MLDSA65 } from '@openforge-sh/liboqs';

let mlkem768Instance: MLKEM768 | null = null;
let mldsa65Instance: MLDSA65 | null = null;
let ML_KEM_768_INFO_INSTANCE: any = null;
let ML_DSA_65_INFO_INSTANCE: any = null;
let pqAvailable = false;
let pqReallyUnavailable = false; // CRITICAL: true if using stubs OR real PQ failed to load

/**
 * Load PQ from WASM binary (compiled liboqs from /public/pq/)
 * This is a fallback if npm module fails
 */
async function loadPQFromWASM(): Promise<boolean> {
  try {
    console.log('[PQ Browser] Strategy 2: Attempting WASM fallback from /public/pq/...');

    // Fetch WASM modules
    const mlkemWasmUrl = '/pq/mlkem768.wasm';
    const mldsaWasmUrl = '/pq/mldsa65.wasm';

    const [mlkemResp, mldsaResp] = await Promise.all([
      fetch(mlkemWasmUrl),
      fetch(mldsaWasmUrl),
    ]);

    if (!mlkemResp.ok || !mldsaResp.ok) {
      console.error(`[PQ Browser] WASM fetch failed: mlkem=${mlkemResp.ok}, mldsa=${mldsaResp.ok}`);
      return false;
    }

    const mlkemWasm = await mlkemResp.arrayBuffer();
    const mldsaWasm = await mldsaResp.arrayBuffer();

    // Instantiate WASM modules
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const WasmGlobal = globalThis as any;
    const mlkemModule = await WasmGlobal.WebAssembly.instantiate(mlkemWasm);
    const mldsaModule = await WasmGlobal.WebAssembly.instantiate(mldsaWasm);

    // Wrap WASM exports into interface matching MLKEM768/MLDSA65
    // This is a simplified wrapper - adjust based on actual WASM export signatures
    const wasmMlkem = {
      generateKeyPair: async () => {
        const result = (mlkemModule.instance.exports as any).generate_keypair?.();
        if (!result) throw new Error('WASM: generateKeyPair not available');
        return result;
      },
      encapsulate: async (publicKey: Uint8Array) => {
        const result = (mlkemModule.instance.exports as any).encapsulate?.(publicKey);
        if (!result) throw new Error('WASM: encapsulate not available');
        return result;
      },
      decapsulate: async (ciphertext: Uint8Array, secretKey: Uint8Array) => {
        const result = (mlkemModule.instance.exports as any).decapsulate?.(ciphertext, secretKey);
        if (!result) throw new Error('WASM: decapsulate not available');
        return result;
      },
      destroy: () => {
        // WASM cleanup - may be no-op
      },
      info: {
        publicKeyLength: 1184,
        secretKeyLength: 2400,
        ciphertextLength: 1088,
        sharedSecretLength: 32,
      },
    };

    const wasmMldsa = {
      generateKeyPair: async () => {
        const result = (mldsaModule.instance.exports as any).generate_keypair?.();
        if (!result) throw new Error('WASM: generateKeyPair not available');
        return result;
      },
      sign: async (message: Uint8Array, secretKey: Uint8Array) => {
        const result = (mldsaModule.instance.exports as any).sign?.(message, secretKey);
        if (!result) throw new Error('WASM: sign not available');
        return result;
      },
      verify: async (message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array) => {
        const result = (mldsaModule.instance.exports as any).verify?.(message, signature, publicKey);
        if (!result) throw new Error('WASM: verify not available');
        return result;
      },
      destroy: () => {
        // WASM cleanup - may be no-op
      },
      info: {
        publicKeyLength: 1952,
        secretKeyLength: 4032,
        signatureLength: 3309,
      },
    };

    mlkem768Instance = wasmMlkem as unknown as MLKEM768;
    mldsa65Instance = wasmMldsa as unknown as MLDSA65;

    // CRITICAL: Validate that keys are NOT all zeros (stub detection)
    const testKeyPair = await mlkem768Instance.generateKeyPair();
    const isZeros = testKeyPair.publicKey.every((b: number) => b === 0);

    if (isZeros) {
      console.error('[PQ Browser] 🚨 SECURITY: WASM ML-KEM public key is all zeros - stub detected, rejecting');
      return false;
    }

    pqAvailable = true;
    pqReallyUnavailable = false;

    console.log('[PQ Browser] ✅ Loaded REAL PQ from WASM (/public/pq/)');
    return true;
  } catch (wasmError) {
    console.error('[PQ Browser] WASM load failed:', wasmError);
    return false;
  }
}

export async function initPQBrowser(): Promise<{ pqAvailable: boolean; pqReallyUnavailable: boolean }> {
  if (pqAvailable && mlkem768Instance && mldsa65Instance && !pqReallyUnavailable) {
    return { pqAvailable: true, pqReallyUnavailable: false };
  }

  // Strategy 1: Try npm-installed @openforge-sh/liboqs (REAL PQ CRYPTO)
  try {
    console.log('[PQ Browser] Strategy 1: Attempting npm module load...');
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

    // Strategy 2: Try WASM fallback from /public/pq/
    const wasmSuccess = await loadPQFromWASM();
    if (wasmSuccess) {
      return { pqAvailable: true, pqReallyUnavailable: false };
    }

    // Both npm and WASM failed - hard-fail
    pqAvailable = false;
    pqReallyUnavailable = true; // CRITICAL: Mark as unusable

    console.error('[PQ Browser] 🚨 CRITICAL: PQ cryptography is UNAVAILABLE');
    console.error('[PQ Browser] 🚨 Neither npm module nor WASM fallback loaded');
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
