/**
 * Browser-safe PQ loader (dual-strategy: npm for Node/SSR + real WASM adapters for browser)
 * NO ../../../../dist references, NO import.meta
 * NO inline stubs - stubs are cryptographically worthless
 *
 * Strategy:
 * 1. Try npm-installed @openforge-sh/liboqs (works in Node/SSR only)
 * 2. If npm fails, try real WASM via mlkem-wasm and mldsa-wasm npm packages (browser)
 * 3. If both fail → Hard-fail (pqReallyUnavailable = true)
 *
 * Real PQ crypto from WebAssembly-based npm packages:
 * - mlkem-wasm: ML-KEM-768 (single JS file with embedded WASM, real crypto)
 * - mldsa-wasm: ML-DSA-65 (single JS file with embedded WASM, real crypto)
 * Both provide WebCrypto-compatible APIs that we adapt to our interface
 */

import type { MLKEM768, MLDSA65 } from '@openforge-sh/liboqs';
import { createMLKEM768Adapter, createMLDSA65Adapter } from './wasm-adapters.js';

let mlkem768Instance: MLKEM768 | null = null;
let mldsa65Instance: MLDSA65 | null = null;
let ML_KEM_768_INFO_INSTANCE: any = null;
let ML_DSA_65_INFO_INSTANCE: any = null;
let pqAvailable = false;
let pqReallyUnavailable = false; // CRITICAL: true if all strategies fail
let pqInitialized = false; // CRITICAL: tracks completion (success or failure)

/**
 * Load PQ using real mlkem-wasm and mldsa-wasm npm packages
 * These contain actual WebAssembly implementations of ML-KEM-768 and ML-DSA-65
 */
async function loadPQFromWASMAdapters(): Promise<boolean> {
  try {
    console.log('[PQ Browser] Strategy 2: Attempting mlkem-wasm and mldsa-wasm adapters...');

    // Create adapters that wrap WebCrypto-style APIs into our expected interface
    mlkem768Instance = await createMLKEM768Adapter();
    mldsa65Instance = await createMLDSA65Adapter();

    // Set info objects from adapter instances
    ML_KEM_768_INFO_INSTANCE = mlkem768Instance.info;
    ML_DSA_65_INFO_INSTANCE = mldsa65Instance.info;

    // CRITICAL: Validate that keys are NOT all zeros (stub detection)
    console.log('[PQ Browser] Testing ML-KEM-768 key generation...');
    const testKeyPair = await mlkem768Instance.generateKeyPair();

    if (!testKeyPair.publicKey || testKeyPair.publicKey.length === 0) {
      throw new Error('ML-KEM generated empty public key');
    }

    if (testKeyPair.publicKey.length !== 1184) {
      throw new Error(`Invalid ML-KEM-768 public key length: ${testKeyPair.publicKey.length}, expected 1184`);
    }

    const isZeros = testKeyPair.publicKey.every((b: number) => b === 0);
    if (isZeros) {
      console.error('[PQ Browser] 🚨 SECURITY: ML-KEM public key is all zeros - stub detected, rejecting');
      return false;
    }

    // Additional stub detection: at least some bytes should be non-zero
    const nonZeroCount = testKeyPair.publicKey.filter((b: number) => b !== 0).length;
    if (nonZeroCount < 100) {
      console.error(`[PQ Browser] 🚨 SECURITY: ML-KEM key has too many zeros (${nonZeroCount}/1184 non-zero)`);
      return false;
    }

    console.log('[PQ Browser] Testing ML-DSA-65 key generation...');
    const testMldsaKeyPair = await mldsa65Instance.generateKeyPair();

    if (!testMldsaKeyPair.publicKey || testMldsaKeyPair.publicKey.length === 0) {
      throw new Error('ML-DSA generated empty public key');
    }

    if (testMldsaKeyPair.publicKey.length !== 1952) {
      throw new Error(`Invalid ML-DSA-65 public key length: ${testMldsaKeyPair.publicKey.length}, expected 1952`);
    }

    const mldsaZeros = testMldsaKeyPair.publicKey.every((b: number) => b === 0);
    if (mldsaZeros) {
      console.error('[PQ Browser] 🚨 SECURITY: ML-DSA public key is all zeros - stub detected, rejecting');
      return false;
    }

    pqAvailable = true;
    pqReallyUnavailable = false;

    console.log('[PQ Browser] ✅ Loaded REAL PQ from mlkem-wasm and mldsa-wasm adapters');
    return true;
  } catch (adapterError) {
    console.error('[PQ Browser] WASM adapter load failed:', adapterError);
    mlkem768Instance = null;
    mldsa65Instance = null;
    return false;
  }
}

export async function initPQBrowser(): Promise<{ pqAvailable: boolean; pqReallyUnavailable: boolean }> {
  if (pqAvailable && mlkem768Instance && mldsa65Instance && !pqReallyUnavailable) {
    pqInitialized = true;
    return { pqAvailable: true, pqReallyUnavailable: false };
  }

  // Strategy 1: Try npm-installed @openforge-sh/liboqs (Node/SSR only - NOT browser)
  try {
    console.log('[PQ Browser] Strategy 1: Attempting npm module (@openforge-sh/liboqs)...');
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
    pqInitialized = true;

    console.log('[PQ Browser] ✅ Loaded REAL PQ from npm (@openforge-sh/liboqs)');
    return { pqAvailable: true, pqReallyUnavailable: false };
  } catch (npmError) {
    console.error('[PQ Browser] Strategy 1 failed (expected in browser):', npmError);

    // Strategy 2: Try real WASM adapters (mlkem-wasm and mldsa-wasm npm packages)
    console.log('[PQ Browser] Falling back to Strategy 2...');
    const wasmSuccess = await loadPQFromWASMAdapters();
    if (wasmSuccess) {
      pqInitialized = true;
      return { pqAvailable: true, pqReallyUnavailable: false };
    }

    // Both strategies failed - hard-fail
    pqAvailable = false;
    pqReallyUnavailable = true; // CRITICAL: Mark as unusable
    pqInitialized = true; // Still mark as initialized (just failed)

    console.error('[PQ Browser] 🚨 CRITICAL: PQ cryptography is UNAVAILABLE');
    console.error('[PQ Browser] 🚨 Neither npm module (Strategy 1) nor WASM adapters (Strategy 2) loaded');
    console.error('[PQ Browser] 🚨 Post-quantum protection FAILED - application must refuse to create sessions');

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

export function isPQInitialized(): boolean {
  return pqInitialized;
}

/**
 * Wait for PQ crypto initialization to complete (success or failure)
 * This prevents race conditions where E2E tries to use PQ before it's ready
 *
 * @param timeoutMs Maximum time to wait in milliseconds (default: 30000 = 30s)
 * @returns Promise that resolves when PQ initialization completes
 * @throws Error if initialization doesn't complete within timeout
 */
export async function waitForPQReady(timeoutMs: number = 30000): Promise<void> {
  if (pqInitialized) {
    // Already initialized (success or failure)
    return;
  }

  const startTime = Date.now();
  return new Promise((resolve, reject) => {
    const checkInterval = setInterval(() => {
      if (pqInitialized) {
        clearInterval(checkInterval);
        const elapsed = Date.now() - startTime;
        console.log(`[PQ Browser] ✓ PQ initialization completed after ${elapsed}ms`);
        resolve();
        return;
      }

      const elapsed = Date.now() - startTime;
      if (elapsed > timeoutMs) {
        clearInterval(checkInterval);
        const error = new Error(
          `PQ crypto initialization timeout after ${elapsed}ms. ` +
          'This may indicate slow network, missing WASM modules, or browser compatibility issue.'
        );
        console.error('[PQ Browser] ✗ ' + error.message);
        reject(error);
      }
    }, 50); // Check every 50ms
  });
}
