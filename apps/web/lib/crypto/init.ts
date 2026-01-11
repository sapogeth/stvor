/**
 * Centralized Crypto Initialization
 *
 * Provides a single, race-free initialization point for all crypto dependencies:
 * - WebCrypto API validation
 * - libsodium WASM loading
 * - liboqs WASM loading (when available)
 * - IndexedDB keystore warming
 *
 * Call initCryptoOnce() from your root client component to ensure crypto
 * is ready before any operations. Multiple calls are safe (idempotent).
 */

import { getCryptoOrThrow, getCryptoStatus } from '@/lib/runtime/crypto-safe';
import { debugLibsodiumAvailability } from '@/lib/keystore';
import { validateProductionEnvironment } from '@/lib/production-guard';

/**
 * Initialization state machine
 */
type InitState = 'idle' | 'initializing' | 'ready' | 'failed';

let initState: InitState = 'idle';
let initPromise: Promise<void> | null = null;
let initError: Error | null = null;

/**
 * Initialize all crypto dependencies exactly once.
 * Safe to call multiple times from different components.
 *
 * @returns Promise that resolves when crypto is ready
 * @throws Error if initialization fails (includes actionable diagnostics)
 *
 * @example
 * ```typescript
 * // In root layout or provider
 * useEffect(() => {
 *   initCryptoOnce().catch(err => {
 *     console.error('Crypto init failed:', err);
 *     setError(err.message);
 *   });
 * }, []);
 * ```
 */
export async function initCryptoOnce(): Promise<void> {
  // Return cached promise if already initializing/ready
  if (initPromise) return initPromise;

  // Re-throw if previous init failed
  if (initState === 'failed' && initError) {
    throw initError;
  }

  // Already initialized
  if (initState === 'ready') {
    return Promise.resolve();
  }

  // Start initialization
  initState = 'initializing';
  initPromise = (async () => {
    try {
      // Step 0: Validate production environment (Clerk keys, relay keys)
      if (process.env.NODE_ENV !== 'production') {
        console.log('[crypto-init] Validating production environment...');
      }
      validateProductionEnvironment();

      // Step 1: Validate WebCrypto environment
      const { ce } = getCryptoOrThrow();
      if (process.env.NODE_ENV !== 'production') {
        console.log('[crypto-init] WebCrypto available:', {
          context: ce.context,
          isSecure: ce.isSecure,
          hasSubtle: ce.hasSubtle,
          hasRandomUUID: ce.hasRandomUUID,
          hasGetRandomValues: ce.hasGetRandomValues,
        });
      }

      // Step 2: Initialize libsodium WASM
      if (process.env.NODE_ENV !== 'production') {
        console.log('[crypto-init] Loading libsodium WASM...');
      }
      // Use statically imported browser-safe crypto
      const crypto = await import('@/lib/crypto');
      const initPrimitives = crypto.initCrypto;
      if (typeof initPrimitives !== 'function') {
        throw new Error('initCrypto not available from @ilyazh/crypto');
      }
      await initPrimitives();
      if (process.env.NODE_ENV !== 'production') {
        console.log('[crypto-init] libsodium ready');
      }

      // Step 2.5: Debug libsodium availability (KDF validation)
      if (process.env.NODE_ENV !== 'production') {
        console.log('[crypto-init] Checking KDF availability...');
      }
      await debugLibsodiumAvailability();

      // Step 3: Initialize liboqs WASM (PQ cryptography)
      if (process.env.NODE_ENV !== 'production') {
        console.log('[crypto-init] Loading liboqs WASM...');
      }
      const crypto = await import('@/lib/crypto');
      const { pqAvailable, pqReallyUnavailable } = await crypto.initPQBrowser();
      if (process.env.NODE_ENV !== 'production') {
        console.log('[crypto-init] liboqs initialization result:', {
          pqAvailable,
          pqReallyUnavailable,
        });
      }

      // Step 4: Warm up IndexedDB keystore
      // Open the database to ensure it's ready for first access
      // This prevents "Failed to initialize encryption keys" flicker
      if (process.env.NODE_ENV !== 'production') {
        console.log('[crypto-init] Warming IndexedDB keystore...');
      }
      await warmIndexedDB();
      if (process.env.NODE_ENV !== 'production') {
        console.log('[crypto-init] IndexedDB ready');
      }

      // Step 5: Mark as ready and signal to waiting code
      initState = 'ready';

      // Set global flag so code waiting for PQ crypto can detect readiness
      // This is checked by waitForPQReady() in identity.ts
      if (typeof window !== 'undefined') {
        (window as any).__PQ_READY = true;
      }

      if (process.env.NODE_ENV !== 'production') {
        console.log('[crypto-init] ✓ All crypto dependencies initialized');
        console.log('[crypto-init] ✓ window.__PQ_READY = true');
      }
    } catch (error) {
      initState = 'failed';
      initError = error instanceof Error ? error : new Error(String(error));
      console.error('[crypto-init] ✗ Initialization failed:', initError);

      // Add diagnostics to error message
      const status = getCryptoStatus();
      const diagnostics = [
        `Context: ${status.context}`,
        `Secure: ${status.isSecure}`,
        `Subtle: ${status.hasSubtle}`,
        `GetRandomValues: ${status.hasGetRandomValues}`,
      ].join(', ');

      initError.message = `${initError.message}\n\nDiagnostics: ${diagnostics}`;
      throw initError;
    }
  })();

  return initPromise;
}

/**
 * Warm up IndexedDB by opening and closing the keystore database.
 * This ensures the database is ready for first access and prevents
 * "please refresh" messages caused by cold-start race conditions.
 */
async function warmIndexedDB(): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    // Check if IndexedDB is available
    if (typeof indexedDB === 'undefined') {
      reject(new Error('IndexedDB is not available in this environment'));
      return;
    }

    try {
      // Open the keystore database (same name as keystore.ts)
      const request = indexedDB.open('ilyazh-keystore-v3', 2);

      request.onerror = () => {
        const err = request.error || new Error('IndexedDB open failed');
        if (process.env.NODE_ENV !== 'production') {
          console.warn('[crypto-init] IndexedDB warm-up failed:', err);
        }

        // Don't reject - IndexedDB might be disabled in private mode
        // The actual keystore operations will handle this gracefully
        resolve();
      };

      request.onsuccess = () => {
        const db = request.result;
        if (process.env.NODE_ENV !== 'production') {
          console.log('[crypto-init] IndexedDB opened:', db.name, 'v' + db.version);
        }

        // Verify expected object stores exist
        const expectedStores = ['identity', 'sessions', 'prekeys'];
        const actualStores = Array.from(db.objectStoreNames);

        const missing = expectedStores.filter(s => !actualStores.includes(s));
        if (missing.length > 0 && process.env.NODE_ENV !== 'production') {
          console.warn('[crypto-init] Missing object stores:', missing);
        }

        db.close();
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = request.result;
        if (process.env.NODE_ENV !== 'production') {
          console.log('[crypto-init] IndexedDB upgrade needed:', {
            oldVersion: event.oldVersion,
            newVersion: event.newVersion,
          });
        }

        // Create object stores if they don't exist
        // IMPORTANT: This must match the schema in keystore.ts exactly!
        if (!db.objectStoreNames.contains('identity')) {
          db.createObjectStore('identity', { keyPath: 'username' });  // Fixed: was 'id', should be 'username'
          if (process.env.NODE_ENV !== 'production') {
            console.log('[crypto-init] Created "identity" store');
          }
        }
        if (!db.objectStoreNames.contains('sessions')) {
          const sessionStore = db.createObjectStore('sessions', { keyPath: 'sessionId' });
          sessionStore.createIndex('peerUsername', 'peerUsername', { unique: false });
          sessionStore.createIndex('lastUsed', 'lastUsed', { unique: false });
          if (process.env.NODE_ENV !== 'production') {
            console.log('[crypto-init] Created "sessions" store with indexes');
          }
        }
        if (!db.objectStoreNames.contains('prekeys')) {
          db.createObjectStore('prekeys');  // Uses out-of-line keys (username as key)
          if (process.env.NODE_ENV !== 'production') {
            console.log('[crypto-init] Created "prekeys" store');
          }
        }
      };

      request.onblocked = () => {
        if (process.env.NODE_ENV !== 'production') {
          console.warn('[crypto-init] IndexedDB open blocked (close other tabs?)');
        }
        // Don't reject - will resolve when unblocked
      };
    } catch (error) {
      if (process.env.NODE_ENV !== 'production') {
        console.warn('[crypto-init] IndexedDB warm-up error:', error);
      }
      // Don't reject - might be in a restricted environment
      resolve();
    }
  });
}

/**
 * Get current initialization state (for diagnostics/UI).
 *
 * @returns Current state: idle, initializing, ready, or failed
 */
export function getCryptoInitState(): InitState {
  return initState;
}

/**
 * Get initialization error (if any).
 *
 * @returns Error from last failed initialization, or null
 */
export function getCryptoInitError(): Error | null {
  return initError;
}

/**
 * Reset initialization state (for testing only).
 * DO NOT use in production code.
 *
 * @internal
 */
export function _resetCryptoInit(): void {
  initState = 'idle';
  initPromise = null;
  initError = null;
}

/**
 * Check if crypto is fully initialized and ready to use.
 *
 * @returns true if ready, false otherwise
 */
export function isCryptoReady(): boolean {
  return initState === 'ready';
}
