'use client';

/**
 * Client-side crypto initialization component (with dynamic imports)
 *
 * This component initializes crypto dependencies in two phases:
 * 1. Light phase: WebCrypto, IndexedDB, basic classical crypto (X25519/AES)
 * 2. Heavy phase: Post-quantum crypto (ML-KEM-768/ML-DSA-65) - dynamically loaded
 *
 * This split ensures the root page can render immediately without webpack errors,
 * while still providing full E2E encryption support once loaded.
 *
 * Place this in your root layout to ensure crypto is ready before any operations.
 */

import { useEffect, useState } from 'react';

export function CryptoInitializer() {
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    (async () => {
      try {
        console.log('[CryptoInitializer] Starting crypto initialization...');

        // Phase 1: Load the crypto init module dynamically
        // This prevents webpack from choking on liboqs during page compilation
        const { initCryptoOnce } = await import('@/lib/crypto/init');

        console.log('[CryptoInitializer] Initializing classical crypto (X25519/AES)...');
        await initCryptoOnce();

        if (!mounted) return;

        console.log('[CryptoInitializer] ✓ Crypto initialized successfully');
        setReady(true);
      } catch (err) {
        if (!mounted) return;

        console.error('[CryptoInitializer] ✗ Crypto initialization failed:', err);
        const message = err instanceof Error ? err.message : String(err);
        setError(message);

        // Don't throw - allow the app to continue with degraded functionality
        // The actual crypto operations will handle missing crypto gracefully
      }
    })();

    return () => {
      mounted = false;
    };
  }, []);

  // Don't show error UI in this component - let the error boundary handle it
  // This is just for initialization
  if (error) {
    console.error('[CryptoInitializer] Error:', error);
  }

  return null; // This component doesn't render anything
}
