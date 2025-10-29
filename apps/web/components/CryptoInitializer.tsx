'use client';

/**
 * Client-side crypto initialization component
 *
 * This component initializes all crypto dependencies on app load:
 * - WebCrypto API validation
 * - libsodium WASM loading
 * - IndexedDB keystore warming
 *
 * Place this in your root layout to ensure crypto is ready before any operations.
 */

import { useEffect, useState } from 'react';
import { initCryptoOnce, getCryptoInitState, getCryptoInitError } from '@/lib/crypto/init';

export function CryptoInitializer() {
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    console.log('[CryptoInitializer] Starting crypto initialization...');

    initCryptoOnce()
      .then(() => {
        console.log('[CryptoInitializer] ✓ Crypto initialized successfully');
      })
      .catch((err) => {
        console.error('[CryptoInitializer] ✗ Crypto initialization failed:', err);
        setError(err.message);
      });
  }, []);

  // Don't show error UI in this component - let the error boundary handle it
  // This is just for initialization
  if (error) {
    console.error('[CryptoInitializer] Error:', error);
  }

  return null; // This component doesn't render anything
}
