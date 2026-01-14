/**
 * Client-side crypto module with STATIC imports
 * 
 * ARCHITECTURE DECISION:
 * - NO dynamic imports (import() causes bare specifier issues in browser)
 * - Crypto is loaded SYNCHRONOUSLY in client bundle
 * - Yes, bundle is larger, but it's CORRECT and RELIABLE
 * - Worker has its own static import path
 * 
 * SECURITY NOTE:
 * - This module re-exports @ilyazh/crypto (protocol crypto)
 * - NEVER import this as "crypto" - use "protocolCrypto" alias
 * - Identifier "crypto" is reserved for Web Crypto API
 */
'use client';

// STATIC import - no lazy loading, no dynamic imports
import * as protocolCryptoExports from '@ilyazh/crypto';

// Re-export everything synchronously
export * from '@ilyazh/crypto';

// Default export for compatibility (import protocolCrypto from '@/lib/crypto')
export default protocolCryptoExports;
