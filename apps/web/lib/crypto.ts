/**
 * Client-side crypto module with STATIC imports
 * 
 * ARCHITECTURE DECISION:
 * - NO dynamic imports (import() causes bare specifier issues in browser)
 * - Crypto is loaded SYNCHRONOUSLY in client bundle
 * - Yes, bundle is larger, but it's CORRECT and RELIABLE
 * - Worker has its own static import path
 */
'use client';

// STATIC import - no lazy loading, no dynamic imports
import * as crypto from '@ilyazh/crypto';

// Re-export everything synchronously
export * from '@ilyazh/crypto';

// Ensure crypto is available for modules that need it
export default crypto;
