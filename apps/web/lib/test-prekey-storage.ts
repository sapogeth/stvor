/**
 * Test utility for verifying prekey multi-key storage
 *
 * This demonstrates how the multi-key storage prevents "No prekey secrets found" errors
 * when different parts of the app use different casing for Clerk IDs.
 */

import { loadPrekeySecrets } from './prekeys';

/**
 * Test prekey storage with various key formats
 * Call this from browser console to verify multi-key lookup
 */
export async function testPrekeyStorage(userId: string) {
  console.log('=== Testing Prekey Multi-Key Storage ===');
  console.log('User ID:', userId);

  // Test variations
  const testKeys = [
    userId,
    userId.toLowerCase(),
    userId.toUpperCase(),
    `prekey:${userId}`,
    `prekey:${userId.toLowerCase()}`,
  ];

  console.log('\nTesting with keys:', testKeys);

  for (const key of testKeys) {
    console.log(`\nTrying key: "${key}"`);
    const secrets = await loadPrekeySecrets(key);

    if (secrets) {
      console.log('✓ Found secrets!', {
        bundleId: secrets.bundleId,
        timestamp: new Date(secrets.timestamp).toISOString(),
      });
    } else {
      console.log('✗ No secrets found');
    }
  }

  console.log('\n=== Test Complete ===');
}

// Make it available in browser console
if (typeof window !== 'undefined') {
  (window as any).testPrekeyStorage = testPrekeyStorage;
}
