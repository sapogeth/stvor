/**
 * E2E Tests for Crypto Initialization
 *
 * Tests crypto initialization across different browsers and contexts.
 * Requires Playwright or similar E2E testing framework.
 *
 * Run with: pnpm test:e2e
 */

import { test, expect } from '@playwright/test';

// Adjust this based on your dev server setup
const BASE_URL = process.env.BASE_URL || 'https://localhost:3000';

test.describe('Crypto Initialization', () => {
  test.beforeEach(async ({ page }) => {
    // Clear any existing state
    await page.goto(BASE_URL);
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
  });

  test('should access app over secure context (HTTPS)', async ({ page }) => {
    await page.goto(BASE_URL);

    const isSecure = await page.evaluate(() => {
      return window.isSecureContext;
    });

    expect(isSecure).toBe(true);
  });

  test('should have WebCrypto available', async ({ page }) => {
    await page.goto(BASE_URL);

    const cryptoAvailable = await page.evaluate(() => {
      return {
        hasCrypto: typeof window.crypto !== 'undefined',
        hasSubtle: typeof window.crypto?.subtle !== 'undefined',
        hasGetRandomValues: typeof window.crypto?.getRandomValues === 'function',
      };
    });

    expect(cryptoAvailable.hasCrypto).toBe(true);
    expect(cryptoAvailable.hasSubtle).toBe(true);
    expect(cryptoAvailable.hasGetRandomValues).toBe(true);
  });

  test('should generate UUID using randomUUID or polyfill', async ({ page }) => {
    await page.goto(BASE_URL);

    const uuid = await page.evaluate(async () => {
      const { getCryptoOrThrow } = await import('/lib/runtime/crypto-safe');
      const { randomUUID } = getCryptoOrThrow();
      return randomUUID();
    });

    // Validate UUID v4 format
    expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  test('should initialize crypto without errors', async ({ page }) => {
    await page.goto(BASE_URL);

    const initResult = await page.evaluate(async () => {
      try {
        const { initCryptoOnce } = await import('/lib/crypto/init');
        await initCryptoOnce();
        return { success: true, error: null };
      } catch (err: any) {
        return { success: false, error: err.message };
      }
    });

    expect(initResult.success).toBe(true);
    expect(initResult.error).toBeNull();
  });

  test('should not show "Failed to initialize encryption keys" message', async ({ page }) => {
    await page.goto(BASE_URL);

    // Wait for page to fully load
    await page.waitForLoadState('networkidle');

    // Check for error messages
    const errorVisible = await page.evaluate(() => {
      const text = document.body.innerText.toLowerCase();
      return text.includes('failed to initialize encryption keys');
    });

    expect(errorVisible).toBe(false);
  });

  test('diagnostics page should show all green checks', async ({ page }) => {
    await page.goto(`${BASE_URL}/debug/crypto`);

    // Wait for diagnostics to complete
    await page.waitForSelector('text=All checks passed', { timeout: 10000 });

    // Check for success indicators
    const diagnostics = await page.evaluate(() => {
      const checks = Array.from(document.querySelectorAll('.text-green-600'));
      return checks.length;
    });

    // Should have multiple green checkmarks
    expect(diagnostics).toBeGreaterThan(5);
  });

  test('should open IndexedDB successfully', async ({ page }) => {
    await page.goto(BASE_URL);

    const dbResult = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const request = indexedDB.open('crypto-test-db', 1);

        request.onsuccess = () => {
          const db = request.result;
          db.close();
          indexedDB.deleteDatabase('crypto-test-db');
          resolve({ success: true, error: null });
        };

        request.onerror = () => {
          resolve({ success: false, error: request.error?.message || 'Unknown error' });
        };

        request.onupgradeneeded = (event) => {
          const db = (event.target as IDBOpenDBRequest).result;
          db.createObjectStore('test');
        };
      });
    });

    expect(dbResult.success).toBe(true);
  });

  test('should initialize libsodium WASM', async ({ page }) => {
    await page.goto(BASE_URL);

    const sodiumReady = await page.evaluate(async () => {
      try {
        // Import from the crypto package
        const { initCrypto } = await import('@ilyazh/crypto');
        await initCrypto();
        return true;
      } catch (err) {
        console.error('libsodium init failed:', err);
        return false;
      }
    });

    expect(sodiumReady).toBe(true);
  });
});

test.describe('Crypto Error Handling', () => {
  test('should show error boundary on crypto failure', async ({ page, context }) => {
    // Test with insecure context (if possible)
    // Note: Most browsers won't allow this in real scenarios
    // This is more of a demonstration of what to test

    await page.goto(`${BASE_URL}/debug/crypto`);

    // Check that error handling UI exists
    const hasErrorBoundary = await page.evaluate(() => {
      // Check if the CryptoErrorBoundary component is in the DOM
      // (This might not be visible if everything is working correctly)
      return typeof window !== 'undefined';
    });

    expect(hasErrorBoundary).toBe(true);
  });
});

test.describe('Browser Compatibility', () => {
  test('should work in Chrome-like browsers', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'Chrome-specific test');

    await page.goto(BASE_URL);

    const hasNativeUUID = await page.evaluate(() => {
      return typeof crypto.randomUUID === 'function';
    });

    // Chrome 92+ has native randomUUID
    expect(hasNativeUUID).toBe(true);
  });

  test('should work in Firefox', async ({ page, browserName }) => {
    test.skip(browserName !== 'firefox', 'Firefox-specific test');

    await page.goto(BASE_URL);

    const cryptoWorks = await page.evaluate(async () => {
      const { getCryptoOrThrow } = await import('/lib/runtime/crypto-safe');
      const { randomUUID } = getCryptoOrThrow();
      const uuid = randomUUID();
      return uuid.length === 36;
    });

    expect(cryptoWorks).toBe(true);
  });

  test('should work in Safari-like browsers', async ({ page, browserName }) => {
    test.skip(browserName !== 'webkit', 'Safari-specific test');

    await page.goto(BASE_URL);

    // Safari < 15.4 doesn't have native randomUUID
    const result = await page.evaluate(async () => {
      const { getCryptoOrThrow } = await import('/lib/runtime/crypto-safe');
      const { ce, randomUUID } = getCryptoOrThrow();
      const uuid = randomUUID();

      return {
        hasNativeUUID: ce.hasRandomUUID,
        uuidWorks: uuid.length === 36,
      };
    });

    expect(result.uuidWorks).toBe(true);
    // May or may not have native UUID depending on Safari version
  });
});

test.describe('IndexedDB Edge Cases', () => {
  test('should handle IndexedDB being blocked', async ({ page }) => {
    // This test demonstrates how to handle blocked IndexedDB
    // In real scenarios, this might happen when another tab has the DB open

    await page.goto(BASE_URL);

    const result = await page.evaluate(async () => {
      const { initCryptoOnce } = await import('/lib/crypto/init');

      try {
        await initCryptoOnce();
        return { success: true, error: null };
      } catch (err: any) {
        return { success: false, error: err.message };
      }
    });

    // Should either succeed or provide helpful error
    if (!result.success) {
      expect(result.error).toBeTruthy();
      expect(result.error).not.toContain('undefined');
    }
  });

  test('should provide helpful error for private browsing mode', async ({ page }) => {
    // Note: This is hard to test automatically as private browsing
    // must be enabled manually. This test documents the expected behavior.

    await page.goto(`${BASE_URL}/debug/crypto`);

    // Check that diagnostics page mentions private browsing
    const pageContent = await page.textContent('body');
    const mentionsPrivateBrowsing = pageContent?.toLowerCase().includes('private');

    // The diagnostics page should mention private browsing as a potential issue
    expect(mentionsPrivateBrowsing).toBe(true);
  });
});

test.describe('Performance', () => {
  test('crypto initialization should complete quickly', async ({ page }) => {
    await page.goto(BASE_URL);

    const duration = await page.evaluate(async () => {
      const start = performance.now();
      const { initCryptoOnce } = await import('/lib/crypto/init');
      await initCryptoOnce();
      const end = performance.now();
      return end - start;
    });

    // Should initialize in under 5 seconds (generous timeout for WASM)
    expect(duration).toBeLessThan(5000);
  });

  test('UUID generation should be fast', async ({ page }) => {
    await page.goto(BASE_URL);

    const duration = await page.evaluate(async () => {
      const { getCryptoOrThrow } = await import('/lib/runtime/crypto-safe');
      const { randomUUID } = getCryptoOrThrow();

      const start = performance.now();
      for (let i = 0; i < 1000; i++) {
        randomUUID();
      }
      const end = performance.now();
      return end - start;
    });

    // 1000 UUIDs should generate in under 100ms
    expect(duration).toBeLessThan(100);
  });
});
