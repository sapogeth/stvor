'use client';

/**
 * Crypto Diagnostics Page
 *
 * Displays comprehensive diagnostics for cryptographic features and browser support.
 * Use this page to debug crypto initialization issues and browser compatibility.
 *
 * Access at: /debug/crypto
 */

import { useEffect, useState } from 'react';
import { getCryptoStatus } from '@/lib/runtime/crypto-safe';
import { getCryptoInitState, getCryptoInitError, initCryptoOnce } from '@/lib/crypto/init';
import type { CryptoEnv } from '@/lib/runtime/crypto-env';

interface DiagnosticsState {
  env: CryptoEnv | null;
  initState: string;
  initError: string | null;
  indexedDBTest: 'pending' | 'success' | 'failed';
  indexedDBError: string | null;
  workerTest: 'pending' | 'success' | 'failed' | 'skipped';
  workerError: string | null;
  sodiumTest: 'pending' | 'success' | 'failed';
  sodiumError: string | null;
  uuid: string | null;
}

export default function CryptoDiagnosticsPage() {
  const [diagnostics, setDiagnostics] = useState<DiagnosticsState>({
    env: null,
    initState: 'idle',
    initError: null,
    indexedDBTest: 'pending',
    indexedDBError: null,
    workerTest: 'pending',
    workerError: null,
    sodiumTest: 'pending',
    sodiumError: null,
    uuid: null,
  });

  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    runDiagnostics();
  }, []);

  async function runDiagnostics() {
    setIsLoading(true);

    // Step 1: Detect crypto environment
    const env = getCryptoStatus();
    setDiagnostics(prev => ({ ...prev, env }));

    // Step 2: Get initialization state
    const initState = getCryptoInitState();
    const initError = getCryptoInitError();
    setDiagnostics(prev => ({
      ...prev,
      initState,
      initError: initError?.message || null,
    }));

    // Step 3: Test UUID generation
    try {
      const { randomUUID } = await import('@/lib/runtime/crypto-safe').then(m => m.getCryptoOrThrow());
      const uuid = randomUUID();
      setDiagnostics(prev => ({ ...prev, uuid }));
    } catch (err) {
      console.error('UUID test failed:', err);
    }

    // Step 4: Test IndexedDB
    await testIndexedDB();

    // Step 5: Test libsodium
    await testSodium();

    // Step 6: Test Web Worker crypto (only if workers are supported)
    if (typeof Worker !== 'undefined') {
      await testWorkerCrypto();
    } else {
      setDiagnostics(prev => ({ ...prev, workerTest: 'skipped' }));
    }

    setIsLoading(false);
  }

  async function testIndexedDB() {
    try {
      if (typeof indexedDB === 'undefined') {
        throw new Error('IndexedDB API not available');
      }

      const testDB = await new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open('crypto-diagnostics-test', 1);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
        request.onupgradeneeded = (event) => {
          const db = (event.target as IDBOpenDBRequest).result;
          if (!db.objectStoreNames.contains('test')) {
            db.createObjectStore('test');
          }
        };
      });

      // Test write
      await new Promise<void>((resolve, reject) => {
        const tx = testDB.transaction(['test'], 'readwrite');
        const store = tx.objectStore('test');
        const request = store.put({ value: 'test' }, 'test-key');
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });

      // Test read
      await new Promise<void>((resolve, reject) => {
        const tx = testDB.transaction(['test'], 'readonly');
        const store = tx.objectStore('test');
        const request = store.get('test-key');
        request.onsuccess = () => {
          if (request.result?.value === 'test') {
            resolve();
          } else {
            reject(new Error('Read value mismatch'));
          }
        };
        request.onerror = () => reject(request.error);
      });

      testDB.close();

      // Clean up test database
      indexedDB.deleteDatabase('crypto-diagnostics-test');

      setDiagnostics(prev => ({ ...prev, indexedDBTest: 'success' }));
    } catch (err: any) {
      setDiagnostics(prev => ({
        ...prev,
        indexedDBTest: 'failed',
        indexedDBError: err?.message || String(err),
      }));
    }
  }

  async function testSodium() {
    try {
      await initCryptoOnce();
      setDiagnostics(prev => ({
        ...prev,
        sodiumTest: 'success',
        initState: getCryptoInitState(),
      }));
    } catch (err: any) {
      setDiagnostics(prev => ({
        ...prev,
        sodiumTest: 'failed',
        sodiumError: err?.message || String(err),
      }));
    }
  }

  async function testWorkerCrypto() {
    try {
      // Create inline worker to test crypto availability
      const workerCode = `
        self.onmessage = function() {
          try {
            if (typeof self.crypto === 'undefined') {
              self.postMessage({ error: 'crypto object not available' });
              return;
            }
            if (typeof self.crypto.subtle === 'undefined') {
              self.postMessage({ error: 'crypto.subtle not available' });
              return;
            }
            if (typeof self.crypto.getRandomValues !== 'function') {
              self.postMessage({ error: 'crypto.getRandomValues not available' });
              return;
            }

            // Test getRandomValues
            const arr = new Uint8Array(16);
            self.crypto.getRandomValues(arr);

            self.postMessage({ success: true });
          } catch (err) {
            self.postMessage({ error: err.message });
          }
        };
      `;

      const blob = new Blob([workerCode], { type: 'application/javascript' });
      const worker = new Worker(URL.createObjectURL(blob));

      const result = await new Promise<any>((resolve, reject) => {
        const timeout = setTimeout(() => {
          worker.terminate();
          reject(new Error('Worker test timeout'));
        }, 5000);

        worker.onmessage = (e) => {
          clearTimeout(timeout);
          worker.terminate();
          resolve(e.data);
        };

        worker.onerror = (err) => {
          clearTimeout(timeout);
          worker.terminate();
          reject(err);
        };

        worker.postMessage({});
      });

      if (result.error) {
        throw new Error(result.error);
      }

      setDiagnostics(prev => ({ ...prev, workerTest: 'success' }));
    } catch (err: any) {
      setDiagnostics(prev => ({
        ...prev,
        workerTest: 'failed',
        workerError: err?.message || String(err),
      }));
    }
  }

  function getStatusIcon(status: 'pending' | 'success' | 'failed' | 'skipped') {
    switch (status) {
      case 'success':
        return <span className="text-green-600 text-xl">✓</span>;
      case 'failed':
        return <span className="text-red-600 text-xl">✗</span>;
      case 'skipped':
        return <span className="text-gray-400 text-xl">⊘</span>;
      default:
        return <span className="text-gray-400 text-xl">⋯</span>;
    }
  }

  function getBooleanIcon(value: boolean) {
    return value ? (
      <span className="text-green-600">✓ Yes</span>
    ) : (
      <span className="text-red-600">✗ No</span>
    );
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 p-8">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-3xl font-bold mb-6">Crypto Diagnostics</h1>
          <div className="bg-white rounded-lg shadow p-6">
            <p className="text-gray-600">Running diagnostics...</p>
          </div>
        </div>
      </div>
    );
  }

  const env = diagnostics.env!;

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <div className="max-w-4xl mx-auto space-y-6">
        <div>
          <h1 className="text-3xl font-bold mb-2">Crypto Diagnostics</h1>
          <p className="text-gray-600">
            Browser support matrix for cryptographic features
          </p>
        </div>

        {/* Environment Detection */}
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="px-6 py-4 bg-gray-100 border-b">
            <h2 className="text-xl font-semibold">Runtime Environment</h2>
          </div>
          <div className="p-6 space-y-3">
            <div className="flex justify-between items-center">
              <span className="font-medium">Context:</span>
              <span className="font-mono text-sm bg-gray-100 px-3 py-1 rounded">
                {env.context}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="font-medium">window object:</span>
              {getBooleanIcon(env.hasWindow)}
            </div>
            <div className="flex justify-between items-center">
              <span className="font-medium">self object:</span>
              {getBooleanIcon(env.hasSelf)}
            </div>
            <div className="flex justify-between items-center">
              <span className="font-medium">Secure Context (HTTPS):</span>
              {getBooleanIcon(env.isSecure)}
            </div>
          </div>
        </div>

        {/* WebCrypto API */}
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="px-6 py-4 bg-gray-100 border-b">
            <h2 className="text-xl font-semibold">WebCrypto API</h2>
          </div>
          <div className="p-6 space-y-3">
            <div className="flex justify-between items-center">
              <span className="font-medium">crypto object:</span>
              {getBooleanIcon(env.cryptoRef !== null)}
            </div>
            <div className="flex justify-between items-center">
              <span className="font-medium">crypto.subtle:</span>
              {getBooleanIcon(env.hasSubtle)}
            </div>
            <div className="flex justify-between items-center">
              <span className="font-medium">crypto.getRandomValues:</span>
              {getBooleanIcon(env.hasGetRandomValues)}
            </div>
            <div className="flex justify-between items-center">
              <span className="font-medium">crypto.randomUUID:</span>
              <div className="flex items-center gap-2">
                {getBooleanIcon(env.hasRandomUUID)}
                {!env.hasRandomUUID && (
                  <span className="text-xs text-gray-500">(using polyfill)</span>
                )}
              </div>
            </div>
            {diagnostics.uuid && (
              <div className="mt-4 pt-4 border-t">
                <div className="text-sm text-gray-600 mb-1">Sample UUID:</div>
                <div className="font-mono text-xs bg-gray-100 p-3 rounded break-all">
                  {diagnostics.uuid}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Feature Tests */}
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="px-6 py-4 bg-gray-100 border-b">
            <h2 className="text-xl font-semibold">Feature Tests</h2>
          </div>
          <div className="p-6 space-y-4">
            <div className="flex items-start gap-3">
              {getStatusIcon(diagnostics.indexedDBTest)}
              <div className="flex-1">
                <div className="font-medium">IndexedDB</div>
                {diagnostics.indexedDBError && (
                  <div className="text-sm text-red-600 mt-1">
                    {diagnostics.indexedDBError}
                  </div>
                )}
              </div>
            </div>

            <div className="flex items-start gap-3">
              {getStatusIcon(diagnostics.workerTest)}
              <div className="flex-1">
                <div className="font-medium">Web Worker Crypto</div>
                {diagnostics.workerError && (
                  <div className="text-sm text-red-600 mt-1">
                    {diagnostics.workerError}
                  </div>
                )}
              </div>
            </div>

            <div className="flex items-start gap-3">
              {getStatusIcon(diagnostics.sodiumTest)}
              <div className="flex-1">
                <div className="font-medium">libsodium WASM</div>
                <div className="text-sm text-gray-500 mt-1">
                  Init state: <span className="font-mono">{diagnostics.initState}</span>
                </div>
                {diagnostics.sodiumError && (
                  <div className="text-sm text-red-600 mt-1">
                    {diagnostics.sodiumError}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Errors */}
        {diagnostics.initError && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-red-800 mb-2">
              Initialization Error
            </h3>
            <pre className="text-sm text-red-700 whitespace-pre-wrap font-mono">
              {diagnostics.initError}
            </pre>
          </div>
        )}

        {/* Recommendations */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-blue-900 mb-3">
            Recommendations
          </h3>
          <ul className="space-y-2 text-sm text-blue-800">
            {!env.isSecure && (
              <li className="flex gap-2">
                <span>⚠️</span>
                <span>
                  <strong>Not secure context:</strong> Access this app over HTTPS or from
                  localhost to enable WebCrypto.
                </span>
              </li>
            )}
            {!env.hasSubtle && (
              <li className="flex gap-2">
                <span>⚠️</span>
                <span>
                  <strong>Missing crypto.subtle:</strong> Update to a modern browser
                  (Chrome 37+, Firefox 34+, Safari 11+, Edge 79+).
                </span>
              </li>
            )}
            {diagnostics.indexedDBTest === 'failed' && (
              <li className="flex gap-2">
                <span>⚠️</span>
                <span>
                  <strong>IndexedDB unavailable:</strong> Disable private browsing mode or
                  check browser settings. Some features may not work.
                </span>
              </li>
            )}
            {diagnostics.workerTest === 'failed' && (
              <li className="flex gap-2">
                <span>⚠️</span>
                <span>
                  <strong>Worker crypto unavailable:</strong> Safari may restrict crypto in
                  Workers. Crypto operations will run on main thread instead.
                </span>
              </li>
            )}
            {env.isSecure && env.hasSubtle && diagnostics.indexedDBTest === 'success' && (
              <li className="flex gap-2">
                <span>✅</span>
                <span>
                  <strong>All checks passed!</strong> Your browser fully supports encrypted
                  messaging.
                </span>
              </li>
            )}
          </ul>
        </div>

        {/* Actions */}
        <div className="flex gap-4">
          <button
            onClick={() => window.location.reload()}
            className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            Rerun Diagnostics
          </button>
          <button
            onClick={() => window.history.back()}
            className="px-6 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition-colors"
          >
            Go Back
          </button>
        </div>
      </div>
    </div>
  );
}
