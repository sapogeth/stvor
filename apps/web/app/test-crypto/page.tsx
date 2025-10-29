'use client';

/**
 * Simple Crypto Test Page
 * Tests the crypto patch in isolation
 */

import { useEffect, useState } from 'react';
import { getCryptoOrThrow, isCryptoAvailable } from '@/lib/runtime/crypto-safe';
import { initCryptoOnce, getCryptoInitState } from '@/lib/crypto/init';

export default function TestCryptoPage() {
  const [status, setStatus] = useState<any>({});
  const [logs, setLogs] = useState<string[]>([]);

  const addLog = (msg: string) => {
    console.log(msg);
    setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  useEffect(() => {
    runTests();
  }, []);

  async function runTests() {
    addLog('🧪 Starting crypto tests...');

    // Test 1: Check if crypto is available
    addLog('Test 1: Checking crypto availability...');
    const available = isCryptoAvailable();
    addLog(`✓ Crypto available: ${available}`);
    setStatus((prev: any) => ({ ...prev, available }));

    if (!available) {
      addLog('❌ Crypto not available - stopping tests');
      return;
    }

    // Test 2: Get crypto interface
    addLog('Test 2: Getting crypto interface...');
    try {
      const { ce, randomUUID } = getCryptoOrThrow();
      addLog(`✓ Crypto interface obtained`);
      addLog(`  - Context: ${ce.context}`);
      addLog(`  - Secure: ${ce.isSecure}`);
      addLog(`  - Has UUID: ${ce.hasRandomUUID ? 'native' : 'polyfill'}`);

      setStatus((prev: any) => ({
        ...prev,
        context: ce.context,
        isSecure: ce.isSecure,
        hasNativeUUID: ce.hasRandomUUID
      }));

      // Test 3: Generate UUID
      addLog('Test 3: Generating UUID...');
      const uuid = randomUUID();
      addLog(`✓ UUID generated: ${uuid}`);
      setStatus((prev: any) => ({ ...prev, uuid }));

    } catch (err: any) {
      addLog(`❌ Failed: ${err.message}`);
      setStatus((prev: any) => ({ ...prev, error: err.message }));
      return;
    }

    // Test 4: Initialize crypto
    addLog('Test 4: Initializing crypto...');
    try {
      await initCryptoOnce();
      const state = getCryptoInitState();
      addLog(`✓ Crypto initialized: ${state}`);
      setStatus((prev: any) => ({ ...prev, initState: state }));
    } catch (err: any) {
      addLog(`❌ Init failed: ${err.message}`);
      setStatus((prev: any) => ({ ...prev, initError: err.message }));
      return;
    }

    // Test 5: Test IndexedDB
    addLog('Test 5: Testing IndexedDB...');
    try {
      const testDB = await new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open('test-crypto-db', 1);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
        request.onupgradeneeded = (event) => {
          const db = (event.target as IDBOpenDBRequest).result;
          db.createObjectStore('test');
        };
      });

      testDB.close();
      indexedDB.deleteDatabase('test-crypto-db');
      addLog('✓ IndexedDB working');
      setStatus((prev: any) => ({ ...prev, indexedDB: 'working' }));
    } catch (err: any) {
      addLog(`❌ IndexedDB failed: ${err.message}`);
      setStatus((prev: any) => ({ ...prev, indexedDB: 'failed', indexedDBError: err.message }));
    }

    addLog('🎉 All tests completed!');
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-6">🧪 Crypto Test Page</h1>

        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4">Status</h2>
          <pre className="bg-gray-900 p-4 rounded text-sm overflow-auto">
            {JSON.stringify(status, null, 2)}
          </pre>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-xl font-semibold mb-4">Logs</h2>
          <div className="bg-gray-900 p-4 rounded text-sm space-y-1 max-h-96 overflow-auto font-mono">
            {logs.map((log, idx) => (
              <div key={idx}>{log}</div>
            ))}
          </div>
        </div>

        <div className="mt-6">
          <button
            onClick={() => {
              setLogs([]);
              setStatus({});
              runTests();
            }}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg font-medium"
          >
            Rerun Tests
          </button>
          <a
            href="/debug/crypto"
            className="ml-4 px-6 py-2 bg-green-600 hover:bg-green-700 rounded-lg font-medium inline-block"
          >
            Go to Diagnostics
          </a>
          <a
            href="/"
            className="ml-4 px-6 py-2 bg-gray-600 hover:bg-gray-700 rounded-lg font-medium inline-block"
          >
            Go Home
          </a>
        </div>
      </div>
    </div>
  );
}
