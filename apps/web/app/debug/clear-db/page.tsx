'use client';

/**
 * Database Reset Tool
 *
 * Use this page to clear IndexedDB when encountering errors like:
 * "Failed to store record in an IDBObjectStore: Evaluating the object store's key path did not yield a value"
 */

import { useEffect, useState } from 'react';

export default function ClearDBPage() {
  const [status, setStatus] = useState<string>('Ready to clear databases');
  const [databases, setDatabases] = useState<string[]>([]);
  const [logs, setLogs] = useState<string[]>([]);

  const addLog = (msg: string) => {
    console.log(msg);
    setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  useEffect(() => {
    listDatabases();
  }, []);

  async function listDatabases() {
    try {
      if ('databases' in indexedDB) {
        const dbs = await indexedDB.databases();
        const dbNames = dbs.map(db => db.name || 'unknown');
        setDatabases(dbNames);
        addLog(`Found ${dbNames.length} databases: ${dbNames.join(', ')}`);
      } else {
        addLog('indexedDB.databases() not supported in this browser');
        setDatabases(['ilyazh-keystore-v2', 'ilyazh-keystore', 'test-crypto-db']);
      }
    } catch (err: any) {
      addLog(`Error listing databases: ${err.message}`);
    }
  }

  async function clearAllDatabases() {
    setStatus('Clearing databases...');
    addLog('🗑️  Starting database cleanup...');

    const dbsToClear = databases.length > 0
      ? databases
      : ['ilyazh-keystore-v2', 'ilyazh-keystore', 'test-crypto-db'];

    for (const dbName of dbsToClear) {
      try {
        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase(dbName);

          request.onsuccess = () => {
            addLog(`✓ Deleted database: ${dbName}`);
            resolve();
          };

          request.onerror = () => {
            addLog(`✗ Failed to delete ${dbName}: ${request.error?.message}`);
            reject(request.error);
          };

          request.onblocked = () => {
            addLog(`⚠️  Delete blocked for ${dbName} (close all other tabs)`);
          };
        });
      } catch (err: any) {
        addLog(`Error deleting ${dbName}: ${err.message}`);
      }
    }

    // Also clear localStorage
    try {
      localStorage.clear();
      addLog('✓ Cleared localStorage');
    } catch (err: any) {
      addLog(`✗ Failed to clear localStorage: ${err.message}`);
    }

    // Also clear sessionStorage
    try {
      sessionStorage.clear();
      addLog('✓ Cleared sessionStorage');
    } catch (err: any) {
      addLog(`✗ Failed to clear sessionStorage: ${err.message}`);
    }

    setStatus('✅ Cleanup complete! Please refresh the page.');
    addLog('🎉 All databases and storage cleared!');

    await listDatabases();
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-6">🗑️  Database Reset Tool</h1>

        <div className="bg-yellow-900 border border-yellow-700 rounded-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-2 text-yellow-200">⚠️ Warning</h2>
          <p className="text-yellow-100">
            This will delete all local data including:
          </p>
          <ul className="list-disc list-inside mt-2 text-yellow-100">
            <li>Identity keys</li>
            <li>Session states</li>
            <li>Prekey bundles</li>
            <li>All stored messages</li>
            <li>localStorage data</li>
          </ul>
          <p className="mt-2 text-yellow-100 font-semibold">
            You will need to re-register after clearing.
          </p>
        </div>

        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4">Current Status</h2>
          <p className="mb-4">{status}</p>

          {databases.length > 0 && (
            <div className="mb-4">
              <h3 className="font-semibold mb-2">Found Databases:</h3>
              <ul className="list-disc list-inside">
                {databases.map((db, idx) => (
                  <li key={idx} className="font-mono text-sm">{db}</li>
                ))}
              </ul>
            </div>
          )}

          <button
            onClick={clearAllDatabases}
            className="px-6 py-3 bg-red-600 hover:bg-red-700 rounded-lg font-semibold transition-colors"
          >
            🗑️  Clear All Databases & Storage
          </button>
        </div>

        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4">Logs</h2>
          <div className="bg-gray-900 p-4 rounded text-sm space-y-1 max-h-96 overflow-auto font-mono">
            {logs.length === 0 ? (
              <div className="text-gray-500">No logs yet...</div>
            ) : (
              logs.map((log, idx) => (
                <div key={idx}>{log}</div>
              ))
            )}
          </div>
        </div>

        <div className="flex gap-4">
          <button
            onClick={() => window.location.reload()}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg font-medium"
          >
            Refresh Page
          </button>
          <a
            href="/test-crypto"
            className="px-6 py-2 bg-green-600 hover:bg-green-700 rounded-lg font-medium inline-block"
          >
            Test Crypto
          </a>
          <a
            href="/"
            className="px-6 py-2 bg-gray-600 hover:bg-gray-700 rounded-lg font-medium inline-block"
          >
            Go Home
          </a>
        </div>

        <div className="mt-8 p-4 bg-gray-800 rounded-lg">
          <h3 className="font-semibold mb-2">Common Errors Fixed By This Tool:</h3>
          <ul className="text-sm space-y-1 text-gray-300">
            <li>✓ "Failed to store record in an IDBObjectStore"</li>
            <li>✓ "Evaluating the object store's key path did not yield a value"</li>
            <li>✓ "VersionError" when opening database</li>
            <li>✓ "Failed to initialize encryption keys"</li>
            <li>✓ Stuck on "Generating identity keys..."</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
