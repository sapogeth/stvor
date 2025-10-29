'use client';

import { useState } from 'react';
import Link from 'next/link';

export default function ResetPage() {
  const [status, setStatus] = useState<string>('');
  const [loading, setLoading] = useState(false);

  const handleReset = async () => {
    setLoading(true);
    setStatus('Clearing data...');

    try {
      // Clear localStorage
      localStorage.clear();
      setStatus('Cleared localStorage...');

      // Delete IndexedDB databases
      await new Promise((resolve, reject) => {
        const request = indexedDB.deleteDatabase('ilyazh-keystore');
        request.onsuccess = () => {
          setStatus('Deleted ilyazh-keystore database...');
          resolve(true);
        };
        request.onerror = () => reject(request.error);
        request.onblocked = () => {
          setStatus('Database deletion blocked. Close all other tabs and try again.');
        };
      });

      // Also try deleting old database name
      await new Promise((resolve) => {
        const request = indexedDB.deleteDatabase('ilyazh_keystore');
        request.onsuccess = () => resolve(true);
        request.onerror = () => resolve(false);
      });

      setStatus('✅ All data cleared successfully! You can now go to homepage.');
      setLoading(false);
    } catch (err) {
      setStatus(`❌ Error: ${err instanceof Error ? err.message : String(err)}`);
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-500 to-purple-600 p-4">
      <div className="bg-white rounded-2xl shadow-2xl p-8 max-w-md w-full">
        <h1 className="text-3xl font-bold text-gray-900 mb-6 text-center">
          🔄 Reset Database
        </h1>

        <div className="mb-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
          <p className="text-sm text-yellow-800">
            <strong>Warning:</strong> This will delete all your identity keys, sessions, and prekey bundles.
            You'll need to generate new keys and start fresh handshakes.
          </p>
        </div>

        {status && (
          <div className="mb-6 p-4 bg-gray-100 rounded-lg">
            <p className="text-sm text-gray-800 whitespace-pre-wrap">{status}</p>
          </div>
        )}

        <button
          onClick={handleReset}
          disabled={loading}
          className={`w-full py-3 px-4 rounded-lg font-semibold text-white transition-colors ${
            loading
              ? 'bg-gray-400 cursor-not-allowed'
              : 'bg-red-600 hover:bg-red-700'
          }`}
        >
          {loading ? 'Resetting...' : 'Reset All Data'}
        </button>

        <div className="mt-4">
          <Link
            href="/"
            className="block text-center py-2 text-blue-600 hover:text-blue-700 transition-colors"
          >
            ← Back to Homepage
          </Link>
        </div>

        <div className="mt-6 text-xs text-gray-500 space-y-1">
          <p><strong>What gets deleted:</strong></p>
          <ul className="list-disc list-inside ml-2">
            <li>Username from localStorage</li>
            <li>Ed25519 + ML-DSA-65 identity keypairs</li>
            <li>X25519 + ML-KEM-768 prekey bundles</li>
            <li>All session state and encryption keys</li>
          </ul>
        </div>
      </div>
    </main>
  );
}
