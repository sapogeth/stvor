'use client';

import { useEffect, useState } from 'react';

export default function ResetDBPage() {
  const [status, setStatus] = useState('🔄 Resetting database...');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        // Clear localStorage (including migration flag)
        localStorage.clear();
        setStatus('✅ Cleared localStorage...');
        await new Promise(r => setTimeout(r, 500));

        // Delete databases
        const deleteDB = (name: string) => new Promise<void>((resolve) => {
          const req = indexedDB.deleteDatabase(name);
          req.onsuccess = () => resolve();
          req.onerror = () => resolve();
          req.onblocked = () => resolve();
        });

        setStatus('🗑️ Deleting databases...');
        await deleteDB('ilyazh-keystore');
        await deleteDB('ilyazh_keystore');

        setStatus('✅ Database reset complete! Redirecting...');
        setLoading(false);

        setTimeout(() => {
          window.location.href = '/';
        }, 1500);
      } catch (err) {
        setStatus(`❌ Error: ${err instanceof Error ? err.message : String(err)}`);
        setLoading(false);
      }
    })();
  }, []);

  return (
    <main className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-500 to-purple-600 p-4">
      <div className="bg-white rounded-2xl shadow-2xl p-8 max-w-md w-full text-center">
        <h1 className="text-3xl font-bold text-gray-900 mb-6">
          Database Reset
        </h1>

        {loading && (
          <div className="mb-6">
            <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-600"></div>
          </div>
        )}

        <div className="mb-6 p-4 bg-gray-100 rounded-lg">
          <p className="text-lg text-gray-800">{status}</p>
        </div>

        {!loading && (
          <a
            href="/"
            className="inline-block py-3 px-6 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors"
          >
            Go to Homepage
          </a>
        )}
      </div>
    </main>
  );
}
