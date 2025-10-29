'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

export default function Home() {
  const [username, setUsername] = useState('');
  const [isRegistered, setIsRegistered] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const stored = localStorage.getItem('ilyazh_username');
    if (stored) {
      setUsername(stored);
      setIsRegistered(true);
    }
  }, []);

  const handleRegister = async () => {
    if (!username.trim()) return;

    try {
      // Generate identity keys (done in client lib)
      localStorage.setItem('ilyazh_username', username);
      setIsRegistered(true);
    } catch (err) {
      console.error('Registration failed:', err);
    }
  };

  // Prevent hydration mismatch
  if (!mounted) {
    return (
      <main className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
        <div className="text-lg">Loading...</div>
      </main>
    );
  }

  if (isRegistered) {
    return (
      <>
        {/* SECURITY: Development warning banner */}
        {process.env.NODE_ENV === 'development' && (
          <div
            style={{
              background: '#ff6b6b',
              color: 'white',
              padding: '12px 20px',
              textAlign: 'center',
              fontWeight: 'bold',
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              zIndex: 9999,
              fontSize: '14px',
              borderBottom: '3px solid #c92a2a',
            }}
          >
            ⚠️ DEVELOPMENT MODE - Post-quantum crypto is MOCKED. Not secure!
          </div>
        )}
        <main
          className="min-h-screen flex flex-col items-center justify-center p-8 bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800"
          style={{ paddingTop: process.env.NODE_ENV === 'development' ? '50px' : '0' }}
        >
          <div className="w-full max-w-2xl bg-white dark:bg-gray-800 rounded-lg shadow-xl p-8">
            <h1 className="text-4xl font-bold mb-4 text-center">
              🔐 Ilyazh Messenger
            </h1>
          <p className="text-center text-gray-600 dark:text-gray-400 mb-8">
            Logged in as <strong>{username}</strong>
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Link
              href="/chat"
              className="p-6 bg-blue-500 hover:bg-blue-600 text-white rounded-lg text-center transition"
            >
              <div className="text-4xl mb-2">💬</div>
              <div className="font-semibold">Chat</div>
              <div className="text-sm opacity-80">1:1 Encrypted Messages</div>
            </Link>

            <Link
              href="/benchmarks"
              className="p-6 bg-green-500 hover:bg-green-600 text-white rounded-lg text-center transition"
            >
              <div className="text-4xl mb-2">📊</div>
              <div className="font-semibold">Benchmarks</div>
              <div className="text-sm opacity-80">Performance Metrics</div>
            </Link>

            <Link
              href="/security"
              className="p-6 bg-purple-500 hover:bg-purple-600 text-white rounded-lg text-center transition"
            >
              <div className="text-4xl mb-2">🔒</div>
              <div className="font-semibold">Security</div>
              <div className="text-sm opacity-80">Session Invariants</div>
            </Link>
          </div>

          <div className="mt-8 p-4 bg-gray-100 dark:bg-gray-700 rounded-lg">
            <h3 className="font-semibold mb-2">Protocol: Ilyazh-Web3E2E v0.8</h3>
            <ul className="text-sm space-y-1 text-gray-700 dark:text-gray-300">
              <li>✓ Hybrid AKE: X25519 + ML-KEM-768</li>
              <li>✓ Dual Signatures: Ed25519 + ML-DSA-65</li>
              <li>✓ Double Ratchet with mandated cadence</li>
              <li>✓ sid-in-AAD for all records</li>
              <li>✓ AES-256-GCM + HKDF-SHA-384</li>
            </ul>
          </div>

          <button
            onClick={() => {
              localStorage.removeItem('ilyazh_username');
              setIsRegistered(false);
              setUsername('');
            }}
            className="mt-4 w-full p-2 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded transition"
          >
            Logout
          </button>
        </div>
      </main>
      </>
    );
  }

  return (
    <>
      {/* SECURITY: Development warning banner */}
      {process.env.NODE_ENV === 'development' && (
        <div
          style={{
            background: '#ff6b6b',
            color: 'white',
            padding: '12px 20px',
            textAlign: 'center',
            fontWeight: 'bold',
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            zIndex: 9999,
            fontSize: '14px',
            borderBottom: '3px solid #c92a2a',
          }}
        >
          ⚠️ DEVELOPMENT MODE - Post-quantum crypto is MOCKED. Not secure!
        </div>
      )}
      <main
        className="min-h-screen flex flex-col items-center justify-center p-8 bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800"
        style={{ paddingTop: process.env.NODE_ENV === 'development' ? '50px' : '0' }}
      >
      <div className="w-full max-w-md bg-white dark:bg-gray-800 rounded-lg shadow-xl p-8">
        <h1 className="text-4xl font-bold mb-4 text-center">
          🔐 Ilyazh Messenger
        </h1>
        <p className="text-center text-gray-600 dark:text-gray-400 mb-8">
          Post-Quantum E2E Encrypted Messaging
        </p>

        <div className="space-y-4">
          <input
            type="text"
            placeholder="Enter username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleRegister()}
            className="w-full p-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 dark:bg-gray-700"
          />

          <button
            onClick={handleRegister}
            className="w-full p-3 bg-blue-500 hover:bg-blue-600 text-white rounded-lg font-semibold transition"
          >
            Register / Login
          </button>
        </div>

        <div className="mt-8 text-xs text-gray-500 dark:text-gray-400 text-center">
          <p>Protocol v0.8 • Database-free • Server sees only opaque blobs</p>
        </div>
      </div>
    </main>
  );
}
