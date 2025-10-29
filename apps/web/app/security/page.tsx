'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

export default function SecurityPage() {
  const [sessionData, setSessionData] = useState({
    sessionId: 'a7b3c9d2e5f1a8b4c6d7e9f2a3b5c8d1e4f7a9b2c5d8e1f4a7b3c9d2e5f1a8b4',
    currentEpoch: 0,
    messagesThisEpoch: 0,
    totalMessages: 0,
    epochStartTime: Date.now(),
    sessionStartTime: Date.now(),
    nextRekeyIn: 0,
    sessionExpiresIn: 0,
  });

  useEffect(() => {
    const stored = localStorage.getItem('ilyazh_username');
    if (!stored) {
      window.location.href = '/';
    }

    // Update timers
    const interval = setInterval(() => {
      const now = Date.now();
      const epochAge = now - sessionData.epochStartTime;
      const sessionAge = now - sessionData.sessionStartTime;

      const REKEY_TIME_LIMIT = 24 * 60 * 60 * 1000; // 24h
      const SESSION_TIME_CAP = 7 * 24 * 60 * 60 * 1000; // 7d

      setSessionData((prev) => ({
        ...prev,
        nextRekeyIn: Math.max(0, REKEY_TIME_LIMIT - epochAge),
        sessionExpiresIn: Math.max(0, SESSION_TIME_CAP - sessionAge),
      }));
    }, 1000);

    return () => clearInterval(interval);
  }, [sessionData.epochStartTime, sessionData.sessionStartTime]);

  const formatTime = (ms: number) => {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };

  const REKEY_MESSAGE_LIMIT = 1 << 20; // 2^20
  const SESSION_MESSAGE_CAP = Math.pow(2, 32);

  const epochProgress = (sessionData.messagesThisEpoch / REKEY_MESSAGE_LIMIT) * 100;
  const sessionProgress = (sessionData.totalMessages / SESSION_MESSAGE_CAP) * 100;

  return (
    <main className="min-h-screen bg-gray-50 dark:bg-gray-900 p-8">
      <div className="max-w-4xl mx-auto">
        <Link href="/" className="text-blue-500 hover:underline text-sm mb-4 block">
          ← Back to Home
        </Link>

        <h1 className="text-4xl font-bold mb-2">🔒 Security Dashboard</h1>
        <p className="text-gray-600 dark:text-gray-400 mb-8">
          Session Invariants & Cadence Enforcement
        </p>

        {/* Session ID */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4">Session Information</h2>
          <div className="space-y-3">
            <div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Session ID (sid)</div>
              <div className="font-mono text-xs bg-gray-100 dark:bg-gray-700 p-2 rounded mt-1 break-all">
                {sessionData.sessionId}
              </div>
              <div className="text-xs text-green-600 dark:text-green-400 mt-1">
                ✓ Included in AAD of every record (normative requirement)
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 mt-4">
              <div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Current Epoch</div>
                <div className="text-2xl font-bold">{sessionData.currentEpoch}</div>
              </div>
              <div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Total Messages</div>
                <div className="text-2xl font-bold">{sessionData.totalMessages.toLocaleString()}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Cadence Enforcement */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4">Mandated Re-encapsulation Cadence</h2>

          {/* Epoch Limits */}
          <div className="mb-6">
            <div className="flex justify-between items-center mb-2">
              <div className="text-sm font-medium">Epoch Message Limit</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                {sessionData.messagesThisEpoch.toLocaleString()} / {REKEY_MESSAGE_LIMIT.toLocaleString()} (2^20)
              </div>
            </div>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
              <div
                className={`h-3 rounded-full transition-all ${
                  epochProgress > 80 ? 'bg-red-500' : epochProgress > 50 ? 'bg-yellow-500' : 'bg-green-500'
                }`}
                style={{ width: `${Math.min(100, epochProgress)}%` }}
              />
            </div>
            <div className="text-xs text-gray-600 dark:text-gray-400 mt-1">
              {epochProgress > 90 && '⚠️ Approaching limit - rekey required'}
            </div>
          </div>

          <div className="mb-6">
            <div className="flex justify-between items-center mb-2">
              <div className="text-sm font-medium">Epoch Time Limit</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                Next rekey in: {formatTime(sessionData.nextRekeyIn)}
              </div>
            </div>
            <div className="text-xs text-gray-600 dark:text-gray-400">
              Maximum 24 hours per epoch (enforced)
            </div>
          </div>

          {/* Session Caps */}
          <div className="border-t dark:border-gray-700 pt-4">
            <div className="text-sm font-medium mb-2">Session Hard Caps</div>

            <div className="mb-4">
              <div className="flex justify-between items-center mb-1">
                <div className="text-xs">Total Messages</div>
                <div className="text-xs text-gray-600 dark:text-gray-400">
                  {sessionData.totalMessages.toLocaleString()} / {SESSION_MESSAGE_CAP.toLocaleString()} (2^32)
                </div>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div
                  className="bg-blue-500 h-2 rounded-full"
                  style={{ width: `${Math.min(100, sessionProgress)}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between items-center mb-1">
                <div className="text-xs">Session Age</div>
                <div className="text-xs text-gray-600 dark:text-gray-400">
                  Expires in: {formatTime(sessionData.sessionExpiresIn)}
                </div>
              </div>
              <div className="text-xs text-gray-600 dark:text-gray-400">
                Maximum 7 days (604,800 seconds)
              </div>
            </div>
          </div>
        </div>

        {/* Protocol Invariants */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4">Protocol Invariants</h2>
          <div className="space-y-3">
            <div className="flex items-start space-x-3">
              <div className="text-green-500 text-xl">✓</div>
              <div className="flex-1">
                <div className="font-medium">sid-in-AAD</div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Session ID included in AAD of every encrypted record
                </div>
              </div>
            </div>

            <div className="flex items-start space-x-3">
              <div className="text-green-500 text-xl">✓</div>
              <div className="flex-1">
                <div className="font-medium">Dual Signatures</div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Both Ed25519 and ML-DSA-65 verified during handshake (default mode)
                </div>
              </div>
            </div>

            <div className="flex items-start space-x-3">
              <div className="text-green-500 text-xl">✓</div>
              <div className="flex-1">
                <div className="font-medium">Nonce Policy</div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  R64 || C32 structure (ratchet ID + monotonic counter) prevents reuse
                </div>
              </div>
            </div>

            <div className="flex items-start space-x-3">
              <div className="text-green-500 text-xl">✓</div>
              <div className="flex-1">
                <div className="font-medium">Key Erasure</div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Message keys zeroized immediately after use
                </div>
              </div>
            </div>

            <div className="flex items-start space-x-3">
              <div className="text-green-500 text-xl">✓</div>
              <div className="flex-1">
                <div className="font-medium">Hybrid Security</div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  X25519 + ML-KEM-768 combiner ensures security if either primitive is secure
                </div>
              </div>
            </div>

            <div className="flex items-start space-x-3">
              <div className="text-green-500 text-xl">✓</div>
              <div className="flex-1">
                <div className="font-medium">Transcript Binding</div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Handshake transcript hashed with SHA-384, signatures cover full context
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Cryptographic Suite */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
          <h2 className="text-xl font-semibold mb-4">Cryptographic Suite</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <div className="font-medium mb-2">Key Exchange</div>
              <ul className="space-y-1 text-gray-600 dark:text-gray-400">
                <li>• Classical: X25519 (Curve25519 DH)</li>
                <li>• Post-Quantum: ML-KEM-768 (FIPS 203)</li>
              </ul>
            </div>

            <div>
              <div className="font-medium mb-2">Signatures</div>
              <ul className="space-y-1 text-gray-600 dark:text-gray-400">
                <li>• Classical: Ed25519</li>
                <li>• Post-Quantum: ML-DSA-65 (FIPS 204)</li>
              </ul>
            </div>

            <div>
              <div className="font-medium mb-2">Key Derivation</div>
              <ul className="space-y-1 text-gray-600 dark:text-gray-400">
                <li>• HKDF-SHA-384</li>
                <li>• Domain-separated labels</li>
              </ul>
            </div>

            <div>
              <div className="font-medium mb-2">Encryption</div>
              <ul className="space-y-1 text-gray-600 dark:text-gray-400">
                <li>• AES-256-GCM (AEAD)</li>
                <li>• 12-byte nonce, 16-byte tag</li>
              </ul>
            </div>
          </div>

          <div className="mt-4 pt-4 border-t dark:border-gray-700 text-xs text-gray-600 dark:text-gray-400">
            Protocol: Ilyazh-Web3E2E v0.8 • Wire format: CBOR • All keys stored client-side only
          </div>
        </div>
      </div>
    </main>
  );
}
