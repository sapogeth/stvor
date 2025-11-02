'use client';

/**
 * Device Re-Enrollment Modal
 *
 * SECURITY CONTEXT:
 * This modal appears when:
 * - User's identity exists on relay server (registered from another device)
 * - This device has no private keys in IndexedDB
 *
 * SECURITY GUARANTEE:
 * - Re-enrollment generates a NEW keypair on this device
 * - Old devices will lose access (server identity is overwritten)
 * - This prevents key extraction attacks (server never sends private keys)
 * - User must have physical access to make this choice
 *
 * This is a security feature, not a bug. E2E encryption means one device
 * cannot "download" another device's keys.
 */

import { useState } from 'react';
import { reEnrollDevice } from '@/lib/identity';

interface DeviceReEnrollModalProps {
  username: string;
  onSuccess: () => void;
  onCancel: () => void;
}

export function DeviceReEnrollModal({
  username,
  onSuccess,
  onCancel,
}: DeviceReEnrollModalProps) {
  const [isEnrolling, setIsEnrolling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleReEnroll = async () => {
    setIsEnrolling(true);
    setError(null);

    try {
      await reEnrollDevice(username);
      onSuccess();
    } catch (err) {
      console.error('[DeviceReEnrollModal] Re-enrollment failed:', err);
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
    } finally {
      setIsEnrolling(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white rounded-lg shadow-2xl max-w-md w-full mx-4 p-8">
        {/* Header */}
        <div className="mb-6">
          <h2 className="text-2xl font-bold text-gray-900 mb-2">
            Secure Device Setup
          </h2>
          <p className="text-sm text-gray-600">
            Account: <span className="font-mono font-semibold">{username}</span>
          </p>
        </div>

        {/* Explanation */}
        <div className="mb-6 space-y-3">
          <p className="text-gray-700">
            This account exists on the server, but this device has no encryption keys.
          </p>
          <p className="text-gray-700">
            For security, private keys cannot be downloaded from the server.
          </p>
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
            <p className="text-sm text-yellow-800 font-semibold mb-1">
              Important Security Notice:
            </p>
            <p className="text-sm text-yellow-700">
              Registering this device will generate new encryption keys and disable access from other devices.
            </p>
          </div>
        </div>

        {/* Error Display */}
        {error && (
          <div className="mb-6 bg-red-50 border border-red-200 rounded-lg p-4">
            <p className="text-sm text-red-800 font-semibold mb-1">Error:</p>
            <p className="text-sm text-red-700">{error}</p>
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-3">
          <button
            onClick={handleReEnroll}
            disabled={isEnrolling}
            className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-semibold py-3 px-4 rounded-lg transition-colors"
          >
            {isEnrolling ? 'Registering Device...' : 'Register This Device'}
          </button>
          <button
            onClick={onCancel}
            disabled={isEnrolling}
            className="flex-1 bg-gray-200 hover:bg-gray-300 disabled:bg-gray-100 text-gray-800 font-semibold py-3 px-4 rounded-lg transition-colors"
          >
            Use Another Account
          </button>
        </div>

        {/* Technical Details (for power users) */}
        <details className="mt-6">
          <summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-700">
            Technical details
          </summary>
          <div className="mt-2 text-xs text-gray-600 space-y-1 bg-gray-50 p-3 rounded border border-gray-200">
            <p>• Zero-knowledge architecture: Server never sees private keys</p>
            <p>• New keypair generated client-side in this browser</p>
            <p>• Private keys stored in IndexedDB (encrypted at rest)</p>
            <p>• Only public keys uploaded to relay server</p>
            <p>• Protocol: Ilyazh-Web3E2E (X25519 + ML-KEM-768)</p>
          </div>
        </details>
      </div>
    </div>
  );
}
