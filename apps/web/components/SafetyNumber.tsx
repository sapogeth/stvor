/**
 * Safety Number Verification UI
 * TOFU (Trust On First Use) verification via out-of-band channel
 */

'use client';

import { useState } from 'react';
import { deriveSafetyNumber } from '@/lib/session-security';

interface SafetyNumberProps {
  ourIdentityEd25519: Uint8Array;
  theirIdentityEd25519: Uint8Array;
  peerName: string;
  onClose: () => void;
}

export function SafetyNumber({ ourIdentityEd25519, theirIdentityEd25519, peerName, onClose }: SafetyNumberProps) {
  const [copied, setCopied] = useState(false);

  // Derive safety number from IDENTITY KEYS (not session ID)
  // CRITICAL: This ensures safety number stays constant across re-handshakes
  const safetyNumber = deriveSafetyNumber(ourIdentityEd25519, theirIdentityEd25519);

  const copyToClipboard = () => {
    navigator.clipboard.writeText(safetyNumber);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-2xl w-full mx-4">
        <h2 className="text-2xl font-bold mb-4 text-gray-900 dark:text-white">
          Safety Number
        </h2>

        <div className="mb-4 text-sm text-gray-600 dark:text-gray-400">
          <p className="mb-2">
            Verify this safety number with <span className="font-semibold">{peerName}</span> through
            a trusted channel (voice call, in person, etc.) to ensure your connection is secure.
          </p>
          <p>
            If the numbers don't match, your connection may be compromised.
          </p>
        </div>

        <div className="bg-gray-100 dark:bg-gray-700 rounded-lg p-4 mb-4">
          <div className="font-mono text-lg text-center break-all leading-relaxed text-gray-900 dark:text-white">
            {safetyNumber}
          </div>
        </div>

        <div className="flex gap-2">
          <button
            onClick={copyToClipboard}
            className="flex-1 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors"
          >
            {copied ? '✓ Copied!' : 'Copy Number'}
          </button>
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-gray-300 dark:bg-gray-600 text-gray-800 dark:text-white rounded hover:bg-gray-400 dark:hover:bg-gray-500 transition-colors"
          >
            Close
          </button>
        </div>

        <div className="mt-4 text-xs text-gray-500 dark:text-gray-400">
          <p className="font-semibold mb-1">How to verify:</p>
          <ol className="list-decimal list-inside space-y-1">
            <li>Contact {peerName} through a trusted channel</li>
            <li>Read your safety number to them (or vice versa)</li>
            <li>Confirm both numbers match exactly</li>
            <li>If they match, your connection is secure</li>
          </ol>
        </div>

        <div className="mt-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-700 rounded">
          <p className="text-xs text-yellow-800 dark:text-yellow-200">
            <span className="font-semibold">⚠️ Warning:</span> If the safety numbers don't match,
            do NOT continue the conversation. Your connection may be intercepted.
          </p>
        </div>
      </div>
    </div>
  );
}
