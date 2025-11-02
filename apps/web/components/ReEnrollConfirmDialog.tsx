'use client';

/**
 * Re-Enrollment Confirmation Dialog
 *
 * SECURITY:
 * - Prevents silent account takeover via auto-re-enrollment
 * - Requires explicit user confirmation before generating new identity
 * - Warns user that this will disable other devices
 * - Explains security implications clearly
 *
 * THREAT MODEL:
 * - Protects against: Malicious relay returning 404, attacker forcing re-enrollment
 * - Requires: User physical access and explicit consent
 *
 * @module ReEnrollConfirmDialog
 */

import { useState } from 'react';

interface ReEnrollConfirmDialogProps {
  username: string;
  reason: string;
  onConfirm: () => Promise<void>;
  onCancel: () => void;
}

export function ReEnrollConfirmDialog({
  username,
  reason,
  onConfirm,
  onCancel,
}: ReEnrollConfirmDialogProps) {
  const [isConfirming, setIsConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmText, setConfirmText] = useState('');

  const handleConfirm = async () => {
    setError(null);
    setIsConfirming(true);

    try {
      await onConfirm();
    } catch (err) {
      console.error('[ReEnrollConfirm] Re-enrollment failed:', err);
      setError(err instanceof Error ? err.message : 'Re-enrollment failed');
      setIsConfirming(false);
    }
  };

  const isConfirmTextValid = confirmText.toLowerCase() === 'confirm';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-white rounded-lg shadow-2xl max-w-lg w-full mx-4 p-8">
        {/* Header */}
        <div className="mb-6 text-center">
          <div className="text-5xl mb-4">⚠️</div>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Device Re-Enrollment Required</h2>
          <p className="text-sm text-gray-600">Account: <span className="font-mono font-semibold">{username}</span></p>
        </div>

        {/* Explanation */}
        <div className="mb-6 space-y-3">
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
            <p className="text-sm text-yellow-800 font-semibold mb-2">Why is this happening?</p>
            <p className="text-sm text-yellow-700">{reason}</p>
          </div>

          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <p className="text-sm text-red-800 font-semibold mb-2">⚠️ Critical Security Warning:</p>
            <ul className="text-sm text-red-700 space-y-1">
              <li>• This will generate a <strong>new encryption identity</strong></li>
              <li>• All other devices will <strong>lose access</strong></li>
              <li>• Old messages may become <strong>unreadable</strong></li>
              <li>• This action <strong>cannot be undone</strong></li>
            </ul>
          </div>

          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <p className="text-sm text-blue-800 font-semibold mb-2">What will happen:</p>
            <ol className="text-sm text-blue-700 space-y-1 list-decimal list-inside">
              <li>New keypair generated on this device</li>
              <li>New identity published to relay server</li>
              <li>Other devices must re-establish sessions</li>
              <li>You can continue chatting with new identity</li>
            </ol>
          </div>
        </div>

        {/* Confirmation Input */}
        <div className="mb-6">
          <label htmlFor="confirmText" className="block text-sm font-semibold text-gray-700 mb-2">
            Type <span className="font-mono bg-gray-100 px-2 py-1 rounded">CONFIRM</span> to proceed:
          </label>
          <input
            id="confirmText"
            type="text"
            value={confirmText}
            onChange={(e) => setConfirmText(e.target.value)}
            disabled={isConfirming}
            className="w-full px-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent disabled:bg-gray-100 font-mono"
            placeholder="Type CONFIRM"
            autoFocus
          />
        </div>

        {/* Error Display */}
        {error && (
          <div className="mb-6 bg-red-50 border border-red-200 rounded-lg p-3">
            <p className="text-sm text-red-700">{error}</p>
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-3">
          <button
            onClick={onCancel}
            disabled={isConfirming}
            className="flex-1 bg-gray-200 hover:bg-gray-300 disabled:bg-gray-100 text-gray-800 font-semibold py-3 px-4 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={isConfirming || !isConfirmTextValid}
            className="flex-1 bg-red-600 hover:bg-red-700 disabled:bg-red-400 text-white font-semibold py-3 px-4 rounded-lg transition-colors"
          >
            {isConfirming ? 'Re-Enrolling Device...' : 'Re-Enroll This Device'}
          </button>
        </div>

        {/* Help Text */}
        <div className="mt-6 text-center">
          <p className="text-xs text-gray-500">
            If you're unsure, click Cancel and contact support for help.
          </p>
        </div>
      </div>
    </div>
  );
}
