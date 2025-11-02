'use client';

/**
 * E2E Unlock Dialog - Password prompt for secure keystore
 *
 * SECURITY:
 * - Password never leaves device
 * - Password never sent to server
 * - Used only to derive encryption key locally
 * - Shows password strength indicator
 * - Enforces minimum password length
 *
 * @module E2EUnlockDialog
 */

import { useState } from 'react';
import { validatePasswordStrength } from '@/lib/e2e-security-config';

export type E2EUnlockMode = 'unlock' | 'create' | 'migrate';

interface E2EUnlockDialogProps {
  mode: E2EUnlockMode;
  onUnlock: (password: string) => Promise<boolean>;
  onCancel?: () => void;
  error?: string | null;
}

export function E2EUnlockDialog({
  mode,
  onUnlock,
  onCancel,
  error: externalError,
}: E2EUnlockDialogProps) {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  const error = externalError || localError;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);

    // Validate password
    if (!password) {
      setLocalError('Password is required');
      return;
    }

    // For create/migrate mode, validate password strength
    if (mode !== 'unlock') {
      const validation = validatePasswordStrength(password);
      if (!validation.valid) {
        setLocalError(validation.error || 'Invalid password');
        return;
      }

      if (password !== confirmPassword) {
        setLocalError('Passwords do not match');
        return;
      }
    }

    setIsUnlocking(true);

    try {
      const success = await onUnlock(password);

      if (!success) {
        setLocalError('Wrong password');
      }
    } catch (err) {
      console.error('[E2EUnlockDialog] Unlock error:', err);
      setLocalError(err instanceof Error ? err.message : 'Unlock failed');
    } finally {
      setIsUnlocking(false);
    }
  };

  const getTitleText = () => {
    switch (mode) {
      case 'unlock':
        return '🔐 Unlock E2E Encryption';
      case 'create':
        return '🔐 Set Encryption Password';
      case 'migrate':
        return '🔐 Upgrade to Secure Storage';
    }
  };

  const getDescriptionText = () => {
    switch (mode) {
      case 'unlock':
        return 'Enter your password to unlock your encryption keys';
      case 'create':
        return 'Choose a strong password to protect your encryption keys on this device';
      case 'migrate':
        return 'Your keys are currently unencrypted. Set a password to enable secure storage.';
    }
  };

  const getButtonText = () => {
    if (isUnlocking) {
      switch (mode) {
        case 'unlock':
          return 'Unlocking...';
        case 'create':
          return 'Creating...';
        case 'migrate':
          return 'Migrating...';
      }
    }
    switch (mode) {
      case 'unlock':
        return 'Unlock';
      case 'create':
        return 'Create Keystore';
      case 'migrate':
        return 'Migrate to Secure Storage';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white rounded-lg shadow-2xl max-w-md w-full mx-4 p-8">
        {/* Header */}
        <div className="mb-6 text-center">
          <h2 className="text-2xl font-bold text-gray-900 mb-2">{getTitleText()}</h2>
          <p className="text-sm text-gray-600">{getDescriptionText()}</p>
        </div>

        {/* Security Notice */}
        <div className="mb-6 bg-blue-50 border border-blue-200 rounded-lg p-4">
          <p className="text-sm text-blue-800 font-semibold mb-1">Security Notice:</p>
          <ul className="text-xs text-blue-700 space-y-1">
            <li>• Password never leaves this device</li>
            <li>• Used only to encrypt keys locally</li>
            <li>• Losing password = losing all keys</li>
            {mode !== 'unlock' && <li>• Choose a strong, memorable password</li>}
          </ul>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Password Input */}
          <div>
            <label htmlFor="password" className="block text-sm font-semibold text-gray-700 mb-1">
              {mode === 'unlock' ? 'Password' : 'Choose Password'}
            </label>
            <div className="relative">
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={isUnlocking}
                className="w-full px-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-100 pr-12"
                placeholder={mode === 'unlock' ? 'Enter password' : 'At least 12 characters'}
                autoFocus
                autoComplete={mode === 'unlock' ? 'current-password' : 'new-password'}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700"
              >
                {showPassword ? '👁️' : '👁️‍🗨️'}
              </button>
            </div>
          </div>

          {/* Confirm Password (create/migrate only) */}
          {mode !== 'unlock' && (
            <div>
              <label
                htmlFor="confirmPassword"
                className="block text-sm font-semibold text-gray-700 mb-1"
              >
                Confirm Password
              </label>
              <input
                id="confirmPassword"
                type={showPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={isUnlocking}
                className="w-full px-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-100"
                placeholder="Re-enter password"
                autoComplete="new-password"
              />
            </div>
          )}

          {/* Error Display */}
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-3">
              <p className="text-sm text-red-700">{error}</p>
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-3">
            <button
              type="submit"
              disabled={isUnlocking || !password || (mode !== 'unlock' && !confirmPassword)}
              className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-semibold py-3 px-4 rounded-lg transition-colors"
            >
              {getButtonText()}
            </button>
            {onCancel && (
              <button
                type="button"
                onClick={onCancel}
                disabled={isUnlocking}
                className="px-4 bg-gray-200 hover:bg-gray-300 disabled:bg-gray-100 text-gray-800 font-semibold py-3 rounded-lg transition-colors"
              >
                Cancel
              </button>
            )}
          </div>
        </form>

        {/* Help Text */}
        {mode === 'unlock' && (
          <div className="mt-6 text-center">
            <p className="text-xs text-gray-500">
              Forgot password? You'll need to re-enroll this device with a new identity.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
