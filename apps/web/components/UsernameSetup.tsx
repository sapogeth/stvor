'use client';

/**
 * Username Setup Component
 *
 * SECURITY CONTEXT:
 * This component appears when:
 * - User is authenticated via Clerk
 * - E2E crypto keys are initialized
 * - User has not chosen a username yet
 *
 * SECURITY GUARANTEE:
 * - Username is just a human-readable handle (@username)
 * - Changing username does NOT affect E2E encryption
 * - Clerk userId remains the canonical identity for crypto
 * - Profile is stored server-side, but private keys stay local
 */

import { useState } from 'react';
import { setProfile, checkUsernameAvailable } from '@/lib/profiles';

interface UsernameSetupProps {
  onComplete: (username: string) => void;
}

export function UsernameSetup({ onComplete }: UsernameSetupProps) {
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [isChecking, setIsChecking] = useState(false);
  const [isAvailable, setIsAvailable] = useState<boolean | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validateUsername = (value: string): boolean => {
    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
    return usernameRegex.test(value);
  };

  const handleUsernameChange = async (value: string) => {
    setUsername(value);
    setError(null);
    setIsAvailable(null);

    if (!value) {
      return;
    }

    if (!validateUsername(value)) {
      setError('Use 3-20 characters (letters, numbers, underscore)');
      return;
    }

    // Check availability
    setIsChecking(true);
    try {
      const available = await checkUsernameAvailable(value);
      setIsAvailable(available);
      if (!available) {
        setError('Username already taken');
      }
    } catch (err) {
      console.error('[UsernameSetup] Failed to check availability:', err);
      setError('Failed to check availability');
    } finally {
      setIsChecking(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!username || !validateUsername(username)) {
      setError('Invalid username format');
      return;
    }

    if (isAvailable === false) {
      setError('Username already taken');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      await setProfile(username, displayName || undefined);
      onComplete(username);
    } catch (err) {
      console.error('[UsernameSetup] Failed to set profile:', err);
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="bg-white rounded-lg shadow-2xl max-w-md w-full mx-4 p-8">
        {/* Header */}
        <div className="mb-6 text-center">
          <div className="text-5xl mb-4">👤</div>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">
            Choose Your Stv0r Username
          </h2>
          <p className="text-sm text-gray-600 mb-2">
            This will be your public handle for finding and starting conversations
          </p>
          <p className="text-xs text-gray-500">
            Your username is public, but your encryption keys stay private
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Username Input */}
          <div>
            <label
              htmlFor="username"
              className="block text-sm font-semibold text-gray-700 mb-1"
            >
              Username
            </label>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 font-mono">
                @
              </span>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => handleUsernameChange(e.target.value)}
                placeholder="myusername"
                disabled={isSubmitting}
                className="w-full pl-8 pr-10 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-100 font-mono"
                autoComplete="off"
                maxLength={20}
              />
              {/* Status Indicator */}
              <div className="absolute right-3 top-1/2 -translate-y-1/2">
                {isChecking && (
                  <div className="animate-spin h-5 w-5 border-2 border-blue-500 border-t-transparent rounded-full"></div>
                )}
                {!isChecking && isAvailable === true && (
                  <div className="text-green-500 text-xl">✓</div>
                )}
                {!isChecking && isAvailable === false && (
                  <div className="text-red-500 text-xl">✗</div>
                )}
              </div>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              3-20 characters: letters, numbers, underscore
            </p>
          </div>

          {/* Display Name Input (Optional) */}
          <div>
            <label
              htmlFor="displayName"
              className="block text-sm font-semibold text-gray-700 mb-1"
            >
              Display Name <span className="text-gray-400 font-normal">(optional)</span>
            </label>
            <input
              id="displayName"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="John Doe"
              disabled={isSubmitting}
              className="w-full px-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-100"
              maxLength={50}
            />
            <p className="text-xs text-gray-500 mt-1">
              Your display name (can be changed later)
            </p>
          </div>

          {/* Error Display */}
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-3">
              <p className="text-sm text-red-700">{error}</p>
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={
              isSubmitting ||
              !username ||
              isChecking ||
              isAvailable === false ||
              !validateUsername(username)
            }
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-semibold py-3 px-4 rounded-lg transition-colors"
          >
            {isSubmitting ? 'Creating Profile...' : 'Continue'}
          </button>
        </form>

        {/* Security Notice */}
        <div className="mt-6 text-xs text-gray-500 text-center">
          <p>🔒 Your username is public but your encryption keys stay private</p>
        </div>
      </div>
    </div>
  );
}
