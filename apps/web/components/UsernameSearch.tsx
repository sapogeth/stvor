'use client';

/**
 * Username Search Component
 *
 * Enhanced input field for searching and selecting usernames
 * - Real-time availability checking
 * - Visual feedback for valid/invalid usernames
 * - Integration with profiles API
 */

import { useState, useEffect, useRef } from 'react';
import { getProfileByUsername } from '@/lib/profiles';

interface UsernameSearchProps {
  value: string;
  onChange: (value: string) => void;
  onKeyDown?: (e: React.KeyboardEvent<HTMLInputElement>) => void;
  disabled?: boolean;
  placeholder?: string;
  autoFocus?: boolean;
}

export function UsernameSearch({
  value,
  onChange,
  onKeyDown,
  disabled,
  placeholder = 'Search username (@username)',
  autoFocus,
}: UsernameSearchProps) {
  const [isChecking, setIsChecking] = useState(false);
  const [isValid, setIsValid] = useState<boolean | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const checkTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Validate username format
  const validateFormat = (username: string): boolean => {
    if (!username) return false;
    const usernameRegex = /^@?[a-zA-Z0-9_]{3,20}$/;
    return usernameRegex.test(username);
  };

  // Check if username exists
  useEffect(() => {
    // Clear previous timeout
    if (checkTimeoutRef.current) {
      clearTimeout(checkTimeoutRef.current);
    }

    // Reset state for empty input
    if (!value) {
      setIsValid(null);
      setErrorMessage(null);
      return;
    }

    // Strip @ prefix if present
    const normalizedValue = value.startsWith('@') ? value.slice(1) : value;

    // Validate format first
    if (!validateFormat(normalizedValue)) {
      setIsValid(false);
      setErrorMessage('Invalid format (3-20 chars: letters, numbers, underscore)');
      return;
    }

    // Debounce the API check
    setIsChecking(true);
    checkTimeoutRef.current = setTimeout(async () => {
      try {
        const profile = await getProfileByUsername(normalizedValue);

        if (profile) {
          setIsValid(true);
          setErrorMessage(null);
        } else {
          setIsValid(false);
          setErrorMessage('User not found');
        }
      } catch (err) {
        console.error('[UsernameSearch] Failed to check username:', err);
        setIsValid(false);
        setErrorMessage('Failed to verify username');
      } finally {
        setIsChecking(false);
      }
    }, 500); // 500ms debounce

    return () => {
      if (checkTimeoutRef.current) {
        clearTimeout(checkTimeoutRef.current);
      }
    };
  }, [value]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    let newValue = e.target.value;

    // Auto-add @ prefix if user types alphanumeric first
    if (newValue && !newValue.startsWith('@') && /^[a-zA-Z0-9_]/.test(newValue)) {
      newValue = '@' + newValue;
    }

    onChange(newValue);
  };

  // Determine border color based on state
  const getBorderColor = () => {
    if (!value) return 'border-gray-300 dark:border-gray-600';
    if (isChecking) return 'border-blue-400 dark:border-blue-500';
    if (isValid === true) return 'border-green-500 dark:border-green-400';
    if (isValid === false) return 'border-red-500 dark:border-red-400';
    return 'border-gray-300 dark:border-gray-600';
  };

  return (
    <div className="relative">
      <input
        type="text"
        value={value}
        onChange={handleChange}
        onKeyDown={onKeyDown}
        disabled={disabled}
        placeholder={placeholder}
        autoFocus={autoFocus}
        className={`w-full p-3 pr-12 border ${getBorderColor()} rounded-lg focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 disabled:opacity-50 transition-colors font-mono`}
        autoComplete="off"
      />

      {/* Status Indicator */}
      <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center space-x-2">
        {isChecking && (
          <div className="animate-spin h-5 w-5 border-2 border-blue-500 border-t-transparent rounded-full"></div>
        )}
        {!isChecking && isValid === true && (
          <div className="text-green-500 text-xl font-bold">✓</div>
        )}
        {!isChecking && isValid === false && (
          <div className="text-red-500 text-xl font-bold">✗</div>
        )}
      </div>

      {/* Error Message */}
      {errorMessage && !isChecking && (
        <div className="mt-1 text-sm text-red-600 dark:text-red-400">
          {errorMessage}
        </div>
      )}

      {/* Helper Text */}
      {!errorMessage && value && !isChecking && isValid && (
        <div className="mt-1 text-sm text-green-600 dark:text-green-400">
          User found
        </div>
      )}
    </div>
  );
}
