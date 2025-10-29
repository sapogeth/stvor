'use client';

/**
 * Error Boundary for Crypto Initialization Errors
 *
 * Catches and displays user-friendly messages when crypto initialization fails.
 * Provides actionable guidance based on the specific error type.
 *
 * Usage:
 *   <CryptoErrorBoundary>
 *     <YourApp />
 *   </CryptoErrorBoundary>
 */

import React, { Component, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
  /** Optional custom fallback UI */
  fallback?: (error: Error, reset: () => void) => ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class CryptoErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('[CryptoErrorBoundary] Caught error:', error);
    console.error('[CryptoErrorBoundary] Error info:', errorInfo);
  }

  reset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError && this.state.error) {
      if (this.props.fallback) {
        return this.props.fallback(this.state.error, this.reset);
      }

      return (
        <CryptoErrorFallback
          error={this.state.error}
          reset={this.reset}
        />
      );
    }

    return this.props.children;
  }
}

/**
 * Default fallback UI for crypto errors
 */
function CryptoErrorFallback({ error, reset }: { error: Error; reset: () => void }) {
  const errorMessage = error.message.toLowerCase();

  // Categorize the error
  let category: 'secure-context' | 'indexeddb' | 'browser-support' | 'wasm' | 'unknown' = 'unknown';
  let title = 'Cryptography Initialization Failed';
  let description = error.message;
  let solutions: string[] = [];

  if (errorMessage.includes('secure context') || errorMessage.includes('https')) {
    category = 'secure-context';
    title = 'Secure Connection Required';
    description = 'This application requires a secure connection (HTTPS) to use encryption features.';
    solutions = [
      'Access this application over HTTPS',
      'If testing locally, use localhost (which is treated as secure)',
      'Configure your server to serve over HTTPS',
    ];
  } else if (errorMessage.includes('indexeddb') || errorMessage.includes('private')) {
    category = 'indexeddb';
    title = 'Storage Access Required';
    description = 'This application requires IndexedDB to store encryption keys securely.';
    solutions = [
      'Disable private browsing / incognito mode',
      'Check browser settings to ensure site data is allowed',
      'Clear browser storage and try again',
      'Try a different browser if the issue persists',
    ];
  } else if (errorMessage.includes('subtle') || errorMessage.includes('getrandomvalues') || errorMessage.includes('browser')) {
    category = 'browser-support';
    title = 'Browser Not Supported';
    description = 'Your browser does not support the required cryptographic features.';
    solutions = [
      'Update your browser to the latest version',
      'Use a modern browser: Chrome 37+, Firefox 34+, Safari 11+, Edge 79+',
      'Check that JavaScript is enabled',
    ];
  } else if (errorMessage.includes('wasm') || errorMessage.includes('sodium') || errorMessage.includes('liboqs')) {
    category = 'wasm';
    title = 'Cryptography Libraries Failed to Load';
    description = 'Failed to initialize WebAssembly cryptography libraries.';
    solutions = [
      'Check your internet connection',
      'Disable browser extensions that may block WebAssembly',
      'Try refreshing the page',
      'Clear browser cache and reload',
    ];
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <div className="max-w-2xl w-full bg-white rounded-lg shadow-lg overflow-hidden">
        {/* Header */}
        <div className="bg-red-600 px-6 py-4">
          <div className="flex items-center gap-3 text-white">
            <svg
              className="w-8 h-8"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
              />
            </svg>
            <h1 className="text-xl font-bold">{title}</h1>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 mb-2">
              What happened?
            </h2>
            <p className="text-gray-700">{description}</p>
          </div>

          {solutions.length > 0 && (
            <div>
              <h2 className="text-lg font-semibold text-gray-900 mb-3">
                How to fix this:
              </h2>
              <ul className="space-y-2">
                {solutions.map((solution, idx) => (
                  <li key={idx} className="flex gap-3 text-gray-700">
                    <span className="text-red-600 font-bold">{idx + 1}.</span>
                    <span>{solution}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Technical details (collapsed by default) */}
          <details className="border rounded-lg">
            <summary className="px-4 py-3 cursor-pointer font-medium text-gray-700 hover:bg-gray-50">
              Technical Details
            </summary>
            <div className="px-4 py-3 border-t bg-gray-50">
              <pre className="text-xs text-gray-600 whitespace-pre-wrap font-mono break-all">
                {error.message}
                {error.stack && (
                  <>
                    {'\n\nStack trace:\n'}
                    {error.stack}
                  </>
                )}
              </pre>
            </div>
          </details>

          {/* Actions */}
          <div className="flex flex-wrap gap-3 pt-4">
            <button
              onClick={() => window.location.reload()}
              className="px-6 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors font-medium"
            >
              Reload Page
            </button>
            <button
              onClick={reset}
              className="px-6 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition-colors font-medium"
            >
              Try Again
            </button>
            <a
              href="/debug/crypto"
              className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
            >
              Run Diagnostics
            </a>
          </div>

          {/* Help link */}
          <div className="pt-4 border-t">
            <p className="text-sm text-gray-600">
              Still having issues?{' '}
              <a
                href="/debug/crypto"
                className="text-blue-600 hover:text-blue-700 underline"
              >
                Visit the diagnostics page
              </a>
              {' '}for more information about your browser's crypto support.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Simpler inline error display for use within existing layouts
 */
export function CryptoErrorInline({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  return (
    <div className="bg-red-50 border border-red-200 rounded-lg p-4">
      <div className="flex gap-3">
        <svg
          className="w-6 h-6 text-red-600 flex-shrink-0"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        <div className="flex-1">
          <h3 className="font-semibold text-red-900 mb-1">
            Cryptography Error
          </h3>
          <p className="text-sm text-red-800 mb-3">{error.message}</p>
          <div className="flex gap-2">
            {onRetry && (
              <button
                onClick={onRetry}
                className="text-sm px-3 py-1 bg-red-100 text-red-700 rounded hover:bg-red-200 transition-colors"
              >
                Retry
              </button>
            )}
            <a
              href="/debug/crypto"
              className="text-sm px-3 py-1 bg-red-100 text-red-700 rounded hover:bg-red-200 transition-colors"
            >
              Diagnostics
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
