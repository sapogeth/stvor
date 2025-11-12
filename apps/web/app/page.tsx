'use client';

/**
 * Home Page with Clerk Authentication
 *
 * SECURITY ARCHITECTURE:
 * - Clerk handles user authentication (login/logout)
 * - After Clerk auth, E2E keys are generated client-side
 * - Clerk userId is used as the identifier for key registration
 * - Private keys stored in IndexedDB, NEVER sent to Clerk or server
 * - Only public keys are uploaded to relay for key exchange
 */

import { useState, useEffect } from 'react';
import { useUser, UserButton } from '@clerk/nextjs';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { getOrCreateIdentity, IdentityReEnrollError } from '@/lib/identity';
import { generateAndUploadPrekeyBundle, loadPrekeySecrets } from '@/lib/prekeys';
import { DeviceReEnrollModal } from '@/components/DeviceReEnrollModal';
import { UsernameSetup } from '@/components/UsernameSetup';
import { getProfileByUsername } from '@/lib/profiles';

export default function Home() {
  const { isSignedIn, user, isLoaded } = useUser();
  const router = useRouter();
  const [cryptoReady, setCryptoReady] = useState(false);
  const [initError, setInitError] = useState<string | null>(null);
  const [reEnrollError, setReEnrollError] = useState<IdentityReEnrollError | null>(null);
  const [hasUsername, setHasUsername] = useState<boolean | null>(null);
  const [username, setUsername] = useState<string | null>(null);

  // Initialize E2E crypto keys after Clerk authentication
  useEffect(() => {
    if (!isLoaded || !isSignedIn || !user?.id) return;

    const initCrypto = async () => {
      try {
        console.log('[Home] User authenticated via Clerk:', user.id);
        console.log('[Home] Initializing E2E encryption keys...');

        // Use Clerk userId as the identity identifier
        const userId = user.id;

        // Get or create E2E identity keys (stored in IndexedDB)
        const identity = await getOrCreateIdentity(userId);
        console.log('[Home] E2E identity ready');

        // Check if we have a prekey bundle, generate if not
        const prekeySecrets = await loadPrekeySecrets(userId);
        if (!prekeySecrets) {
          console.log('[Home] Generating prekey bundle...');
          await generateAndUploadPrekeyBundle(userId, identity);
          console.log('[Home] Prekey bundle uploaded');
        } else {
          console.log('[Home] Existing prekey bundle found');
        }

        setCryptoReady(true);
        console.log('[Home] E2E crypto initialization complete');
      } catch (err) {
        console.error('[Home] Failed to initialize E2E crypto:', err);

        // Check if this is a device re-enrollment case
        if (err instanceof IdentityReEnrollError) {
          console.log('[Home] Device re-enrollment required');
          setReEnrollError(err);
        } else {
          setInitError(err instanceof Error ? err.message : String(err));
        }
      }
    };

    initCrypto();
  }, [isLoaded, isSignedIn, user?.id]);

  // Check if user has a username after crypto initialization
  useEffect(() => {
    if (!cryptoReady || !user?.id) return;

    const checkUsername = async () => {
      try {
        // Check if we have a stored human-readable username
        const storedUsername = localStorage.getItem(`username:${user.id}`);

        if (storedUsername) {
          // We have a stored username - check if it's a Clerk auto-generated ID
          if (storedUsername.startsWith('user_')) {
            // This is a Clerk ID, not a human-readable username - force setup
            console.log('[Home] Clerk ID detected, showing username setup');
            setUsername(null);
            setHasUsername(false);
          } else {
            // Valid human-readable username
            setUsername(storedUsername);
            setHasUsername(true);
          }
        } else {
          // No stored username - need to set one up
          setHasUsername(false);
        }
      } catch (err) {
        console.error('[Home] Failed to check username:', err);
        // Default to showing username setup if check fails
        setHasUsername(false);
      }
    };

    checkUsername();
  }, [cryptoReady, user?.id]);

  // Handle device re-enrollment modal
  const handleReEnrollSuccess = () => {
    setReEnrollError(null);
    // Retry crypto initialization
    window.location.reload();
  };

  const handleReEnrollCancel = () => {
    setReEnrollError(null);
    // User wants to use another account - sign out
    window.location.href = '/sign-in';
  };

  // Handle username setup completion
  const handleUsernameComplete = (newUsername: string) => {
    if (user?.id) {
      localStorage.setItem(`username:${user.id}`, newUsername);
      setUsername(newUsername);
      setHasUsername(true);
    }
  };

  // Show re-enrollment modal if needed
  if (reEnrollError) {
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
        <DeviceReEnrollModal
          username={reEnrollError.username}
          onSuccess={handleReEnrollSuccess}
          onCancel={handleReEnrollCancel}
        />
      </>
    );
  }

  // Prevent hydration mismatch
  if (!isLoaded) {
    return (
      <main className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
        <div className="text-lg">Loading...</div>
      </main>
    );
  }

  // Show sign-in prompt if not authenticated
  if (!isSignedIn) {
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
              🔐 Stv0r Messenger
            </h1>
            <p className="text-center text-gray-600 dark:text-gray-400 mb-8">
              Quantum-Resistant E2E Encrypted Messaging
            </p>

            <div className="space-y-4">
              <Link
                href="/sign-in"
                className="block w-full p-3 bg-blue-500 hover:bg-blue-600 text-white rounded-lg font-semibold text-center transition"
              >
                Sign In
              </Link>

              <Link
                href="/sign-up"
                className="block w-full p-3 bg-gray-500 hover:bg-gray-600 text-white rounded-lg font-semibold text-center transition"
              >
                Create Account
              </Link>
            </div>

            <div className="mt-8 text-xs text-gray-500 dark:text-gray-400 text-center">
              <p className="mb-2">🔒 Privacy-First Architecture:</p>
              <ul className="text-left space-y-1">
                <li>• Clerk handles authentication only</li>
                <li>• Keys generated on your device</li>
                <li>• Private keys never leave browser</li>
                <li>• Server sees only encrypted data</li>
              </ul>
            </div>
          </div>
        </main>
      </>
    );
  }

  // Show crypto initialization status
  if (!cryptoReady && !initError) {
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
          <div className="w-full max-w-md bg-white dark:bg-gray-800 rounded-lg shadow-xl p-8 text-center">
            <div className="text-4xl mb-4">🔐</div>
            <h2 className="text-xl font-semibold mb-2">Initializing Encryption</h2>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Generating your quantum-resistant keypairs...
            </p>
            <div className="animate-pulse text-blue-500">
              <div className="h-2 bg-blue-200 rounded-full w-full">
                <div className="h-2 bg-blue-500 rounded-full w-1/2 animate-slide"></div>
              </div>
            </div>
          </div>
        </main>
      </>
    );
  }

  // Show error state
  if (initError) {
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
            <div className="text-center mb-4">
              <div className="text-4xl mb-2">❌</div>
              <h2 className="text-xl font-semibold text-red-600">Initialization Failed</h2>
            </div>
            <p className="text-gray-600 dark:text-gray-400 mb-4 text-sm">
              {initError}
            </p>
            <button
              onClick={() => window.location.reload()}
              className="w-full p-3 bg-blue-500 hover:bg-blue-600 text-white rounded-lg font-semibold transition"
            >
              Retry
            </button>
          </div>
        </main>
      </>
    );
  }

  // Show username setup if crypto is ready but user has no username
  if (cryptoReady && hasUsername === false) {
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
        <UsernameSetup onComplete={handleUsernameComplete} />
      </>
    );
  }

  // Wait for username check to complete
  if (cryptoReady && hasUsername === null) {
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
          <div className="text-lg">Checking profile...</div>
        </main>
      </>
    );
  }

  // Authenticated and crypto ready - redirect to home
  if (cryptoReady && hasUsername) {
    router.push('/home');
    return null;
  }

  // Authenticated and crypto ready - show old dashboard (legacy)
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
        className="min-h-screen flex flex-col items-center justify-center p-8 bg-black text-white"
        style={{ paddingTop: process.env.NODE_ENV === 'development' ? '50px' : '0' }}
      >
        <div className="w-full max-w-2xl bg-gray-900 border border-gray-800 rounded-xl shadow-2xl p-8">
          <div className="flex items-center justify-between mb-6">
            <div>
              <div className="flex items-center space-x-3 mb-3">
                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
                  <span className="text-white font-bold text-2xl">S</span>
                </div>
                <h1 className="text-4xl font-bold tracking-wider">STVOR</h1>
              </div>
              <p className="text-gray-400 mt-1">
                Logged in as <strong className="text-white">{user?.primaryEmailAddress?.emailAddress || user?.username || user?.id}</strong>
              </p>
            </div>
            <UserButton afterSignOutUrl="/" />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Link
              href="/chat"
              className="p-6 bg-gray-800 hover:bg-gray-700 border border-gray-700 hover:border-green-500 text-white rounded-lg text-center transition group"
            >
              <div className="text-4xl mb-2">💬</div>
              <div className="font-semibold text-green-500">Chat</div>
              <div className="text-sm text-gray-400">1:1 Encrypted Messages</div>
            </Link>

            <Link
              href="/benchmarks"
              className="p-6 bg-gray-800 hover:bg-gray-700 border border-gray-700 hover:border-green-500 text-white rounded-lg text-center transition group"
            >
              <div className="text-4xl mb-2">📊</div>
              <div className="font-semibold text-green-500">Benchmarks</div>
              <div className="text-sm text-gray-400">Performance Metrics</div>
            </Link>

            <Link
              href="/security"
              className="p-6 bg-gray-800 hover:bg-gray-700 border border-gray-700 hover:border-green-500 text-white rounded-lg text-center transition group"
            >
              <div className="text-4xl mb-2">🔒</div>
              <div className="font-semibold text-green-500">Security</div>
              <div className="text-sm text-gray-400">Session Invariants</div>
            </Link>
          </div>

          <div className="mt-8 p-4 bg-gray-950 rounded-lg border border-gray-800">
            <h3 className="font-semibold mb-3 text-green-500">Protocol: Ilyazh-Web3E2E v0.8</h3>
            <ul className="text-sm space-y-2 text-gray-300">
              <li className="flex items-start">
                <span className="text-green-500 mr-2">✓</span>
                <span>Hybrid AKE: X25519 + ML-KEM-768</span>
              </li>
              <li className="flex items-start">
                <span className="text-green-500 mr-2">✓</span>
                <span>Dual Signatures: Ed25519 + ML-DSA-65</span>
              </li>
              <li className="flex items-start">
                <span className="text-green-500 mr-2">✓</span>
                <span>Double Ratchet with mandated cadence</span>
              </li>
              <li className="flex items-start">
                <span className="text-green-500 mr-2">✓</span>
                <span>sid-in-AAD for all records</span>
              </li>
              <li className="flex items-start">
                <span className="text-green-500 mr-2">✓</span>
                <span>AES-256-GCM + HKDF-SHA-384</span>
              </li>
              <li className="flex items-start pt-2 border-t border-gray-700 mt-2">
                <span className="mr-2">🔑</span>
                <span>Auth: Clerk (identity only, zero access to keys)</span>
              </li>
            </ul>
          </div>
        </div>
      </main>
    </>
  );
}
