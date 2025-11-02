/**
 * Sign In Page
 *
 * Uses Clerk's prebuilt SignIn component for secure authentication.
 * After sign-in, user will be redirected to home page where E2E keys are generated.
 */

import { SignIn } from '@clerk/nextjs';

export default function SignInPage() {
  return (
    <main className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold mb-2">🔐 Stv0r Messenger</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Quantum-resistant end-to-end encrypted messaging
          </p>
        </div>

        <SignIn
          appearance={{
            elements: {
              rootBox: 'mx-auto',
              card: 'shadow-2xl',
            },
          }}
          routing="path"
          path="/sign-in"
          signUpUrl="/sign-up"
          afterSignInUrl="/"
        />

        <div className="mt-6 text-center text-sm text-gray-600 dark:text-gray-400">
          <p className="mb-2">🔒 Your privacy is guaranteed:</p>
          <ul className="text-xs space-y-1">
            <li>• Authentication is handled by Clerk</li>
            <li>• Encryption keys are generated on your device</li>
            <li>• Private keys never leave your browser</li>
            <li>• Messages are encrypted before transmission</li>
          </ul>
        </div>
      </div>
    </main>
  );
}
