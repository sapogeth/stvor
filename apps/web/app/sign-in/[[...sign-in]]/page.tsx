/**
 * Sign In Page - Dark Theme
 * Matches STVOR design aesthetic
 */

import { SignIn } from '@clerk/nextjs';

export default function SignInPage() {
  return (
    <main className="min-h-screen flex items-center justify-center bg-black text-white p-4">
      <div className="w-full max-w-md">
        {/* Logo and Title */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center space-x-3 mb-4">
            <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
              <span className="text-white font-bold text-3xl">S</span>
            </div>
          </div>
          <h1 className="text-4xl font-bold mb-2 tracking-wider">STVOR</h1>
          <p className="text-lg text-green-500 mb-1">Welcome!</p>
          <p className="text-sm text-gray-400">
            Quantum-resistant end-to-end encrypted messaging
          </p>
        </div>

        {/* Clerk Sign In */}
        <SignIn
          appearance={{
            elements: {
              rootBox: 'mx-auto',
              card: 'bg-gray-900 shadow-2xl border border-gray-800',
              headerTitle: 'text-white',
              headerSubtitle: 'text-gray-400',
              socialButtonsBlockButton: 'bg-gray-800 border-gray-700 text-white hover:bg-gray-700',
              formButtonPrimary: 'bg-green-500 hover:bg-green-600 text-white',
              formFieldInput: 'bg-black border-gray-800 text-white',
              formFieldLabel: 'text-gray-300',
              footerActionLink: 'text-green-500 hover:text-green-400',
              identityPreviewText: 'text-white',
              formFieldInputShowPasswordButton: 'text-gray-400 hover:text-white',
            },
            variables: {
              colorPrimary: '#22c55e',
              colorBackground: '#111827',
              colorInputBackground: '#000000',
              colorInputText: '#ffffff',
            },
          }}
          routing="path"
          path="/sign-in"
          signUpUrl="/sign-up"
          forceRedirectUrl="/"
        />

        {/* Privacy Info */}
        <div className="mt-8 p-4 bg-gray-900 rounded-lg border border-gray-800">
          <p className="text-center text-sm text-gray-400 mb-3">🔒 Your privacy is guaranteed:</p>
          <ul className="text-xs space-y-2 text-gray-500">
            <li className="flex items-start">
              <span className="text-green-500 mr-2">✓</span>
              <span>Authentication handled by Clerk (industry standard)</span>
            </li>
            <li className="flex items-start">
              <span className="text-green-500 mr-2">✓</span>
              <span>Encryption keys generated on your device only</span>
            </li>
            <li className="flex items-start">
              <span className="text-green-500 mr-2">✓</span>
              <span>Private keys never leave your browser</span>
            </li>
            <li className="flex items-start">
              <span className="text-green-500 mr-2">✓</span>
              <span>Messages encrypted before transmission</span>
            </li>
          </ul>
        </div>
      </div>
    </main>
  );
}
