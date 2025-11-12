/**
 * Sign Up Page - Dark Theme
 * Matches STVOR design aesthetic
 */

import { SignUp } from '@clerk/nextjs';

export default function SignUpPage() {
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
          <p className="text-lg text-green-500 mb-1">Join Us!</p>
          <p className="text-sm text-gray-400">
            Create your secure quantum-resistant account
          </p>
        </div>

        {/* Clerk Sign Up */}
        <SignUp
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
              otpCodeFieldInput: 'bg-black border-gray-800 text-white',
            },
            variables: {
              colorPrimary: '#22c55e',
              colorBackground: '#111827',
              colorInputBackground: '#000000',
              colorInputText: '#ffffff',
            },
          }}
          routing="path"
          path="/sign-up"
          signInUrl="/sign-in"
          forceRedirectUrl="/"
        />

        {/* Privacy Info */}
        <div className="mt-8 p-4 bg-gray-900 rounded-lg border border-gray-800">
          <p className="text-center text-sm text-gray-400 mb-3">🛡️ What you get:</p>
          <ul className="text-xs space-y-2 text-gray-500">
            <li className="flex items-start">
              <span className="text-green-500 mr-2">✓</span>
              <span>Post-quantum cryptography (ML-KEM-768 + ML-DSA-65)</span>
            </li>
            <li className="flex items-start">
              <span className="text-green-500 mr-2">✓</span>
              <span>Zero-knowledge architecture (we can't read your messages)</span>
            </li>
            <li className="flex items-start">
              <span className="text-green-500 mr-2">✓</span>
              <span>Forward secrecy (Double Ratchet protocol)</span>
            </li>
            <li className="flex items-start">
              <span className="text-green-500 mr-2">✓</span>
              <span>Decentralized reputation system</span>
            </li>
          </ul>
        </div>
      </div>
    </main>
  );
}
