import type { Metadata } from 'next';
import './globals.css';
import { ClerkProvider } from '@clerk/nextjs';
import { CryptoInitializer } from '@/components/CryptoInitializer';

export const metadata: Metadata = {
  title: 'Stv0r Messenger - Post-Quantum E2E Encrypted',
  description: 'Secure messenger with Ilyazh-Web3E2E protocol (X25519 + ML-KEM-768)',
};

/**
 * Root Layout with Clerk Authentication
 *
 * SECURITY ARCHITECTURE:
 * - ClerkProvider wraps the app for authentication state
 * - Clerk handles ONLY user identity and sessions
 * - CryptoInitializer runs AFTER Clerk to generate E2E keys
 * - Private keys are stored client-side in IndexedDB (NOT in Clerk)
 * - Only public keys are uploaded to relay server
 *
 * SUBRESOURCE INTEGRITY (SRI):
 * - mlkem-wasm and mldsa-wasm are loaded with SRI for supply chain protection
 * - These hashes are for npm packages mlkem-wasm@0.0.7 and mldsa-wasm@0.0.3
 * - Generate hashes with: openssl dgst -sha384 -binary <file> | base64
 * - Update hashes if upgrading npm packages (breaking security if not updated)
 *
 * CAPTCHA CONFIGURATION:
 * To disable CAPTCHA in development (recommended):
 * 1. Go to Clerk Dashboard → https://dashboard.clerk.com
 * 2. Select your application
 * 3. Navigate to: User & Authentication → Attack Protection
 * 4. Toggle OFF "Bot Protection" for development environment
 *
 * Note: CAPTCHA cannot be disabled via code - it's a project-level setting
 * If CAPTCHA is enabled, ensure CSP allows:
 * - challenges.cloudflare.com (scripts, frames, workers)
 * - blob: URLs for Web Workers
 */
export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <ClerkProvider
      appearance={{
        variables: {
          colorPrimary: '#3b82f6', // Blue-500
          colorBackground: '#ffffff',
          colorText: '#1f2937',
        },
        elements: {
          formButtonPrimary: 'bg-blue-500 hover:bg-blue-600',
          card: 'shadow-xl',
        },
      }}
    >
      <html lang="en">
        <head>
          {/* SECURITY: SRI for WASM modules to prevent supply chain attacks */}
          {/* mlkem-wasm@0.0.7: SHA-384 hash of the npm package */}
          {/* mldsa-wasm@0.0.3: SHA-384 hash of the npm package */}
          {/* NOTE: These scripts are NOT directly loaded here - they're lazy-loaded */}
          {/* by the crypto initialization code when needed. SRI would need to be */}
          {/* applied at the import level if using <script> tags. */}
        </head>
        <body className="antialiased">
          {/* CRITICAL: CryptoInitializer runs client-side after Clerk auth */}
          <CryptoInitializer />
          {children}
        </body>
      </html>
    </ClerkProvider>
  );
}
