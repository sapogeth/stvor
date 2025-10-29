import type { Metadata } from 'next';
import './globals.css';
import { CryptoInitializer } from '@/components/CryptoInitializer';

export const metadata: Metadata = {
  title: 'Ilyazh Messenger - Post-Quantum E2E Encrypted',
  description: 'Web messenger with Ilyazh-Web3E2E protocol (X25519 + ML-KEM-768)',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">
        <CryptoInitializer />
        {children}
      </body>
    </html>
  );
}
