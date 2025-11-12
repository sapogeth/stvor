'use client';

/**
 * Marketplace Page - Under Development
 */

export default function MarketplacePage() {
  return (
    <div className="flex items-center justify-center min-h-screen p-8">
      <div className="text-center max-w-md">
        <div className="text-8xl mb-6">🛒</div>
        <h1 className="text-4xl font-bold mb-4">Marketplace</h1>
        <p className="text-xl text-gray-400 mb-6">Coming Soon</p>
        <p className="text-gray-500">
          We're building an exciting marketplace where you can buy and sell items securely
          using our encrypted platform. Stay tuned!
        </p>
        <div className="mt-8 p-4 bg-gray-900 rounded-lg">
          <h3 className="font-semibold mb-2 text-green-500">Planned Features:</h3>
          <ul className="text-left space-y-2 text-sm text-gray-300">
            <li>• Secure peer-to-peer transactions</li>
            <li>• Encrypted communications with sellers</li>
            <li>• Reputation system</li>
            <li>• Escrow services</li>
            <li>• Cryptocurrency payments</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
