'use client';

/**
 * DAO / Groups Page - Under Development
 */

export default function GroupsPage() {
  return (
    <div className="flex items-center justify-center min-h-screen p-8">
      <div className="text-center max-w-md">
        <div className="text-8xl mb-6">👥</div>
        <h1 className="text-4xl font-bold mb-4">DAO / Groups</h1>
        <p className="text-xl text-gray-400 mb-6">Coming Soon</p>
        <p className="text-gray-500">
          Join decentralized autonomous organizations and groups where decisions are made
          collectively through secure voting mechanisms.
        </p>
        <div className="mt-8 p-4 bg-gray-900 rounded-lg">
          <h3 className="font-semibold mb-2 text-green-500">Planned Features:</h3>
          <ul className="text-left space-y-2 text-sm text-gray-300">
            <li>• Create and join DAOs</li>
            <li>• Decentralized governance</li>
            <li>• Proposal voting system</li>
            <li>• Token-based memberships</li>
            <li>• Encrypted group chats</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
