'use client';

/**
 * Dashboard Layout - Twitter/X-like design
 * Dark theme with left sidebar navigation
 */

import { useUser } from '@clerk/nextjs';
import { usePathname } from 'next/navigation';
import Link from 'next/link';
import { Home, MessageCircle, Bell, Settings, ShoppingBag, Newspaper, Users, User } from 'lucide-react';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { user } = useUser();
  const pathname = usePathname();

  const navigation = [
    { name: 'Home', href: '/home', icon: Home },
    { name: 'Chats', href: '/chats', icon: MessageCircle },
    { name: 'Notifications', href: '/notifications', icon: Bell },
    { name: 'Settings', href: '/settings', icon: Settings },
    { name: 'Marketplace', href: '/marketplace', icon: ShoppingBag },
    { name: 'News', href: '/news', icon: Newspaper },
    { name: 'DAO / Groups', href: '/groups', icon: Users },
  ];

  const isActive = (href: string) => pathname === href;

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Main container */}
      <div className="flex max-w-screen-2xl mx-auto">
        {/* Left Sidebar */}
        <aside className="w-64 min-h-screen border-r border-gray-800 px-4 py-6 fixed left-0 top-0 hidden md:block">
          {/* Logo */}
          <Link href="/home" className="flex items-center space-x-2 mb-8 px-2">
            <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
              <span className="text-white font-bold text-xl">S</span>
            </div>
            <span className="text-2xl font-bold tracking-wider">STVOR</span>
          </Link>

          {/* Navigation */}
          <nav className="space-y-1">
            {navigation.map((item) => {
              const Icon = item.icon;
              const active = isActive(item.href);

              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={`flex items-center space-x-4 px-4 py-3 rounded-lg transition-colors ${
                    active
                      ? 'bg-gray-800 text-green-500'
                      : 'text-gray-400 hover:bg-gray-900 hover:text-white'
                  }`}
                >
                  <Icon className={`w-6 h-6 ${active ? 'text-green-500' : ''}`} />
                  <span className="font-medium">{item.name}</span>
                </Link>
              );
            })}
          </nav>

          {/* User Profile Button */}
          <Link
            href="/profile"
            className={`mt-8 flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors ${
              pathname === '/profile'
                ? 'bg-gray-800'
                : 'hover:bg-gray-900'
            }`}
          >
            <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden">
              {user?.imageUrl ? (
                <img src={user.imageUrl} alt={user.firstName || 'User'} className="w-full h-full object-cover" />
              ) : (
                <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-blue-500 to-purple-600">
                  <User className="w-6 h-6" />
                </div>
              )}
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium truncate">
                {user?.firstName || user?.username || 'User'}
              </div>
              <div className="text-xs text-gray-500 truncate">
                @{user?.username || 'username'}
              </div>
            </div>
          </Link>
        </aside>

        {/* Main Content */}
        <main className="flex-1 md:ml-64">
          {children}
        </main>
      </div>

      {/* Mobile Bottom Navigation */}
      <nav className="md:hidden fixed bottom-0 left-0 right-0 bg-black border-t border-gray-800 px-4 py-2 z-50">
        <div className="flex justify-around items-center">
          {navigation.slice(0, 5).map((item) => {
            const Icon = item.icon;
            const active = isActive(item.href);

            return (
              <Link
                key={item.name}
                href={item.href}
                className={`p-2 ${active ? 'text-green-500' : 'text-gray-400'}`}
              >
                <Icon className="w-6 h-6" />
              </Link>
            );
          })}
        </div>
      </nav>
    </div>
  );
}
