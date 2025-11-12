'use client';

/**
 * Dashboard Layout - Twitter/X-like design
 * Dark theme with left sidebar navigation + Clerk integration
 * FULLY RESPONSIVE for mobile
 */

import { useUser, UserButton } from '@clerk/nextjs';
import { usePathname } from 'next/navigation';
import Link from 'next/link';
import { Home, MessageCircle, Bell, Settings, ShoppingBag, Newspaper, Users, Menu, X } from 'lucide-react';
import { useState } from 'react';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { user } = useUser();
  const pathname = usePathname();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navigation = [
    { name: 'Home', href: '/home', icon: Home },
    { name: 'E2E Chat', href: '/chat', icon: MessageCircle },
    { name: 'Notifications', href: '/notifications', icon: Bell },
    { name: 'Settings', href: '/settings', icon: Settings },
    { name: 'Marketplace', href: '/marketplace', icon: ShoppingBag },
    { name: 'News', href: '/news', icon: Newspaper },
    { name: 'DAO / Groups', href: '/groups', icon: Users },
  ];

  const isActive = (href: string) => pathname === href;

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Mobile Header */}
      <header className="md:hidden fixed top-0 left-0 right-0 bg-black/95 backdrop-blur-sm border-b border-gray-800 z-50 px-4 py-3">
        <div className="flex items-center justify-between">
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 hover:bg-gray-900 rounded-lg transition"
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>

          <Link href="/home" className="flex items-center space-x-2">
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
              <span className="text-white font-bold">S</span>
            </div>
            <span className="text-xl font-bold">STVOR</span>
          </Link>

          <UserButton afterSignOutUrl="/" />
        </div>
      </header>

      {/* Mobile Sidebar Overlay */}
      {mobileMenuOpen && (
        <>
          <div
            className="md:hidden fixed inset-0 bg-black/50 z-40"
            onClick={() => setMobileMenuOpen(false)}
          />
          <aside className="md:hidden fixed left-0 top-0 bottom-0 w-64 bg-black border-r border-gray-800 z-50 overflow-y-auto">
            <div className="p-4">
              {/* Logo */}
              <Link href="/home" className="flex items-center space-x-2 mb-8">
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
                      onClick={() => setMobileMenuOpen(false)}
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
                onClick={() => setMobileMenuOpen(false)}
                className={`mt-8 flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors ${
                  pathname === '/profile' ? 'bg-gray-800' : 'hover:bg-gray-900'
                }`}
              >
                <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                  {user?.imageUrl ? (
                    <img src={user.imageUrl} alt={user.firstName || 'User'} className="w-full h-full object-cover" />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-blue-500 to-purple-600 text-white font-bold">
                      {user?.firstName?.[0] || 'U'}
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

              {/* Clerk UserButton */}
              <div className="mt-6 px-4">
                <div className="flex items-center justify-between p-3 bg-gray-900 rounded-lg">
                  <span className="text-sm text-gray-400">Account</span>
                  <UserButton afterSignOutUrl="/" />
                </div>
              </div>
            </div>
          </aside>
        </>
      )}

      {/* Desktop Sidebar */}
      <aside className="hidden md:block w-64 min-h-screen border-r border-gray-800 px-4 py-6 fixed left-0 top-0">
        {/* Logo */}
        <Link href="/home" className="flex items-center space-x-2 mb-8 px-2">
          <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
            <span className="text-white font-bold text-xl">S</span>
          </div>
          <span className="text-2xl font-bold tracking-wider">STVOR</span>
        </Link>

        {/* Navigation */}
        <nav className="space-y-1 mb-8">
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
          className={`flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors mb-4 ${
            pathname === '/profile' ? 'bg-gray-800' : 'hover:bg-gray-900'
          }`}
        >
          <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
            {user?.imageUrl ? (
              <img src={user.imageUrl} alt={user.firstName || 'User'} className="w-full h-full object-cover" />
            ) : (
              <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-blue-500 to-purple-600 text-white font-bold">
                {user?.firstName?.[0] || 'U'}
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

        {/* Clerk UserButton */}
        <div className="px-4">
          <div className="flex items-center justify-between p-3 bg-gray-900 rounded-lg">
            <span className="text-sm text-gray-400">Account</span>
            <UserButton afterSignOutUrl="/" />
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="md:ml-64 pt-16 md:pt-0 pb-16 md:pb-0">
        {children}
      </main>

      {/* Mobile Bottom Navigation */}
      <nav className="md:hidden fixed bottom-0 left-0 right-0 bg-black border-t border-gray-800 px-2 py-2 z-40">
        <div className="flex justify-around items-center">
          {navigation.slice(0, 5).map((item) => {
            const Icon = item.icon;
            const active = isActive(item.href);

            return (
              <Link
                key={item.name}
                href={item.href}
                className={`p-3 rounded-lg transition-colors ${
                  active ? 'text-green-500 bg-gray-900' : 'text-gray-400'
                }`}
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
