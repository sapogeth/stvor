'use client';

/**
 * Home/Feed Page - Twitter/X-like News Feed
 */

import { useState, useEffect } from 'react';
import { useUser } from '@clerk/nextjs';
import { MessageCircle, ShoppingCart, MessageSquare, MoreHorizontal } from 'lucide-react';

export default function HomePage() {
  const { user } = useUser();
  const [activeTab, setActiveTab] = useState<'feed' | 'following'>('feed');
  const [username, setUsername] = useState<string | null>(null);

  // Load username from localStorage
  useEffect(() => {
    if (!user?.id) return;

    const storedUsername = localStorage.getItem(`username:${user.id}`);
    if (storedUsername && !storedUsername.startsWith('user_')) {
      setUsername(storedUsername);
    }
  }, [user?.id]);

  // Mock data - в будущем будет загружаться с сервера
  const announcements = [
    {
      id: 1,
      title: 'New Feature:',
      description: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit,',
    },
    {
      id: 2,
      title: 'New Feature:',
      description: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit,',
    },
    {
      id: 3,
      title: 'Bug Fixed:',
      description: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit,',
    },
    {
      id: 4,
      title: 'Bug Fixed:',
      description: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit,',
    },
    {
      id: 5,
      title: 'Bug Fixed:',
      description: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit,',
    },
    {
      id: 6,
      title: 'Bug Fixed:',
      description: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit,',
    },
    {
      id: 7,
      title: 'Bug Fixed:',
      description: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit,',
    },
  ];

  const trending = [
    { topic: 'Malaysia', views: '28.1K Views', category: 'Trending · Global' },
    { topic: 'USA', views: '28.1K Views', category: 'Trending · Global' },
    { topic: '#KLP48', views: '28.1K Views', category: 'Trending in Malaysia' },
    { topic: 'APU', views: '28.1K Views', category: 'Trending · Global' },
  ];

  return (
    <div className="flex min-h-screen">
      {/* Main Feed */}
      <div className="flex-1 border-r border-gray-800">
        {/* Header */}
        <div className="sticky top-0 bg-black/80 backdrop-blur-sm border-b border-gray-800 z-10">
          <div className="flex items-center justify-between p-4">
            <h1 className="text-xl font-bold">Home</h1>
            <button className="text-gray-400 hover:text-white transition">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
              </svg>
            </button>
          </div>
        </div>

        {/* Welcome Banner */}
        <div className="border-b border-gray-800 p-6">
          <div className="flex items-start justify-between mb-4">
            <div>
              <h2 className="text-2xl font-bold mb-1">
                👋 Hello, <span className="text-green-500">@{username || 'user'}!</span>
              </h2>
              <p className="text-gray-400 flex items-center text-sm">
                <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                Connected securely via Ilyazh
              </p>
            </div>
          </div>

          <button className="px-6 py-2.5 bg-transparent border border-green-500 text-green-500 rounded-lg font-medium hover:bg-green-500/10 transition">
            Start a new encrypted chat
          </button>
        </div>

        {/* About Us Section */}
        <div className="border-b border-gray-800 p-6">
          <h3 className="text-xl font-bold mb-3">About Us</h3>
          <div className="space-y-3">
            <div>
              <h4 className="font-semibold mb-1">Stvor Web3 - Trust for the Next Generation</h4>
              <p className="text-gray-400 text-sm">
                Stvor is a decentralized social messenger built on a proprietary end-to-end encryption protocol, enhanced with elements of transparency, reputation, and crowdsourcing.
              </p>
            </div>
            <div>
              <p className="text-gray-400 text-sm">
                We've combined the best ideas from <span className="text-white font-medium">Arkham, DeBank, and Polymarket</span>, adapting them for everyday communication — to create a space of trust, anonymity, and action.
              </p>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="border-b border-gray-800 p-6">
          <h3 className="text-xl font-bold mb-4">Quick Actions</h3>
          <div className="grid grid-cols-3 gap-4">
            <button className="p-4 bg-gray-900 border border-gray-800 rounded-lg hover:border-green-500 transition group">
              <MessageCircle className="w-8 h-8 text-green-500 mx-auto mb-2 group-hover:scale-110 transition" />
              <div className="text-sm font-medium">New Post</div>
            </button>
            <button className="p-4 bg-gray-900 border border-gray-800 rounded-lg hover:border-green-500 transition group">
              <ShoppingCart className="w-8 h-8 text-green-500 mx-auto mb-2 group-hover:scale-110 transition" />
              <div className="text-sm font-medium">Sell on Marketplace</div>
            </button>
            <button className="p-4 bg-gray-900 border border-gray-800 rounded-lg hover:border-green-500 transition group">
              <MessageSquare className="w-8 h-8 text-green-500 mx-auto mb-2 group-hover:scale-110 transition" />
              <div className="text-sm font-medium">Start New Chat</div>
            </button>
          </div>
        </div>

        {/* Announcements */}
        <div className="border-b border-gray-800 p-6">
          <h3 className="text-xl font-bold mb-4">Announcements</h3>
          <div className="space-y-3">
            {announcements.map((item) => (
              <div key={item.id} className="text-sm">
                <span className="font-semibold">{item.title}</span>{' '}
                <span className="text-gray-400">{item.description}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Posts Feed - Under Development */}
        <div className="p-6">
          <div className="text-center py-12 text-gray-500">
            <div className="text-6xl mb-4">🚧</div>
            <h3 className="text-xl font-semibold mb-2">Posts Feed - Under Development</h3>
            <p className="text-sm">We're working hard to bring you this feature soon!</p>
          </div>
        </div>
      </div>

      {/* Right Sidebar */}
      <aside className="w-96 p-4 hidden xl:block">
        {/* Search */}
        <div className="mb-4">
          <input
            type="text"
            placeholder="Search"
            className="w-full bg-gray-900 border border-gray-800 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-green-500 transition"
          />
        </div>

        {/* Announcements Widget */}
        <div className="bg-gray-900 rounded-xl p-4 mb-4">
          <h3 className="font-bold text-lg mb-4">Announcements</h3>
          <div className="space-y-3">
            {announcements.slice(0, 7).map((item) => (
              <div key={item.id} className="text-sm">
                <span className="font-semibold">{item.title}</span>{' '}
                <span className="text-gray-400">{item.description}</span>
              </div>
            ))}
          </div>
        </div>

        {/* What's Happening */}
        <div className="bg-gray-900 rounded-xl p-4">
          <h3 className="font-bold text-lg mb-4">What's happening</h3>
          <div className="space-y-4">
            {trending.map((item, index) => (
              <div key={index} className="flex items-start justify-between group cursor-pointer">
                <div className="flex-1">
                  <div className="text-xs text-gray-500 mb-0.5">{item.category}</div>
                  <div className="font-semibold">{item.topic}</div>
                  <div className="text-xs text-gray-500">{item.views}</div>
                </div>
                <button className="opacity-0 group-hover:opacity-100 text-gray-500 hover:text-white transition">
                  <MoreHorizontal className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </div>
      </aside>
    </div>
  );
}
