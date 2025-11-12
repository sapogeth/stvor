'use client';

/**
 * Profile Page - User profile with Quick Actions
 */

import { useState } from 'react';
import { useUser } from '@clerk/nextjs';
import { Edit2, MessageCircle, ShoppingCart, MessageSquare, MoreHorizontal } from 'lucide-react';

export default function ProfilePage() {
  const { user } = useUser();
  const [showNewMessageRequest, setShowNewMessageRequest] = useState(true);

  const trending = [
    { topic: 'Malaysia', category: 'Trending · Global', views: '28.1K Views' },
    { topic: 'USA', category: 'Trending · Global', views: '28.1K Views' },
    { topic: '#KLP48', category: 'Trending in Malaysia', views: '28.1K Views' },
    { topic: 'APU', category: 'Trending · Global', views: '28.1K Views' },
  ];

  return (
    <div className="flex min-h-screen">
      {/* Main Content */}
      <div className="flex-1 border-r border-gray-800 max-w-2xl">
        {/* Header */}
        <div className="sticky top-0 bg-black/80 backdrop-blur-sm border-b border-gray-800 z-10 p-4">
          <h1 className="text-xl font-bold">STVOR</h1>
          <p className="text-sm text-gray-400">New message request: 0</p>
        </div>

        {/* Profile Banner */}
        <div className="relative">
          <div className="h-48 bg-gradient-to-r from-blue-900 to-purple-900"></div>
          <div className="absolute -bottom-16 left-6">
            <div className="w-32 h-32 rounded-full border-4 border-black bg-gray-700 overflow-hidden">
              {user?.imageUrl ? (
                <img src={user.imageUrl} alt={user.firstName || 'User'} className="w-full h-full object-cover" />
              ) : (
                <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-blue-500 to-purple-600 text-white text-4xl font-bold">
                  {user?.firstName?.[0] || 'U'}
                </div>
              )}
            </div>
          </div>
          <button className="absolute top-4 right-4 p-2 bg-black/50 hover:bg-black/70 rounded-full transition">
            <Edit2 className="w-5 h-5" />
          </button>
        </div>

        {/* Profile Info */}
        <div className="px-6 pt-20 pb-6 border-b border-gray-800">
          <div className="flex items-start justify-between mb-4">
            <div className="flex-1">
              <div className="flex items-center space-x-2 mb-1">
                <h2 className="text-2xl font-bold">STVORUSER</h2>
                <Edit2 className="w-4 h-4 text-green-500 cursor-pointer" />
              </div>
              <p className="text-gray-400">@stv0r</p>
            </div>
            <span className="px-3 py-1 bg-green-500/20 text-green-500 text-sm rounded-full font-medium">
              Online
            </span>
          </div>

          {/* Account Information */}
          <div className="mb-4">
            <div className="bg-gray-900 rounded-lg p-4 mb-2">
              <h3 className="font-semibold text-green-500 mb-2">● Account Information</h3>
              <div className="space-y-1 text-sm text-gray-300">
                <p>+000 000 00 00</p>
                <p className="text-gray-500">Mobile</p>
              </div>
            </div>

            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">@stv0r</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Username</span>
              </div>
              <div className="space-y-1">
                <span className="text-gray-400">Apr 10, 1995 (30 years old)</span>
                <p className="text-gray-500 text-xs">Date of birth</p>
              </div>
            </div>
          </div>

          {/* Bio */}
          <div className="mb-4">
            <h4 className="font-semibold mb-2">Bio</h4>
            <p className="text-sm text-gray-300 leading-relaxed">
              Lorem ipsum dolor sit amet, consectetur adipiscing elit. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
            </p>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="p-6 border-b border-gray-800">
          <h3 className="text-xl font-bold mb-4">Quick Actions</h3>
          <div className="grid grid-cols-3 gap-4">
            <button className="p-4 bg-gray-900 border border-gray-800 rounded-lg hover:border-green-500 transition group">
              <MessageCircle className="w-8 h-8 text-green-500 mx-auto mb-2 group-hover:scale-110 transition" />
              <div className="text-sm font-medium">New Post</div>
            </button>
            <button className="p-4 bg-gray-900 border border-gray-800 rounded-lg hover:border-green-500 transition group">
              <ShoppingCart className="w-8 h-8 text-green-500 mx-auto mb-2 group-hover:scale-110 transition" />
              <div className="text-sm font-medium">New Stories</div>
            </button>
            <button className="p-4 bg-gray-900 border border-gray-800 rounded-lg hover:border-green-500 transition group">
              <MessageSquare className="w-8 h-8 text-green-500 mx-auto mb-2 group-hover:scale-110 transition" />
              <div className="text-sm font-medium">Start New Chat</div>
            </button>
          </div>
        </div>

        {/* New Message Request */}
        {showNewMessageRequest && (
          <div className="p-6 border-b border-gray-800">
            <div className="flex items-start justify-between mb-3">
              <div className="bg-green-500/20 p-2 rounded-lg">
                <MessageCircle className="w-6 h-6 text-green-500" />
              </div>
              <button
                onClick={() => setShowNewMessageRequest(false)}
                className="text-gray-400 hover:text-white transition"
              >
                ×
              </button>
            </div>
            <h4 className="font-semibold mb-1">New message request: 1</h4>
            <div className="flex items-center space-x-3 mb-3">
              <div className="w-10 h-10 rounded-full bg-gray-700"></div>
              <div className="flex-1">
                <div className="font-medium">Name of account</div>
                <div className="text-sm text-gray-400">New message</div>
              </div>
            </div>
          </div>
        )}

        {/* Posts Section - Under Development */}
        <div className="p-6">
          <div className="text-center py-12 text-gray-500">
            <div className="text-6xl mb-4">📝</div>
            <h3 className="text-xl font-semibold mb-2">Posts - Under Development</h3>
            <p className="text-sm">Your posts will appear here soon!</p>
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

        {/* Announcements */}
        <div className="bg-gray-900 rounded-xl p-4 mb-4">
          <h3 className="font-bold text-lg mb-4">Announcements</h3>
          <div className="space-y-3">
            {[1, 2, 3, 4, 5, 6, 7].map((i) => (
              <div key={i} className="text-sm">
                <span className="font-semibold">{i % 2 === 0 ? 'New Feature:' : 'Bug Fixed:'}</span>{' '}
                <span className="text-gray-400">Lorem ipsum dolor sit amet, consectetur adipiscing elit,</span>
              </div>
            ))}
          </div>
        </div>

        {/* You Might Like */}
        <div className="bg-gray-900 rounded-xl p-4">
          <h3 className="font-bold text-lg mb-4">You might like</h3>
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
