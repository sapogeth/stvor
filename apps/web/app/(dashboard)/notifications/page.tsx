'use client';

/**
 * Notifications Page - All/Posts/Mentions tabs
 */

import { useState } from 'react';
import { Heart, MessageCircle, Repeat, User, MoreHorizontal } from 'lucide-react';

type NotificationType = 'like' | 'reply' | 'mention' | 'repost';

interface Notification {
  id: number;
  type: NotificationType;
  user: string;
  username: string;
  content?: string;
  timestamp: string;
  counts?: { likes?: number; comments?: number; shares?: number };
}

export default function NotificationsPage() {
  const [activeTab, setActiveTab] = useState<'all' | 'posts' | 'mentions'>('all');

  // Mock notifications data
  const notifications: Notification[] = [
    {
      id: 1,
      type: 'reply',
      user: 'STVOR',
      username: '@stv0r',
      content: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit',
      timestamp: '2h ago',
      counts: { likes: 6000, comments: 250, shares: 6 },
    },
    {
      id: 2,
      type: 'like',
      user: 'STVOR',
      username: '@stv0r',
      timestamp: '2h ago',
      counts: { likes: 6000 },
    },
    {
      id: 3,
      type: 'reply',
      user: 'STVOR',
      username: '@stv0r',
      content: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit',
      timestamp: '2h ago',
      counts: { likes: 6000, comments: 250, shares: 6 },
    },
    {
      id: 4,
      type: 'repost',
      user: 'STVOR',
      username: '@stv0r',
      content: 'Lorem ipsum dolor sit amet, consectetur......',
      timestamp: '2h ago',
    },
    {
      id: 5,
      type: 'reply',
      user: 'STVOR',
      username: '@stv0r',
      content: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit',
      timestamp: '2h ago',
      counts: { likes: 6000, comments: 250, shares: 6 },
    },
  ];

  const renderNotificationIcon = (type: NotificationType) => {
    switch (type) {
      case 'like':
        return <Heart className="w-8 h-8 text-red-500 fill-red-500" />;
      case 'reply':
        return <MessageCircle className="w-8 h-8 text-blue-500" />;
      case 'repost':
        return <MessageCircle className="w-8 h-8 text-purple-500 fill-purple-500" />;
      case 'mention':
        return <User className="w-8 h-8 text-green-500" />;
      default:
        return null;
    }
  };

  const getNotificationText = (type: NotificationType, user: string) => {
    switch (type) {
      case 'like':
        return `${user} Liked your post`;
      case 'reply':
        return `Replying to @stv0r2`;
      case 'repost':
        return `${user} New Post`;
      case 'mention':
        return `${user} mentioned you`;
      default:
        return '';
    }
  };

  const tabs = [
    { key: 'all' as const, label: 'All' },
    { key: 'posts' as const, label: 'Posts' },
    { key: 'mentions' as const, label: 'Mentions' },
  ];

  return (
    <div className="flex min-h-screen">
      {/* Main Content */}
      <div className="flex-1 border-r border-gray-800 max-w-2xl">
        {/* Header */}
        <div className="sticky top-0 bg-black/80 backdrop-blur-sm border-b border-gray-800 z-10">
          <div className="p-4">
            <h1 className="text-xl font-bold mb-4">Notification</h1>
          </div>

          {/* Tabs */}
          <div className="flex border-b border-gray-800">
            {tabs.map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`flex-1 px-4 py-4 font-medium transition relative ${
                  activeTab === tab.key
                    ? 'text-white'
                    : 'text-gray-500 hover:bg-gray-900'
                }`}
              >
                {tab.label}
                {activeTab === tab.key && (
                  <div className="absolute bottom-0 left-0 right-0 h-1 bg-purple-500 rounded-t"></div>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Notifications List */}
        <div className="divide-y divide-gray-800">
          {notifications.map((notification) => (
            <div
              key={notification.id}
              className="p-4 hover:bg-gray-900/50 transition cursor-pointer group relative"
            >
              <button className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 text-gray-500 hover:text-white transition">
                <MoreHorizontal className="w-5 h-5" />
              </button>

              <div className="flex space-x-3">
                {/* Icon */}
                <div className="flex-shrink-0 pt-1">
                  {renderNotificationIcon(notification.type)}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  {/* User Avatar and Name */}
                  <div className="flex items-center space-x-2 mb-1">
                    <div className="w-10 h-10 rounded-full bg-gray-700"></div>
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold">{notification.user}</span>
                        <span className="text-gray-500 text-sm">{notification.username}</span>
                        <span className="text-gray-500 text-sm">· {notification.timestamp}</span>
                      </div>
                      <div className="text-sm text-gray-400">
                        {getNotificationText(notification.type, notification.user)}
                      </div>
                    </div>
                  </div>

                  {/* Notification Content */}
                  {notification.content && (
                    <div className="mt-2 text-sm text-gray-300">
                      {notification.content}
                    </div>
                  )}

                  {/* Interaction Counts */}
                  {notification.counts && (
                    <div className="flex items-center space-x-6 mt-3 text-gray-500 text-sm">
                      {notification.counts.likes !== undefined && (
                        <div className="flex items-center space-x-1">
                          <Heart className="w-4 h-4" />
                          <span>{notification.counts.likes >= 1000 ? `${(notification.counts.likes / 1000).toFixed(1)}K` : notification.counts.likes}</span>
                        </div>
                      )}
                      {notification.counts.comments !== undefined && (
                        <div className="flex items-center space-x-1">
                          <MessageCircle className="w-4 h-4" />
                          <span>{notification.counts.comments}</span>
                        </div>
                      )}
                      {notification.counts.shares !== undefined && (
                        <div className="flex items-center space-x-1">
                          <Repeat className="w-4 h-4" />
                          <span>{notification.counts.shares}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Empty State for Posts/Mentions tabs */}
        {activeTab !== 'all' && (
          <div className="p-12 text-center text-gray-500">
            <div className="text-6xl mb-4">📭</div>
            <h3 className="text-xl font-semibold mb-2">No {activeTab} yet</h3>
            <p className="text-sm">When you get {activeTab}, they'll show up here.</p>
          </div>
        )}
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

        {/* Popular Today */}
        <div className="bg-gray-900 rounded-xl p-4 mb-4">
          <h3 className="font-bold text-lg mb-4">Popular Today</h3>
          <div className="space-y-4">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="flex items-start space-x-3">
                <div className="w-10 h-10 rounded-full bg-gray-700"></div>
                <div className="flex-1 min-w-0">
                  <div className="font-semibold">@accountnam{i}</div>
                  <div className="text-sm text-gray-400">Breaking News</div>
                  <div className="text-xs text-gray-500">11 hours ago · Entertainment · 28.1K Views</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* What's Happening */}
        <div className="bg-gray-900 rounded-xl p-4">
          <h3 className="font-bold text-lg mb-4">What's happening</h3>
          <div className="space-y-4">
            {[
              { topic: 'Malaysia', category: 'Trending · Global', views: '28.1K Views' },
              { topic: 'USA', category: 'Trending · Global', views: '28.1K Views' },
              { topic: '#KLP48', category: 'Trending in Malaysia', views: '28.1K Views' },
              { topic: 'APU', category: 'Trending · Global', views: '28.1K Views' },
            ].map((item, index) => (
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
