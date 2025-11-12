'use client';

/**
 * News Page - News feed with post creation
 */

import { useState, useEffect } from 'react';
import { useUser } from '@clerk/nextjs';
import { Image, Smile, MoreHorizontal, Heart, MessageCircle, Repeat, Trash2, Loader2 } from 'lucide-react';
import * as postsApi from '@/lib/api/posts';

export default function NewsPage() {
  const { user } = useUser();
  const [postContent, setPostContent] = useState('');
  const [posts, setPosts] = useState<postsApi.Post[]>([]);
  const [username, setUsername] = useState<string | null>(null);
  const [isPosting, setIsPosting] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Load username from localStorage
  useEffect(() => {
    if (!user?.id) return;

    const storedUsername = localStorage.getItem(`username:${user.id}`);
    if (storedUsername && !storedUsername.startsWith('user_')) {
      setUsername(storedUsername);
    }
  }, [user?.id]);

  // Load posts feed
  useEffect(() => {
    loadFeed();
  }, []);

  const loadFeed = async () => {
    setIsLoading(true);
    const feedPosts = await postsApi.getFeed(20);
    setPosts(feedPosts);
    setIsLoading(false);
  };

  const trending = [
    { topic: 'Malaysia', category: 'Trending · Global', views: '28.1K Views' },
    { topic: 'USA', category: 'Trending · Global', views: '28.1K Views' },
    { topic: '#KLP48', category: 'Trending in Malaysia', views: '28.1K Views' },
    { topic: 'APU', category: 'Trending · Global', views: '28.1K Views' },
  ];

  const popularAccounts = [
    { name: '@accountnam3', subtitle: 'Breaking News', time: '11 hours ago', category: 'Entertainment', views: '28.1K Views' },
    { name: '@accountnam3', subtitle: 'Breaking News', time: '11 hours ago', category: 'Entertainment', views: '28.1K Views' },
    { name: '@accountnam3', subtitle: 'Breaking News', time: '11 hours ago', category: 'Entertainment', views: '28.1K Views' },
    { name: '@accountnam3', subtitle: 'Breaking News', time: '11 hours ago', category: 'Entertainment', views: '28.1K Views' },
    { name: '@accountnam3', subtitle: 'Breaking News', time: '11 hours ago', category: 'Entertainment', views: '28.1K Views' },
  ];

  const handlePost = async () => {
    if (!postContent.trim() || !username) {
      setError('Username not set or post is empty');
      return;
    }

    setIsPosting(true);
    setError(null);

    const result = await postsApi.createPost(username, {
      content: postContent.trim(),
    });

    setIsPosting(false);

    if (result.success) {
      setPostContent('');
      // Reload feed to show new post
      await loadFeed();
    } else {
      setError(result.error || 'Failed to create post');
    }
  };

  const handleLike = async (postId: string) => {
    if (!username) return;

    const success = await postsApi.likePost(postId, username);
    if (success) {
      // Update local state
      setPosts(posts.map(p =>
        p.postId === postId
          ? { ...p, likesCount: p.likesCount + 1 }
          : p
      ));
    }
  };

  const handleDelete = async (postId: string) => {
    if (!username) return;

    const success = await postsApi.deletePost(postId, username);
    if (success) {
      // Remove from local state
      setPosts(posts.filter(p => p.postId !== postId));
    }
  };

  const formatTimestamp = (timestamp: number): string => {
    const now = Date.now();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    return 'just now';
  };

  return (
    <div className="flex min-h-screen">
      {/* Main Feed */}
      <div className="flex-1 border-r border-gray-800 max-w-2xl">
        {/* Header */}
        <div className="sticky top-0 bg-black/80 backdrop-blur-sm border-b border-gray-800 z-10 p-4">
          <h1 className="text-xl font-bold">News</h1>
        </div>

        {/* Create Post */}
        <div className="border-b border-gray-800 p-4">
          <div className="flex space-x-3">
            <div className="flex-shrink-0">
              <div className="w-12 h-12 rounded-full bg-gray-700 overflow-hidden">
                {user?.imageUrl ? (
                  <img src={user.imageUrl} alt={user.firstName || 'User'} className="w-full h-full object-cover" />
                ) : (
                  <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-blue-500 to-purple-600 text-white text-lg font-bold">
                    {user?.firstName?.[0] || 'U'}
                  </div>
                )}
              </div>
            </div>

            <div className="flex-1">
              {error && (
                <div className="mb-3 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-500 text-sm">
                  {error}
                </div>
              )}

              <textarea
                value={postContent}
                onChange={(e) => setPostContent(e.target.value)}
                placeholder="What's happening?"
                className="w-full bg-transparent text-lg focus:outline-none resize-none mb-3"
                rows={3}
                disabled={isPosting || !username}
              />

              {!username && (
                <div className="mb-3 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg text-yellow-500 text-sm">
                  Please set your username in settings before posting
                </div>
              )}

              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <button className="p-2 text-green-500 hover:bg-green-500/10 rounded-full transition" disabled>
                    <Image className="w-5 h-5" />
                  </button>
                  <button className="p-2 text-green-500 hover:bg-green-500/10 rounded-full transition" disabled>
                    <Smile className="w-5 h-5" />
                  </button>
                </div>

                <button
                  onClick={handlePost}
                  disabled={!postContent.trim() || isPosting || !username}
                  className={`px-6 py-2 rounded-full font-semibold transition flex items-center space-x-2 ${
                    postContent.trim() && !isPosting && username
                      ? 'bg-green-500 text-white hover:bg-green-600'
                      : 'bg-gray-800 text-gray-500 cursor-not-allowed'
                  }`}
                >
                  {isPosting && <Loader2 className="w-4 h-4 animate-spin" />}
                  <span>{isPosting ? 'Posting...' : 'Post'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Posts Feed */}
        <div className="divide-y divide-gray-800">
          {isLoading ? (
            <div className="p-12 text-center text-gray-500">
              <Loader2 className="w-8 h-8 animate-spin mx-auto mb-3" />
              <p>Loading posts...</p>
            </div>
          ) : posts.length === 0 ? (
            <div className="p-12 text-center text-gray-500">
              <p className="text-lg mb-2">No posts yet</p>
              <p className="text-sm">Be the first to post something!</p>
            </div>
          ) : (
            posts.map((post) => (
              <div key={post.postId} className="p-4 hover:bg-gray-900/30 transition">
                <div className="flex space-x-3">
                  <div className="flex-shrink-0">
                    <div className="w-12 h-12 rounded-full bg-gradient-to-br from-green-500 to-blue-600 flex items-center justify-center text-white font-bold">
                      {post.authorUsername[0].toUpperCase()}
                    </div>
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2 mb-1">
                      <span className="font-bold">@{post.authorUsername}</span>
                      <span className="text-gray-500">· {formatTimestamp(post.createdAt)}</span>
                      {username === post.authorUsername && (
                        <button
                          onClick={() => handleDelete(post.postId)}
                          className="ml-auto text-gray-500 hover:text-red-500 transition"
                          title="Delete post"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>

                    <p className="text-sm mb-3 whitespace-pre-wrap">{post.content}</p>

                    {post.imageUrl && (
                      <img
                        src={post.imageUrl}
                        alt="Post attachment"
                        className="rounded-lg mb-3 max-w-full"
                      />
                    )}

                    <div className="flex items-center justify-between text-gray-500 text-sm max-w-md">
                      <button
                        onClick={() => handleLike(post.postId)}
                        className="flex items-center space-x-2 hover:text-red-500 transition group"
                      >
                        <Heart className="w-5 h-5 group-hover:fill-red-500" />
                        <span>{post.likesCount >= 1000 ? `${(post.likesCount / 1000).toFixed(1)}K` : post.likesCount}</span>
                      </button>

                      <button className="flex items-center space-x-2 hover:text-blue-500 transition">
                        <MessageCircle className="w-5 h-5" />
                        <span>{post.commentsCount}</span>
                      </button>

                      <button className="flex items-center space-x-2 hover:text-green-500 transition">
                        <Repeat className="w-5 h-5" />
                        <span>{post.sharesCount}</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))
          )}
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

        {/* Popular Today */}
        <div className="bg-gray-900 rounded-xl p-4 mb-4">
          <h3 className="font-bold text-lg mb-4">Popular Today</h3>
          <div className="space-y-4">
            {popularAccounts.map((account, index) => (
              <div key={index} className="flex items-start space-x-3">
                <div className="w-10 h-10 rounded-full bg-gray-700"></div>
                <div className="flex-1 min-w-0">
                  <div className="font-semibold">{account.name}</div>
                  <div className="text-sm text-gray-400">{account.subtitle}</div>
                  <div className="text-xs text-gray-500">{account.time} · {account.category} · {account.views}</div>
                </div>
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
