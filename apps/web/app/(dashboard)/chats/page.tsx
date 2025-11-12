'use client';

/**
 * Chats/Messages Page - Messenger interface
 */

import { useState } from 'react';
import { Search, MoreHorizontal, Send, Smile, Image, Mic } from 'lucide-react';

interface Chat {
  id: number;
  name: string;
  username: string;
  lastMessage: string;
  time: string;
  unread: boolean;
  avatar?: string;
}

export default function ChatsPage() {
  const [selectedChat, setSelectedChat] = useState<Chat | null>(null);
  const [message, setMessage] = useState('');

  // Mock chats data
  const chats: Chat[] = [
    {
      id: 1,
      name: 'Name of account',
      username: '@username',
      lastMessage: 'New message',
      time: 'XX:XX',
      unread: true,
    },
    {
      id: 2,
      name: 'Name of account',
      username: '@username',
      lastMessage: 'New message',
      time: 'XX:XX',
      unread: false,
    },
    {
      id: 3,
      name: 'Name of account',
      username: '@username',
      lastMessage: 'New message',
      time: 'XX:XX',
      unread: false,
    },
    {
      id: 4,
      name: 'Name of account',
      username: '@username',
      lastMessage: 'New message',
      time: 'XX:XX',
      unread: false,
    },
    {
      id: 5,
      name: 'Name of account',
      username: '@username',
      lastMessage: 'New message',
      time: 'XX:XX',
      unread: false,
    },
    {
      id: 6,
      name: 'Name of account',
      username: '@username',
      lastMessage: 'New message',
      time: 'XX:XX',
      unread: false,
    },
    {
      id: 7,
      name: 'Name of account',
      username: '@username',
      lastMessage: 'New message',
      time: 'XX:XX',
      unread: false,
    },
    {
      id: 8,
      name: 'Name of account',
      username: '@username',
      lastMessage: 'New message',
      time: 'XX:XX',
      unread: false,
    },
    {
      id: 9,
      name: 'Name of account',
      username: '@username',
      lastMessage: 'New message',
      time: 'XX:XX',
      unread: false,
    },
  ];

  const handleSendMessage = () => {
    if (message.trim()) {
      // TODO: Implement actual message sending
      console.log('Sending message:', message);
      setMessage('');
    }
  };

  return (
    <div className="flex h-screen">
      {/* Chats List */}
      <div className="w-96 border-r border-gray-800 flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-gray-800">
          <div className="flex items-center justify-between mb-4">
            <h1 className="text-xl font-bold">Chats</h1>
            <div className="flex items-center space-x-2">
              <span className="text-sm text-gray-400">New message request: 0</span>
              <button className="text-gray-400 hover:text-white transition">
                <MoreHorizontal className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search"
              className="w-full bg-gray-900 border border-gray-800 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-green-500 transition"
            />
          </div>
        </div>

        {/* Chats List Header */}
        <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
          <h2 className="font-semibold">All Chats</h2>
          <button className="text-sm text-green-500 hover:underline">Edit</button>
        </div>

        {/* Chats */}
        <div className="flex-1 overflow-y-auto">
          {chats.map((chat) => (
            <button
              key={chat.id}
              onClick={() => setSelectedChat(chat)}
              className={`w-full p-4 flex items-center space-x-3 hover:bg-gray-900 transition ${
                selectedChat?.id === chat.id ? 'bg-gray-900' : ''
              }`}
            >
              <div className="relative">
                <div className="w-12 h-12 rounded-full bg-gray-700"></div>
                {chat.unread && (
                  <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full border-2 border-black"></div>
                )}
              </div>
              <div className="flex-1 min-w-0 text-left">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-semibold truncate">{chat.name}</span>
                  <span className="text-xs text-gray-500 ml-2">{chat.time}</span>
                </div>
                <div className="text-sm text-gray-400 truncate">{chat.lastMessage}</div>
              </div>
            </button>
          ))}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-800 text-center text-xs text-gray-500">
          <div className="mb-1">
            Mon 9 at 0h 45 · 4 4
          </div>
          <div className="text-green-500">Encrypted by Ilyazh</div>
        </div>
      </div>

      {/* Chat Content */}
      <div className="flex-1 flex flex-col">
        {selectedChat ? (
          <>
            {/* Chat Header */}
            <div className="p-4 border-b border-gray-800 flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-full bg-gray-700"></div>
                <div>
                  <div className="font-semibold">{selectedChat.name}</div>
                  <div className="text-sm text-gray-400">last seen recently</div>
                </div>
              </div>
              <button className="text-gray-400 hover:text-white transition">
                <MoreHorizontal className="w-5 h-5" />
              </button>
            </div>

            {/* Messages Area */}
            <div className="flex-1 p-6 overflow-y-auto flex items-center justify-center">
              <div className="text-center text-gray-500">
                <div className="text-6xl mb-4">🔒</div>
                <h3 className="text-xl font-semibold mb-2">End-to-End Encrypted</h3>
                <p className="text-sm max-w-md">
                  Start a conversation with {selectedChat.name}. Your messages are protected with quantum-resistant encryption.
                </p>
              </div>
            </div>

            {/* Message Input */}
            <div className="p-4 border-t border-gray-800">
              <div className="flex items-center space-x-3">
                <button className="text-gray-400 hover:text-white transition">
                  <Smile className="w-6 h-6" />
                </button>

                <div className="flex-1 flex items-center space-x-2 bg-gray-900 rounded-full px-4 py-2 border border-gray-800 focus-within:border-green-500 transition">
                  <input
                    type="text"
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                    placeholder="Write a encrypted message..."
                    className="flex-1 bg-transparent focus:outline-none text-sm"
                  />
                  <button className="text-gray-400 hover:text-white transition">
                    <Image className="w-5 h-5" />
                  </button>
                </div>

                <button className="text-gray-400 hover:text-white transition">
                  <Mic className="w-6 h-6" />
                </button>

                <button
                  onClick={handleSendMessage}
                  disabled={!message.trim()}
                  className={`p-2 rounded-full transition ${
                    message.trim()
                      ? 'bg-green-500 text-white hover:bg-green-600'
                      : 'bg-gray-800 text-gray-500 cursor-not-allowed'
                  }`}
                >
                  <Send className="w-5 h-5" />
                </button>
              </div>
            </div>
          </>
        ) : (
          /* No Chat Selected */
          <div className="flex-1 flex items-center justify-center text-gray-500">
            <div className="text-center">
              <div className="text-6xl mb-4">💬</div>
              <h3 className="text-xl font-semibold mb-2">Select a message</h3>
              <p className="text-sm">
                Choose from your existing conversations,<br />
                start a new one, or just keep swimming.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
