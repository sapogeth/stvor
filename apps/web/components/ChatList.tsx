'use client';

/**
 * Chat List Component
 * Shows list of recent conversations with last message preview
 */

import { useEffect, useState } from 'react';
import { getAllChatIds, getLastMessage, type StoredMessage } from '@/lib/message-store';
import { MessageCircle, Search } from 'lucide-react';

interface ChatPreview {
  chatId: string;
  recipientUsername: string;
  lastMessage: StoredMessage | null;
  unreadCount: number;
}

interface ChatListProps {
  currentUsername: string;
  onSelectChat: (recipientUsername: string) => void;
  onStartNewChat: () => void;
}

export function ChatList({ currentUsername, onSelectChat, onStartNewChat }: ChatListProps) {
  const [chats, setChats] = useState<ChatPreview[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    loadChats();
  }, []);

  const loadChats = async () => {
    try {
      const chatIds = await getAllChatIds();
      console.log('[ChatList] Found chatIds:', chatIds);

      const chatPreviews: ChatPreview[] = [];

      for (const chatId of chatIds) {
        const lastMsg = await getLastMessage(chatId);

        // Extract recipient username from the stored message
        // The recipient is stored in each message record
        let recipientUsername = 'unknown';

        if (lastMsg) {
          // If we sent the last message, the recipient field has the other person's username
          // If we received the last message, the sender field has the other person's username
          if (lastMsg.sender === currentUsername.toLowerCase()) {
            recipientUsername = lastMsg.recipient;
          } else {
            recipientUsername = lastMsg.sender;
          }
        }

        chatPreviews.push({
          chatId,
          recipientUsername,
          lastMessage: lastMsg,
          unreadCount: 0, // TODO: implement unread tracking
        });
      }

      // Sort by last message timestamp (most recent first)
      chatPreviews.sort((a, b) => {
        const timeA = a.lastMessage?.timestamp || 0;
        const timeB = b.lastMessage?.timestamp || 0;
        return timeB - timeA;
      });

      setChats(chatPreviews);
    } catch (err) {
      console.error('[ChatList] Failed to load chats:', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredChats = chats.filter(chat =>
    chat.recipientUsername.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const formatTimestamp = (timestamp: number) => {
    const now = Date.now();
    const diff = now - timestamp;

    // Less than 1 minute
    if (diff < 60000) return 'Только что';

    // Less than 1 hour
    if (diff < 3600000) {
      const minutes = Math.floor(diff / 60000);
      return `${minutes} мин назад`;
    }

    // Less than 24 hours
    if (diff < 86400000) {
      const hours = Math.floor(diff / 3600000);
      return `${hours} ч назад`;
    }

    // Less than 7 days
    if (diff < 604800000) {
      const days = Math.floor(diff / 86400000);
      return `${days} д назад`;
    }

    // Show date
    return new Date(timestamp).toLocaleDateString('ru-RU');
  };

  const truncateMessage = (text: string, maxLength: number = 50) => {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-2 border-green-500 border-t-transparent"></div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Search Bar */}
      <div className="p-4 border-b border-gray-800">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Поиск чатов..."
            className="w-full pl-10 pr-4 py-2 bg-black border border-gray-800 text-white rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent placeholder:text-gray-600"
          />
        </div>
      </div>

      {/* New Chat Button */}
      <div className="p-4 border-b border-gray-800">
        <button
          onClick={onStartNewChat}
          className="w-full flex items-center justify-center space-x-2 px-4 py-3 bg-green-500 hover:bg-green-600 text-white rounded-lg font-semibold transition"
        >
          <MessageCircle className="w-5 h-5" />
          <span>Новый Чат</span>
        </button>
      </div>

      {/* Chat List */}
      <div className="flex-1 overflow-y-auto">
        {filteredChats.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-8 text-center">
            <MessageCircle className="w-16 h-16 text-gray-700 mb-4" />
            <h3 className="text-lg font-semibold text-gray-300 mb-2">
              {searchQuery ? 'Чаты не найдены' : 'Нет активных чатов'}
            </h3>
            <p className="text-sm text-gray-500 mb-4">
              {searchQuery
                ? 'Попробуйте изменить поисковый запрос'
                : 'Начните новый чат, чтобы общаться безопасно'}
            </p>
            {!searchQuery && (
              <button
                onClick={onStartNewChat}
                className="px-6 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg font-semibold transition"
              >
                Начать Чат
              </button>
            )}
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {filteredChats.map((chat) => (
              <button
                key={chat.chatId}
                onClick={() => onSelectChat(chat.recipientUsername)}
                className="w-full p-4 hover:bg-gray-900 transition text-left"
              >
                <div className="flex items-start space-x-3">
                  {/* Avatar */}
                  <div className="flex-shrink-0">
                    <div className="w-12 h-12 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
                      <span className="text-white font-bold text-lg">
                        {chat.recipientUsername[0]?.toUpperCase() || '?'}
                      </span>
                    </div>
                  </div>

                  {/* Chat Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <h3 className="font-semibold text-white truncate">
                        @{chat.recipientUsername}
                      </h3>
                      {chat.lastMessage && (
                        <span className="text-xs text-gray-500 flex-shrink-0 ml-2">
                          {formatTimestamp(chat.lastMessage.timestamp)}
                        </span>
                      )}
                    </div>

                    {chat.lastMessage && (
                      <div className="flex items-center space-x-2">
                        <p className="text-sm text-gray-400 truncate">
                          {chat.lastMessage.sender === currentUsername ? 'Вы: ' : ''}
                          {truncateMessage(chat.lastMessage.text)}
                        </p>
                        {chat.lastMessage.encrypted && (
                          <span className="text-xs text-green-500 flex-shrink-0">🔐</span>
                        )}
                      </div>
                    )}

                    {!chat.lastMessage && (
                      <p className="text-sm text-gray-500 italic">Нет сообщений</p>
                    )}
                  </div>

                  {/* Unread Badge */}
                  {chat.unreadCount > 0 && (
                    <div className="flex-shrink-0">
                      <div className="w-6 h-6 rounded-full bg-green-500 flex items-center justify-center">
                        <span className="text-xs font-bold text-white">
                          {chat.unreadCount > 9 ? '9+' : chat.unreadCount}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
