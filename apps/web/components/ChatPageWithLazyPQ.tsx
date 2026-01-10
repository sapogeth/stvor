/**
 * Пример использования ленивой загрузки PQ в чат-компоненте
 *
 * Когда пользователь открывает чат, мы:
 * 1. Показываем loading spinner
 * 2. Инициализируем PQ в фоне (Web Worker)
 * 3. Когда готово, показываем чат UI
 *
 * Таким образом, главная страница загружается БЫСТРО,
 * а PQ инициализируется только когда нужно.
 */

'use client';

import { useEffect, useState } from 'react';
import { useLazyPQ } from '@/lib/lazy-pq-loader';

interface ChatPageProps {
  chatId: string;
  username: string;
}

export function ChatPageWithLazyPQ({ chatId, username }: ChatPageProps) {
  const { state, error, initialize } = useLazyPQ();
  const [chatContent, setChatContent] = useState('');

  // STEP 1: Когда компонент монтируется, инициализируем PQ в фоне
  useEffect(() => {
    initialize().catch((err) => {
      console.error('[ChatPage] Failed to initialize PQ:', err);
      // Можно показать пользователю ошибку или fallback UI
    });
  }, [initialize]); // initialize - стабильная функция из useLazyPQ

  // STEP 2: Когда PQ готов, загружаем чат-сообщения
  useEffect(() => {
    if (state !== 'ready') return;

    console.log('[ChatPage] PQ is ready, loading chat...');

    const loadChat = async () => {
      try {
        // Здесь используем PQ для расшифровки сообщений, handshake и т.д.
        const messages = await fetchChatMessages(chatId);
        setChatContent(messages);
      } catch (err) {
        console.error('[ChatPage] Failed to load chat:', err);
      }
    };

    loadChat();
  }, [state, chatId]);

  // STEP 3: Показываем разные UI в зависимости от состояния

  if (state === 'loading') {
    return (
      <div className="chat-loading">
        <div className="spinner">Initializing secure chat...</div>
        <p>Setting up post-quantum cryptography...</p>
      </div>
    );
  }

  if (state === 'error' || error) {
    return (
      <div className="chat-error">
        <h3>Failed to initialize secure chat</h3>
        <p>{error?.message || 'Unknown error'}</p>
        <button onClick={() => window.location.reload()}>Retry</button>
      </div>
    );
  }

  // state === 'ready'
  return (
    <div className="chat-container">
      <h1>Chat with {username}</h1>
      <div className="chat-messages">{chatContent}</div>
      <ChatInput chatId={chatId} />
    </div>
  );
}

/**
 * Компонент для ввода сообщений (использует уже инициализированный PQ)
 */
function ChatInput({ chatId }: { chatId: string }) {
  const [message, setMessage] = useState('');

  const handleSend = async () => {
    try {
      // PQ уже инициализирован к этому моменту
      // Можно использовать криптографию без опасения блокировки UI
      const encrypted = await encryptAndSendMessage(chatId, message);
      setMessage('');
    } catch (err) {
      console.error('[ChatInput] Failed to send message:', err);
    }
  };

  return (
    <div className="chat-input">
      <input
        type="text"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') handleSend();
        }}
        placeholder="Type a message..."
      />
      <button onClick={handleSend}>Send</button>
    </div>
  );
}

// ============================================================================
// HELPERS (заглушки для примера)
// ============================================================================

async function fetchChatMessages(chatId: string): Promise<string> {
  // Получаем сообщения из API
  // Они уже зашифрованы, и мы расшифровываем их используя инициализированный PQ
  return `Messages for chat ${chatId}`;
}

async function encryptAndSendMessage(chatId: string, message: string): Promise<void> {
  // Шифруем сообщение используя PQ-криптографию и отправляем
  console.log(`[ChatInput] Sending encrypted message to ${chatId}: ${message}`);
}
