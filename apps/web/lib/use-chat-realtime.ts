/**
 * React Hook: useCharRealtime
 *
 * Manages WebSocket connection for a specific chat
 * Handles:
 * - Real-time message delivery
 * - Typing indicators
 * - Read receipts
 * - Connection state
 */

'use client';

import { useCallback, useState, useEffect, useRef } from 'react';
import type { WSMessage } from './websocket-client';
import { useWebSocket } from './websocket-client';

export interface ChatRealtimeState {
  typingUsers: Map<string, number>; // username -> timestamp
  readReceipts: Map<string, number>; // username -> lastReadSequence
  onlineUsers: Set<string>;
}

export interface UseChatRealtimeOptions {
  chatId: string;
  username: string;
  wsUrl: string;
  enabled?: boolean;
  onMessage?: (msg: WSMessage) => void;
  onTypingChange?: (typingUsers: Set<string>) => void;
  onReadReceiptChange?: (receipts: Map<string, number>) => void;
}

export function useChatRealtime(options: UseChatRealtimeOptions) {
  const {
    chatId,
    username,
    wsUrl,
    enabled = true,
    onMessage,
    onTypingChange,
    onReadReceiptChange,
  } = options;

  const [state, setState] = useState<ChatRealtimeState>({
    typingUsers: new Map(),
    readReceipts: new Map(),
    onlineUsers: new Set(),
  });

  const typingTimeouts = useRef<Map<string, NodeJS.Timeout>>(new Map());

  // Handle incoming WebSocket messages
  const handleWSMessage = useCallback(
    (msg: WSMessage) => {
      // Only process messages for this chat
      if (msg.chatId && msg.chatId !== chatId) {
        return;
      }

      // Handle group invitations globally (not chat-specific)
      if (msg.type === 'group_invitation') {
        console.log('[ChatRealtime] Received group invitation:', msg);
        // Store the invitation in IndexedDB
        if (typeof window !== 'undefined') {
          import('@/lib/group-invitations').then(({ storeGroupInvitation }) => {
            storeGroupInvitation({
              invitationId: `${msg.groupId}-${msg.creatorUsername}`,
              groupId: msg.groupId || '',
              groupName: msg.groupName || '',
              creatorUsername: msg.creatorUsername || '',
              creatorDisplayName: msg.creator || msg.creatorUsername || '',
              recipientUsername: msg.recipientUsername || username,
              createdAt: msg.timestamp || Date.now(),
              status: 'pending',
            }).catch(err => console.error('[ChatRealtime] Failed to store invitation:', err));
          }).catch(err => console.error('[ChatRealtime] Failed to import:', err));
        }
        // Trigger a notification or update state as needed
        return;
      }

      switch (msg.type) {
        case 'message':
          // Forward to consumer
          onMessage?.(msg);
          break;

        case 'typing': {
          const typingUsername = msg.senderId;
          if (!typingUsername) break;

          const isTyping = msg.content?.typing ?? true;

          setState((prev) => {
            const newTypingUsers = new Map(prev.typingUsers);

            if (isTyping) {
              newTypingUsers.set(typingUsername, Date.now());

              // Clear existing timeout
              const existingTimeout = typingTimeouts.current.get(typingUsername);
              if (existingTimeout) {
                clearTimeout(existingTimeout);
              }

              // Set new timeout (3 seconds as per relay)
              const timeout = setTimeout(() => {
                setState((prev) => {
                  const updated = new Map(prev.typingUsers);
                  updated.delete(typingUsername);
                  onTypingChange?.(new Set(updated.keys()));
                  return { ...prev, typingUsers: updated };
                });
                typingTimeouts.current.delete(typingUsername);
              }, 3000);

              typingTimeouts.current.set(typingUsername, timeout);
            } else {
              newTypingUsers.delete(typingUsername);
              const timeout = typingTimeouts.current.get(typingUsername);
              if (timeout) {
                clearTimeout(timeout);
                typingTimeouts.current.delete(typingUsername);
              }
            }

            const typingSet = new Set(newTypingUsers.keys());
            onTypingChange?.(typingSet);

            return { ...prev, typingUsers: newTypingUsers };
          });
          break;
        }

        case 'read': {
          const readUsername = msg.senderId;
          const lastReadSequence = msg.content?.lastReadSequence ?? 0;

          if (!readUsername) break;

          setState((prev) => {
            const newReceipts = new Map(prev.readReceipts);
            newReceipts.set(readUsername, lastReadSequence);
            onReadReceiptChange?.(newReceipts);
            return { ...prev, readReceipts: newReceipts };
          });
          break;
        }

        case 'presence': {
          const presenceUsername = msg.senderId;
          if (!presenceUsername) break;

          const status = msg.content?.status || 'online';

          setState((prev) => {
            const newOnlineUsers = new Set(prev.onlineUsers);

            if (status === 'joined' || status === 'online') {
              newOnlineUsers.add(presenceUsername);
            } else if (status === 'left' || status === 'offline') {
              newOnlineUsers.delete(presenceUsername);
            }

            return { ...prev, onlineUsers: newOnlineUsers };
          });
          break;
        }
      }
    },
    [chatId, onMessage, onTypingChange, onReadReceiptChange]
  );

  // WebSocket connection
  const { client, connected, error, sendMessage, sendTypingIndicator, sendReadReceipt } =
    useWebSocket({
      url: wsUrl,
      username,
      chatIds: [chatId],
      onMessage: handleWSMessage,
      enabled,
    });

  // Subscribe to chat when effect runs
  useEffect(() => {
    if (client && enabled) {
      client.subscribeTo(chatId);
    }
  }, [client, chatId, enabled]);

  // Cleanup typing timeouts on unmount
  useEffect(() => {
    return () => {
      for (const timeout of typingTimeouts.current.values()) {
        clearTimeout(timeout);
      }
      typingTimeouts.current.clear();
    };
  }, []);

  return {
    // State
    connected,
    error,
    typingUsers: state.typingUsers,
    readReceipts: state.readReceipts,
    onlineUsers: state.onlineUsers,

    // Methods
    sendMessage: (content: any) => sendMessage(chatId, content),
    sendTypingIndicator: () => sendTypingIndicator(chatId),
    sendReadReceipt: (lastReadSequence: number) => sendReadReceipt(chatId, lastReadSequence),
    unsubscribe: () => client?.unsubscribeFrom(chatId),
  };
}
