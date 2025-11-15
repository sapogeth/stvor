'use client';

/**
 * Group Chat Page
 * End-to-end encrypted group messaging with real-time features
 */

import { useState, useEffect, useRef } from 'react';
import { useUser } from '@clerk/nextjs';
import Link from 'next/link';
import { useRouter, useParams } from 'next/navigation';
import { useWebSocket } from '@/lib/websocket-client';
import { useChatRealtime } from '@/lib/use-chat-realtime';
import { TypingIndicator, OnlineUsers } from '@/components/TypingIndicator';
import { loadGroupChat, decryptFromGroup, encryptForGroup, StoredGroupChat } from '@/lib/group-chat';
import { hasGroupInvitation, hasAcceptedInvitation } from '@/lib/group-invitations';

const getRelayUrl = () => {
  if (typeof window === 'undefined') return 'http://localhost:3001';
  const hostname = window.location.hostname;
  if (hostname !== 'localhost' && hostname !== '127.0.0.1') {
    return `http://${hostname}:3001`;
  }
  return process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';
};

interface GroupMessage {
  id: string;
  sender: string;
  text: string;
  timestamp: number;
  encrypted: boolean;
}

export default function GroupChatPage() {
  const { user } = useUser();
  const router = useRouter();
  const params = useParams();
  const groupId = params.groupId as string;

  const [groupChat, setGroupChat] = useState<StoredGroupChat | null>(null);
  const [messages, setMessages] = useState<GroupMessage[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isAuthorized, setIsAuthorized] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const username = user?.username || user?.firstName || 'unknown';
  const wsUrl = getRelayUrl().replace('http://', 'ws://');

  // Load group chat from IndexedDB and check authorization
  useEffect(() => {
    if (!groupId || !username) return;

    const load = async () => {
      try {
        const group = await loadGroupChat(groupId);
        if (!group) {
          setError('Group not found');
          setLoading(false);
          return;
        }

        // Check if user is the creator (automatically authorized)
        const isCreator = group.myRole === 'admin';

        // Check if user is a participant in the group
        const isParticipant = group.participants.includes(username);

        if (isCreator || isParticipant) {
          setGroupChat(group);
          setIsAuthorized(true);
          setLoading(false);
        } else {
          // User is not creator or participant, check invitation status
          const hasAccepted = await hasAcceptedInvitation(username, groupId);
          if (hasAccepted) {
            // They have ACCEPTED the invitation, give full access
            setGroupChat(group);
            setIsAuthorized(true);
            setLoading(false);
          } else {
            // Check if they have a PENDING invitation
            const hasPending = await hasGroupInvitation(username, groupId);
            if (hasPending) {
              // They have a pending invitation, allow them to view but not chat
              setGroupChat(group);
              setIsAuthorized(false);
              setError('You need to accept the invitation first');
              setLoading(false);
            } else {
              setError('You do not have access to this group. Ask the creator to invite you.');
              setLoading(false);
            }
          }
        }
      } catch (err) {
        console.error('[GroupChat] Failed to load group:', err);
        setError('Failed to load group');
        setLoading(false);
      }
    };

    load();
  }, [groupId, username]);

  // WebSocket real-time features (only enabled if authorized)
  const { connected, typingUsers, onlineUsers, sendTypingIndicator, sendReadReceipt } = useChatRealtime({
    chatId: groupId,
    username,
    wsUrl,
    enabled: !!groupChat && isAuthorized,
    onMessage: async (msg) => {
      if (msg.type === 'message' && msg.chatId === groupId) {
        // Decrypt message
        try {
          if (groupChat && msg.content?.recipient) {
            const plaintext = await decryptFromGroup(
              groupChat,
              msg.senderId || 'unknown',
              msg.content
            );

            const decrypted = new TextDecoder().decode(plaintext);

            setMessages((prev) => [
              ...prev,
              {
                id: `${msg.timestamp}`,
                sender: msg.senderId || 'unknown',
                text: decrypted,
                timestamp: msg.timestamp || Date.now(),
                encrypted: true,
              },
            ]);
          }
        } catch (err) {
          console.error('[GroupChat] Failed to decrypt message:', err);
        }
      }
    },
  });

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Handle message send
  const handleSendMessage = async () => {
    if (!inputValue.trim() || !groupChat || !connected || !isAuthorized) {
      return;
    }

    try {
      const plaintext = new TextEncoder().encode(inputValue);

      // Encrypt for group
      const encrypted = await encryptForGroup(groupChat, plaintext);

      // Format message for relay (encrypted returns base64 strings already)
      const recipientData: any = {};
      if (encrypted.recipients) {
        for (const [recipientUsername, wrap] of Object.entries(encrypted.recipients)) {
          recipientData[recipientUsername] = wrap;
        }
      }

      // Send via relay
      const response = await fetch(`/api/relay/group/${groupId}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'group_message',
          sender: username,
          message: {
            aad: encrypted.aad,
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
            recipients: recipientData,
          },
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to send message: ${response.status} - ${errorText}`);
      }

      // Add to local messages
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now().toString(),
          sender: username,
          text: inputValue,
          timestamp: Date.now(),
          encrypted: true,
        },
      ]);

      setInputValue('');
    } catch (err) {
      console.error('[GroupChat] Failed to send message:', err);
      setError('Failed to send message: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading group chat...</p>
        </div>
      </div>
    );
  }

  if (error || !groupChat) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <p className="text-red-600 mb-4">{error || 'Group not found'}</p>
          <Link href="/groups" className="text-blue-600 hover:underline">
            Back to groups
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shadow-sm">
        <div className="max-w-6xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{groupChat.groupName}</h1>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                {groupChat.participants.length} members {!connected && '(disconnected)'}
              </p>
            </div>
            <div className="flex items-center gap-4">
              <div
                className={`w-3 h-3 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`}
                title={connected ? 'Connected' : 'Disconnected'}
              ></div>
              <Link href="/groups" className="text-blue-600 hover:underline text-sm">
                Back
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Online Users */}
      <OnlineUsers onlineUsers={onlineUsers} currentUsername={username} allParticipants={groupChat.participants} />

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <p className="text-gray-500">No messages yet. Start the conversation!</p>
          </div>
        ) : (
          messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex ${msg.sender === username ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
                  msg.sender === username
                    ? 'bg-blue-500 text-white'
                    : 'bg-white dark:bg-gray-800 text-gray-900 dark:text-white border border-gray-200 dark:border-gray-700'
                }`}
              >
                {msg.sender !== username && (
                  <p className="text-xs font-semibold mb-1 opacity-75">{msg.sender}</p>
                )}
                <p className="break-words">{msg.text}</p>
                <p className="text-xs mt-1 opacity-70">
                  {new Date(msg.timestamp).toLocaleTimeString()}
                </p>
              </div>
            </div>
          ))
        )}

        {/* Typing Indicator */}
        <TypingIndicator typingUsers={typingUsers} currentUsername={username} />

        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-4">
        {!isAuthorized && !error?.includes('not have access') ? (
          <div className="max-w-6xl mx-auto">
            <div className="p-4 bg-yellow-50 dark:bg-yellow-900 border border-yellow-200 dark:border-yellow-700 rounded-lg mb-4">
              <p className="text-yellow-800 dark:text-yellow-200 text-sm">
                You have been invited to this group. Go to your notifications and accept the invitation to start chatting.
              </p>
              <Link
                href="/notifications"
                className="text-yellow-700 dark:text-yellow-300 hover:underline text-sm mt-2 inline-block"
              >
                View Invitations →
              </Link>
            </div>
          </div>
        ) : null}

        <div className="max-w-6xl mx-auto flex gap-2">
          <input
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyPress={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleSendMessage();
              }
            }}
            onInput={() => {
              if (inputValue.length === 1) {
                sendTypingIndicator();
              }
            }}
            placeholder="Type a message... (end-to-end encrypted)"
            className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            disabled={!connected || !isAuthorized}
          />
          <button
            onClick={handleSendMessage}
            disabled={!connected || !inputValue.trim() || !isAuthorized}
            className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition"
          >
            Send
          </button>
        </div>
        {error && <p className="text-red-600 text-sm mt-2">{error}</p>}
      </div>
    </div>
  );
}
