'use client';

/**
 * Typing Indicator Component
 * Shows which users are currently typing in a chat
 */

import React, { useState, useEffect } from 'react';

interface TypingIndicatorProps {
  typingUsers: Map<string, number>; // username -> timestamp
  currentUsername: string;
}

export function TypingIndicator({ typingUsers, currentUsername }: TypingIndicatorProps) {
  const [displayText, setDisplayText] = useState('');

  // Update display based on typing users
  useEffect(() => {
    // Filter out current user and get display names
    const otherTypingUsers = Array.from(typingUsers.keys()).filter((u) => u !== currentUsername);

    if (otherTypingUsers.length === 0) {
      setDisplayText('');
      return;
    }

    if (otherTypingUsers.length === 1) {
      setDisplayText(`${otherTypingUsers[0]} is typing...`);
    } else if (otherTypingUsers.length === 2) {
      setDisplayText(`${otherTypingUsers[0]} and ${otherTypingUsers[1]} are typing...`);
    } else {
      setDisplayText(`${otherTypingUsers.length} people are typing...`);
    }
  }, [typingUsers, currentUsername]);

  if (!displayText) {
    return null;
  }

  return (
    <div className="flex items-center gap-2 px-4 py-2 text-sm text-gray-500 dark:text-gray-400">
      <div className="flex gap-1">
        <span className="w-1.5 h-1.5 rounded-full bg-gray-400 dark:bg-gray-500 animate-bounce"></span>
        <span
          className="w-1.5 h-1.5 rounded-full bg-gray-400 dark:bg-gray-500 animate-bounce"
          style={{ animationDelay: '0.1s' }}
        ></span>
        <span
          className="w-1.5 h-1.5 rounded-full bg-gray-400 dark:bg-gray-500 animate-bounce"
          style={{ animationDelay: '0.2s' }}
        ></span>
      </div>
      <span>{displayText}</span>
    </div>
  );
}

interface ReadReceiptProps {
  readReceipts: Map<string, number>; // username -> lastReadSequence
  currentUsername: string;
  lastMessageSequence: number;
}

export function ReadReceipt({ readReceipts, currentUsername, lastMessageSequence }: ReadReceiptProps) {
  const [displayUsers, setDisplayUsers] = useState<string[]>([]);

  // Update display based on read receipts
  useEffect(() => {
    // Find users who have read the last message
    const usersWhoHaveRead = Array.from(readReceipts.entries())
      .filter(([username, sequence]) => username !== currentUsername && sequence >= lastMessageSequence)
      .map(([username]) => username);

    setDisplayUsers(usersWhoHaveRead);
  }, [readReceipts, currentUsername, lastMessageSequence]);

  if (displayUsers.length === 0) {
    return null;
  }

  return (
    <div className="flex items-center gap-2 px-4 py-1 text-xs text-gray-400 dark:text-gray-500">
      <span className="text-blue-500">✓✓</span>
      <span>Read by: {displayUsers.join(', ')}</span>
    </div>
  );
}

interface OnlineUsersProps {
  onlineUsers: Set<string>;
  currentUsername: string;
  allParticipants?: string[];
}

export function OnlineUsers({ onlineUsers, currentUsername, allParticipants }: OnlineUsersProps) {
  const [otherOnlineUsers, setOtherOnlineUsers] = useState<string[]>([]);

  useEffect(() => {
    const others = Array.from(onlineUsers).filter((u) => u !== currentUsername);
    setOtherOnlineUsers(others);
  }, [onlineUsers, currentUsername]);

  if (otherOnlineUsers.length === 0 && !allParticipants) {
    return null;
  }

  return (
    <div className="px-4 py-2 border-b border-gray-200 dark:border-gray-700">
      <div className="flex flex-wrap gap-2">
        {allParticipants?.map((participant) => {
          const isOnline = otherOnlineUsers.includes(participant);
          return (
            <div
              key={participant}
              className={`flex items-center gap-1.5 px-2 py-1 rounded-full text-sm ${
                isOnline
                  ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100'
                  : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400'
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${isOnline ? 'bg-green-500' : 'bg-gray-400'}`}></span>
              <span>{participant}</span>
              {isOnline ? <span className="text-xs">online</span> : <span className="text-xs">offline</span>}
            </div>
          );
        })}
      </div>
    </div>
  );
}
