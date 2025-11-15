/**
 * WebSocket Client for Real-Time Messaging
 * Handles connection, reconnection, typing indicators, read receipts
 */

'use client';

import { useEffect, useRef, useCallback, useState } from 'react';

// ==================== Types ====================

export interface WSMessage {
  type: 'message' | 'typing' | 'read' | 'ping' | 'pong' | 'presence' | 'error';
  chatId?: string;
  senderId?: string;
  recipientId?: string;
  content?: any;
  timestamp?: number;
}

export interface WSConnectionConfig {
  url: string; // WebSocket URL (e.g., ws://localhost:3001/ws)
  username: string;
  chatIds?: string[];
  reconnectAttempts?: number;
  reconnectDelay?: number;
  heartbeatInterval?: number;
}

export interface TypingUser {
  username: string;
  since: number; // timestamp when typing started
}

export interface ReadReceipt {
  username: string;
  lastReadSequence: number;
  timestamp: number;
}

// ==================== WebSocket Client Class ====================

export class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private username: string;
  private chatIds: Set<string>;
  private reconnectAttempts: number = 3;
  private reconnectDelay: number = 1000;
  private reconnectCount: number = 0;
  private isConnected: boolean = false;
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private heartbeatIntervalMs: number = 30000; // 30 seconds

  // Callbacks
  private onMessageCallback: ((msg: WSMessage) => void) | null = null;
  private onConnectionCallback: ((connected: boolean) => void) | null = null;
  private onErrorCallback: ((error: Error) => void) | null = null;

  constructor(config: WSConnectionConfig) {
    this.url = config.url;
    this.username = config.username;
    this.chatIds = new Set(config.chatIds || []);
    this.reconnectAttempts = config.reconnectAttempts || 3;
    this.reconnectDelay = config.reconnectDelay || 1000;
    this.heartbeatIntervalMs = config.heartbeatInterval || 30000;
  }

  /**
   * Connect to WebSocket server
   */
  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        // Build WebSocket URL with query parameters
        const params = new URLSearchParams({
          username: this.username,
          chatIds: Array.from(this.chatIds).join(','),
        });

        const wsUrl = `${this.url}?${params.toString()}`;

        console.log(`[WebSocket] Connecting to ${wsUrl}`);

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
          console.log(`[WebSocket] ✅ Connected as ${this.username}`);
          this.isConnected = true;
          this.reconnectCount = 0;

          // Start heartbeat
          this.startHeartbeat();

          // Notify listeners
          this.onConnectionCallback?.(true);

          resolve();
        };

        this.ws.onmessage = (event: MessageEvent) => {
          try {
            const message: WSMessage = JSON.parse(event.data);
            this.onMessageCallback?.(message);
          } catch (err) {
            console.error('[WebSocket] Failed to parse message:', err);
          }
        };

        this.ws.onerror = (event: Event) => {
          console.error('[WebSocket] Connection error:', event);
          const error = new Error('WebSocket connection error');
          this.onErrorCallback?.(error);
          reject(error);
        };

        this.ws.onclose = () => {
          console.log('[WebSocket] ❌ Connection closed');
          this.isConnected = false;
          this.stopHeartbeat();
          this.onConnectionCallback?.(false);

          // Attempt reconnection
          this.attemptReconnect();
        };
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        this.onErrorCallback?.(error);
        reject(error);
      }
    });
  }

  /**
   * Disconnect from WebSocket server
   */
  disconnect(): void {
    this.stopHeartbeat();

    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }

    this.isConnected = false;
    console.log('[WebSocket] Disconnected');
  }

  /**
   * Send message through WebSocket
   */
  send(message: WSMessage): boolean {
    if (!this.isConnected || !this.ws) {
      console.warn('[WebSocket] Not connected, cannot send message');
      return false;
    }

    try {
      this.ws.send(JSON.stringify(message));
      return true;
    } catch (err) {
      console.error('[WebSocket] Failed to send message:', err);
      return false;
    }
  }

  /**
   * Send encrypted message
   */
  sendMessage(chatId: string, encryptedContent: any): boolean {
    return this.send({
      type: 'message',
      chatId,
      senderId: this.username,
      content: encryptedContent,
      timestamp: Date.now(),
    });
  }

  /**
   * Send typing indicator
   */
  sendTypingIndicator(chatId: string): boolean {
    return this.send({
      type: 'typing',
      chatId,
      senderId: this.username,
      content: { typing: true },
      timestamp: Date.now(),
    });
  }

  /**
   * Send read receipt
   */
  sendReadReceipt(chatId: string, lastReadSequence: number): boolean {
    return this.send({
      type: 'read',
      chatId,
      senderId: this.username,
      content: { lastReadSequence },
      timestamp: Date.now(),
    });
  }

  /**
   * Subscribe to a chat
   */
  subscribeTo(chatId: string): boolean {
    this.chatIds.add(chatId);

    return this.send({
      type: 'presence',
      chatId,
      content: { action: 'subscribe', chatId },
      timestamp: Date.now(),
    });
  }

  /**
   * Unsubscribe from a chat
   */
  unsubscribeFrom(chatId: string): boolean {
    this.chatIds.delete(chatId);

    return this.send({
      type: 'presence',
      chatId,
      content: { action: 'unsubscribe', chatId },
      timestamp: Date.now(),
    });
  }

  /**
   * Get connection status
   */
  getStatus(): boolean {
    return this.isConnected && this.ws?.readyState === WebSocket.OPEN;
  }

  /**
   * Register callback for incoming messages
   */
  onMessage(callback: (msg: WSMessage) => void): void {
    this.onMessageCallback = callback;
  }

  /**
   * Register callback for connection state changes
   */
  onConnection(callback: (connected: boolean) => void): void {
    this.onConnectionCallback = callback;
  }

  /**
   * Register callback for errors
   */
  onError(callback: (error: Error) => void): void {
    this.onErrorCallback = callback;
  }

  // ==================== Private Methods ====================

  /**
   * Attempt to reconnect
   */
  private attemptReconnect(): void {
    if (this.reconnectCount < this.reconnectAttempts) {
      this.reconnectCount++;
      const delay = this.reconnectDelay * Math.pow(2, this.reconnectCount - 1); // Exponential backoff

      console.log(
        `[WebSocket] Reconnecting in ${delay}ms (attempt ${this.reconnectCount}/${this.reconnectAttempts})`
      );

      setTimeout(() => {
        this.connect().catch((err) => {
          console.error('[WebSocket] Reconnection failed:', err);
        });
      }, delay);
    } else {
      console.error('[WebSocket] Max reconnection attempts reached');
      this.onErrorCallback?.(new Error('Failed to reconnect to WebSocket'));
    }
  }

  /**
   * Start heartbeat to keep connection alive
   */
  private startHeartbeat(): void {
    this.stopHeartbeat();

    this.heartbeatInterval = setInterval(() => {
      if (this.isConnected && this.ws?.readyState === WebSocket.OPEN) {
        this.send({
          type: 'ping',
          timestamp: Date.now(),
        });
      }
    }, this.heartbeatIntervalMs);

    console.log(`[WebSocket] Heartbeat started (interval: ${this.heartbeatIntervalMs}ms)`);
  }

  /**
   * Stop heartbeat
   */
  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
      console.log('[WebSocket] Heartbeat stopped');
    }
  }
}

// ==================== React Hook ====================

export interface UseWebSocketOptions {
  url: string;
  username: string;
  chatIds?: string[];
  onMessage?: (msg: WSMessage) => void;
  enabled?: boolean;
}

export function useWebSocket(options: UseWebSocketOptions) {
  const clientRef = useRef<WebSocketClient | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const { url, username, chatIds = [], onMessage, enabled = true } = options;

  // Initialize and connect
  useEffect(() => {
    if (!enabled || !username) {
      return;
    }

    const client = new WebSocketClient({
      url,
      username,
      chatIds,
    });

    client.onConnection(setConnected);
    client.onError(setError);
    if (onMessage) {
      client.onMessage(onMessage);
    }

    clientRef.current = client;

    client.connect().catch((err) => {
      console.error('[WebSocket] Connection failed:', err);
      setError(err instanceof Error ? err : new Error(String(err)));
    });

    // Cleanup on unmount
    return () => {
      client.disconnect();
      clientRef.current = null;
    };
  }, [url, username, enabled, onMessage, chatIds.join(',')]); // Include chatIds in dependency

  // Public API
  return {
    client: clientRef.current,
    connected,
    error,

    // Convenience methods
    send: (msg: WSMessage) => clientRef.current?.send(msg) ?? false,
    sendMessage: (chatId: string, content: any) =>
      clientRef.current?.sendMessage(chatId, content) ?? false,
    sendTypingIndicator: (chatId: string) =>
      clientRef.current?.sendTypingIndicator(chatId) ?? false,
    sendReadReceipt: (chatId: string, sequence: number) =>
      clientRef.current?.sendReadReceipt(chatId, sequence) ?? false,
    subscribeTo: (chatId: string) => clientRef.current?.subscribeTo(chatId) ?? false,
    unsubscribeFrom: (chatId: string) => clientRef.current?.unsubscribeFrom(chatId) ?? false,
  };
}
