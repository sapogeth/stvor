/**
 * WebSocket Server for Real-Time Messaging
 * Handles real-time message delivery, typing indicators, read receipts
 */

import type { FastifyInstance } from 'fastify';
import type { WebSocket } from '@fastify/websocket';
import fastifyWebsocket from '@fastify/websocket';
import { normalizeUsername } from './utils/normalize';

// ==================== Types ====================

interface WSMessage {
  type: 'message' | 'typing' | 'read' | 'ping' | 'pong' | 'presence' | 'error';
  chatId?: string;
  senderId?: string;
  recipientId?: string;
  content?: any;
  timestamp?: number;
}

interface ConnectedClient {
  username: string;
  ws: WebSocket;
  chatIds: Set<string>; // Chats this client is subscribed to
  lastActivity: number;
}

// ==================== WebSocket Manager ====================

export class WebSocketManager {
  private clients = new Map<string, ConnectedClient>();
  private chatSubscriptions = new Map<string, Set<string>>(); // chatId -> Set<username>
  private typingIndicators = new Map<string, Map<string, number>>(); // chatId -> (username -> timeout)
  private readReceipts = new Map<string, Map<string, number>>(); // chatId -> (username -> lastReadSequence)

  /**
   * Register a new WebSocket connection
   */
  registerClient(username: string, ws: WebSocket, chatIds: string[] = []) {
    const normalizedUsername = normalizeUsername(username);

    // Create client entry
    const client: ConnectedClient = {
      username: normalizedUsername,
      ws,
      chatIds: new Set(chatIds),
      lastActivity: Date.now(),
    };

    this.clients.set(normalizedUsername, client);
    console.log(`[WebSocket] ✅ Client connected: ${normalizedUsername} (${this.clients.size} connected)`);

    // Subscribe to requested chats
    for (const chatId of chatIds) {
      this.subscribeToChat(normalizedUsername, chatId);
    }

    // Send welcome message
    this.sendToClient(normalizedUsername, {
      type: 'presence',
      content: { status: 'connected', username: normalizedUsername },
      timestamp: Date.now(),
    });
  }

  /**
   * Unregister a client
   */
  unregisterClient(username: string) {
    const normalizedUsername = normalizeUsername(username);
    const client = this.clients.get(normalizedUsername);

    if (!client) return;

    // Unsubscribe from all chats
    for (const chatId of client.chatIds) {
      this.unsubscribeFromChat(normalizedUsername, chatId);
    }

    // Remove client
    this.clients.delete(normalizedUsername);
    console.log(`[WebSocket] ❌ Client disconnected: ${normalizedUsername} (${this.clients.size} connected)`);
  }

  /**
   * Subscribe client to a chat
   */
  subscribeToChat(username: string, chatId: string) {
    const normalizedUsername = normalizeUsername(username);

    // Add to client's chat list
    const client = this.clients.get(normalizedUsername);
    if (client) {
      client.chatIds.add(chatId);
    }

    // Add to chat's subscriber list
    if (!this.chatSubscriptions.has(chatId)) {
      this.chatSubscriptions.set(chatId, new Set());
    }
    this.chatSubscriptions.get(chatId)!.add(normalizedUsername);

    console.log(`[WebSocket] ${normalizedUsername} subscribed to chat ${chatId.slice(0, 12)}...`);

    // Notify other clients in the chat
    this.broadcastToChat(chatId, {
      type: 'presence',
      content: { status: 'joined', username: normalizedUsername },
      timestamp: Date.now(),
    }, normalizedUsername); // Exclude sender
  }

  /**
   * Unsubscribe client from a chat
   */
  unsubscribeFromChat(username: string, chatId: string) {
    const normalizedUsername = normalizeUsername(username);

    // Remove from client's chat list
    const client = this.clients.get(normalizedUsername);
    if (client) {
      client.chatIds.delete(chatId);
    }

    // Remove from chat's subscriber list
    const subscribers = this.chatSubscriptions.get(chatId);
    if (subscribers) {
      subscribers.delete(normalizedUsername);
      if (subscribers.size === 0) {
        this.chatSubscriptions.delete(chatId);
      }
    }

    // Cleanup typing indicators for this user in this chat
    const chatTyping = this.typingIndicators.get(chatId);
    if (chatTyping) {
      const timeout = chatTyping.get(normalizedUsername);
      if (timeout) {
        clearTimeout(timeout);
      }
      chatTyping.delete(normalizedUsername);
    }

    console.log(`[WebSocket] ${normalizedUsername} unsubscribed from chat ${chatId.slice(0, 12)}...`);

    // Notify other clients
    this.broadcastToChat(chatId, {
      type: 'presence',
      content: { status: 'left', username: normalizedUsername },
      timestamp: Date.now(),
    }, normalizedUsername); // Exclude sender
  }

  /**
   * Send message to specific client
   */
  sendToClient(username: string, message: WSMessage) {
    const normalizedUsername = normalizeUsername(username);
    const client = this.clients.get(normalizedUsername);

    if (!client) {
      console.warn(`[WebSocket] Client not connected: ${normalizedUsername}`);
      return false;
    }

    try {
      client.ws.send(JSON.stringify(message));
      client.lastActivity = Date.now();
      return true;
    } catch (err) {
      console.error(`[WebSocket] Failed to send to ${normalizedUsername}:`, err);
      // If send fails, unregister the client
      this.unregisterClient(normalizedUsername);
      return false;
    }
  }

  /**
   * Broadcast message to all clients in a chat
   */
  broadcastToChat(chatId: string, message: WSMessage, excludeUsername?: string) {
    const subscribers = this.chatSubscriptions.get(chatId);
    if (!subscribers || subscribers.size === 0) {
      return 0;
    }

    let count = 0;
    for (const username of subscribers) {
      if (excludeUsername && username === normalizeUsername(excludeUsername)) {
        continue;
      }

      if (this.sendToClient(username, message)) {
        count++;
      }
    }

    return count;
  }

  /**
   * Broadcast message to both participants of a 1-on-1 chat
   */
  broadcastToParticipants(chatId: string, message: WSMessage, senderUsername?: string) {
    const subscribers = this.chatSubscriptions.get(chatId) || new Set();
    const recipientCount = subscribers.size - (senderUsername ? 1 : 0);

    // Send to all connected subscribers (excluding sender)
    this.broadcastToChat(chatId, message, senderUsername);

    return recipientCount;
  }

  /**
   * Handle incoming message from client
   */
  handleMessage(username: string, rawMessage: string): any {
    const normalizedUsername = normalizeUsername(username);

    try {
      const message: WSMessage = JSON.parse(rawMessage);

      switch (message.type) {
        case 'message':
          return this.handleEncryptedMessage(normalizedUsername, message);

        case 'typing':
          return this.handleTypingIndicator(normalizedUsername, message);

        case 'read':
          return this.handleReadReceipt(normalizedUsername, message);

        case 'ping':
          return this.handlePing(normalizedUsername, message);

        case 'presence':
          return this.handlePresence(normalizedUsername, message);

        default:
          console.warn(`[WebSocket] Unknown message type: ${message.type}`);
          return { error: 'Unknown message type' };
      }
    } catch (err) {
      console.error(`[WebSocket] Failed to parse message from ${normalizedUsername}:`, err);
      return { error: 'Invalid message format' };
    }
  }

  /**
   * Handle encrypted message delivery
   * Message is already encrypted, just route to recipient
   */
  private handleEncryptedMessage(senderUsername: string, message: WSMessage) {
    if (!message.chatId) {
      return { error: 'chatId required' };
    }

    // Forward message to all other subscribers in chat (except sender)
    const recipientCount = this.broadcastToChat(message.chatId, {
      type: 'message',
      chatId: message.chatId,
      senderId: senderUsername,
      content: message.content,
      timestamp: Date.now(),
    }, senderUsername);

    console.log(`[WebSocket] Message in chat ${message.chatId.slice(0, 12)}... delivered to ${recipientCount} recipients`);

    return { delivered: recipientCount };
  }

  /**
   * Handle typing indicator
   * Broadcast that user is typing (3-second window)
   */
  private handleTypingIndicator(senderUsername: string, message: WSMessage) {
    if (!message.chatId) {
      return { error: 'chatId required' };
    }

    const chatId = message.chatId;

    // Initialize typing map for this chat if needed
    if (!this.typingIndicators.has(chatId)) {
      this.typingIndicators.set(chatId, new Map());
    }

    const chatTyping = this.typingIndicators.get(chatId)!;

    // Cancel previous timeout if exists
    const existingTimeout = chatTyping.get(senderUsername);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }

    // Set new timeout (3 seconds)
    const timeout = setTimeout(() => {
      chatTyping.delete(senderUsername);
      // Broadcast typing stopped
      this.broadcastToChat(chatId, {
        type: 'typing',
        chatId,
        senderId: senderUsername,
        content: { typing: false },
        timestamp: Date.now(),
      }, senderUsername);
    }, 3000);

    chatTyping.set(senderUsername, timeout as any);

    // Broadcast typing indicator
    this.broadcastToChat(chatId, {
      type: 'typing',
      chatId,
      senderId: senderUsername,
      content: { typing: true },
      timestamp: Date.now(),
    }, senderUsername);

    console.log(`[WebSocket] Typing indicator from ${senderUsername} in chat ${chatId.slice(0, 12)}...`);

    return { acknowledged: true };
  }

  /**
   * Handle read receipt
   * Track which messages user has read
   */
  private handleReadReceipt(senderUsername: string, message: WSMessage) {
    if (!message.chatId) {
      return { error: 'chatId required' };
    }

    const chatId = message.chatId;
    const lastReadSequence = message.content?.lastReadSequence || 0;

    // Initialize read receipts map for this chat if needed
    if (!this.readReceipts.has(chatId)) {
      this.readReceipts.set(chatId, new Map());
    }

    const chatReads = this.readReceipts.get(chatId)!;
    chatReads.set(senderUsername, lastReadSequence);

    // Broadcast read receipt to all subscribers in chat
    this.broadcastToChat(chatId, {
      type: 'read',
      chatId,
      senderId: senderUsername,
      content: { lastReadSequence },
      timestamp: Date.now(),
    });

    console.log(`[WebSocket] Read receipt from ${senderUsername} in chat ${chatId.slice(0, 12)}... (read up to sequence ${lastReadSequence})`);

    return { acknowledged: true };
  }

  /**
   * Handle ping (keep-alive)
   */
  private handlePing(senderUsername: string, message: WSMessage) {
    // Update last activity
    const client = this.clients.get(senderUsername);
    if (client) {
      client.lastActivity = Date.now();
    }

    // Send pong back
    this.sendToClient(senderUsername, {
      type: 'pong',
      timestamp: Date.now(),
    });

    return { acknowledged: true };
  }

  /**
   * Handle presence updates
   */
  private handlePresence(senderUsername: string, message: WSMessage) {
    const content = message.content || {};

    // If user is requesting to join a chat
    if (content.action === 'subscribe' && content.chatId) {
      this.subscribeToChat(senderUsername, content.chatId);
      return { subscribed: content.chatId };
    }

    // If user is requesting to leave a chat
    if (content.action === 'unsubscribe' && content.chatId) {
      this.unsubscribeFromChat(senderUsername, content.chatId);
      return { unsubscribed: content.chatId };
    }

    // Just a presence update - broadcast to subscribed chats
    const client = this.clients.get(senderUsername);
    if (client) {
      for (const chatId of client.chatIds) {
        this.broadcastToChat(chatId, {
          type: 'presence',
          chatId,
          senderId: senderUsername,
          content: { status: content.status || 'online' },
          timestamp: Date.now(),
        }, senderUsername);
      }
    }

    return { acknowledged: true };
  }

  /**
   * Get list of connected users in a chat
   */
  getConnectedUsers(chatId: string): string[] {
    const subscribers = this.chatSubscriptions.get(chatId);
    return subscribers ? Array.from(subscribers) : [];
  }

  /**
   * Get typing users in a chat
   */
  getTypingUsers(chatId: string): string[] {
    const chatTyping = this.typingIndicators.get(chatId);
    return chatTyping ? Array.from(chatTyping.keys()) : [];
  }

  /**
   * Get last read sequence for user in chat
   */
  getLastReadSequence(chatId: string, username: string): number {
    const chatReads = this.readReceipts.get(chatId);
    return chatReads?.get(username) || 0;
  }

  /**
   * Get connection stats
   */
  getStats() {
    return {
      connectedClients: this.clients.size,
      activeChats: this.chatSubscriptions.size,
      typingIndicators: this.typingIndicators.size,
    };
  }

  /**
   * Cleanup: close all connections
   */
  async closeAll() {
    for (const client of this.clients.values()) {
      try {
        client.ws.close();
      } catch (err) {
        // Ignore errors
      }
    }
    this.clients.clear();
    console.log('[WebSocket] All connections closed');
  }
}

// ==================== WebSocket Server Setup ====================

export async function setupWebSocket(fastify: FastifyInstance) {
  const wsManager = new WebSocketManager();

  // Register WebSocket plugin
  await fastify.register(fastifyWebsocket);

  /**
   * WebSocket endpoint: /ws
   * CRITICAL SECURITY: Requires JWT authentication
   * Query parameters:
   *   - username: Required, user's normalized username (must match JWT claim)
   *   - token: Required, JWT token for authentication
   *   - chatIds: Optional, comma-separated list of chat IDs to subscribe to
   *
   * Authentication flow:
   * 1. Client provides JWT token (from /register or /directory endpoint)
   * 2. Token is verified using JWT_SECRET
   * 3. Username from token must match query parameter username
   * 4. Only then is WebSocket connection allowed
   */
  fastify.get('/ws', { websocket: true }, (ws: WebSocket, req: any) => {
    const username = req.query.username as string;
    const token = req.query.token as string;
    const chatIdsParam = req.query.chatIds as string;

    // CRITICAL SECURITY: Username is required
    if (!username) {
      console.error('[WebSocket] ❌ CRITICAL: Connection attempt without username');
      ws.send(JSON.stringify({
        type: 'error',
        content: { error: 'username query parameter required' },
      }));
      ws.close(4001, 'Username required');
      return;
    }

    // CRITICAL SECURITY: JWT token is MANDATORY
    // WebSocket must authenticate like HTTP endpoints
    if (!token) {
      console.error(`[WebSocket] ❌ CRITICAL: WebSocket connection attempt without JWT token from ${username}`);
      console.error('[WebSocket]    WebSocket connections MUST authenticate with JWT token');
      console.error('[WebSocket]    This prevents unauthorized access and message interception');
      ws.send(JSON.stringify({
        type: 'error',
        content: { error: 'JWT token required for WebSocket authentication' },
      }));
      ws.close(4001, 'Authentication required');
      return;
    }

    // CRITICAL SECURITY: Verify JWT token
    try {
      // Use fastify's JWT verifier
      const decoded = fastify.jwt.verify(token) as any;

      // Validate token contains userId
      if (!decoded.userId) {
        console.error(`[WebSocket] ❌ CRITICAL: JWT token missing userId claim from ${username}`);
        ws.send(JSON.stringify({
          type: 'error',
          content: { error: 'Invalid JWT token: missing userId' },
        }));
        ws.close(4001, 'Invalid token');
        return;
      }

      // Validate username matches token claim (if token has username)
      if (decoded.username && decoded.username !== username) {
        console.error(`[WebSocket] ❌ CRITICAL: JWT token mismatch - token claims ${decoded.username} but request is for ${username}`);
        ws.send(JSON.stringify({
          type: 'error',
          content: { error: 'Username does not match JWT token' },
        }));
        ws.close(4001, 'Invalid token');
        return;
      }

      console.log(`[WebSocket] ✅ JWT authenticated: ${username} (userId: ${decoded.userId})`);
    } catch (err) {
      console.error(`[WebSocket] ❌ CRITICAL: JWT verification failed for ${username}:`, err instanceof Error ? err.message : String(err));
      ws.send(JSON.stringify({
        type: 'error',
        content: { error: 'JWT verification failed' },
      }));
      ws.close(4001, 'Authentication failed');
      return;
    }

    // Parse chat IDs
    const chatIds = chatIdsParam ? chatIdsParam.split(',') : [];

    // Register client (only after successful JWT authentication)
    wsManager.registerClient(username, ws, chatIds);

    // Handle incoming messages
    ws.on('message', (rawMessage: any) => {
      const result = wsManager.handleMessage(username, rawMessage.toString());

      // Send acknowledgment if needed
      if (result && result.error) {
        wsManager.sendToClient(username, {
          type: 'error',
          content: result,
          timestamp: Date.now(),
        });
      }
    });

    // Handle disconnection
    ws.on('close', () => {
      wsManager.unregisterClient(username);
    });

    // Handle errors
    ws.on('error', (err: any) => {
      console.error(`[WebSocket] Error for ${username}:`, err);
      wsManager.unregisterClient(username);
    });
  });

  /**
   * REST endpoint to get WebSocket stats
   */
  fastify.get('/ws/stats', async () => {
    return wsManager.getStats();
  });

  /**
   * REST endpoint to get connected users in a chat
   */
  fastify.get<{ Params: { chatId: string } }>('/ws/chat/:chatId/users', async (request) => {
    const { chatId } = request.params;
    return {
      chatId,
      connectedUsers: wsManager.getConnectedUsers(chatId),
      typing: wsManager.getTypingUsers(chatId),
    };
  });

  console.log('[WebSocket] ✅ WebSocket server initialized');
  console.log('[WebSocket] ✅ Endpoint: /ws (username query param required)');
  console.log('[WebSocket] ✅ Stats endpoint: GET /ws/stats');
  console.log('[WebSocket] ✅ Chat info endpoint: GET /ws/chat/:chatId/users');

  return wsManager;
}
