/**
 * RELAY JWT VERIFICATION MIDDLEWARE - Web Backend Integration
 * 
 * CRITICAL: This verifies JWTs issued by Next.js backend at /api/relay/session,
 * NOT the old TOFU-based relay JWTs from auth.ts.
 * 
 * Flow:
 * 1. Client authenticates with Clerk (httpOnly cookie)
 * 2. Next.js /api/relay/session verifies Clerk auth and issues relay JWT
 * 3. Client sends: Authorization: Bearer <relay_jwt>
 * 4. Relay verifies JWT signature with RELAY_JWT_SECRET (shared secret)
 * 5. Relay extracts username from JWT payload
 * 6. Relay enforces authorization (e.g., chat membership)
 * 
 * Security:
 * - JWT signed with HS256 (HMAC-SHA256)
 * - Shared secret RELAY_JWT_SECRET between Next.js and relay
 * - Short TTL (24h)
 * - Audience validation: aud === 'ilyazh-relay'
 * - Issuer validation: iss === 'ilyazh-web'
 * 
 * @see apps/web/app/api/relay/session/route.ts (JWT issuance)
 * @see RELAY_AUTH_ROOT_CAUSE_ANALYSIS.md
 */

import type { FastifyRequest, FastifyReply } from 'fastify';
import jwt from 'jsonwebtoken';
import { getStorage, isStorageReady } from './index.js';

const RELAY_JWT_SECRET = process.env.RELAY_JWT_SECRET;

if (!RELAY_JWT_SECRET) {
  console.error(
    '[RelayJWTAuth] FATAL: RELAY_JWT_SECRET not configured. ' +
    'All authenticated requests will be rejected. ' +
    'Add RELAY_JWT_SECRET to .env (must match Next.js backend)'
  );
}

/**
 * JWT Payload from Next.js /api/relay/session
 */
export interface WebRelayJWTPayload {
  /** Canonical username (lowercase) */
  username: string;
  
  /** Clerk user ID */
  userId: string;
  
  /** Issuer (must be 'ilyazh-web') */
  iss: string;
  
  /** Audience (must be 'ilyazh-relay') */
  aud: string;
  
  /** Issued at (Unix timestamp seconds) */
  iat: number;
  
  /** Expires at (Unix timestamp seconds) */
  exp: number;
}

/**
 * Augment FastifyRequest with authenticated user
 * Note: Commented out to avoid conflict with @fastify/jwt types
 */
// declare module 'fastify' {
//   interface FastifyRequest {
//     user?: WebRelayJWTPayload;
//   }
// }

/**
 * Extract JWT from Authorization header
 * 
 * @param request - Fastify request object
 * @returns JWT token string or null
 */
export function extractWebJWT(request: FastifyRequest): string | null {
  const authHeader = request.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  
  return authHeader.slice(7); // Remove "Bearer " prefix
}

/**
 * Verify JWT issued by Next.js backend
 * 
 * @param token - JWT token string
 * @returns Decoded payload or throws error
 * @throws Error if token is invalid, expired, or has wrong audience/issuer
 */
export function verifyWebRelayJWT(token: string): WebRelayJWTPayload {
  if (!RELAY_JWT_SECRET) {
    throw new Error('RELAY_JWT_SECRET not configured');
  }
  
  try {
    const payload = jwt.verify(token, RELAY_JWT_SECRET, {
      algorithms: ['HS256'],
      audience: 'ilyazh-relay',
      issuer: 'ilyazh-web',
    }) as WebRelayJWTPayload;
    
    // Additional validation
    if (!payload.username || !payload.userId) {
      throw new Error('Invalid JWT payload: missing username or userId');
    }
    
    return payload;
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      throw new Error('JWT expired');
    }
    if (err instanceof jwt.JsonWebTokenError) {
      throw new Error(`JWT verification failed: ${err.message}`);
    }
    throw err;
  }
}

/**
 * Check if a Bearer token is a valid relay JWT (for CORS bypass)
 * Used in CORS hook to allow no-origin requests with valid JWT
 * 
 * @param bearerToken - Bearer token string (without "Bearer " prefix)
 * @returns true if token is a valid relay JWT, false otherwise
 */
export function isValidRelayJWT(bearerToken: string | undefined): boolean {
  if (!bearerToken || !RELAY_JWT_SECRET) {
    return false;
  }
  
  try {
    verifyWebRelayJWT(bearerToken);
    return true;
  } catch {
    return false;
  }
}

/**
 * Fastify preHandler hook: Authenticate request with web JWT
 * 
 * Usage:
 * ```typescript
 * fastify.post('/message/:chatId', {
 *   preHandler: requireWebAuth
 * }, async (request, reply) => {
 *   const username = request.user!.username; // Guaranteed to exist
 *   // ...
 * });
 * ```
 * 
 * @param request - Fastify request
 * @param reply - Fastify reply
 */
export async function requireWebAuth(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  console.log('[WebJWTAuth] 🔐 requireWebAuth called for:', request.url);
  console.log('[WebJWTAuth] Auth header present:', !!request.headers.authorization);
  console.log('[WebJWTAuth] RELAY_JWT_SECRET configured:', !!RELAY_JWT_SECRET);
  
  const token = extractWebJWT(request);
  
  if (!token) {
    console.error('[WebJWTAuth] ❌ No JWT token in Authorization header');
    console.error('[WebJWTAuth] Headers:', JSON.stringify(Object.keys(request.headers)));
    request.log.warn('[WebJWTAuth] No JWT token in Authorization header');
    reply.code(401).send({
      error: 'Unauthorized',
      message: 'Authorization header with Bearer token is required',
    });
    return;
  }
  
  console.log('[WebJWTAuth] JWT token extracted (first 20 chars):', token.substring(0, 20));
  
  try {
    const payload = verifyWebRelayJWT(token);
    
    // Attach authenticated user to request
    request.user = payload;
    
    console.log('[WebJWTAuth] ✅ Authenticated user:', payload.username, payload.userId);
  } catch (err) {
    console.error('[WebJWTAuth] ❌ JWT verification failed:', err instanceof Error ? err.message : 'Unknown error');
    console.error('[WebJWTAuth] Error stack:', err instanceof Error ? err.stack : 'No stack');
    console.error('[WebJWTAuth] Token (first 50 chars):', token.substring(0, 50));
    
    reply.code(401).send({
      error: 'Unauthorized',
      message: err instanceof Error ? err.message : 'JWT verification failed',
    });
    return; // CRITICAL: Stop execution after sending error
  }
}

/**
 * Optional authentication: Attach user if JWT present, but don't reject if missing
 * 
 * Usage for endpoints that support both authenticated and unauthenticated access:
 * ```typescript
 * fastify.get('/directory/:username', {
 *   preHandler: optionalWebAuth
 * }, async (request, reply) => {
 *   const username = request.user?.username; // May be undefined
 *   // ...
 * });
 * ```
 */
export async function optionalWebAuth(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const token = extractWebJWT(request);
  
  if (!token) {
    // No token provided - this is OK for optional auth
    return;
  }
  
  try {
    const payload = verifyWebRelayJWT(token);
    request.user = payload;
    
    console.log('[WebJWTAuth] Optional auth: User authenticated', payload.username);
  } catch (err) {
    // Invalid token - reject (if token is provided, it MUST be valid)
    console.warn('[WebJWTAuth] Optional auth: Invalid JWT:', err instanceof Error ? err.message : 'Unknown error');
    
    reply.code(401).send({
      error: 'Unauthorized',
      message: 'Invalid JWT token',
    });
    return; // CRITICAL: Stop execution after sending error
  }
}

/**
 * Check if authenticated user is a member of specified chat
 * 
 * @param request - Fastify request (must have request.user)
 * @param storage - Storage adapter
 * @param chatId - Chat ID to check membership
 * @returns true if user is a member, false otherwise
 */
export async function isParticipant(
  request: FastifyRequest,
  storage: any,
  chatId: string
): Promise<boolean> {
  if (!request.user) {
    return false;
  }
  
  const username = (request.user as any).username;
  
  try {
    // CRITICAL FIX: Use chatParticipants API, not chats.getChat()
    // storage.chats does not exist - only storage.chatParticipants
    if (!storage.chatParticipants) {
      console.error('[WebJWTAuth] CRITICAL: storage.chatParticipants not available');
      return false;
    }
    
    const isMember = await storage.chatParticipants.isParticipant(chatId, username);
    console.log(`[WebJWTAuth] Participant check: user=${username}, chatId=${chatId.slice(0,16)}..., isMember=${isMember}`);
    return isMember;
  } catch (err) {
    console.error('[WebJWTAuth] Error checking chat membership:', chatId, username, err);
    return false;
  }
}

/**
 * Detect if request body contains a handshake message
 * Handshake messages are special: they CREATE the chat, so participants aren't registered yet
 */
function isHandshakeMessage(body: any): boolean {
  // Method 1: Explicit type field
  if (body?.type === 'handshake') {
    return true;
  }
  
  // Method 2: Payload structure hint
  if (body?.payload?.kind === 'handshake') {
    return true;
  }
  
  // Method 3: Cipher metadata hint
  if (body?.cipher?.meta?.kind === 'handshake') {
    return true;
  }
  
  return false;
}

/**
 * Require authenticated user to be a participant of chat
 * 
 * CRITICAL EXCEPTION: Handshake messages are ALLOWED without participant check
 * because handshake messages CREATE the chat (participants registered in handler)
 * 
 * Usage:
 * ```typescript
 * fastify.post('/message/:chatId', {
 *   preHandler: [requireWebAuth, requireParticipant]
 * }, async (request, reply) => {
 *   // User is guaranteed to be authenticated and a participant
 * });
 * ```
 */
export async function requireParticipant(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const chatId = (request.params as { chatId: string }).chatId;
  
  if (!chatId) {
    reply.code(400).send({
      error: 'Bad Request',
      message: 'chatId parameter is required',
    });
    return;
  }
  
  if (!request.user) {
    // Should never happen if requireWebAuth ran first
    reply.code(401).send({
      error: 'Unauthorized',
      message: 'User not authenticated',
    });
    return;
  }
  
  // CRITICAL: Allow handshake messages WITHOUT participant check
  // Handshake messages establish the chat - participants are registered in handler
  const body = (request as any).body;
  if (isHandshakeMessage(body)) {
    console.log('[WebJWTAuth] ✅ Allowing handshake message (creates chat):', (request.user as any).username, chatId.slice(0, 16) + '...');
    return; // Allow handshake through
  }
  
  // Get storage from exported function (not fastify decoration)
  const storage = getStorage();
  
  if (!storage || !isStorageReady()) {
    request.log.error('[WebJWTAuth] Storage not available or not ready');
    reply.code(503).send({
      error: 'Service Unavailable',
      message: 'Storage not ready, please retry',
    });
    return;
  }
  
  const isMember = await isParticipant(request, storage, chatId);
  
  if (!isMember) {
    console.warn('[WebJWTAuth] User not a participant:', (request.user as any)?.username, chatId);
    
    reply.code(403).send({
      error: 'Forbidden',
      message: 'You are not a participant of this chat',
    });
  }
}
