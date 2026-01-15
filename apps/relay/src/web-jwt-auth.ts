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
  const token = extractWebJWT(request);
  
  if (!token) {
    request.log.warn('[WebJWTAuth] No JWT token in Authorization header');
    reply.code(401).send({
      error: 'Unauthorized',
      message: 'Authorization header with Bearer token is required',
    });
    return;
  }
  
  try {
    const payload = verifyWebRelayJWT(token);
    
    // Attach authenticated user to request
    request.user = payload;
    
    console.log('[WebJWTAuth] Authenticated user', payload.username, payload.userId);
  } catch (err) {
    console.warn('[WebJWTAuth] JWT verification failed:', err instanceof Error ? err.message : 'Unknown error');
    
    reply.code(401).send({
      error: 'Unauthorized',
      message: err instanceof Error ? err.message : 'JWT verification failed',
    });
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
    const chat = await storage.chats.getChat(chatId);
    
    if (!chat) {
      return false;
    }
    
    return chat.participants.includes(username);
  } catch (err) {
    console.error('[WebJWTAuth] Error checking chat membership:', chatId, username, err);
    return false;
  }
}

/**
 * Require authenticated user to be a participant of chat
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
  
  // Get storage from request.server
  const storage = (request.server as any).storage;
  
  if (!storage) {
    request.log.error('[WebJWTAuth] Storage not available on server instance');
    reply.code(500).send({
      error: 'Internal Server Error',
      message: 'Storage not configured',
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
