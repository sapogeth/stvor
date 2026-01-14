/**
 * RELAY AUTHENTICATION & ACCESS CONTROL
 * 
 * THREAT MODEL:
 * - T1: Attacker impersonates user by forging username
 * - T2: Attacker replays old messages
 * - T3: Attacker floods relay with junk messages
 * - T4: Metadata leakage (who talks to whom)
 * - T5: Relay compromise (zero-knowledge requirement)
 * 
 * SECURITY DESIGN:
 * 1. TOFU (Trust On First Use): First contact establishes identity binding
 * 2. JWT-based session authentication (short-lived, 15min)
 * 3. Public key binding (Ed25519 + ML-DSA-65)
 * 4. Rate limiting per IP and per user
 * 5. Replay protection via sequence numbers
 * 
 * ENFORCEMENT POINTS:
 * - /register: TOFU binding (username → identity keys)
 * - /sync/:chatId: JWT + participant membership check
 * - /message/:chatId: JWT + sender verification + rate limit
 * 
 * @see ARCHITECTURAL_ASSUMPTIONS.md for relay trust assumptions
 */

import type { FastifyRequest, FastifyReply } from 'fastify';
import type { IStorageAdapter } from '../storage/interfaces';

/**
 * JWT Payload Structure (signed by relay)
 */
export interface RelayJWTPayload {
  /** Username (canonical lowercase form) */
  sub: string;
  username: string;
  
  /** Ed25519 public key (hex) - TOFU-bound */
  identityEd25519: string;
  
  /** ML-DSA-65 public key (hex) - TOFU-bound */
  identityMLDSA: string;
  
  /** Issued at (Unix timestamp seconds) */
  iat: number;
  
  /** Expires at (Unix timestamp seconds) */
  exp: number;
  
  /** Session ID (for revocation tracking) */
  jti: string;
}

/**
 * Verify JWT and return authenticated user identity.
 * Throws on invalid/expired tokens.
 */
export async function verifyJWT(
  fastify: any,
  token: string
): Promise<RelayJWTPayload> {
  try {
    const decoded = await fastify.jwt.verify(token);
    return decoded as RelayJWTPayload;
  } catch (err) {
    throw new Error(`JWT verification failed: ${(err as Error).message}`);
  }
}

/**
 * Extract JWT from Authorization header or X-Relay-Token header.
 */
export function extractJWT(request: FastifyRequest): string | null {
  // Try Authorization: Bearer <token>
  const authHeader = request.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }
  
  // Try X-Relay-Token header (mobile apps)
  const relayToken = request.headers['x-relay-token'] as string | undefined;
  if (relayToken) {
    return relayToken;
  }
  
  return null;
}

/**
 * TOFU Enforcement: Verify public keys match first-use binding.
 * Prevents identity key substitution attacks.
 */
export async function enforceTOFU(
  storage: IStorageAdapter,
  username: string,
  identityEd25519: string,
  identityMLDSA: string
): Promise<{ bound: boolean; error?: string }> {
  const user = await storage.users.getUserByUsername(username);
  
  if (!user) {
    // First-time user - TOFU binding not yet established
    return { bound: false };
  }
  
  // Verify keys match stored binding
  if (user.identityEd25519 !== identityEd25519) {
    return {
      bound: false,
      error: `Ed25519 key mismatch (TOFU violation). Expected ${user.identityEd25519}, got ${identityEd25519}`,
    };
  }
  
  if (user.identityMLDSA !== identityMLDSA) {
    return {
      bound: false,
      error: `ML-DSA-65 key mismatch (TOFU violation). Expected ${user.identityMLDSA}, got ${identityMLDSA}`,
    };
  }
  
  return { bound: true };
}

/**
 * Replay Protection: Check message sequence number.
 * Each chat maintains a monotonic sequence counter.
 */
export async function checkReplayAttack(
  storage: IStorageAdapter,
  chatId: string,
  claimedSequence: number
): Promise<{ valid: boolean; reason?: string }> {
  // Fetch last known sequence for this chat
  const lastSequence = await storage.messages.getLastSequence(chatId);
  
  if (claimedSequence <= lastSequence) {
    return {
      valid: false,
      reason: `Replay detected: sequence ${claimedSequence} <= last known ${lastSequence}`,
    };
  }
  
  // Allow small gaps (1-10) for concurrent sends, reject large gaps
  if (claimedSequence > lastSequence + 10) {
    return {
      valid: false,
      reason: `Sequence gap too large: ${claimedSequence} vs expected ${lastSequence + 1}`,
    };
  }
  
  return { valid: true };
}

/**
 * Rate Limiting: Per-IP and per-user limits.
 * Returns false if limit exceeded (reply already sent).
 */
export async function enforceRateLimit(
  request: FastifyRequest,
  reply: FastifyReply,
  key: string,
  maxRequests: number,
  windowMs: number
): Promise<boolean> {
  // Simple in-memory rate limiter (production: use Redis)
  const now = Date.now();
  const rateLimitKey = `ratelimit:${key}`;
  
  // Check rate limit (stub implementation - replace with Redis)
  // For now, always allow (real implementation in existing rateLimit function)
  return true;
}

/**
 * Security Event Logging for audit trail.
 */
export interface SecurityEvent {
  type: 'TOFU_VIOLATION' | 'REPLAY_ATTACK' | 'RATE_LIMIT_EXCEEDED' | 
        'AUTH_FAILED' | 'UNAUTHORIZED_ACCESS' | 'SUSPICIOUS_ACTIVITY';
  timestamp: number;
  username?: string;
  ip: string;
  details: Record<string, any>;
}

const SECURITY_EVENT_LOG: SecurityEvent[] = [];

export function logSecurityEvent(
  type: SecurityEvent['type'],
  details: Omit<SecurityEvent, 'type' | 'timestamp'>
): void {
  const event: SecurityEvent = {
    type,
    timestamp: Date.now(),
    ...details,
  };
  
  SECURITY_EVENT_LOG.push(event);
  
  // Production: send to SIEM or dedicated security logging service
  console.error(`[SECURITY] ${type}:`, JSON.stringify(event));
}

/**
 * Metadata Protection: Minimize logged PII.
 * Only log hashed identifiers in production.
 */
export function hashForLogging(value: string): string {
  // Stub: Use SHA256 in production
  return value.substring(0, 8) + '...';
}
