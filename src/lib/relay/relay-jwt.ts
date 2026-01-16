import { SignJWT, jwtVerify, JWTPayload } from 'jose';
import { randomBytes } from 'crypto';

// MUST be set in environment, minimum 32 bytes, Ed25519 or HMAC
const RELAY_JWT_SECRET = new TextEncoder().encode(
  process.env.RELAY_JWT_SECRET || (() => { throw new Error('RELAY_JWT_SECRET not set'); })()
);

const RELAY_JWT_ISSUER = 'stvor-relay';
const RELAY_JWT_AUDIENCE = 'stvor-client';
const RELAY_JWT_EXPIRY = '1h'; // Short-lived, client must refresh

export interface RelayJwtPayload extends JWTPayload {
  sub: string;          // userId from Clerk
  sid: string;          // relay session ID
  iat: number;
  exp: number;
}

export interface RelaySession {
  sessionId: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  identityRegistered: boolean;
  identityPublicKey?: string;
}

// In-memory session store (production: use Redis with TTL)
const sessionStore = new Map<string, RelaySession>();

export async function createRelaySession(userId: string): Promise<{ token: string; session: RelaySession }> {
  const sessionId = randomBytes(32).toString('hex');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 60 * 60 * 1000); // 1 hour

  const session: RelaySession = {
    sessionId,
    userId,
    createdAt: now,
    expiresAt,
    identityRegistered: false,
  };

  sessionStore.set(sessionId, session);

  const token = await new SignJWT({ sid: sessionId })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(userId)
    .setIssuer(RELAY_JWT_ISSUER)
    .setAudience(RELAY_JWT_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(RELAY_JWT_EXPIRY)
    .sign(RELAY_JWT_SECRET);

  return { token, session };
}

export async function verifyRelayJwt(token: string): Promise<RelayJwtPayload | null> {
  try {
    const { payload } = await jwtVerify(token, RELAY_JWT_SECRET, {
      issuer: RELAY_JWT_ISSUER,
      audience: RELAY_JWT_AUDIENCE,
    });

    const sessionId = payload.sid as string;
    const session = sessionStore.get(sessionId);

    if (!session) {
      console.error('[RELAY] Session not found:', sessionId);
      return null;
    }

    if (new Date() > session.expiresAt) {
      console.error('[RELAY] Session expired:', sessionId);
      sessionStore.delete(sessionId);
      return null;
    }

    if (session.userId !== payload.sub) {
      console.error('[RELAY] Session userId mismatch');
      return null;
    }

    return payload as RelayJwtPayload;
  } catch (error) {
    console.error('[RELAY] JWT verification failed:', error);
    return null;
  }
}

export function getSession(sessionId: string): RelaySession | null {
  const session = sessionStore.get(sessionId);
  if (!session) return null;
  if (new Date() > session.expiresAt) {
    sessionStore.delete(sessionId);
    return null;
  }
  return session;
}

export function updateSessionIdentity(sessionId: string, publicKey: string): boolean {
  const session = sessionStore.get(sessionId);
  if (!session) return false;
  session.identityRegistered = true;
  session.identityPublicKey = publicKey;
  return true;
}

export function invalidateSession(sessionId: string): void {
  sessionStore.delete(sessionId);
}

// Cleanup expired sessions periodically
setInterval(() => {
  const now = new Date();
  for (const [id, session] of sessionStore.entries()) {
    if (now > session.expiresAt) {
      sessionStore.delete(id);
    }
  }
}, 60 * 1000); // Every minute
