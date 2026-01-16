import { SignJWT, jwtVerify } from 'jose';
import { randomBytes } from 'crypto';
import type { RelaySession, RelayJwtPayload } from './types';

const RELAY_JWT_SECRET = new TextEncoder().encode(
  process.env.RELAY_JWT_SECRET!
);

if (!process.env.RELAY_JWT_SECRET) {
  throw new Error('[FATAL] RELAY_JWT_SECRET not configured');
}

const RELAY_JWT_ISSUER = 'stvor-relay';
const RELAY_JWT_AUDIENCE = 'stvor-client';
const RELAY_JWT_EXPIRY = '1h';

// In-memory store (production: Redis/PostgreSQL)
const sessionStore = new Map<string, RelaySession>();

export async function createRelaySession(
  clerkUserId: string,
  username: string
): Promise<{ token: string; session: RelaySession }> {
  const sessionId = randomBytes(32).toString('hex');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 60 * 60 * 1000);

  const session: RelaySession = {
    sessionId,
    clerkUserId,
    username,
    createdAt: now,
    expiresAt,
    identityRegistered: false,
  };

  sessionStore.set(sessionId, session);

  // JWT содержит clerkUserId в sub, username отдельным claim
  const token = await new SignJWT({ 
    sid: sessionId,
    username: username,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(clerkUserId)  // sub = clerkUserId, НЕ username
    .setIssuer(RELAY_JWT_ISSUER)
    .setAudience(RELAY_JWT_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(RELAY_JWT_EXPIRY)
    .sign(RELAY_JWT_SECRET);

  console.log('[RELAY_JWT] Session created:', {
    sessionId: sessionId.slice(0, 8) + '...',
    clerkUserId,
    username,
  });

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
      console.error('[RELAY_JWT] Session not found:', sessionId?.slice(0, 8));
      return null;
    }

    if (new Date() > session.expiresAt) {
      console.error('[RELAY_JWT] Session expired:', sessionId.slice(0, 8));
      sessionStore.delete(sessionId);
      return null;
    }

    // Verify session userId matches token
    if (session.clerkUserId !== payload.sub) {
      console.error('[RELAY_JWT] Session userId mismatch');
      return null;
    }

    return {
      sub: payload.sub as string,
      sid: sessionId,
      username: payload.username as string,
      iat: payload.iat as number,
      exp: payload.exp as number,
    };
  } catch (error) {
    console.error('[RELAY_JWT] Verification failed:', error);
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

// Cleanup expired sessions
if (typeof setInterval !== 'undefined') {
  setInterval(() => {
    const now = new Date();
    for (const [id, session] of sessionStore.entries()) {
      if (now > session.expiresAt) {
        sessionStore.delete(id);
      }
    }
  }, 60 * 1000);
}
