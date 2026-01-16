import { SignJWT, jwtVerify } from 'jose';
import type { RelaySession, RelayJwtPayload } from './types';

const RELAY_JWT_SECRET = process.env.RELAY_JWT_SECRET
  ? new TextEncoder().encode(process.env.RELAY_JWT_SECRET)
  : null;

const RELAY_JWT_ISSUER = 'stvor-relay';
const RELAY_JWT_AUDIENCE = 'stvor-client';
const RELAY_JWT_EXPIRY = '1h';

const sessionStore = new Map<string, RelaySession>();

function generateSessionId(): string {
  const array = new Uint8Array(32);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(array);
  } else {
    for (let i = 0; i < array.length; i++) {
      array[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function createRelaySession(
  clerkUserId: string,
  username: string
): Promise<{ token: string; session: RelaySession }> {
  if (!RELAY_JWT_SECRET) {
    throw new Error('RELAY_JWT_SECRET not configured');
  }

  const sessionId = generateSessionId();
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

  const token = await new SignJWT({
    sid: sessionId,
    username: username,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(clerkUserId)
    .setIssuer(RELAY_JWT_ISSUER)
    .setAudience(RELAY_JWT_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(RELAY_JWT_EXPIRY)
    .sign(RELAY_JWT_SECRET);

  return { token, session };
}

export async function verifyRelayJwt(token: string): Promise<RelayJwtPayload | null> {
  if (!RELAY_JWT_SECRET) {
    return null;
  }

  try {
    const { payload } = await jwtVerify(token, RELAY_JWT_SECRET, {
      issuer: RELAY_JWT_ISSUER,
      audience: RELAY_JWT_AUDIENCE,
    });

    const sessionId = payload.sid as string;
    const session = sessionStore.get(sessionId);

    if (!session || new Date() > session.expiresAt) {
      if (session) sessionStore.delete(sessionId);
      return null;
    }

    if (session.clerkUserId !== payload.sub) {
      return null;
    }

    return {
      sub: payload.sub as string,
      sid: sessionId,
      username: payload.username as string,
      iat: payload.iat as number,
      exp: payload.exp as number,
    };
  } catch {
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
