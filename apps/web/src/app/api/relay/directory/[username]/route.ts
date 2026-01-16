import { NextRequest, NextResponse } from 'next/server';
import { verifyRelayJwt, getSession, updateSessionIdentity } from '@/lib/relay/relay-jwt-server';
import type { DirectoryEntry } from '@/lib/relay/types';

// In-memory directory (production: database)
const identityDirectory = new Map<string, DirectoryEntry>();

// Rate limiting
const rateLimiter = new Map<string, { count: number; resetAt: Date }>();
const RATE_LIMIT = 100;
const RATE_WINDOW = 60 * 1000;

function checkRateLimit(ip: string): boolean {
  const now = new Date();
  const entry = rateLimiter.get(ip);
  
  if (!entry || now > entry.resetAt) {
    rateLimiter.set(ip, { count: 1, resetAt: new Date(now.getTime() + RATE_WINDOW) });
    return true;
  }
  
  if (entry.count >= RATE_LIMIT) return false;
  entry.count++;
  return true;
}

/**
 * GET: Public lookup (rate-limited)
 * Любой может найти public keys по username
 */
export async function GET(
  request: NextRequest,
  { params }: { params: { username: string } }
) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  
  if (!checkRateLimit(ip)) {
    return NextResponse.json(
      { error: 'RATE_LIMITED', message: 'Too many requests' },
      { status: 429 }
    );
  }

  const { username } = params;
  const identity = identityDirectory.get(username);

  if (!identity) {
    return NextResponse.json(
      { error: 'IDENTITY_NOT_FOUND', message: 'Identity not found' },
      { status: 404 }
    );
  }

  // Return ONLY public data
  return NextResponse.json({
    username,
    publicKeys: identity.publicKeys,
    registeredAt: identity.registeredAt.toISOString(),
  });
}

/**
 * POST: Register new identity
 * 
 * КРИТИЧНО: проверяем что payload.username === params.username
 * НЕ payload.sub === username (это было бы неверно)
 */
export async function POST(
  request: NextRequest,
  { params }: { params: { username: string } }
) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'MISSING_AUTH', message: 'Relay JWT required' },
        { status: 401 }
      );
    }

    const relayToken = authHeader.slice(7);
    const payload = await verifyRelayJwt(relayToken);

    if (!payload) {
      return NextResponse.json(
        { error: 'INVALID_RELAY_TOKEN', message: 'Relay token invalid' },
        { status: 401 }
      );
    }

    const { username } = params;

    // КРИТИЧНО: username из JWT должен совпадать с запрашиваемым username
    // payload.sub = clerkUserId (user_xxx)
    // payload.username = username (rabbit)
    if (payload.username !== username) {
      console.error('[DIRECTORY] Username mismatch:', {
        jwtUsername: payload.username,
        requestedUsername: username,
        clerkUserId: payload.sub,
      });
      return NextResponse.json(
        { error: 'FORBIDDEN', message: 'Cannot register identity for another user' },
        { status: 403 }
      );
    }

    // Check if identity already exists
    const existing = identityDirectory.get(username);
    if (existing) {
      // Allow re-registration only by same owner
      if (existing.clerkUserId !== payload.sub) {
        console.error('[DIRECTORY] Username taken by another user');
        return NextResponse.json(
          { error: 'USERNAME_TAKEN', message: 'Username already registered' },
          { status: 409 }
        );
      }
      // Same user re-registering - allow (key rotation)
      console.log('[DIRECTORY] Re-registration by owner:', username);
    }

    const body = await request.json();
    const { publicKeys, signature } = body;

    if (!publicKeys?.identity || !publicKeys?.signedPreKey || !publicKeys?.kyberPreKey) {
      return NextResponse.json(
        { error: 'INVALID_BODY', message: 'Missing required public keys' },
        { status: 400 }
      );
    }

    if (!signature) {
      return NextResponse.json(
        { error: 'INVALID_BODY', message: 'Missing signature' },
        { status: 400 }
      );
    }

    const now = new Date();
    identityDirectory.set(username, {
      username,
      clerkUserId: payload.sub,  // OWNER = clerkUserId
      publicKeys,
      signature,
      registeredAt: existing?.registeredAt || now,
      updatedAt: now,
    });

    // Update session
    updateSessionIdentity(payload.sid, publicKeys.identity);

    console.log('[DIRECTORY] Identity registered:', {
      username,
      clerkUserId: payload.sub,
    });

    return NextResponse.json({
      success: true,
      username,
      registeredAt: now.toISOString(),
    });
  } catch (error) {
    console.error('[DIRECTORY] Registration error:', error);
    return NextResponse.json(
      { error: 'INTERNAL_ERROR', message: 'Registration failed' },
      { status: 500 }
    );
  }
}

/**
 * PUT: Update existing identity (key rotation)
 */
export async function PUT(
  request: NextRequest,
  { params }: { params: { username: string } }
) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'MISSING_AUTH', message: 'Relay JWT required' },
        { status: 401 }
      );
    }

    const relayToken = authHeader.slice(7);
    const payload = await verifyRelayJwt(relayToken);

    if (!payload) {
      return NextResponse.json(
        { error: 'INVALID_RELAY_TOKEN', message: 'Relay token invalid' },
        { status: 401 }
      );
    }

    const { username } = params;
    const existing = identityDirectory.get(username);

    if (!existing) {
      return NextResponse.json(
        { error: 'IDENTITY_NOT_FOUND', message: 'Identity not found' },
        { status: 404 }
      );
    }

    // КРИТИЧНО: проверяем ownership по clerkUserId
    if (existing.clerkUserId !== payload.sub) {
      console.error('[DIRECTORY] Unauthorized update:', {
        existingOwner: existing.clerkUserId,
        requestor: payload.sub,
      });
      return NextResponse.json(
        { error: 'FORBIDDEN', message: 'Cannot update another user\'s identity' },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { publicKeys, signature } = body;

    if (publicKeys?.signedPreKey) {
      existing.publicKeys.signedPreKey = publicKeys.signedPreKey;
    }
    if (publicKeys?.kyberPreKey) {
      existing.publicKeys.kyberPreKey = publicKeys.kyberPreKey;
    }
    if (signature) {
      existing.signature = signature;
    }
    existing.updatedAt = new Date();

    console.log('[DIRECTORY] Identity updated:', username);

    return NextResponse.json({
      success: true,
      username,
      updatedAt: existing.updatedAt.toISOString(),
    });
  } catch (error) {
    console.error('[DIRECTORY] Update error:', error);
    return NextResponse.json(
      { error: 'INTERNAL_ERROR', message: 'Update failed' },
      { status: 500 }
    );
  }
}
