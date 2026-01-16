import { NextRequest, NextResponse } from 'next/server';
import { verifyRelayJwt, getSession, updateSessionIdentity } from '@/lib/relay/relay-jwt';

// In-memory directory (production: use database)
const identityDirectory = new Map<string, {
  userId: string;
  publicKeys: {
    identity: string;
    signedPreKey: string;
    kyberPreKey: string;
  };
  signature: string;
  registeredAt: Date;
  updatedAt: Date;
}>();

// Rate limiting for public reads
const rateLimiter = new Map<string, { count: number; resetAt: Date }>();
const RATE_LIMIT = 100; // requests per minute
const RATE_WINDOW = 60 * 1000;

function checkRateLimit(ip: string): boolean {
  const now = new Date();
  const entry = rateLimiter.get(ip);
  
  if (!entry || now > entry.resetAt) {
    rateLimiter.set(ip, { count: 1, resetAt: new Date(now.getTime() + RATE_WINDOW) });
    return true;
  }
  
  if (entry.count >= RATE_LIMIT) {
    return false;
  }
  
  entry.count++;
  return true;
}

// GET: Public read (rate-limited, no auth required for lookups)
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
      { error: 'NOT_FOUND', message: 'Identity not found' },
      { status: 404 }
    );
  }

  // Return only public keys, not internal metadata
  return NextResponse.json({
    username,
    publicKeys: identity.publicKeys,
    registeredAt: identity.registeredAt.toISOString(),
  });
}

// POST: Register new identity (Relay JWT required, userId must match)
export async function POST(
  request: NextRequest,
  { params }: { params: { username: string } }
) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'MISSING_AUTH_HEADER', message: 'Relay JWT required' },
        { status: 401 }
      );
    }

    const relayToken = authHeader.slice(7);
    const payload = await verifyRelayJwt(relayToken);

    if (!payload) {
      return NextResponse.json(
        { error: 'INVALID_RELAY_TOKEN', message: 'Relay token verification failed' },
        { status: 401 }
      );
    }

    const { username } = params;

    // CRITICAL: userId from JWT must match the username being registered
    // This prevents impersonation attacks
    if (payload.sub !== username) {
      console.error('[DIRECTORY] UserId mismatch:', payload.sub, '!==', username);
      return NextResponse.json(
        { error: 'FORBIDDEN', message: 'Cannot register identity for another user' },
        { status: 403 }
      );
    }

    // Check if identity already exists
    if (identityDirectory.has(username)) {
      return NextResponse.json(
        { error: 'ALREADY_EXISTS', message: 'Identity already registered' },
        { status: 409 }
      );
    }

    const body = await request.json();
    const { publicKeys, signature } = body;

    // Validate required fields
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

    // TODO: Verify signature over publicKeys using identity key
    // This ensures the client possesses the private key

    const now = new Date();
    identityDirectory.set(username, {
      userId: payload.sub,
      publicKeys,
      signature,
      registeredAt: now,
      updatedAt: now,
    });

    // Update session to mark identity as registered
    updateSessionIdentity(payload.sid, publicKeys.identity);

    console.log('[DIRECTORY] Identity registered:', username);

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

// PUT: Update existing identity (Relay JWT required, must own the identity)
export async function PUT(
  request: NextRequest,
  { params }: { params: { username: string } }
) {
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'MISSING_AUTH_HEADER', message: 'Relay JWT required' },
        { status: 401 }
      );
    }

    const relayToken = authHeader.slice(7);
    const payload = await verifyRelayJwt(relayToken);

    if (!payload) {
      return NextResponse.json(
        { error: 'INVALID_RELAY_TOKEN', message: 'Relay token verification failed' },
        { status: 401 }
      );
    }

    const { username } = params;
    const existing = identityDirectory.get(username);

    if (!existing) {
      return NextResponse.json(
        { error: 'NOT_FOUND', message: 'Identity not found' },
        { status: 404 }
      );
    }

    // CRITICAL: Can only update own identity
    if (existing.userId !== payload.sub) {
      console.error('[DIRECTORY] Unauthorized update attempt:', payload.sub, 'on', username);
      return NextResponse.json(
        { error: 'FORBIDDEN', message: 'Cannot update another user\'s identity' },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { publicKeys, signature } = body;

    // Update only allowed fields
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
