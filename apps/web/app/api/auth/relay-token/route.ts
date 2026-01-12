import { NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { SignJWT } from 'jose';

// Issues a relay JWT signed with the shared secret so the Fastify relay
// accepts requests from this browser session.
export async function POST(request: Request) {
  try {
    const { userId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
    }

    const body = await request.json().catch(() => ({}));
    const username = typeof body?.username === 'string' ? body.username.toLowerCase().trim() : '';

    if (!username || !/^[a-z0-9_]{3,20}$/.test(username)) {
      return NextResponse.json({ error: 'invalid_username' }, { status: 400 });
    }

    const secret = process.env.RELAY_JWT_SECRET || process.env.JWT_SECRET;
    if (!secret) {
      console.error('[RelayToken] Missing RELAY_JWT_SECRET/JWT_SECRET env');
      return NextResponse.json({ error: 'server_misconfigured' }, { status: 500 });
    }

    const token = await new SignJWT({ sub: userId, username })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(new TextEncoder().encode(secret));

    return NextResponse.json({ token, expiresIn: 3600 });
  } catch (err) {
    console.error('[RelayToken] Failed to issue token', err);
    return NextResponse.json({ error: 'internal_error' }, { status: 500 });
  }
}
