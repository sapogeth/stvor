import { NextRequest, NextResponse } from 'next/server';
import { verifyRelayJwt, getSession } from '@/lib/relay/relay-jwt-server';

export async function GET(request: NextRequest) {
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
        { error: 'INVALID_RELAY_TOKEN', message: 'Relay token invalid or expired' },
        { status: 401 }
      );
    }

    const session = getSession(payload.sid);
    if (!session) {
      return NextResponse.json(
        { error: 'SESSION_NOT_FOUND', message: 'Session expired' },
        { status: 401 }
      );
    }

    return NextResponse.json({
      clerkUserId: session.clerkUserId,
      username: session.username,
      sessionId: session.sessionId,
      identityRegistered: session.identityRegistered,
      expiresAt: session.expiresAt.toISOString(),
    });
  } catch (error) {
    console.error('[SESSION] Error:', error);
    return NextResponse.json(
      { error: 'INTERNAL_ERROR', message: 'Session check failed' },
      { status: 500 }
    );
  }
}
