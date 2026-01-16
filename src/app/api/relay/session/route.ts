import { NextRequest, NextResponse } from 'next/server';
import { verifyRelayJwt, getSession } from '@/lib/relay/relay-jwt';

export async function GET(request: NextRequest) {
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

    const session = getSession(payload.sid);
    if (!session) {
      return NextResponse.json(
        { error: 'SESSION_NOT_FOUND', message: 'Session expired or invalid' },
        { status: 401 }
      );
    }

    return NextResponse.json({
      userId: session.userId,
      sessionId: session.sessionId,
      identityRegistered: session.identityRegistered,
      expiresAt: session.expiresAt.toISOString(),
    });
  } catch (error) {
    console.error('[RELAY] Session check error:', error);
    return NextResponse.json(
      { error: 'INTERNAL_ERROR', message: 'Session check failed' },
      { status: 500 }
    );
  }
}
