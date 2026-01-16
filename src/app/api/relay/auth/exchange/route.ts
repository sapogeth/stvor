import { NextRequest, NextResponse } from 'next/server';
import { verifyClerkJwt } from '@/lib/relay/clerk-verify';
import { createRelaySession } from '@/lib/relay/relay-jwt';

export async function POST(request: NextRequest) {
  try {
    // Extract Clerk JWT from Authorization header
    const authHeader = request.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'MISSING_AUTH_HEADER', message: 'Authorization header required' },
        { status: 401 }
      );
    }

    const clerkToken = authHeader.slice(7);

    // Verify Clerk JWT
    const clerkPayload = await verifyClerkJwt(clerkToken);
    if (!clerkPayload) {
      return NextResponse.json(
        { error: 'INVALID_CLERK_TOKEN', message: 'Clerk token verification failed' },
        { status: 401 }
      );
    }

    // Create relay session and JWT
    const { token: relayToken, session } = await createRelaySession(clerkPayload.sub);

    console.log('[RELAY] Session created for user:', clerkPayload.sub, 'sessionId:', session.sessionId);

    return NextResponse.json({
      relayToken,
      expiresAt: session.expiresAt.toISOString(),
      sessionId: session.sessionId,
    });
  } catch (error) {
    console.error('[RELAY] Exchange error:', error);
    return NextResponse.json(
      { error: 'INTERNAL_ERROR', message: 'Token exchange failed' },
      { status: 500 }
    );
  }
}
