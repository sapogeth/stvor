import { NextRequest, NextResponse } from 'next/server';
import { auth, currentUser } from '@clerk/nextjs/server';
import { createRelaySession } from '@/lib/relay/relay-jwt-server';

/**
 * POST /api/relay/auth/exchange
 * 
 * Clerk JWT проверяется через Clerk middleware (httpOnly cookie).
 * Relay JWT выдаётся ТОЛЬКО после успешной Clerk auth.
 * 
 * Relay НИКОГДА не видит Clerk JWT напрямую.
 */
export async function POST(request: NextRequest) {
  try {
    // Clerk auth через middleware (cookie-based, secure)
    const { userId } = await auth();
    
    if (!userId) {
      console.error('[EXCHANGE] No Clerk userId');
      return NextResponse.json(
        { error: 'MISSING_AUTH', message: 'Clerk authentication required' },
        { status: 401 }
      );
    }

    // Получаем username из Clerk user
    const user = await currentUser();
    if (!user) {
      console.error('[EXCHANGE] No Clerk user');
      return NextResponse.json(
        { error: 'MISSING_AUTH', message: 'User not found' },
        { status: 401 }
      );
    }

    // username = Clerk username или первая часть email
    const username = user.username || 
                     user.emailAddresses[0]?.emailAddress?.split('@')[0] ||
                     userId;

    // Создаём relay session
    const { token: relayToken, session } = await createRelaySession(userId, username);

    console.log('[EXCHANGE] Success:', { 
      clerkUserId: userId, 
      username,
      sessionId: session.sessionId.slice(0, 8) + '...',
    });

    return NextResponse.json({
      relayToken,
      expiresAt: session.expiresAt.toISOString(),
      sessionId: session.sessionId,
      username,
    });
  } catch (error) {
    console.error('[EXCHANGE] Error:', error);
    return NextResponse.json(
      { error: 'INTERNAL_ERROR', message: 'Token exchange failed' },
      { status: 500 }
    );
  }
}
