/**
 * POST /api/relay/intent
 * 
 * Register intent to start encrypted chat with peer
 * This is PHASE 1.5 of the handshake protocol
 * 
 * CRITICAL: Uses currentUser() from Clerk (must be in route.ts)
 * This ensures the endpoint has access to session context
 * 
 * Protocol:
 * 1. Client calls: POST /api/relay/intent { peer, identityEd25519 }
 * 2. We verify user is authenticated with currentUser()
 * 3. We store intent in local storage
 * 4. Client can now fetch peer's prekey bundle (which checks intent)
 */

import { NextResponse } from 'next/server';
import { currentUser } from '@clerk/nextjs/server';
import { storeIntent } from '@/lib/intent-storage';

const RELAY_API_KEY = process.env.RELAY_API_KEY || 'dev-key-change-in-production';

export async function POST(req: Request) {
  try {
    // CRITICAL: Use currentUser() from Clerk (not auth())
    // This works only in route.ts, not in middleware
    const user = await currentUser();

    if (!user) {
      console.warn('[api/relay/intent] 🔴 401: No authenticated user');
      return NextResponse.json(
        { error: 'unauthorized', message: 'Authentication required' },
        { status: 401 }
      );
    }

    const username = user.username || user.id;
    console.log('[api/relay/intent] ✅ User authenticated:', { username, userId: user.id });

    // Parse request body
    let peer: string;
    let identityEd25519: string;

    try {
      const body = await req.json();
      peer = body.peer as string;
      identityEd25519 = body.identityEd25519 as string;
    } catch (err) {
      console.warn('[api/relay/intent] 🔴 400: Invalid JSON', err);
      return NextResponse.json(
        { error: 'invalid_request', message: 'Invalid request body' },
        { status: 400 }
      );
    }

    if (!peer || !identityEd25519) {
      console.warn('[api/relay/intent] 🔴 400: Missing required fields', {
        peer: !!peer,
        identityEd25519: !!identityEd25519,
      });
      return NextResponse.json(
        { error: 'invalid_request', message: 'Required: peer, identityEd25519' },
        { status: 400 }
      );
    }

    const peerCanonical = peer.toLowerCase().trim();

    // Prevent self-intent
    if (username.toLowerCase() === peerCanonical) {
      console.warn('[api/relay/intent] 🔴 400: Self-intent blocked');
      return NextResponse.json(
        { error: 'self_intent', message: 'Cannot start chat with yourself' },
        { status: 400 }
      );
    }

    // Store intent in local storage
    storeIntent(username, peerCanonical, identityEd25519);

    console.log('[relay] 🔐 Intent registered ✅', {
      from: username,
      to: peerCanonical,
      identityKeyPrefix: identityEd25519.substring(0, 16) + '...',
    });

    return NextResponse.json({
      ok: true,
      status: 'intent_registered',
      validFor: 3600, // seconds
      message: `Intent registered: ${username} can now access prekey for ${peerCanonical}`,
      expiresAt: Date.now() + 60 * 60 * 1000,
    });
  } catch (err) {
    console.error('[api/relay/intent] 🔴 500: Unexpected error', err);
    return NextResponse.json(
      {
        error: 'internal_error',
        message: err instanceof Error ? err.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}
