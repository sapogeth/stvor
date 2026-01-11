/**
 * POST /api/handshake/fetch-peer
 * 
 * SERVER-ONLY proxy to fetch peer's prekey bundle from relay
 * 
 * SECURITY ARCHITECTURE:
 * - Browser cannot access relay directly
 * - This endpoint uses RELAY_API_KEY from server env
 * - Only authenticated Clerk users can call this
 * - Relay never exposes API key to browser
 * 
 * This is the Signal/WhatsApp/Matrix model:
 * Client → WebServer (with API key) → Relay
 */

import { NextResponse } from 'next/server';
import { currentUser } from '@clerk/nextjs/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  try {
    // Step 1: Verify user is authenticated
    const user = await currentUser();

    if (!user) {
      console.warn('[api/handshake/fetch-peer] 🔴 401: No authenticated user');
      return NextResponse.json(
        { error: 'unauthorized', message: 'Authentication required' },
        { status: 401 }
      );
    }

    const username = user.username || user.id;
    console.log('[api/handshake/fetch-peer] User authenticated:', { username });

    // Step 2: Parse request body
    let peerUsername: string;

    try {
      const body = await req.json();
      peerUsername = (body.username || '').toLowerCase().trim();
    } catch (err) {
      console.warn('[api/handshake/fetch-peer] 🔴 400: Invalid JSON');
      return NextResponse.json(
        { error: 'invalid_request', message: 'Invalid request body' },
        { status: 400 }
      );
    }

    if (!peerUsername) {
      console.warn('[api/handshake/fetch-peer] 🔴 400: Missing username');
      return NextResponse.json(
        { error: 'invalid_request', message: 'Required: username' },
        { status: 400 }
      );
    }

    console.log('[api/handshake/fetch-peer] Fetching peer bundle', {
      from: username,
      to: peerUsername,
    });

    // Step 3: Call relay with SERVER API KEY (never exposed to browser)
    const relayUrl = process.env.RELAY_URL || 'http://localhost:3001';
    const apiKey = process.env.RELAY_API_KEY;

    if (!apiKey) {
      console.error('[api/handshake/fetch-peer] 🔴 500: RELAY_API_KEY not configured');
      return NextResponse.json(
        { error: 'internal_error', message: 'Relay API key not configured' },
        { status: 500 }
      );
    }

    const relayUrl2 = `${relayUrl}/directory/${encodeURIComponent(peerUsername)}`;

    console.log('[api/handshake/fetch-peer] Calling relay', {
      relayUrl: relayUrl2,
    });

    const relayRes = await fetch(relayUrl2, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Authorization': `Bearer ${apiKey}`, // 🔐 Server-only API key
        'X-Relay-User': username, // For logging on relay side
      },
    });

    // Step 4: Handle relay response
    if (!relayRes.ok) {
      const errorText = await relayRes.text();
      console.warn('[api/handshake/fetch-peer] Relay returned error', {
        status: relayRes.status,
        error: errorText,
      });

      return new Response(errorText, {
        status: relayRes.status,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Step 5: Return peer bundle to client
    const peerBundle = await relayRes.json();

    console.log('[api/handshake/fetch-peer] ✅ Got peer bundle', {
      from: username,
      to: peerUsername,
      bundleId: peerBundle.prekey?.bundleId || 'dev',
    });

    return NextResponse.json(peerBundle);
  } catch (err) {
    console.error('[api/handshake/fetch-peer] 🔴 500: Unexpected error', err);
    return NextResponse.json(
      {
        error: 'internal_error',
        message: err instanceof Error ? err.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}
