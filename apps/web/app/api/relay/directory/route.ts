/**
 * GET /api/relay/directory/:username
 * 
 * Fetch peer's identity and prekey bundle
 * 
 * CRITICAL SECURITY: Requires valid intent first
 * This prevents directory enumeration and prekey scraping
 * 
 * Protocol:
 * 1. Client registers intent: POST /api/relay/intent
 * 2. Client fetches directory: GET /api/relay/directory/:username
 * 3. We check if intent exists and is valid
 * 4. We return peer's public keys
 */

import { NextResponse } from 'next/server';
import { currentUser } from '@clerk/nextjs/server';
import { getIntent } from '@/lib/intent-storage';
import { getRelayUrl } from '@/lib/relay-url';

// Force Node.js runtime (not Edge)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(
  req: Request,
  { params }: { params: { username: string } }
) {
  try {
    // Verify user is authenticated
    const user = await currentUser();

    if (!user) {
      console.warn('[api/relay/directory] 🔴 401: No authenticated user');
      return NextResponse.json(
        { error: 'unauthorized', message: 'Authentication required' },
        { status: 401 }
      );
    }

    const username = user.username || user.id;
    const peerUsername = (params.username ?? "").toLowerCase().trim();

    if (!peerUsername) {
      return NextResponse.json(
        { error: 'invalid_request', message: 'Username required' },
        { status: 400 }
      );
    }

    console.log('[api/relay/directory] GET', {
      from: username,
      to: peerUsername,
    });

    // CRITICAL: Check if intent is registered
    const intent = getIntent(username, peerUsername);

    if (!intent) {
      console.warn('[api/relay/directory] 🔴 403: No valid intent', {
        from: username,
        to: peerUsername,
      });
      return NextResponse.json(
        {
          error: 'intent_not_found',
          message: 'Must register intent first (POST /api/relay/intent)',
        },
        { status: 403 }
      );
    }

    console.log('[relay] 🔐 Intent verified ✅', {
      from: username,
      to: peerUsername,
    });

    // Forward request to relay to get peer's prekey bundle
    const relayUrl = getRelayUrl();
    const relayDirectoryUrl = `${relayUrl}/directory/${encodeURIComponent(peerUsername)}`;

    console.log('[api/relay/directory] Forwarding to relay', {
      relayUrl: relayDirectoryUrl,
      from: username,
    });

    const relayRes = await fetch(relayDirectoryUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        // Pass username to relay for logging
        'X-Relay-User': username,
      },
    });

    if (!relayRes.ok) {
      const errorText = await relayRes.text();
      console.warn('[api/relay/directory] Relay returned error', {
        status: relayRes.status,
        error: errorText,
      });

      // Return relay's error response
      return new Response(errorText, {
        status: relayRes.status,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const peerData = await relayRes.json();

    console.log('[api/relay/directory] ✅ Got peer data', {
      from: username,
      to: peerUsername,
      bundleId: peerData.prekey?.bundleId || 'dev',
    });

    return NextResponse.json(peerData);
  } catch (err) {
    console.error('[api/relay/directory] 🔴 500: Unexpected error', err);
    return NextResponse.json(
      {
        error: 'internal_error',
        message: err instanceof Error ? err.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const username = (body.username || body.user || '').toLowerCase();

    const relayUrl = getRelayUrl();
    const res = await fetch(`${relayUrl}/directory/${username}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    const text = await res.text();
    const data = (() => {
      try {
        return JSON.parse(text);
      } catch {
        return { error: 'INVALID_RESPONSE', detail: 'Relay returned non-JSON response' };
      }
    })();
    
    console.log(`[Proxy] Directory POST /${username} -> ${res.status}`);
    return NextResponse.json(data, { status: res.status });
  } catch (error) {
    console.error('[API] directory POST error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
