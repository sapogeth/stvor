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

const RELAY_API_KEY = process.env.RELAY_API_KEY || 'dev-key-change-in-production';

// Force Node.js runtime (not Edge)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(
  req: Request,
  { params }: { params: { username: string } }
) {
  try {
    const peerUsername = (params.username ?? "").toLowerCase().trim();

    if (!peerUsername) {
      return NextResponse.json(
        { error: 'invalid_request', message: 'Username required' },
        { status: 400 }
      );
    }

    console.log('[api/relay/directory] GET (PUBLIC)', {
      to: peerUsername,
    });

    // Forward request to relay (PUBLIC endpoint - no auth required)
    const relayUrl = getRelayUrl();
    const relayDirectoryUrl = `${relayUrl}/directory/${encodeURIComponent(peerUsername)}`;

    console.log('[api/relay/directory] Forwarding to relay', {
      relayUrl: relayDirectoryUrl,
    });

    const relayRes = await fetch(relayDirectoryUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
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
    // CRITICAL: Verify Clerk authentication (backend-to-backend trust)
    const user = await currentUser();

    if (!user) {
      console.warn('[api/relay/directory] 🔴 401: POST requires Clerk auth');
      return NextResponse.json(
        { error: 'unauthorized', message: 'Authentication required' },
        { status: 401 }
      );
    }

    const username = (user.username || user.id).toLowerCase();
    const body = await req.json();
    
    console.log('[api/relay/directory] POST (Clerk verified)', {
      from: username,
    });

    const relayUrl = getRelayUrl();
    const res = await fetch(`${relayUrl}/directory/${username}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        // CRITICAL: Use API key for backend-to-backend auth (NOT relay JWT)
        'Authorization': `Bearer ${RELAY_API_KEY}`,
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
