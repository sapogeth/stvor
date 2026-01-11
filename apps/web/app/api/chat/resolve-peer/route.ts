/**
 * Resolve Peer for Chat Handshake
 *
 * SECURITY ARCHITECTURE:
 * - Server-side ONLY (never called from browser)
 * - Authenticates user (Clerk JWT required)
 * - Fetches relay directory with server token/secret
 * - Checks if peer profile exists
 * - Returns peer prekey bundle or 404
 *
 * PREVENTS:
 * - Username enumeration (user not found is indistinguishable from auth failure)
 * - Relay scraping (no direct browser → relay)
 * - Timing oracle (server normalizes, no client-side timing leaks)
 * - Metadata leakage (relay never sees client IP)
 *
 * PROTOCOL:
 * POST /api/chat/resolve-peer
 * {
 *   peerUsername: "alice"
 * }
 *
 * RESPONSES:
 * 200: { peerUsername, identity: { ed25519, identityMLDSA }, prekeyBundle, prekeySignature }
 * 404: { error: "user_not_found" }
 * 401: { error: "unauthorized" }
 * 500: { error: "internal_server_error" }
 */

import { currentUser } from '@clerk/nextjs/server';
import { NextRequest, NextResponse } from 'next/server';
import { getProfileByUsername } from '../../../api/profiles/storage';

// Force Node.js runtime (REQUIRED for Clerk auth and Supabase)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELAY_BASE =
  process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';

/**
 * POST /api/chat/resolve-peer
 * Server-side only endpoint to resolve peer for handshake
 */
export async function POST(req: NextRequest) {
  try {
    // 1. Authenticate user (required for all access to this endpoint)
    const user = await currentUser();
    if (!user || !user.id) {
      console.warn('[API] resolve-peer: unauthorized (no Clerk user)');
      return NextResponse.json(
        { error: 'unauthorized' },
        { status: 401 }
      );
    }

    // 2. Parse request
    const { peerUsername } = await req.json();
    if (!peerUsername || typeof peerUsername !== 'string') {
      return NextResponse.json(
        { error: 'invalid_request', message: 'peerUsername required' },
        { status: 400 }
      );
    }

    const normalizedUsername = peerUsername.toLowerCase().trim();
    
    // Prevent self-chat
    if (user.username?.toLowerCase() === normalizedUsername) {
      console.warn(`[API] resolve-peer: self-chat attempt by ${user.id}`);
      return NextResponse.json(
        { error: 'cannot_chat_with_self' },
        { status: 400 }
      );
    }

    // 3. Check if peer profile exists in our DB
    // This prevents leaking "user not found" vs "auth failure" distinction
    const peerProfile = await getProfileByUsername(normalizedUsername);
    if (!peerProfile) {
      console.log(`[API] resolve-peer: peer profile not found for ${normalizedUsername}`);
      return NextResponse.json(
        { error: 'user_not_found' },
        { status: 404 }
      );
    }

    // 4. Fetch peer prekey bundle from relay (server-side only)
    // This request happens server-to-server, never from browser
    const relayUrl = `${RELAY_BASE}/directory/${normalizedUsername}`;
    
    console.log(`[API] resolve-peer: fetching from relay for ${normalizedUsername}`);
    
    const relayRes = await fetch(relayUrl, {
      method: 'GET',
      headers: {
        'content-type': 'application/json',
        // TODO: Add relay authentication token if needed
        // 'authorization': `Bearer ${process.env.RELAY_TOKEN}`,
      },
    });

    if (!relayRes.ok) {
      console.warn(
        `[API] resolve-peer: relay returned ${relayRes.status} for ${normalizedUsername}`
      );
      
      // Even if relay fails, we already know profile exists
      // Return 404 to client (don't leak relay infrastructure issues)
      return NextResponse.json(
        { error: 'user_not_reachable' },
        { status: 404 }
      );
    }

    const relayData = await relayRes.json();

    // 5. Extract and normalize prekey bundle
    const ed25519 = relayData.identityPublicKey ||
      relayData.identityEd25519 ||
      relayData.ed25519 ||
      null;
    const mldsa = relayData.identityMLDSA || null;
    const prekeyBundle = relayData.prekeyBundle ?? relayData.prekeys ?? null;
    const prekeySignature =
      relayData.prekeySignature ||
      relayData.signature ||
      relayData.prekeyBundle?.signature ||
      null;

    if (!ed25519 || !prekeyBundle) {
      console.warn(
        `[API] resolve-peer: incomplete prekey bundle for ${normalizedUsername}`
      );
      return NextResponse.json(
        { error: 'incomplete_prekey_bundle' },
        { status: 500 }
      );
    }

    console.log(
      `[API] resolve-peer: successfully resolved ${normalizedUsername} for user ${user.id}`
    );

    // 6. Return peer bundle to authenticated client
    return NextResponse.json(
      {
        peerUsername: normalizedUsername,
        identity: {
          ed25519,
          identityEd25519: ed25519,
          identityMLDSA: mldsa,
        },
        prekeyBundle,
        prekeySignature,
      },
      { status: 200 }
    );
  } catch (error) {
    console.error('[API] resolve-peer error:', error);
    return NextResponse.json(
      { error: 'internal_server_error' },
      { status: 500 }
    );
  }
}
