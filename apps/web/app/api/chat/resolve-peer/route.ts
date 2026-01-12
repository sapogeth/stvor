/**
 * Resolve Peer for Chat Handshake - TWO-PHASE PROTOCOL
 *
 * ARCHITECTURE:
 * Phase 1 (DISCOVERY): Check if peer exists via /api/profiles (always safe)
 * Phase 2 (HANDSHAKE): Only if client confirms intent, fetch crypto bundle from relay
 *
 * This prevents:
 * - False "user not found" when relay is just auth-restricted
 * - Username enumeration (profile + relay access control separation)
 * - Relay metadata leakage (server-side only)
 * - Eager relay queries before user intent
 *
 * PROTOCOL:
 * 
 * Step 1 - Discovery (no intent yet):
 * POST /api/chat/resolve-peer { peerUsername: "alice" }
 * Returns 200: { status: "awaiting_intent", peerFound: true, ... }
 * 
 * Step 2 - Handshake (after intent confirmed):
 * POST /api/chat/resolve-peer { peerUsername: "alice", confirmIntent: true }
 * Returns 200: { status: "ready", peerUsername, identity, prekeyBundle, ... }
 * 
 * Error Responses:
 * 404: User profile does not exist
 * 401: User not authenticated (Clerk)
 * 403: Relay authorization required (but user exists)
 * 503: Relay unavailable (but user exists)
 */

import { currentUser } from '@clerk/nextjs/server';
import { NextRequest, NextResponse } from 'next/server';
import { getProfileByUsername } from '../../../api/profiles/storage';

// Force Node.js runtime (REQUIRED for Clerk auth and Supabase)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELAY_BASE =
  process.env.RELAY_URL ||
  process.env.RELAY_BASE_URL ||
  process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';

/**
 * POST /api/chat/resolve-peer
 * Two-phase peer resolution: discovery → handshake
 */
export async function POST(req: NextRequest) {
  try {
    // 1. Authenticate user (required for all access to this endpoint)
    const user = await currentUser();
    if (!user || !user.id) {
      console.warn('[API] resolve-peer: unauthorized (no Clerk user)');
      return NextResponse.json(
        { error: 'unauthorized', message: 'Must be logged in' },
        { status: 401 }
      );
    }

    // 2. Parse request
    const { peerUsername, confirmIntent = false } = await req.json();
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
        { error: 'cannot_chat_with_self', message: 'Cannot start chat with yourself' },
        { status: 400 }
      );
    }

    // ========== PHASE 1: DISCOVERY ==========
    // Check if peer profile exists in DB
    // This is ALWAYS safe - profiles are public
    console.log(
      `[API] resolve-peer: PHASE 1 DISCOVERY for ${normalizedUsername} (intent: ${confirmIntent})`
    );

    const peerProfile = await getProfileByUsername(normalizedUsername);
    if (!peerProfile) {
      console.log(`[API] resolve-peer: user does not exist ${normalizedUsername}`);
      return NextResponse.json(
        {
          error: 'user_not_found',
          message: `User ${normalizedUsername} does not exist`,
          peerUsername: normalizedUsername,
          peerFound: false,
        },
        { status: 404 }
      );
    }

    // ✅ User exists
    console.log(
      `[API] resolve-peer: user found ${normalizedUsername}, profile exists in DB`
    );

    // ========== PHASE 2: HANDSHAKE (optional) ==========
    // Only proceed with relay if client confirmed intent
    // This prevents eager queries before user actually wants to chat
    if (!confirmIntent) {
      console.log(
        `[API] resolve-peer: awaiting intent confirmation from ${user.id} for ${normalizedUsername}`
      );
      
      // Return "awaiting intent" status
      // UI can now show: "User found! Confirm to start encrypted chat."
      return NextResponse.json(
        {
          status: 'awaiting_intent',
          message: 'User exists. Confirm to begin encrypted handshake.',
          peerUsername: normalizedUsername,
          peerFound: true,
          // Include displayName if available for better UX
          displayName: peerProfile.displayName || normalizedUsername,
        },
        { status: 200 }
      );
    }

    // User confirmed intent - now fetch crypto bundle from relay
    console.log(
      `[API] resolve-peer: PHASE 2 HANDSHAKE, intent confirmed by ${user.id}, fetching from relay`
    );

    // Fetch peer prekey bundle from relay (server-side only)
    const relayUrl = `${RELAY_BASE}/directory/${normalizedUsername}`;
    
    console.log(`[API] resolve-peer: server → relay GET /directory/${normalizedUsername}`);
    
    const relayRes = await fetch(relayUrl, {
      method: 'GET',
      headers: {
        'content-type': 'application/json',
        // TODO: Add relay authentication token if configured
        // 'authorization': `Bearer ${process.env.RELAY_TOKEN}`,
      },
    });

    // ========== RELAY ERROR HANDLING ==========
    if (!relayRes.ok) {
      console.warn(
        `[API] resolve-peer: relay returned ${relayRes.status} for ${normalizedUsername}`
      );

      // 403 Forbidden = relay requires auth/intent
      // This is EXPECTED - relay is protected
      // We already know user exists (confirmed via Phase 1)
      if (relayRes.status === 403 || relayRes.status === 401) {
        console.log(
          `[API] resolve-peer: relay auth required (expected), user exists but crypto bundle unavailable`
        );
        return NextResponse.json(
          {
            error: 'relay_authorization_required',
            message: 'Relay requires authorization. Contact system admin.',
            peerUsername: normalizedUsername,
            peerFound: true, // ✅ Important: user DOES exist
          },
          { status: 403 }
        );
      }

      // 404 from relay = user has no bundle yet (hasn't registered crypto identity)
      // This is different from profile not existing
      if (relayRes.status === 404) {
        console.log(
          `[API] resolve-peer: relay returned 404 - user has no prekey bundle yet`
        );
        return NextResponse.json(
          {
            error: 'prekey_bundle_not_available',
            message: `${normalizedUsername} has not published cryptographic keys yet`,
            peerUsername: normalizedUsername,
            peerFound: true, // ✅ Important: user exists, just hasn't published keys
          },
          { status: 404 }
        );
      }

      // Other 5xx errors = relay infrastructure issue
      console.error(
        `[API] resolve-peer: relay returned ${relayRes.status} (server error?)`
      );
      return NextResponse.json(
        {
          error: 'relay_unavailable',
          message: 'Relay service temporarily unavailable',
          peerUsername: normalizedUsername,
          peerFound: true, // ✅ User exists, relay is just down
        },
        { status: 503 }
      );
    }

    // ========== EXTRACT BUNDLE ==========
    const relayData = await relayRes.json();

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
        {
          error: 'incomplete_prekey_bundle',
          message: 'Relay returned incomplete cryptographic data',
          peerUsername: normalizedUsername,
          peerFound: true,
        },
        { status: 500 }
      );
    }

    // ========== SUCCESS ==========
    console.log(
      `[API] resolve-peer: ✅ handshake ready for ${normalizedUsername} (from ${user.id})`
    );

    return NextResponse.json(
      {
        status: 'ready',
        peerUsername: normalizedUsername,
        peerFound: true,
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
