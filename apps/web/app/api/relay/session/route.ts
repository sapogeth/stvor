/**
 * POST /api/relay/session
 * 
 * Issues a relay-specific JWT after verifying Clerk authentication.
 * 
 * Flow:
 * 1. Verify user is authenticated with Clerk (httpOnly cookie)
 * 2. Extract username from Clerk user object
 * 3. Sign a relay JWT with RELAY_JWT_SECRET (shared with relay)
 * 4. Return JWT to client (stored in memory)
 * 
 * Security:
 * - Relay JWT is SHORT-LIVED (24h)
 * - Relay JWT is SIGNED with secret shared between Next.js and relay
 * - Relay can verify JWT without calling back to Clerk
 * - Client stores JWT in memory (NOT localStorage - XSS risk)
 * 
 * @see RELAY_AUTH_ROOT_CAUSE_ANALYSIS.md
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth, clerkClient } from '@clerk/nextjs/server';
import jwt from 'jsonwebtoken';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELAY_JWT_SECRET = process.env.RELAY_JWT_SECRET;

if (!RELAY_JWT_SECRET) {
  console.error(
    '[RelaySession] FATAL: RELAY_JWT_SECRET not configured. ' +
    'Relay authentication will fail. Add RELAY_JWT_SECRET to .env'
  );
}

export async function POST(req: NextRequest) {
  try {
    // 1. Verify Clerk authentication (from httpOnly cookie)
    const authResult = await auth();
    const userId = authResult?.userId;

    if (!userId) {
      console.warn('[RelaySession] No Clerk session found');
      return NextResponse.json(
        { error: 'Not authenticated', detail: 'No Clerk session found' },
        { status: 401 }
      );
    }

    // 2. Get user details from Clerk
    const clerk = await clerkClient();
    const user = await clerk.users.getUser(userId);
    
    // Extract username (prefer username, fallback to primary email)
    const username = user.username || user.primaryEmailAddress?.emailAddress;
    
    if (!username) {
      console.error('[RelaySession] User has no username or email', { userId });
      return NextResponse.json(
        { error: 'Invalid user', detail: 'No username or email address found' },
        { status: 400 }
      );
    }

    // Canonicalize username (lowercase, trim)
    const canonicalUsername = username.toLowerCase().trim();

    // 3. Sign relay JWT
    if (!RELAY_JWT_SECRET) {
      console.error('[RelaySession] Cannot sign JWT: RELAY_JWT_SECRET not configured');
      return NextResponse.json(
        { error: 'Server misconfiguration', detail: 'Relay JWT secret not configured' },
        { status: 500 }
      );
    }

    const payload = {
      username: canonicalUsername,
      userId,
      iss: 'ilyazh-web', // Issuer
      aud: 'ilyazh-relay', // Audience (relay server)
    };

    const relayJWT = jwt.sign(payload, RELAY_JWT_SECRET, {
      expiresIn: '24h', // Relay sessions expire after 24 hours
      algorithm: 'HS256', // HMAC with SHA-256
    });

    const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours from now

    console.log('[RelaySession] Issued relay JWT', {
      username: canonicalUsername,
      userId,
      expiresAt: new Date(expiresAt).toISOString(),
    });

    // 4. Return JWT to client
    return NextResponse.json({
      relayJWT,
      username: canonicalUsername,
      expiresAt,
    });
  } catch (error) {
    console.error('[RelaySession] Error issuing relay JWT:', error);
    return NextResponse.json(
      { error: 'Internal server error', detail: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}
