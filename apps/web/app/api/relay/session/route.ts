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
import { auth, currentUser } from '@clerk/nextjs/server';
import jwt from 'jsonwebtoken';
import { getUsernameByUserId, setProfile } from '../../profiles/storage';

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

    // 2. Get username from profiles table (NOT from Clerk email!)
    // CRITICAL: The username in JWT MUST match the username used in chats
    // Chat participants are stored as usernames (e.g., 'edf', 'fde')
    // If we use email ('izhaisenbaev@gmail.com') the participant check will fail
    console.log('[RelaySession] Looking up username for userId:', userId);
    let username = await getUsernameByUserId(userId);
    
    if (!username) {
      // AUTO-CREATE PROFILE: If user has Clerk account but no profile,
      // create one automatically using Clerk username or email prefix
      console.log('[RelaySession] ⚠️ No profile found, attempting auto-creation...');
      
      const clerkUser = await currentUser();
      if (!clerkUser) {
        console.error('[RelaySession] ❌ Cannot get Clerk user for auto-profile creation');
        return NextResponse.json(
          { error: 'Profile not found', detail: 'Please complete profile setup first' },
          { status: 400 }
        );
      }
      
      // Derive username from Clerk data (priority: username > email prefix)
      let derivedUsername = clerkUser.username;
      if (!derivedUsername && clerkUser.emailAddresses?.[0]?.emailAddress) {
        derivedUsername = clerkUser.emailAddresses[0].emailAddress.split('@')[0];
      }
      
      if (!derivedUsername) {
        console.error('[RelaySession] ❌ Cannot derive username from Clerk data');
        return NextResponse.json(
          { error: 'Profile not found', detail: 'Please complete profile setup first' },
          { status: 400 }
        );
      }
      
      // Sanitize username (lowercase, alphanumeric + underscore only)
      derivedUsername = derivedUsername.toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20);
      
      if (derivedUsername.length < 3) {
        derivedUsername = `user_${userId.slice(-8)}`;
      }
      
      console.log('[RelaySession] Auto-creating profile:', { userId, derivedUsername });
      
      try {
        const displayName = clerkUser.firstName 
          ? `${clerkUser.firstName}${clerkUser.lastName ? ' ' + clerkUser.lastName : ''}`
          : derivedUsername;
        
        await setProfile(derivedUsername, userId, displayName);
        username = derivedUsername;
        console.log('[RelaySession] ✅ Profile auto-created successfully:', username);
      } catch (profileError) {
        console.error('[RelaySession] ❌ Failed to auto-create profile:', profileError);
        return NextResponse.json(
          { error: 'Profile creation failed', detail: 'Please try again or contact support' },
          { status: 500 }
        );
      }
    }

    // Canonicalize username (lowercase, trim)
    const canonicalUsername = username.toLowerCase().trim();

    console.log('[RelaySession] Resolved username from profiles', {
      userId,
      username: canonicalUsername,
    });

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
