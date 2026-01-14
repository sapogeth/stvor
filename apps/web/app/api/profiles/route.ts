/**
 * Profiles API - Username Management
 *
 * SECURITY ARCHITECTURE:
 * - Profiles store only public metadata (username, display name)
 * - Username is a human-readable handle (@username)
 * - Clerk userId is the canonical identity (never changes)
 * - Usernames can be changed, but userId cannot
 * - Server stores username → userId mapping
 * - Client uses usernames for UX, userId for crypto operations
 *
 * PRIVACY GUARANTEES:
 * - Profiles are public by design (for discoverability)
 * - Private keys NEVER stored in profiles
 * - E2E encryption keys remain client-side only
 * - Profile changes do not affect cryptographic identity
 */

import { currentUser } from '@clerk/nextjs/server';
import { NextRequest, NextResponse } from 'next/server';
import {
  getProfileByUsername,
  isUsernameTakenByOther,
  setProfile,
  deleteProfile,
} from './storage';

// CRITICAL: Node.js runtime (REQUIRED for Clerk SDK and Supabase)
// - Clerk server SDK requires Node.js to decode JWT from cookies
// - Edge runtime cannot access cookies or decode Clerk sessions
// - NO edge, NO force-static, NO preferredRegion
export const runtime = 'nodejs';

/**
 * GET /api/profiles?username=foo
 * Search for a profile by username
 * Falls back to relay directory if not found in local DB
 */
export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const username = searchParams.get('username');

    if (!username) {
      return NextResponse.json(
        { error: 'Missing username parameter' },
        { status: 400 }
      );
    }

    // Normalize username to lowercase
    const normalizedUsername = username.toLowerCase();

    const profile = await getProfileByUsername(normalizedUsername);

    if (!profile) {
      // FALLBACK: Check relay directory for users who have registered prekeys
      // This allows finding old users who haven't explicitly created a profile yet
      console.log(`[profiles] User ${normalizedUsername} not in local DB, checking relay directory...`);
      
      try {
        const relayUrl = process.env.NEXT_PUBLIC_RELAY_URL || process.env.RELAY_URL || 'http://localhost:3001';
        const directoryResponse = await fetch(`${relayUrl}/directory/${normalizedUsername}`, {
          headers: {
            // No authorization needed for directory lookups (public)
            'Accept': 'application/json',
          },
        });

        if (directoryResponse.ok) {
          const relayData = await directoryResponse.json();
          // User found in relay - create a minimal profile response
          console.log(`[profiles] User ${normalizedUsername} found in relay directory, returning minimal profile`);
          return NextResponse.json({
            username: normalizedUsername,
            userId: relayData.userId || normalizedUsername, // Fallback to username if no userId
            displayName: relayData.displayName || normalizedUsername,
            createdAt: relayData.createdAt || new Date().toISOString(),
            fromRelay: true, // Flag that this came from relay, not local DB
          });
        } else if (directoryResponse.status === 404) {
          // Not found anywhere
          console.log(`[profiles] User ${normalizedUsername} not found in relay or local DB`);
          return NextResponse.json(
            { error: 'Profile not found' },
            { status: 404 }
          );
        } else {
          // Relay error but user exists locally - should not reach here, but handle gracefully
          console.warn(`[profiles] Relay directory returned ${directoryResponse.status}, using local DB result`);
          return NextResponse.json(
            { error: 'Profile not found' },
            { status: 404 }
          );
        }
      } catch (relayErr) {
        console.warn(`[profiles] Failed to check relay directory:`, relayErr);
        // Fallback: return 404 if both local DB and relay fail
        return NextResponse.json(
          { error: 'Profile not found' },
          { status: 404 }
        );
      }
    }

    return NextResponse.json({
      username: normalizedUsername,
      userId: profile.userId,
      displayName: profile.displayName,
      createdAt: profile.createdAt,
    });
  } catch (error) {
    console.error('[API] profiles GET error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/profiles
 * Create or update profile for current user
 *
 * Body: { username: string, displayName?: string }
 */
export async function POST(req: NextRequest) {
  try {
    // App Router: use currentUser() (NOT auth() or getAuth())
    // This is the ONLY correct API for app/api/* routes
    const user = await currentUser();

    if (!user) {
      console.error('[API profiles POST] Unauthorized: no currentUser()');
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    console.log('[API profiles POST] Authenticated userId:', user.id);
    const userId = user.id;

    const body = await req.json();
    const { username, displayName } = body;

    if (!username || typeof username !== 'string') {
      return NextResponse.json(
        { error: 'Invalid username' },
        { status: 400 }
      );
    }

    // Validate username format: alphanumeric + underscore, 3-20 chars
    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
    if (!usernameRegex.test(username)) {
      return NextResponse.json(
        {
          error:
            'Invalid username format. Use 3-20 characters (letters, numbers, underscore).',
        },
        { status: 400 }
      );
    }

    // Normalize username to lowercase
    const normalizedUsername = username.toLowerCase();

    // Check if username is already taken by another user
    if (await isUsernameTakenByOther(normalizedUsername, userId)) {
      return NextResponse.json(
        { error: 'Username already taken' },
        { status: 409 }
      );
    }

    // Create/update profile
    const profile = await setProfile(normalizedUsername, userId, displayName);

    return NextResponse.json({
      username: normalizedUsername,
      userId: profile.userId,
      displayName: profile.displayName,
      createdAt: profile.createdAt,
    });
  } catch (error) {
    console.error('[API] profiles POST error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/profiles
 * Delete current user's profile
 */
export async function DELETE(req: NextRequest) {
  try {
    // App Router: use currentUser() (NOT auth() or getAuth())
    const user = await currentUser();

    if (!user) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const userId = user.id;

    if (!(await deleteProfile(userId))) {
      return NextResponse.json(
        { error: 'Profile not found' },
        { status: 404 }
      );
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('[API] profiles DELETE error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
