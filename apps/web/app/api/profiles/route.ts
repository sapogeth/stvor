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

import { auth } from '@clerk/nextjs/server';
import { NextRequest, NextResponse } from 'next/server';
import {
  getProfileByUsername,
  isUsernameTakenByOther,
  setProfile,
  deleteProfile,
} from './storage';

// Force Node.js runtime (required for Clerk SDK and Supabase)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * GET /api/profiles?username=foo
 * Search for a profile by username
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
      return NextResponse.json(
        { error: 'Profile not found' },
        { status: 404 }
      );
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
    // Clerk middleware initializes context; just call auth()
    const { userId } = auth();

    if (!userId) {
      console.error('[API profiles POST] Unauthorized: no userId in auth()');
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    console.log('[API profiles POST] Authenticated userId:', userId);

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
    // Clerk middleware initializes context
    const { userId } = auth();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

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
