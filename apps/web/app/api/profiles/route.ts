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

// In-memory profile storage (replace with database in production)
// Structure: username -> { userId, displayName, createdAt }
const profiles = new Map<
  string,
  {
    userId: string;
    displayName: string;
    createdAt: string;
  }
>();

// Reverse index: userId -> username
const userIdToUsername = new Map<string, string>();

/**
 * GET /api/profiles?username=foo
 * Search for a profile by username
 */
export async function GET(req: NextRequest) {
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

  const profile = profiles.get(normalizedUsername);

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
}

/**
 * POST /api/profiles
 * Create or update profile for current user
 *
 * Body: { username: string, displayName?: string }
 */
export async function POST(req: NextRequest) {
  // Authenticate request
  const { userId } = await auth();

  if (!userId) {
    return NextResponse.json(
      { error: 'Unauthorized' },
      { status: 401 }
    );
  }

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
  const existingProfile = profiles.get(normalizedUsername);
  if (existingProfile && existingProfile.userId !== userId) {
    return NextResponse.json(
      { error: 'Username already taken' },
      { status: 409 }
    );
  }

  // Check if user already has a username and remove old mapping
  const oldUsername = userIdToUsername.get(userId);
  if (oldUsername && oldUsername !== normalizedUsername) {
    profiles.delete(oldUsername);
  }

  // Create/update profile
  const profile = {
    userId,
    displayName: displayName || username,
    createdAt: existingProfile?.createdAt || new Date().toISOString(),
  };

  profiles.set(normalizedUsername, profile);
  userIdToUsername.set(userId, normalizedUsername);

  return NextResponse.json({
    username: normalizedUsername,
    userId: profile.userId,
    displayName: profile.displayName,
    createdAt: profile.createdAt,
  });
}

/**
 * DELETE /api/profiles
 * Delete current user's profile
 */
export async function DELETE() {
  // Authenticate request
  const { userId } = await auth();

  if (!userId) {
    return NextResponse.json(
      { error: 'Unauthorized' },
      { status: 401 }
    );
  }

  const username = userIdToUsername.get(userId);

  if (!username) {
    return NextResponse.json(
      { error: 'Profile not found' },
      { status: 404 }
    );
  }

  profiles.delete(username);
  userIdToUsername.delete(userId);

  return NextResponse.json({ success: true });
}
