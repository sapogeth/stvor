/**
 * Current User Profile API
 *
 * GET /api/profiles/me
 * Returns the current authenticated user's profile
 */

import { auth } from '@clerk/nextjs/server';
import { NextResponse } from 'next/server';
import { getProfileByUserId } from '../storage';

/**
 * GET /api/profiles/me
 * Get current user's profile
 */
export async function GET() {
  // Authenticate request
  const { userId } = await auth();

  if (!userId) {
    return NextResponse.json(
      { error: 'Unauthorized' },
      { status: 401 }
    );
  }

  // Get profile for current user
  const result = getProfileByUserId(userId);

  if (!result) {
    return NextResponse.json(
      { error: 'Profile not found' },
      { status: 404 }
    );
  }

  const { username, profile } = result;

  return NextResponse.json({
    username,
    userId: profile.userId,
    displayName: profile.displayName,
    createdAt: profile.createdAt,
  });
}
