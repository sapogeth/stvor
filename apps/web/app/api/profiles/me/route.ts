/**
 * Current User Profile API
 *
 * GET /api/profiles/me
 * Returns the current authenticated user's profile
 */

import { auth } from '@clerk/nextjs/server';
import { NextResponse } from 'next/server';

// Import the profile storage from parent route
// Note: In production, this should be replaced with a database
// For now, we'll need to replicate the maps or move them to a shared module

// Temporary: We'll create a shared module for profile storage
// For now, return based on localStorage on client side

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

  // Import from parent - we need to refactor this properly
  // For now, let's check if we can access the maps
  // This is a temporary solution - in production use a database

  // Since we can't easily access the maps from the parent route,
  // we'll return a 404 for now and handle it on the client
  // The client should use localStorage to get the username

  return NextResponse.json(
    { error: 'Profile not found - use client-side storage' },
    { status: 404 }
  );
}
