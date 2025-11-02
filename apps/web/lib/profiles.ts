/**
 * Profile Management - Client-side helpers
 *
 * SECURITY ARCHITECTURE:
 * - Profiles are public metadata (usernames, display names)
 * - They map human-readable @usernames to Clerk userIds
 * - Crypto operations still use userId as canonical identifier
 * - Changing username does not affect E2E encryption keys
 */

export interface Profile {
  username: string;
  userId: string;
  displayName: string;
  createdAt: string;
}

/**
 * Search for a profile by username
 */
export async function getProfileByUsername(
  username: string
): Promise<Profile | null> {
  try {
    const response = await fetch(
      `/api/profiles?username=${encodeURIComponent(username)}`
    );

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to fetch profile');
    }

    return await response.json();
  } catch (err) {
    console.error('[profiles] Failed to get profile:', err);
    return null;
  }
}

/**
 * Create or update profile for current user
 */
export async function setProfile(
  username: string,
  displayName?: string
): Promise<Profile> {
  const response = await fetch('/api/profiles', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, displayName }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Failed to set profile');
  }

  return await response.json();
}

/**
 * Delete current user's profile
 */
export async function deleteProfile(): Promise<void> {
  const response = await fetch('/api/profiles', {
    method: 'DELETE',
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Failed to delete profile');
  }
}

/**
 * Check if a username is available
 */
export async function checkUsernameAvailable(
  username: string
): Promise<boolean> {
  const profile = await getProfileByUsername(username);
  return profile === null;
}
