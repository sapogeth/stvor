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
      `/api/profiles?username=${encodeURIComponent(username)}`,
      { credentials: 'include' }
    );

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || 'Failed to fetch profile');
    }

    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      console.error('[profiles] Invalid content-type:', contentType);
      throw new Error('Server returned non-JSON response');
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
  try {
    const response = await fetch('/api/profiles', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, displayName }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || 'Failed to set profile');
    }

    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      console.error('[profiles] Invalid content-type:', contentType);
      throw new Error('Server returned non-JSON response');
    }

    return await response.json();
  } catch (err) {
    throw err;
  }
}

/**
 * Delete current user's profile
 */
export async function deleteProfile(): Promise<void> {
  try {
    const response = await fetch('/api/profiles', {
      method: 'DELETE',
      credentials: 'include',
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || 'Failed to delete profile');
    }
  } catch (err) {
    throw err;
  }
}

/**
 * Check if a username is available
 */
export async function checkUsernameAvailable(
  username: string
): Promise<boolean> {
  try {
    const response = await fetch(
      `/api/profiles/check?username=${encodeURIComponent(username)}`,
      { credentials: 'include' }
    );

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || 'Failed to check username');
    }

    const data = await response.json();
    return Boolean(data.available);
  } catch (err) {
    console.error('[profiles] Failed to check username:', err);
    // Fail closed: treat as taken to avoid collisions
    return false;
  }
}

/**
 * Get current user's profile
 */
export async function getCurrentUserProfile(): Promise<Profile | null> {
  try {
    const response = await fetch('/api/profiles/me', {
      credentials: 'include',
    });

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || 'Failed to fetch current profile');
    }

    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      console.error('[profiles] Invalid content-type:', contentType);
      throw new Error('Server returned non-JSON response');
    }

    return await response.json();
  } catch (err) {
    console.error('[profiles] Failed to get current profile:', err);
    return null;
  }
}
