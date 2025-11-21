/**
 * Shared Profile Storage Module
 *
 * In-memory profile storage accessible from all profile routes.
 * In production, this should be replaced with a database (Supabase, PostgreSQL, etc.)
 *
 * Structure: username -> { userId, displayName, createdAt }
 * Reverse index: userId -> username
 */

export interface Profile {
  userId: string;
  displayName: string;
  createdAt: string;
}

// In-memory profile storage
const profiles = new Map<string, Profile>();

// Reverse index: userId -> username
const userIdToUsername = new Map<string, string>();

/**
 * Get profile by username
 */
export function getProfileByUsername(username: string): Profile | undefined {
  return profiles.get(username.toLowerCase());
}

/**
 * Get username by userId
 */
export function getUsernameByUserId(userId: string): string | undefined {
  return userIdToUsername.get(userId);
}

/**
 * Get profile by userId
 */
export function getProfileByUserId(userId: string): { username: string; profile: Profile } | undefined {
  const username = userIdToUsername.get(userId);
  if (!username) return undefined;

  const profile = profiles.get(username);
  if (!profile) return undefined;

  return { username, profile };
}

/**
 * Create or update profile
 */
export function setProfile(
  username: string,
  userId: string,
  displayName?: string,
  createdAt?: string
): Profile {
  const normalizedUsername = username.toLowerCase();

  // Get existing profile to preserve createdAt
  const existing = profiles.get(normalizedUsername);

  const profile: Profile = {
    userId,
    displayName: displayName || username,
    createdAt: createdAt || existing?.createdAt || new Date().toISOString(),
  };

  // Remove old username mapping if user is changing their username
  const oldUsername = userIdToUsername.get(userId);
  if (oldUsername && oldUsername !== normalizedUsername) {
    profiles.delete(oldUsername);
  }

  profiles.set(normalizedUsername, profile);
  userIdToUsername.set(userId, normalizedUsername);

  return profile;
}

/**
 * Delete profile by userId
 */
export function deleteProfile(userId: string): boolean {
  const username = userIdToUsername.get(userId);

  if (!username) return false;

  profiles.delete(username);
  userIdToUsername.delete(userId);

  return true;
}

/**
 * Check if username exists
 */
export function usernameExists(username: string): boolean {
  return profiles.has(username.toLowerCase());
}

/**
 * Check if username is taken by another user
 */
export function isUsernameTakenByOther(username: string, userId: string): boolean {
  const profile = profiles.get(username.toLowerCase());
  return profile !== undefined && profile.userId !== userId;
}

/**
 * Get all profiles (for debugging/admin purposes)
 */
export function getAllProfiles(): { username: string; profile: Profile }[] {
  return Array.from(profiles.entries()).map(([username, profile]) => ({
    username,
    profile,
  }));
}
