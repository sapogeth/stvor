/**
 * Shared Profile Storage Module
 *
 * Hybrid storage: Primary backend is Supabase (persistent)
 * Fallback is in-memory storage for development without Supabase
 *
 * Structure: username -> { userId, displayName, createdAt }
 * Reverse index: userId -> username (in-memory cache for fast lookups)
 */

import { supabase } from '@/lib/supabase-server';

export interface Profile {
  userId: string;
  displayName: string;
  createdAt: string;
}

// In-memory fallback storage (used when Supabase is unavailable)
const fallbackProfiles = new Map<string, Profile>();
const fallbackUserIdToUsername = new Map<string, string>();

// In-memory cache for frequently accessed profiles
const profileCache = new Map<string, Profile>();
const userIdCache = new Map<string, string>();

/**
 * Get profile by username
 */
export async function getProfileByUsername(username: string): Promise<Profile | undefined> {
  const normalizedUsername = username.toLowerCase();

  // Check cache first
  if (profileCache.has(normalizedUsername)) {
    return profileCache.get(normalizedUsername);
  }

  // Try Supabase
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('*')
        .eq('username', normalizedUsername)
        .single();

      if (error?.code === 'PGRST116') {
        // Not found
        return undefined;
      }

      if (error) {
        console.warn('[DB] Error fetching profile:', error);
        // Fall back to memory storage
      } else if (data) {
        const profile: Profile = {
          userId: data.user_id,
          displayName: data.display_name || data.username,
          createdAt: data.created_at,
        };
        // Cache the result
        profileCache.set(normalizedUsername, profile);
        userIdCache.set(data.user_id, normalizedUsername);
        return profile;
      }
    } catch (err) {
      console.warn('[DB] Supabase query failed, falling back to memory:', err);
    }
  }

  // Fallback to in-memory storage
  return fallbackProfiles.get(normalizedUsername);
}

/**
 * Get username by userId
 * 
 * NOTE: This function includes retry logic because Supabase may have
 * replication delay after a profile is just created.
 */
export async function getUsernameByUserId(userId: string): Promise<string | undefined> {
  // Check cache first
  if (userIdCache.has(userId)) {
    console.log('[DB] getUsernameByUserId: cache hit for', userId);
    return userIdCache.get(userId);
  }

  // Try Supabase with retry logic
  if (supabase) {
    const maxRetries = 3;
    const retryDelayMs = 500;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        console.log(`[DB] getUsernameByUserId: querying Supabase (attempt ${attempt}/${maxRetries})`, { userId });
        
        const { data, error } = await supabase
          .from('profiles')
          .select('username')
          .eq('user_id', userId)
          .single();

        if (error?.code === 'PGRST116') {
          // Not found - might be replication delay, retry
          if (attempt < maxRetries) {
            console.log(`[DB] getUsernameByUserId: not found, retrying in ${retryDelayMs}ms...`);
            await new Promise(resolve => setTimeout(resolve, retryDelayMs));
            continue;
          }
          console.log('[DB] getUsernameByUserId: not found after all retries');
          return undefined;
        }

        if (error) {
          console.warn('[DB] Error fetching username:', error);
        } else if (data) {
          console.log('[DB] getUsernameByUserId: found username', data.username);
          userIdCache.set(userId, data.username);
          return data.username;
        }
      } catch (err) {
        console.warn('[DB] Supabase query failed:', err);
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, retryDelayMs));
          continue;
        }
      }
    }
  }

  // Fallback to in-memory storage
  const fallbackUsername = fallbackUserIdToUsername.get(userId);
  if (fallbackUsername) {
    console.log('[DB] getUsernameByUserId: found in fallback memory', fallbackUsername);
  }
  return fallbackUsername;
}

/**
 * Get profile by userId
 */
export async function getProfileByUserId(userId: string): Promise<{ username: string; profile: Profile } | undefined> {
  const username = await getUsernameByUserId(userId);
  if (!username) return undefined;

  const profile = await getProfileByUsername(username);
  if (!profile) return undefined;

  return { username, profile };
}

/**
 * Create or update profile
 */
export async function setProfile(
  username: string,
  userId: string,
  displayName?: string,
  createdAt?: string
): Promise<Profile> {
  const normalizedUsername = username.toLowerCase();
  const now = new Date().toISOString();
  const finalCreatedAt = createdAt || now;
  const finalDisplayName = displayName || username;

  const profile: Profile = {
    userId,
    displayName: finalDisplayName,
    createdAt: finalCreatedAt,
  };

  console.log('[DB] setProfile: saving profile', { username: normalizedUsername, userId, displayName: finalDisplayName });

  // Try Supabase first
  if (supabase) {
    try {
      const { data, error: upsertError } = await supabase
        .from('profiles')
        .upsert(
          {
            username: normalizedUsername,
            user_id: userId,
            display_name: finalDisplayName,
            created_at: finalCreatedAt,
            updated_at: now,
          },
          { onConflict: 'username' }
        )
        .select();

      if (upsertError) {
        console.error('[DB] ❌ Error upserting profile:', upsertError);
        // Fall through to fallback storage
      } else {
        // Success - update caches
        console.log('[DB] ✅ Profile saved to Supabase successfully', { data });
        profileCache.set(normalizedUsername, profile);
        userIdCache.set(userId, normalizedUsername);
        return profile;
      }
    } catch (err) {
      console.error('[DB] ❌ Supabase upsert failed, falling back to memory:', err);
    }
  } else {
    console.warn('[DB] ⚠️ Supabase client not initialized, using fallback memory storage');
  }

  // Fallback: use in-memory storage
  const oldUsername = fallbackUserIdToUsername.get(userId);
  if (oldUsername && oldUsername !== normalizedUsername) {
    fallbackProfiles.delete(oldUsername);
  }

  fallbackProfiles.set(normalizedUsername, profile);
  fallbackUserIdToUsername.set(userId, normalizedUsername);

  // Update caches
  profileCache.set(normalizedUsername, profile);
  userIdCache.set(userId, normalizedUsername);

  return profile;
}

/**
 * Delete profile by userId
 */
export async function deleteProfile(userId: string): Promise<boolean> {
  const username = await getUsernameByUserId(userId);
  if (!username) return false;

  const normalizedUsername = username.toLowerCase();

  // Try Supabase first
  if (supabase) {
    try {
      const { error } = await supabase
        .from('profiles')
        .delete()
        .eq('user_id', userId);

      if (error) {
        console.warn('[DB] Error deleting profile:', error);
        // Fall through to fallback storage
      } else {
        // Success - clear caches
        profileCache.delete(normalizedUsername);
        userIdCache.delete(userId);
        return true;
      }
    } catch (err) {
      console.warn('[DB] Supabase delete failed, falling back to memory:', err);
    }
  }

  // Fallback: use in-memory storage
  fallbackProfiles.delete(normalizedUsername);
  fallbackUserIdToUsername.delete(userId);

  // Clear caches
  profileCache.delete(normalizedUsername);
  userIdCache.delete(userId);

  return true;
}

/**
 * Check if username exists
 */
export async function usernameExists(username: string): Promise<boolean> {
  const profile = await getProfileByUsername(username);
  return profile !== undefined;
}

/**
 * Check if username is taken by another user
 */
export async function isUsernameTakenByOther(username: string, userId: string): Promise<boolean> {
  const profile = await getProfileByUsername(username);
  return profile !== undefined && profile.userId !== userId;
}

/**
 * Get all profiles (for debugging/admin purposes)
 */
export async function getAllProfiles(): Promise<{ username: string; profile: Profile }[]> {
  // Try Supabase first
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('*');

      if (error) {
        console.warn('[DB] Error fetching all profiles:', error);
      } else if (data) {
        return data.map((row: any) => ({
          username: row.username,
          profile: {
            userId: row.user_id,
            displayName: row.display_name || row.username,
            createdAt: row.created_at,
          },
        }));
      }
    } catch (err) {
      console.warn('[DB] Supabase query failed, falling back to memory:', err);
    }
  }

  // Fallback to in-memory storage
  return Array.from(fallbackProfiles.entries()).map(([username, profile]) => ({
    username,
    profile,
  }));
}
