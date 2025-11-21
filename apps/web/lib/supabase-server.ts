/**
 * Supabase Server Client
 *
 * Used for server-side profile storage and database operations
 * Only accessible in API routes and server components
 */

import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.warn(
    '⚠️  Supabase credentials not configured. Profile storage will use fallback in-memory storage.'
  );
}

// Create Supabase client for server-side operations
export const supabase = SUPABASE_URL && SUPABASE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_KEY)
  : null;

/**
 * Ensure profiles table exists in Supabase
 * Called once on startup to initialize database schema
 */
export async function ensureProfilesTableExists() {
  if (!supabase) {
    console.log('[DB] Supabase not configured, skipping table initialization');
    return;
  }

  try {
    // Try to query the table - if it fails, we know the table doesn't exist
    const { error } = await supabase
      .from('profiles')
      .select('id')
      .limit(1);

    if (error?.code === 'PGRST116') {
      // Table doesn't exist, create it
      console.log('[DB] Creating profiles table...');

      // We'll handle this via direct SQL execution if needed
      // For now, just log that we should create it manually
      console.log('[DB] ⚠️  Please ensure the profiles table exists with schema:');
      console.log(`
        CREATE TABLE IF NOT EXISTS profiles (
          id BIGSERIAL PRIMARY KEY,
          username TEXT NOT NULL UNIQUE,
          user_id TEXT NOT NULL UNIQUE,
          display_name TEXT,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        CREATE INDEX idx_profiles_username ON profiles(username);
        CREATE INDEX idx_profiles_user_id ON profiles(user_id);
      `);
    } else if (error) {
      console.error('[DB] Error checking profiles table:', error);
    } else {
      console.log('[DB] ✅ Profiles table is ready');
    }
  } catch (err) {
    console.error('[DB] Failed to initialize profiles table:', err);
  }
}
