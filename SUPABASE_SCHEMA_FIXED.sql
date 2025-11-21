-- ============================================================================
-- SUPABASE SCHEMA: Profiles & Identity (Production-Ready)
-- ============================================================================

-- Create profiles table with proper constraints and indexes
CREATE TABLE IF NOT EXISTS profiles (
  -- Primary key: normalized username (lowercase, unique)
  username TEXT PRIMARY KEY,

  -- Clerk user ID (immutable, required)
  user_id TEXT NOT NULL UNIQUE,

  -- Display name (mutable, optional)
  display_name TEXT,

  -- Timestamps (auto-managed)
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,

  -- Constraints
  CONSTRAINT username_not_empty CHECK (username != ''),
  CONSTRAINT username_lowercase CHECK (username = LOWER(username)),
  CONSTRAINT user_id_not_empty CHECK (user_id != '')
);

-- Create indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_profiles_created_at ON profiles(created_at);
CREATE INDEX IF NOT EXISTS idx_profiles_updated_at ON profiles(updated_at);

-- Create identities table for audit trail (optional but recommended)
CREATE TABLE IF NOT EXISTS identities (
  -- Primary key: username
  username TEXT PRIMARY KEY REFERENCES profiles(username) ON DELETE CASCADE,

  -- Ed25519 public key (hex-encoded)
  ed25519 TEXT NOT NULL,

  -- ML-DSA-65 public key (hex-encoded)
  mldsa TEXT NOT NULL,

  -- Relay's signature verification public key (hex-encoded)
  relay_public_key TEXT,

  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
  last_verified TIMESTAMP WITH TIME ZONE,

  -- Constraints
  CONSTRAINT ed25519_not_empty CHECK (ed25519 != ''),
  CONSTRAINT mldsa_not_empty CHECK (mldsa != '')
);

CREATE INDEX IF NOT EXISTS idx_identities_created_at ON identities(created_at);
CREATE INDEX IF NOT EXISTS idx_identities_last_verified ON identities(last_verified);

-- Create prekey_bundles table for Prekey rotation
CREATE TABLE IF NOT EXISTS prekey_bundles (
  -- Primary key: (username, bundle_id)
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT NOT NULL REFERENCES profiles(username) ON DELETE CASCADE,

  -- Prekey bundle data (JSON: { prekeys: [{id, key, signature}], signature })
  bundle_data JSONB NOT NULL,

  -- Usage tracking
  used_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
  last_used TIMESTAMP WITH TIME ZONE,

  -- Constraints
  CONSTRAINT bundle_data_not_null CHECK (bundle_data IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_prekey_bundles_username ON prekey_bundles(username);
CREATE INDEX IF NOT EXISTS idx_prekey_bundles_created_at ON prekey_bundles(created_at);

-- ============================================================================
-- FUNCTION: Upsert profile (atomic create or update)
-- ============================================================================

CREATE OR REPLACE FUNCTION upsert_profile(
  p_username TEXT,
  p_user_id TEXT,
  p_display_name TEXT DEFAULT NULL
) RETURNS TABLE(
  username TEXT,
  user_id TEXT,
  display_name TEXT,
  created_at TIMESTAMP WITH TIME ZONE,
  updated_at TIMESTAMP WITH TIME ZONE,
  is_new BOOLEAN
) AS $$
BEGIN
  RETURN QUERY
  INSERT INTO profiles (username, user_id, display_name)
  VALUES (LOWER(p_username), p_user_id, p_display_name)
  ON CONFLICT (username) DO UPDATE
  SET display_name = COALESCE(p_display_name, profiles.display_name),
      updated_at = CURRENT_TIMESTAMP
  RETURNING
    profiles.username,
    profiles.user_id,
    profiles.display_name,
    profiles.created_at,
    profiles.updated_at,
    (profiles.created_at = CURRENT_TIMESTAMP) AS is_new;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- FUNCTION: Get profile with audit info
-- ============================================================================

CREATE OR REPLACE FUNCTION get_profile_with_identity(p_username TEXT)
RETURNS TABLE(
  username TEXT,
  user_id TEXT,
  display_name TEXT,
  created_at TIMESTAMP WITH TIME ZONE,
  updated_at TIMESTAMP WITH TIME ZONE,
  ed25519 TEXT,
  mldsa TEXT,
  relay_public_key TEXT,
  identity_verified BOOLEAN
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    p.username,
    p.user_id,
    p.display_name,
    p.created_at,
    p.updated_at,
    COALESCE(i.ed25519, ''::TEXT),
    COALESCE(i.mldsa, ''::TEXT),
    COALESCE(i.relay_public_key, ''::TEXT),
    (i.last_verified IS NOT NULL) AS identity_verified
  FROM profiles p
  LEFT JOIN identities i ON p.username = i.username
  WHERE p.username = LOWER(p_username);
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- POLICIES: Row-Level Security (if using Supabase auth)
-- ============================================================================

-- Enable RLS on profiles table
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Allow authenticated users to read profiles
CREATE POLICY "Anyone can read profiles" ON profiles
  FOR SELECT
  USING (true);

-- Allow anyone to create/update/delete (Clerk handles auth in app)
CREATE POLICY "Anyone can create profiles" ON profiles
  FOR INSERT
  WITH CHECK (true);

CREATE POLICY "Anyone can update profiles" ON profiles
  FOR UPDATE
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Anyone can delete profiles" ON profiles
  FOR DELETE
  USING (true);

-- Enable RLS on identities table
ALTER TABLE identities ENABLE ROW LEVEL SECURITY;

-- Allow anyone to read identities
CREATE POLICY "Anyone can read identities" ON identities
  FOR SELECT
  USING (true);

-- Allow anyone to manage identities (Clerk auth in app)
CREATE POLICY "Anyone can manage identities" ON identities
  FOR ALL
  USING (true)
  WITH CHECK (true);

-- ============================================================================
-- METADATA
-- ============================================================================

-- Schema version
COMMENT ON TABLE profiles IS 'User profiles with Clerk integration';
COMMENT ON TABLE identities IS 'E2E identity keypairs (ed25519, ML-DSA-65)';
COMMENT ON COLUMN profiles.username IS 'Normalized lowercase username, primary key';
COMMENT ON COLUMN profiles.user_id IS 'Clerk user ID, must be unique';
COMMENT ON COLUMN identities.ed25519 IS 'Public identity key (hex-encoded)';
COMMENT ON COLUMN identities.mldsa IS 'Post-quantum identity key (hex-encoded)';
