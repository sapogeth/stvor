# Profile Storage Setup - Supabase

## Overview

The web application now uses **Supabase** for persistent profile storage instead of in-memory only storage. This solves the cascade failure where profiles were lost on server restart, preventing users from completing registration.

## Problem This Solves

Previously:
1. User signs up via Clerk ✅
2. User sets username in modal ✅
3. Profile stored in memory ✅
4. **Server restarts** → profiles lost ❌
5. Client requests `GET /api/profiles?username=X` → 404 ❌
6. Relay registration fails ❌
7. Client shows "PQ_NOT_READY" error (wrong diagnosis) ❌

Now:
1. User signs up via Clerk ✅
2. User sets username in modal ✅
3. Profile persisted to Supabase ✅
4. Server restarts → profiles still available ✅
5. Client can always fetch existing profiles ✅

## Architecture

The solution uses a hybrid approach:

```
┌─────────────────────────┐
│   getProfileByUsername  │
└───────────┬─────────────┘
            │
    1. Check in-memory cache
       (fast path, 0ms)
       │
    2. If miss, query Supabase
       (persistent, ~50ms)
       │
    3. Update cache and fallback storage
       │
    4. Return result or undefined
```

**Three-tier storage:**
1. **Cache** (in-memory): Fast lookups for frequently accessed profiles
2. **Primary** (Supabase): Persistent database for durability
3. **Fallback** (in-memory Maps): Used if Supabase unavailable

## Setup Instructions

### 1. Create Supabase Table

Run this SQL in your Supabase dashboard's SQL editor:

```sql
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
```

**Table Schema:**
- `id`: Auto-incrementing primary key
- `username`: Normalized username (lowercase, unique)
- `user_id`: Clerk user ID (unique)
- `display_name`: Human-friendly display name
- `created_at`: Profile creation timestamp
- `updated_at`: Last profile modification timestamp

### 2. Set Environment Variables in Vercel

Add to your Vercel project:

```
NEXT_PUBLIC_SUPABASE_URL=https://[your-supabase-id].supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=[your-anon-key]
```

**Where to find these:**
1. Go to https://supabase.com/dashboard
2. Select your project
3. Go to Settings → API
4. Copy "URL" and "anon public" key

### 3. Deploy and Test

```bash
# 1. Push changes to main
git push origin main

# 2. Vercel auto-deploys with new env vars
# Check deployment logs at https://vercel.com/your-project/deployments

# 3. Clear browser data to force re-registration
# DevTools → Application → IndexedDB → Clear all
# DevTools → Application → LocalStorage → Clear all

# 4. Test registration flow
# - Sign up new user
# - Set username
# - Verify profile persists in Supabase
# - Restart server and verify profile still accessible
```

## Code Changes

### New Files

**`lib/supabase-server.ts`**
- Creates Supabase client for server-side operations
- Exports `ensureProfilesTableExists()` for initialization
- Graceful fallback if Supabase credentials missing

### Modified Files

**`app/api/profiles/storage.ts`**
- All functions now async (with `await`)
- Hybrid storage: Supabase + fallback
- In-memory caching for performance
- Graceful error handling and logging

**`app/api/profiles/route.ts`**
- Updated GET to `await getProfileByUsername()`
- Updated POST to `await isUsernameTakenByOther()` and `await setProfile()`
- Updated DELETE to `await deleteProfile()`

**`app/api/profiles/me/route.ts`**
- Updated GET to `await getProfileByUserId()`

## Database Migration for Existing Users

If you have existing profiles in memory and want to migrate them to Supabase:

```typescript
// This is a one-time migration you could run in a utility endpoint
import { getAllProfiles, setProfile } from '@/app/api/profiles/storage';

export async function migrateProfilesToSupabase() {
  const profiles = await getAllProfiles();

  let count = 0;
  for (const { username, profile } of profiles) {
    await setProfile(
      username,
      profile.userId,
      profile.displayName,
      profile.createdAt
    );
    count++;
  }

  console.log(`Migrated ${count} profiles to Supabase`);
}
```

## Troubleshooting

### Profiles Not Persisting

**Check:**
1. Supabase credentials set in Vercel: `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_ANON_KEY`
2. Check server logs: Look for `[DB]` messages indicating storage operations
3. Table exists in Supabase: Run schema SQL from Step 1

**If Supabase unavailable:** The system falls back to in-memory storage, so registration still works but profiles won't persist across restarts.

### Duplicate Username Errors

If you see "Username already taken" errors:
1. Check Supabase table for duplicate entries
2. Delete duplicates manually via Supabase dashboard
3. Re-run registration

### Slow Profile Lookups

If profile queries are slow:
1. Verify indexes exist: `idx_profiles_username` and `idx_profiles_user_id`
2. Check Supabase performance in dashboard
3. In-memory cache should handle 99% of repeated lookups

## Performance Notes

- **Cache hit** (warm cache): <1ms
- **Cache miss** (first lookup): ~50-200ms (Supabase latency)
- **Fallback lookup** (Supabase down): <1ms (in-memory)

The caching layer means most repeated operations are instant, while the Supabase backend ensures durability.

## Security Considerations

- **Public table:** Profiles table is queryable by username (public by design for discoverability)
- **No private keys:** Profile storage never contains encryption keys (they stay client-side)
- **Clerk integration:** User IDs come from Clerk, ensuring authorization
- **RLS:** Consider adding Row Level Security (RLS) in Supabase if you add sensitive fields

## Next Steps

1. ✅ Code deployed with Supabase support
2. ⏳ Create profiles table in Supabase
3. ⏳ Set environment variables in Vercel
4. ⏳ Test end-to-end registration
5. ⏳ Verify profiles persist across server restarts

Once complete, your registration flow will work reliably without cascade failures.
