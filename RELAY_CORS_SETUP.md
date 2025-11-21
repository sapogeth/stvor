# Relay CORS Configuration for Production

## Problem Fixed

The relay server was rejecting requests from the production web domains:
```
[CORS] ❌ BLOCKED origin: https://www.stvor.xyz
```

This prevented identity verification and caused:
- "identity verification failed" errors
- PQ_NOT_READY fallback errors (wrong diagnosis)
- Complete registration flow failures

## Solution

The relay's CORS configuration now includes production domains.

## How to Deploy to Railway

### Option 1: Set via Railway Dashboard (Recommended)

1. Go to https://railway.app/project/ilyazhrelay-production
2. Select the environment (e.g., `production`)
3. Go to **Variables**
4. Add or update the `ALLOWED_ORIGINS` variable:

```
https://stvor.xyz,https://www.stvor.xyz,https://clerk.stvor.xyz,http://localhost:3000,http://localhost:3002,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3002
```

**Important:** No spaces after commas. One line only.

5. Click **Deploy** to restart with new environment variable

### Option 2: Set via .env (Local Development)

The local `.env` file already has the production domains configured:

```bash
ALLOWED_ORIGINS=https://stvor.xyz,https://www.stvor.xyz,https://clerk.stvor.xyz,http://localhost:3000,http://localhost:3002,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3002
```

For development, you can simplify to just localhost if needed.

## Verification

After deploying to Railway, check the logs for:

```
[Startup] 🔐 CORS: Allowed origins: https://stvor.xyz, https://www.stvor.xyz, https://clerk.stvor.xyz, ...
```

This confirms CORS is configured correctly.

If you see:
```
[CORS] ❌ BLOCKED origin: https://www.stvor.xyz
```

Then `ALLOWED_ORIGINS` was not properly set in Railway environment.

## Domains to Allow

For production `https://stvor.xyz`, the relay must allow:

| Domain | Purpose |
|--------|---------|
| `https://stvor.xyz` | Web app main domain |
| `https://www.stvor.xyz` | Web app www subdomain |
| `https://clerk.stvor.xyz` | Clerk authentication custom domain |
| `http://localhost:3000` | Local development (web) |
| `http://localhost:3002` | Local development (web alternate) |
| `http://localhost:3001` | Local development (relay) |
| `http://127.0.0.1:*` | Local loopback addresses |

## Code Changes

**File:** `apps/relay/src/index.ts`
- CORS configuration now properly parses environment variable
- Trims whitespace from comma-separated list
- Logs allowed origins on startup for debugging

**File:** `apps/relay/.env`
- `ALLOWED_ORIGINS` includes both production and local origins

## Testing the Fix

1. **Browser console** (DevTools → Network):
   - Make request to https://www.stvor.xyz
   - Check the request to `/api/relay/directory/{username}`
   - If CORS is fixed: `Access-Control-Allow-Origin: https://www.stvor.xyz` header appears
   - If still blocked: `CORS error` message appears

2. **Relay logs**:
   - If origin allowed: No `[CORS] ❌ BLOCKED` message
   - If origin blocked: See the blocked origin error

3. **End-to-end test**:
   - Sign up on https://www.stvor.xyz
   - Set username
   - Should complete identity verification without errors
   - Should NOT see "identity verification failed"

## Environment-Specific Configuration

### Development
```
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3002,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3002
```

### Staging
```
ALLOWED_ORIGINS=https://staging-stvor.xyz,http://localhost:3000,http://localhost:3002
```

### Production
```
ALLOWED_ORIGINS=https://stvor.xyz,https://www.stvor.xyz,https://clerk.stvor.xyz,http://localhost:3000,http://localhost:3002
```

## Debugging

If you're still seeing CORS errors after setting `ALLOWED_ORIGINS`:

1. **Check Railway logs** in real-time:
   ```
   railway logs -f
   ```

2. **Look for startup message**:
   ```
   [Startup] 🔐 CORS: Allowed origins: ...
   ```

3. **Verify environment variable is set**:
   - Railway Dashboard → Variables
   - Confirm `ALLOWED_ORIGINS` is visible

4. **Restart the service**:
   - Go to Railway → Environment → More options → Restart

5. **Check for typos**:
   - No trailing commas
   - No extra spaces (they're trimmed, but avoid them)
   - Correct protocol: `https://` for production, `http://` for local

## Related Issues

This fix addresses the cascade failure in user registration:

1. ✅ Profile storage migrated to Supabase (persistent)
2. ✅ API response shape fixed (nested identity object)
3. ✅ Relay identity key configured (Ed25519 signing)
4. ✅ **Relay CORS fixed** (production domain allowed)

Once all four are deployed, registration should work end-to-end.
