# Environment Configuration Guide

## Overview

The Ilyazh messenger application requires proper environment variable configuration for both the web app and relay server to function correctly, especially when dealing with group invitations and messaging.

## Critical Issue: RELAY_BASE_URL

The web application uses a transparent API proxy at `/api/relay/*` to forward requests to the relay server. This proxy needs the `RELAY_BASE_URL` environment variable to know where to send requests.

### Without RELAY_BASE_URL:
- ❌ Group message creation fails with 502 errors
- ❌ Directory lookups fail
- ❌ Prekey bundle operations fail
- ❌ All group features broken

### With RELAY_BASE_URL:
- ✅ All relay endpoints accessible
- ✅ Group invitations work
- ✅ Real-time messaging works
- ✅ End-to-end encryption works

## Configuration by Environment

### Local Development (.env.local)

```bash
# Public variables (browser-accessible)
NEXT_PUBLIC_RELAY_URL=http://localhost:3001
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...

# Server-side variables (NOT exposed to browser)
RELAY_BASE_URL=http://localhost:3001
CLERK_SECRET_KEY=sk_test_...

# Optional: Debug flags (only in local dev)
NEXT_PUBLIC_DEBUG_CRYPTO=1
NEXT_PUBLIC_DEBUG_AUTH=1
NEXT_PUBLIC_DEBUG_SYNC=1
NEXT_PUBLIC_DEBUG_IDENTITY=1
```

### Production (.env.production or Vercel)

**IMPORTANT:** The `.env.production` file should be configured but cannot be committed to git. Set these in Vercel dashboard instead:

```bash
# Set in Vercel Dashboard → Project Settings → Environment Variables

# Public variables (browser-accessible)
NEXT_PUBLIC_RELAY_URL=https://ilyazhrelay-production.up.railway.app

# Server-side variables (CRITICAL for API proxy)
RELAY_BASE_URL=https://ilyazhrelay-production.up.railway.app

# Clerk production keys
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_...
CLERK_SECRET_KEY=sk_live_...

# Production safety (MUST be disabled in production)
NEXT_PUBLIC_DEBUG_CRYPTO=0
NEXT_PUBLIC_DEBUG_AUTH=0
NEXT_PUBLIC_DEBUG_SYNC=0
NEXT_PUBLIC_DEBUG_IDENTITY=0
```

## Environment Variable Explanations

### `NEXT_PUBLIC_RELAY_URL`
- **Type:** PUBLIC (exposed to browser)
- **Used by:** Client-side WebSocket connections
- **Example:** `https://ilyazhrelay-production.up.railway.app`
- **Note:** Only needed for WebSocket real-time features, not API requests

### `RELAY_BASE_URL`
- **Type:** SERVER-SIDE (never exposed to browser)
- **Used by:** Next.js API routes at `/api/relay/*`
- **Example:** `https://ilyazhrelay-production.up.railway.app`
- **CRITICAL:** Without this, all group messaging fails
- **Set via:** Vercel environment variables (for production)

### `CLERK_SECRET_KEY`
- **Type:** SERVER-SIDE SECRET
- **Used by:** JWT token validation, session management
- **NEVER COMMIT:** Always set via environment dashboard
- **Set via:** Vercel environment variables

### `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`
- **Type:** PUBLIC (safe in browser)
- **Used by:** Clerk authentication UI
- **Example:** `pk_test_divine-lizard-64.clerk.accounts.dev`
- **Get from:** https://dashboard.clerk.com/apps/YOUR_APP/api-keys

## How the API Proxy Works

```
User in Browser
       ↓
Calls: POST /api/relay/group/{groupId}/message
       ↓
Next.js Route Handler (/api/relay/[...path]/route.ts)
       ↓
Reads: RELAY_BASE_URL
       ↓
Forwards to: https://ilyazhrelay-production.up.railway.app/group/{groupId}/message
       ↓
Relay Server Response
       ↓
Returns to Browser
```

## Setting Up for Production (Vercel)

### Step 1: Configure in Vercel Dashboard

Go to: https://vercel.com/dashboard → Select Project → Settings → Environment Variables

Add these variables:

| Variable | Value | Type |
|----------|-------|------|
| `RELAY_BASE_URL` | `https://ilyazhrelay-production.up.railway.app` | Server-side |
| `NEXT_PUBLIC_RELAY_URL` | `https://ilyazhrelay-production.up.railway.app` | Public |
| `CLERK_SECRET_KEY` | Get from Clerk dashboard | Server-side |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | Get from Clerk dashboard | Public |

### Step 2: Get Clerk Keys

1. Visit: https://dashboard.clerk.com
2. Select your application
3. Go to: API Keys
4. Copy:
   - Publishable Key → `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`
   - Secret Key → `CLERK_SECRET_KEY`

### Step 3: Deploy

```bash
# Push changes to main branch
git push origin main

# Vercel will automatically redeploy with new environment variables
```

## Troubleshooting

### ❌ 502 Error on Group Message Send

**Cause:** `RELAY_BASE_URL` not set or incorrect

**Solution:**
```bash
# Check Vercel dashboard has RELAY_BASE_URL set
# Verify it matches your relay server URL
# Redeploy:
git push origin main
```

### ❌ WebSocket Connection Fails

**Cause:** `NEXT_PUBLIC_RELAY_URL` not set or using HTTP instead of HTTPS

**Solution:**
```bash
# Ensure NEXT_PUBLIC_RELAY_URL is HTTPS
# In production: https://your-relay-url.up.railway.app
# Local dev: http://localhost:3001 is OK
```

### ❌ Invitation Accept Fails with 404

**Cause:** Route group syntax in navigation (already fixed in commit d6dc173)

**Solution:**
- This was fixed in commit d6dc173
- Ensure routes use `/groups/[groupId]` not `/(dashboard)/groups/[groupId]`
- Redeploy to get latest code

## Local Development Checklist

- [ ] `.env.local` created from `.env.example`
- [ ] `NEXT_PUBLIC_RELAY_URL=http://localhost:3001`
- [ ] `RELAY_BASE_URL=http://localhost:3001`
- [ ] `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` set from Clerk
- [ ] `CLERK_SECRET_KEY` set from Clerk
- [ ] Relay server running on port 3001: `npm run dev` in `apps/relay`
- [ ] Web app running on port 3000: `npm run dev` in `apps/web`

## Production Checklist

- [ ] All environment variables set in Vercel dashboard
- [ ] `RELAY_BASE_URL` points to production relay
- [ ] `NEXT_PUBLIC_RELAY_URL` matches relay URL
- [ ] Clerk keys are production keys (pk_live_...)
- [ ] All debug flags set to 0
- [ ] Railway relay server is running and accessible
- [ ] Redeploy triggered after env var changes

## Reference

- **Relay Server Repository:** https://github.com/sapogeth/stvor
- **Vercel Dashboard:** https://vercel.com/dashboard
- **Clerk API Keys:** https://dashboard.clerk.com/apps/YOUR_APP/api-keys
- **Railway Dashboard:** https://railway.app/dashboard

---

**Last Updated:** 2025-11-16
**Version:** 1.0
**Status:** Production Ready
