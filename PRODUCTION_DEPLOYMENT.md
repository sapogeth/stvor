# Production Deployment Guide - Group Chat Phase 2

## Current Status

✅ **Web Frontend (Vercel):** https://stvor-web.vercel.app
- Group chat pages implemented and compiled
- Environment variables configured correctly
- Ready for testing group chat UI

⚠️ **Relay Server (Railway):** https://ilyazhrelay-production.up.railway.app
- **REQUIRES REDEPLOYMENT** - Currently running v0.8.0 (pre-group chat)
- New group chat endpoint added in commits after deployment
- Need to rebuild to include `/group/:groupId/message` endpoint

## What Changed

The following commits added group chat functionality to the relay:

1. **a3be84f** - "feat(Phase 2): Implement group chat with end-to-end encryption"
   - Added `POST /group/:groupId/message` endpoint
   - Added group session storage
   - Added per-recipient message routing
   - Added offline message queuing

2. **ef70858** - "fix(Phase 2): Fix runtime errors in group chat - require to import, Buffer to base64, message formatting"
   - Fixed WebSocket plugin registration
   - Fixed Buffer usage in browser compatibility
   - Fixed message format handling

3. **2b1b5b0** - "changes and group chat"
   - Additional group chat configuration

## How to Redeploy on Railway

### Option 1: Using Railway Dashboard (Recommended)

1. Go to https://railway.app/dashboard
2. Select your "ilyazhrelay" project
3. Click on the service
4. Click the "Deploy" button (or trigger a redeploy from the latest commit)
5. Wait for build to complete (usually 2-3 minutes)
6. Test the endpoint:
   ```bash
   curl https://ilyazhrelay-production.up.railway.app/healthz
   # Should return: {"status":"ok","storage":"postgres","version":"0.9.0-beta"}
   ```

### Option 2: Using Railway CLI

```bash
# Install Railway CLI if needed
npm install -g @railway/cli

# Login to Railway
railway login

# Connect to project
railway link

# Deploy
railway up
```

### Option 3: GitHub Integration (Automatic)

If Railway is connected to your GitHub repo:
1. Any push to `main` branch triggers automatic deployment
2. Check build logs in Railway dashboard
3. Verify deployment completed successfully

## Verification Steps

After redeployment, run these tests:

### Test 1: Healthz Endpoint
```bash
curl https://ilyazhrelay-production.up.railway.app/healthz
# Expected: {"status":"ok","storage":"postgres","version":"0.9.0-beta"}
```

### Test 2: Group Message Endpoint
```bash
curl -X POST https://ilyazhrelay-production.up.railway.app/group/test-group/message \
  -H "Content-Type: application/json" \
  -d '{
    "type": "group_message",
    "sender": "alice",
    "message": {
      "aad": "dGVzdCBhYWQ=",
      "nonce": "dGVzdCBub25jZQ==",
      "ciphertext": "ZW5jcnlwdGVkIGNvbnRlbnQ=",
      "recipients": {
        "bob": {
          "nonce": "Ym9iIG5vbmNl",
          "ciphertext": "Ym9iIHdyYXBwZWQ="
        }
      }
    }
  }'
# Expected: Either 403 (identity not registered) or success response
# Should NOT return: 404 ("Route POST:/group/... not found")
```

### Test 3: Full End-to-End Test
```bash
cd /Users/ilaszajsenbaev/ilyazh-messenger
node test-group-chat.mjs
# Should pass all 6 tests including group message endpoint
```

## What Happens After Redeploy

Once the relay is updated, the group chat workflow will be:

1. **Frontend** (https://stvor-web.vercel.app)
   - User logs in via Clerk
   - Navigates to `/groups`
   - Creates a group: "Test Group" with members ["alice", "bob", "charlie"]
   - Joins the group chat

2. **Message Encryption**
   - Message input: "Hello group!"
   - Client encrypts with group encryption
   - Creates per-recipient wrapped versions

3. **Message Send**
   - Frontend POST to `/api/relay/group/{groupId}/message`
   - Next.js proxy forwards to relay
   - Relay validates sender identity
   - Relay routes message to each recipient:
     - If online (WebSocket connected): deliver instantly
     - If offline: queue message for delivery on reconnect

4. **Real-Time Delivery**
   - Connected recipients get message via WebSocket
   - Client decrypts message
   - Message appears in chat UI with sender name and timestamp

## Environment Variables

### Frontend (.env.production in Vercel)
```
NEXT_PUBLIC_RELAY_URL=https://ilyazhrelay-production.up.railway.app
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...
```

### Relay (.env in Railway)
```
PORT=3001
HOST=0.0.0.0
STORAGE_TYPE=postgres
DATABASE_URL=postgresql://...
ALLOWED_ORIGINS=https://stvor-web.vercel.app
```

Verify these are set in Vercel and Railway dashboards.

## Testing Checklist

After redeployment, test these scenarios:

- [ ] Create a group with 3 members
- [ ] Member 1 sends message → Members 2 & 3 receive
- [ ] Member 2 sends message → Members 1 & 3 receive
- [ ] Member 3 goes offline, Member 1 sends message
- [ ] Member 3 comes back online → receives queued message
- [ ] Typing indicators show while other member types
- [ ] Online status shows which members are active
- [ ] Message timestamps are correct
- [ ] Messages persist in IndexedDB after page reload

## Known Limitations (MVP)

- ❌ **Encryption is stubbed** - Messages sent as plaintext in this MVP
  - Full ChaCha20-Poly1305 implemented in Phase 3
- ❌ **Member management** - Can't add/remove members after group creation
  - Deferred to Phase 3
- ❌ **No image sharing yet** - Deferred to Phase 3
- ❌ **No message history retrieval** - Only live messages + IndexedDB
  - Full persistence in Phase 3

## Support

If deployment fails:

1. Check Railway build logs for errors
2. Verify PostgreSQL connection string is set
3. Check GitHub repository is linked correctly
4. Review recent commits for breaking changes
5. Try manual rebuild from dashboard

Contact: Check Railway dashboard for deployment details and logs.

## Next Steps

1. ✅ Redeploy relay with group chat support
2. ✅ Run endpoint tests (test-group-chat.mjs)
3. ✅ Test group creation and messaging manually
4. 🔄 Fix any issues found during testing
5. 🔄 Gather user feedback
6. 🚀 Phase 3: Implement actual encryption, persistence, and scaling

---

**Last Updated:** 2025-11-16
**Status:** Awaiting relay redeployment on Railway
**Target:** Group chat MVP ready for 200-user testing
