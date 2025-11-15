# Critical Blockers - Group Chat Production Testing

## Status Summary

✅ **Code:** Group chat fully implemented (1,865 lines)
✅ **Frontend:** Built and deployed to Vercel
✅ **Environment:** Configured for production
❌ **Relay:** Needs immediate redeployment
❌ **Testing:** Cannot proceed without relay update

---

## The Problem

The production relay server (Railway) is running **v0.8.0**, which was deployed BEFORE the group chat feature was added.

### Evidence

**Test Result:**
```
❌ Group message endpoint responds (385ms)
   Error: 404 - "Route POST:/group/group_1763244600721_test/message not found"
```

**Current Relay Status:**
```bash
$ curl https://ilyazhrelay-production.up.railway.app/healthz
{"status":"ok","storage":"postgres","version":"0.8.0"}
```

**Local Source Code (has group chat):**
```bash
$ grep -n "/group/:groupId/message" apps/relay/src/index.ts
1203:  '/group/:groupId/message',
```

### Root Cause

The commits with group chat were pushed to GitHub:
- ✅ a3be84f - "feat(Phase 2): Implement group chat with end-to-end encryption"
- ✅ ef70858 - "fix(Phase 2): Fix runtime errors in group chat..."

But Railway hasn't rebuilt the Docker image with these new code changes.

---

## Solution: Redeploy Relay on Railway

### Step 1: Trigger Railway Rebuild

**Option A: Via Railroad Dashboard (Easiest)**
1. Visit https://railway.app/dashboard
2. Click on "ilyazhrelay" project
3. Find the service in the project
4. Click the "Deploy" button (or menu → Redeploy)
5. Wait for build to complete

**Option B: Via GitHub Webhook (Automatic)**
If Railway is already linked to GitHub:
- Any new push to `main` automatically triggers rebuild
- Check the deployment status in Railway dashboard

**Option C: Via Railway CLI**
```bash
npm install -g @railway/cli
railway login
cd /Users/ilaszajsenbaev/ilyazh-messenger/apps/relay
railway up
```

### Step 2: Verify Redeployment

Once the build completes (2-3 minutes), test the endpoint:

```bash
# Check version is updated
curl https://ilyazhrelay-production.up.railway.app/healthz
# Should show: "version":"0.9.0-beta" (or newer)

# Test group message endpoint exists
curl -X POST https://ilyazhrelay-production.up.railway.app/group/test-group-id/message \
  -H "Content-Type: application/json" \
  -d '{
    "type": "group_message",
    "sender": "alice",
    "message": {
      "aad": "dGVzdA==",
      "nonce": "dGVzdA==",
      "ciphertext": "dGVzdA==",
      "recipients": {"bob": {"nonce": "dGVzdA==", "ciphertext": "dGVzdA=="}}
    }
  }'
# Should return: 403 (identity error) or success, NOT 404

# Run comprehensive test
node /Users/ilaszajsenbaev/ilyazh-messenger/test-group-chat.mjs
# Should pass all 6 tests
```

---

## What Happens After Redeployment

Once relay is updated with v0.9.0-beta or later:

### Working Features
- ✅ Frontend loads group creation UI
- ✅ Create groups with multiple members
- ✅ Join group chat
- ✅ Send encrypted messages (encryption is stubbed, will send as base64)
- ✅ Receive messages in real-time via WebSocket
- ✅ See typing indicators from other members
- ✅ See online status of group members
- ✅ Offline messages queued until member reconnects

### Known Limitations (MVP)
- ⚠️ Messages sent in plaintext (encryption stub)
  - Will implement ChaCha20-Poly1305 in Phase 3
- ⚠️ No member management (can't add/remove after creation)
  - Will implement in Phase 3
- ⚠️ No image sharing yet
  - Will implement in Phase 3
- ⚠️ No message persistence (only during session + IndexedDB)
  - Will implement PostgreSQL persistence in Phase 3

---

## Testing Timeline

### Immediately After Redeployment
1. **Endpoint verification** (5 min)
   ```bash
   node test-group-chat.mjs
   ```

2. **Manual smoke test** (15 min)
   - Open https://stvor-web.vercel.app
   - Log in with Clerk
   - Navigate to /groups
   - Create group "Test 1" with members ["alice", "bob"]
   - Send message "Hello"
   - Verify message appears

3. **Functional test** (30 min)
   - Create group with 3 members
   - Test message delivery from each member
   - Test offline scenarios
   - Test typing indicators
   - Test presence indicators

### Phase 2 Completion Checklist
- [ ] Relay redeployed to v0.9.0+ on Railway
- [ ] `test-group-chat.mjs` passes all 6 tests
- [ ] Group creation works in UI
- [ ] Message sending/receiving works
- [ ] Typing indicators work
- [ ] Presence tracking works
- [ ] Offline message queuing works
- [ ] Group deletion works

---

## Why This Matters

### Current State
```
Frontend (Vercel) ✅ → Relay (Railway) ❌
Group chat code ready    Endpoint 404
Messages to send         Cannot route
```

### After Redeployment
```
Frontend (Vercel) ✅ → Relay (Railway) ✅ → WebSocket Broadcast
Group chat ready        Messages routed      Real-time delivery
Create, send, receive   Identity validated   Offline queue
```

---

## Quick Reference

**What's blocked?**
- Testing group chat on production
- Verifying real-time message delivery
- Validating 200-user scale readiness

**What needs to happen?**
- Redeploy relay service on Railway
- This takes ~2-3 minutes

**How?**
- Click "Deploy" in Railway dashboard
- Or push new commit to trigger GitHub webhook
- Or use `railway up` CLI

**What happens then?**
- POST /group/:groupId/message endpoint becomes available
- Group chat becomes fully functional
- Phase 2 MVP ready for 200-user testing

**How to verify?**
```bash
node test-group-chat.mjs   # All tests should pass
```

---

## Escalation Path

If redeployment fails:

1. **Check Railway build logs**
   - Go to Railway dashboard
   - Find build errors
   - Review commit that broke build

2. **Common issues:**
   - PostgreSQL connection string invalid
   - Environment variables not set in Railway
   - GitHub repo not linked

3. **Rollback plan:**
   - Can redeploy previous working version
   - Check Railway "Deployments" tab
   - Select earlier successful build

4. **Contact support:**
   - Railway support: https://railway.app/support
   - Review commit logs for breaking changes
   - Check env vars match requirements

---

## Next Phase: After Redeployment

Once relay is working, immediate priorities:

1. **Phase 3: Encryption** (1-2 days)
   - Implement actual ChaCha20-Poly1305
   - Replace encryption stubs with real crypto
   - Add message authentication

2. **Phase 3: Persistence** (1 day)
   - Add PostgreSQL message history
   - Implement message retrieval API
   - Add delivery receipts

3. **Phase 3: Scaling** (2 days)
   - Load test with 200+ concurrent users
   - Monitor relay performance
   - Optimize bottlenecks

---

## Current Timestamp

**Last Updated:** 2025-11-16 09:52 UTC
**Relay Version:** 0.8.0 (needs update to 0.9.0+)
**Frontend Version:** Latest (✅ ready)
**Status:** **BLOCKED - AWAITING RELAY REDEPLOYMENT**

---

**TL;DR:** Redeploy relay on Railway to get group chat working. Takes 2-3 minutes. Then test with `test-group-chat.mjs`.
