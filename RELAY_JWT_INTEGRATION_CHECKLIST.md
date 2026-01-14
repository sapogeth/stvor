# RELAY JWT INTEGRATION - FINAL CHECKLIST

**Date**: 2026-01-14  
**Status**: IN PROGRESS  
**Blocking**: Message delivery, handshake completion, sync

---

## IMPLEMENTATION STATUS

### ✅ COMPLETED (Part 1 - Infrastructure)

- [x] Create `/api/relay/session` endpoint (issues relay JWT)
- [x] Create `relay-jwt-manager.ts` (client JWT caching)
- [x] Update `createAuthHeaders()` to use relay JWT (now async)
- [x] Update `ratchet-refresh.ts` to use relay JWT
- [x] Create `RELAY_AUTH_ROOT_CAUSE_ANALYSIS.md`
- [x] Commit 569b14d pushed to main

### ⚠️ IN PROGRESS (Part 2 - Integration)

- [x] Create `apps/relay/src/web-jwt-auth.ts` (JWT verification middleware)
- [ ] Update relay endpoints to use `requireWebAuth` middleware
- [ ] Update all `createAuthHeaders()` call sites (make async/await)
- [ ] Remove ALL "DEV mode continue" logic
- [ ] Add `RELAY_JWT_SECRET` to environment variables
- [ ] Test end-to-end: Clerk login → relay JWT → handshake → message delivery

---

## RELAY ENDPOINT AUTHORIZATION MATRIX

| Endpoint | Auth Required | Authorization Check | Middleware |
|----------|---------------|---------------------|------------|
| **Directory** |
| `GET /directory/:username` | Optional | None (public directory) | `optionalWebAuth` |
| `POST /directory/:username` | **REQUIRED** | User must own username | `requireWebAuth` + custom |
| **Chat Initialization** |
| `POST /chat/init` | **REQUIRED** | None (creates new chat) | `requireWebAuth` |
| **Messages** |
| `POST /message/:chatId` | **REQUIRED** | Must be participant | `requireWebAuth` + `requireParticipant` |
| `GET /message/:chatId` | **REQUIRED** | Must be participant | `requireWebAuth` + `requireParticipant` |
| **Sync** |
| `GET /sync/:chatId` | **REQUIRED** | Must be participant | `requireWebAuth` + `requireParticipant` |
| **Intent Registration** |
| `POST /intent/:chatId` | **REQUIRED** | None (intent is discovery) | `requireWebAuth` |
| **Prekeys** |
| `GET /prekeys/:username` | Optional | None (public prekeys) | `optionalWebAuth` |

---

## RELAY SERVER INTEGRATION STEPS

### Step 1: Add JWT Secret to Environment

**File**: `apps/relay/.env`

```bash
# Add this line (must match Next.js backend)
RELAY_JWT_SECRET=<generate-random-string-min-32-chars>
```

**Generate secret**:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

**Deploy to Railway**:
```bash
railway variables set RELAY_JWT_SECRET=<secret>
```

---

### Step 2: Update Relay Endpoints

**File**: `apps/relay/src/index.ts`

#### Example: POST /message/:chatId

**Before (BROKEN)**:
```typescript
fastify.post('/message/:chatId', async (request, reply) => {
  const { chatId } = request.params as { chatId: string };
  
  // NO AUTH CHECK ❌
  // Anyone can send messages
  
  const message = await storage.messages.saveMessage(chatId, ...);
  return { success: true };
});
```

**After (CORRECT)**:
```typescript
import { requireWebAuth, requireParticipant } from './web-jwt-auth';

fastify.post('/message/:chatId', {
  preHandler: [requireWebAuth, requireParticipant] // ✅ Auth + authorization
}, async (request, reply) => {
  const { chatId } = request.params as { chatId: string };
  const username = request.user!.username; // Guaranteed by middleware
  
  // Verify sender matches authenticated user
  const message = await storage.messages.saveMessage(chatId, username, ...);
  return { success: true };
});
```

#### Example: GET /sync/:chatId

**Before (BROKEN)**:
```typescript
fastify.get('/sync/:chatId', async (request, reply) => {
  const messages = await storage.messages.getMessages(chatId);
  return messages; // ❌ No auth, anyone can read any chat
});
```

**After (CORRECT)**:
```typescript
import { requireWebAuth, requireParticipant } from './web-jwt-auth';

fastify.get('/sync/:chatId', {
  preHandler: [requireWebAuth, requireParticipant] // ✅ Auth + authorization
}, async (request, reply) => {
  const { chatId } = request.params as { chatId: string };
  const username = request.user!.username;
  
  request.log.info('[Sync] Fetching messages', { chatId, username });
  
  const messages = await storage.messages.getMessages(chatId);
  return messages;
});
```

#### Example: POST /directory/:username

**Before (BROKEN)**:
```typescript
fastify.post('/directory/:username', async (request, reply) => {
  const { username } = request.params;
  // ❌ Anyone can register any username
  await storage.users.createUser(username, ...);
});
```

**After (CORRECT)**:
```typescript
import { requireWebAuth } from './web-jwt-auth';

fastify.post('/directory/:username', {
  preHandler: requireWebAuth // ✅ Must be authenticated
}, async (request, reply) => {
  const { username: targetUsername } = request.params as { username: string };
  const authenticatedUsername = request.user!.username;
  
  // Verify user can only register their own username
  if (targetUsername.toLowerCase() !== authenticatedUsername.toLowerCase()) {
    return reply.code(403).send({
      error: 'Forbidden',
      message: 'You can only register your own username'
    });
  }
  
  await storage.users.createUser(authenticatedUsername, ...);
  return { success: true };
});
```

---

## CLIENT-SIDE INTEGRATION STEPS

### Step 1: Update All `createAuthHeaders()` Call Sites

**Locations** (7 sites):
1. `apps/web/app/chat/page.tsx` line 427
2. `apps/web/app/chat/page.tsx` line 520
3. `apps/web/app/chat/page.tsx` line 587
4. `apps/web/app/chat/page.tsx` line 807
5. `apps/web/app/chat/page.tsx` line 1461
6. `apps/web/app/chat/page.tsx` line 1676
7. `apps/web/app/chat/page.tsx` line 1838

**Pattern**:
```typescript
// Before (WRONG - createAuthHeaders is now async)
const res = await fetch('/api/relay/message/123', {
  headers: createAuthHeaders(username), // ❌ Missing await
});

// After (CORRECT)
const headers = await createAuthHeaders(username); // ✅ Add await
const res = await fetch('/api/relay/message/123', {
  headers,
});
```

---

### Step 2: Remove ALL "DEV Mode Continue" Logic

**Search pattern**: `continue.*dev|proceeding.*without|fallback`

**Known locations**:
1. `apps/web/lib/identity.ts` - ✅ ALREADY FIXED (commit 02e1536)
2. `apps/web/lib/prekeys.ts` - ⚠️ CHECK FOR DEV MODE
3. `apps/web/lib/ratchet-refresh.ts` - ⚠️ CHECK FOR 403 CONTINUE

**Example fix**:
```typescript
// Before (WRONG)
if (res.status === 403) {
  console.warn('Relay returned 403 - continuing in DEV mode'); // ❌
  // Generate identity anyway
}

// After (CORRECT)
if (res.status === 403) {
  relayAuthController.markFailed('Relay authentication failed', 403); // ✅
  throw new Error('Cannot proceed: Authentication failed');
}
```

---

### Step 3: Add Relay Auth State Gating

**Pattern for ALL relay operations**:
```typescript
import { requireRelayAuth } from '@/lib/relay-auth-controller';

async function sendMessage(chatId: string, message: string) {
  // 1. Check relay auth state FIRST
  requireRelayAuth('send message'); // Throws if not authenticated
  
  // 2. Get relay JWT headers
  const headers = await createAuthHeaders(username);
  
  // 3. Make request
  const res = await fetch(`/api/relay/message/${chatId}`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ message }),
  });
  
  // 4. Handle auth failure
  if (res.status === 401 || res.status === 403) {
    relayAuthController.markFailed('Message send failed', res.status);
    throw new Error('Authentication failed');
  }
  
  return res.json();
}
```

**Apply to**:
- Prekey upload
- Intent registration
- Handshake sending
- Message sending
- Sync polling

---

## HANDSHAKE SUCCESS CRITERIA (Step-by-Step)

### Prerequisites
1. ✅ User authenticated with Clerk (httpOnly cookie)
2. ✅ Relay JWT obtained from `/api/relay/session`
3. ✅ Relay JWT cached in memory
4. ✅ `relayAuthController.state === VERIFIED`

### Phase 1: Identity Verification
1. ✅ Client calls `getOrCreateIdentity(username)`
2. ✅ `createAuthHeaders()` fetches relay JWT
3. ✅ Request to `/api/relay/directory/:username` includes `Authorization: Bearer <jwt>`
4. ✅ Relay verifies JWT with `requireWebAuth` middleware
5. ✅ Relay returns 200 OK with identity OR 404 Not Found
6. ✅ On 403: `relayAuthController.markFailed()` → abort → show red banner

### Phase 2: Prekey Publication
1. ✅ Client calls `createAndPublishPrekeyBundle()`
2. ✅ Generate prekey bundle (X25519 + ML-KEM-768)
3. ✅ Sign bundle with Ed25519 identity key
4. ✅ POST to `/api/relay/directory/:username` with relay JWT
5. ✅ Relay verifies:
   - JWT valid (`requireWebAuth`)
   - Username matches authenticated user
6. ✅ Relay stores prekey bundle
7. ✅ Relay returns 200 OK
8. ✅ On 403: abort, mark relay auth FAILED

### Phase 3: Intent Registration
1. ✅ Client calls `registerIntentWithRelay(peer)`
2. ✅ POST to `/api/relay/intent/:chatId` with relay JWT
3. ✅ Body: `{ to: peer, from: username }`
4. ✅ Relay verifies JWT (`requireWebAuth`)
5. ✅ Relay registers intent (allows fetching peer's prekey)
6. ✅ Relay returns 200 OK
7. ✅ On 403: `machine.transition(HandshakeState.FAILED)` → abort

### Phase 4: Fetch Peer Prekey
1. ✅ Client fetches peer prekey bundle
2. ✅ GET `/api/relay/prekeys/:peer` (optional auth)
3. ✅ Relay checks intent registration
4. ✅ Relay returns peer's prekey bundle
5. ✅ Client verifies Ed25519 signature on bundle

### Phase 5: X3DH Handshake
1. ✅ Client performs X3DH key agreement
2. ✅ Derives shared secret from:
   - IK_A, IK_B (identity keys)
   - EK_A, SPK_B (ephemeral + signed prekey)
   - EK_A, OPK_B (ephemeral + one-time prekey)
   - PQ_KEM ciphertext (ML-KEM-768)
3. ✅ Initialize Double Ratchet with shared secret
4. ✅ Encrypt initial message with ratchet

### Phase 6: Send Handshake Message
1. ✅ Client creates handshake message:
   ```json
   {
     "type": "handshake",
     "from": "alice",
     "to": "bob",
     "identityKey": "...",
     "ephemeralKey": "...",
     "preKeyId": 123,
     "ciphertext": "...",
     "signature": "..."
   }
   ```
2. ✅ POST to `/api/relay/message/:chatId` with relay JWT
3. ✅ Relay verifies:
   - JWT valid (`requireWebAuth`)
   - Sender is participant (`requireParticipant`)
4. ✅ Relay stores message for delivery
5. ✅ Relay returns 200 OK
6. ✅ `machine.transition(HandshakeState.HANDSHAKE_SENT)`
7. ✅ On 403: `markFailed()` → abort → show UI error

### Phase 7: Peer Receives Handshake
1. ✅ Peer polls `/api/relay/sync/:chatId` with relay JWT
2. ✅ Relay verifies:
   - JWT valid (`requireWebAuth`)
   - Peer is participant (`requireParticipant`)
3. ✅ Relay returns handshake message
4. ✅ Peer performs X3DH responder protocol
5. ✅ Peer initializes Double Ratchet
6. ✅ Peer sends response message (encrypted)

### Phase 8: Session Established
1. ✅ Client receives response message via sync
2. ✅ Client advances ratchet state
3. ✅ `machine.transition(HandshakeState.SESSION_ESTABLISHED)`
4. ✅ Encrypted messaging now operational

### Failure Modes (All Must Abort)
- ❌ JWT expired → refresh → retry ONCE → if fails, abort
- ❌ 401 Unauthorized → `relayAuthController.markFailed()` → red banner
- ❌ 403 Forbidden → `relayAuthController.markFailed()` → red banner
- ❌ Intent registration failed → `machine.transition(FAILED)` → abort
- ❌ Prekey fetch failed → abort handshake
- ❌ Signature verification failed → abort (potential MITM)

---

## ENVIRONMENT VARIABLES CHECKLIST

### Next.js Backend (.env.local)
```bash
# Clerk authentication
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...
CLERK_SECRET_KEY=sk_test_...

# Relay JWT (NEW - must match relay)
RELAY_JWT_SECRET=<random-32-char-base64-string>

# Relay URL
RELAY_URL=https://ilyazhrelay-production.up.railway.app
```

### Relay Server (.env or Railway)
```bash
# Relay JWT (NEW - must match Next.js)
RELAY_JWT_SECRET=<same-secret-as-nextjs>

# Storage
STORAGE_TYPE=postgres
DATABASE_URL=postgresql://...

# Port
PORT=3001
```

### Vercel (Production)
```bash
# Add to Vercel project settings
RELAY_JWT_SECRET=<same-secret>
RELAY_URL=https://ilyazhrelay-production.up.railway.app
```

---

## TESTING CHECKLIST

### Unit Tests
- [ ] `verifyWebRelayJWT()` accepts valid JWT
- [ ] `verifyWebRelayJWT()` rejects expired JWT
- [ ] `verifyWebRelayJWT()` rejects wrong audience
- [ ] `verifyWebRelayJWT()` rejects wrong issuer
- [ ] `verifyWebRelayJWT()` rejects invalid signature

### Integration Tests
- [ ] Client obtains relay JWT from `/api/relay/session`
- [ ] Client caches JWT in memory
- [ ] Client refreshes JWT before expiry
- [ ] Relay accepts valid JWT
- [ ] Relay rejects invalid JWT (401)
- [ ] Relay enforces participant check (403)

### E2E Tests
- [ ] User signs in with Clerk
- [ ] Identity created and published
- [ ] Prekey bundle uploaded
- [ ] Intent registered
- [ ] Handshake sent
- [ ] Peer receives handshake
- [ ] Session established
- [ ] Encrypted messages delivered
- [ ] Sync polling works

### Failure Tests
- [ ] 401 shows red banner
- [ ] 403 shows red banner
- [ ] No messages sent after auth failure
- [ ] Sync stops after 403
- [ ] No DEV mode continuation

---

## DEPLOYMENT ORDER

1. **Deploy relay server first**:
   ```bash
   cd apps/relay
   railway up
   railway variables set RELAY_JWT_SECRET=<secret>
   ```

2. **Deploy Next.js backend**:
   ```bash
   # Add RELAY_JWT_SECRET to Vercel
   vercel env add RELAY_JWT_SECRET
   vercel --prod
   ```

3. **Test in staging**:
   - Sign in with Clerk
   - Verify relay JWT obtained
   - Send test message
   - Check relay logs for JWT verification

4. **Monitor production**:
   - Watch for 401/403 errors
   - Check relay JWT cache hit rate
   - Monitor handshake completion rate

---

## SUCCESS METRICS

### Before Fix
- ✗ Handshake completion rate: **0%**
- ✗ Message delivery: **0%**
- ✗ Sync working: **No**
- ✗ Auth failures: **100%** (all 401/403)

### After Fix (Target)
- ✓ Handshake completion rate: **>95%**
- ✓ Message delivery: **>99%**
- ✓ Sync working: **Yes**
- ✓ Auth failures: **<1%** (only legitimate failures)

---

END OF CHECKLIST
