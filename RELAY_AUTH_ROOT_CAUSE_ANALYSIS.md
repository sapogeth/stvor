/**
 * RELAY AUTHENTICATION ARCHITECTURE - ROOT CAUSE ANALYSIS
 * 
 * Date: 2026-01-14
 * Severity: CRITICAL - BLOCKS ALL MESSAGING
 * 
 * =============================================================================
 * 
 * ## CURRENT BROKEN STATE
 * 
 * ### Why Handshake Never Completes
 * 
 * 1. Client calls `POST /api/relay/message/:chatId` with handshake message
 * 2. Next.js proxy extracts Clerk JWT from httpOnly cookie
 * 3. Proxy forwards to relay with `Authorization: Bearer <CLERK_JWT>`
 * 4. **Relay CANNOT verify Clerk JWT** (relay doesn't have Clerk public keys)
 * 5. Relay returns 401 Unauthorized
 * 6. Client continues in "DEV mode" (WRONG!)
 * 7. Handshake state never transitions to SESSION_ESTABLISHED
 * 
 * ### Why Messages Are Rejected (401)
 * 
 * **Root cause**: Relay uses a DIFFERENT authentication system than Clerk.
 * 
 * - Clerk issues JWTs signed with Clerk's private key
 * - Relay expects JWTs signed with relay's private key (or shared secret)
 * - No cryptographic way for relay to verify Clerk JWTs without Clerk's public keys
 * - Relay has no mechanism to fetch/validate Clerk JWTs
 * 
 * **Architecture mismatch**:
 * ```
 * Client → Clerk → JWT_CLERK
 *   ↓
 * Next.js API → Forward JWT_CLERK → Relay
 *                                      ↓
 *                                   ❌ Cannot verify JWT_CLERK
 *                                   ❌ Returns 401
 * ```
 * 
 * ### Why Sync Loops Forever (403)
 * 
 * Same authentication failure pattern:
 * - Client polls `/api/relay/sync/:chatId`
 * - Proxy forwards Clerk JWT
 * - Relay returns 403 Forbidden (not authenticated)
 * - Client retries infinitely (no backoff, no abort)
 * 
 * =============================================================================
 * 
 * ## CORRECT RELAY AUTHENTICATION FLOW
 * 
 * ### Architecture Overview
 * 
 * ```
 * ┌─────────┐  1. Sign in      ┌───────┐
 * │ Client  │ ───────────────> │ Clerk │
 * └─────────┘                   └───────┘
 *      │                            │
 *      │                       2. httpOnly cookie
 *      │                         (JWT_CLERK)
 *      │                            │
 *      │  3. Request relay JWT      │
 *      │ ───────────────────────────▼────────────┐
 *      │                        ┌─────────────┐  │
 *      │                        │  Next.js    │  │
 *      │                        │  /api/relay/│  │
 *      │                        │  session    │  │
 *      │                        └─────────────┘  │
 *      │                             │           │
 *      │                        4. Verify        │
 *      │                           JWT_CLERK     │
 *      │                           (httpOnly)    │
 *      │                             │           │
 *      │                        5. Extract       │
 *      │                           username      │
 *      │                             │           │
 *      │                        6. Sign relay    │
 *      │                           JWT with      │
 *      │                           RELAY_SECRET  │
 *      │                             │           │
 *      │  7. Return JWT_RELAY        │           │
 *      │ <───────────────────────────┘           │
 *      │                                         │
 *      │  8. Store in memory                     │
 *      │     (NOT localStorage)                  │
 *      │                                         │
 *      │  9. ALL relay requests:                 │
 *      │     Authorization: Bearer JWT_RELAY     │
 *      │ ────────────────────────────────────────▼──────┐
 *      │                                      ┌────────┐ │
 *      │                                      │ Relay  │ │
 *      │                                      │ Server │ │
 *      │                                      └────────┘ │
 *      │                                          │      │
 *      │                                     10. Verify  │
 *      │                                         JWT_RELAY
 *      │                                         (RELAY_SECRET)
 *      │                                          │      │
 *      │                                     11. Extract │
 *      │                                         username│
 *      │                                          │      │
 *      │  12. Return 200 OK                  12. Enforce│
 *      │ <───────────────────────────────────────┘ membership
 * ```
 * 
 * ### Step-by-Step Flow
 * 
 * #### Phase 1: Obtain Relay JWT (once per session)
 * 
 * **Client**:
 * ```typescript
 * // On app load or after Clerk sign-in
 * const response = await fetch('/api/relay/session', {
 *   method: 'POST',
 *   credentials: 'include', // Send Clerk httpOnly cookie
 * });
 * 
 * const { relayJWT, expiresAt } = await response.json();
 * 
 * // Store in memory (NOT localStorage - XSS risk)
 * window.__RELAY_JWT = relayJWT;
 * window.__RELAY_JWT_EXPIRES = expiresAt;
 * ```
 * 
 * **Backend (`/api/relay/session`)**:
 * ```typescript
 * import { auth } from '@clerk/nextjs/server';
 * import jwt from 'jsonwebtoken';
 * 
 * export async function POST(req: NextRequest) {
 *   // 1. Verify Clerk session (from httpOnly cookie)
 *   const { userId } = await auth();
 *   if (!userId) {
 *     return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
 *   }
 * 
 *   // 2. Get username from Clerk
 *   const user = await clerkClient.users.getUser(userId);
 *   const username = user.username || user.emailAddresses[0].emailAddress;
 * 
 *   // 3. Sign relay JWT with shared secret
 *   const RELAY_JWT_SECRET = process.env.RELAY_JWT_SECRET!; // Must match relay
 *   const relayJWT = jwt.sign(
 *     { 
 *       username,
 *       userId,
 *       iss: 'ilyazh-web',
 *       aud: 'ilyazh-relay',
 *     },
 *     RELAY_JWT_SECRET,
 *     { expiresIn: '24h' } // Relay sessions expire after 24h
 *   );
 * 
 *   return NextResponse.json({
 *     relayJWT,
 *     expiresAt: Date.now() + 24 * 60 * 60 * 1000,
 *   });
 * }
 * ```
 * 
 * **Relay (verification)**:
 * ```typescript
 * import jwt from 'jsonwebtoken';
 * 
 * function verifyRelayJWT(authHeader: string): { username: string } | null {
 *   if (!authHeader.startsWith('Bearer ')) return null;
 *   
 *   const token = authHeader.slice(7);
 *   const RELAY_JWT_SECRET = process.env.RELAY_JWT_SECRET!;
 *   
 *   try {
 *     const payload = jwt.verify(token, RELAY_JWT_SECRET, {
 *       audience: 'ilyazh-relay',
 *       issuer: 'ilyazh-web',
 *     });
 *     
 *     return { username: payload.username };
 *   } catch (err) {
 *     console.error('[Relay] JWT verification failed:', err.message);
 *     return null;
 *   }
 * }
 * ```
 * 
 * #### Phase 2: Use Relay JWT for All Requests
 * 
 * **Client (updated auth helper)**:
 * ```typescript
 * async function getRelayAuthHeaders(): Promise<HeadersInit> {
 *   // Check if JWT exists and is not expired
 *   if (!window.__RELAY_JWT || Date.now() > window.__RELAY_JWT_EXPIRES) {
 *     // Refresh JWT
 *     const res = await fetch('/api/relay/session', {
 *       method: 'POST',
 *       credentials: 'include',
 *     });
 *     
 *     if (!res.ok) {
 *       // Clerk session expired or user logged out
 *       relayAuthController.markFailed('Cannot obtain relay JWT', 401);
 *       throw new Error('Relay authentication failed');
 *     }
 *     
 *     const { relayJWT, expiresAt } = await res.json();
 *     window.__RELAY_JWT = relayJWT;
 *     window.__RELAY_JWT_EXPIRES = expiresAt;
 *   }
 *   
 *   return {
 *     'Authorization': `Bearer ${window.__RELAY_JWT}`,
 *     'Content-Type': 'application/json',
 *   };
 * }
 * ```
 * 
 * **Usage**:
 * ```typescript
 * // Handshake
 * const headers = await getRelayAuthHeaders();
 * const res = await fetch(`/api/relay/message/${chatId}`, {
 *   method: 'POST',
 *   headers,
 *   body: JSON.stringify(handshakeMessage),
 * });
 * 
 * if (res.status === 401 || res.status === 403) {
 *   relayAuthController.markFailed('Relay rejected authentication', res.status);
 *   throw new Error('Cannot send handshake: Authentication failed');
 * }
 * ```
 * 
 * =============================================================================
 * 
 * ## CODE PATHS THAT MUST HARD-FAIL
 * 
 * ### 1. Identity Creation (apps/web/lib/identity.ts)
 * 
 * **Location**: `getOrCreateIdentity()`
 * 
 * **Current (WRONG)**:
 * ```typescript
 * } else if (response.status === 403) {
 *   logWarn('proceeding without verification'); // ❌ WRONG
 * }
 * ```
 * 
 * **Required (CORRECT)**:
 * ```typescript
 * } else if (response.status === 403) {
 *   relayAuthController.markFailed('Directory check failed', 403);
 *   throw new Error('Cannot verify identity: Relay authentication failed');
 * }
 * ```
 * 
 * **Action**: ✅ ALREADY FIXED (commit 02e1536)
 * 
 * ---
 * 
 * ### 2. Prekey Upload (apps/web/lib/prekeys.ts)
 * 
 * **Location**: `createAndPublishPrekeyBundle()`
 * 
 * **Required**:
 * ```typescript
 * const headers = await getRelayAuthHeaders(); // NEW
 * const res = await fetch(directoryUrl, {
 *   method: 'POST',
 *   headers,
 *   body: JSON.stringify(prekeyBundle),
 * });
 * 
 * if (res.status === 401 || res.status === 403) {
 *   relayAuthController.markFailed('Prekey upload failed', res.status);
 *   throw new Error('Cannot publish prekey bundle: Authentication failed');
 * }
 * ```
 * 
 * **Action**: ⚠️ NEEDS UPDATE
 * 
 * ---
 * 
 * ### 3. Intent Registration (apps/web/lib/prekeys.ts)
 * 
 * **Location**: `registerIntentWithRelay()`
 * 
 * **Current (PARTIALLY CORRECT)**:
 * ```typescript
 * if (!intentRes.ok) {
 *   throw new Error('Intent registration failed'); // Good, but needs relay auth check
 * }
 * ```
 * 
 * **Required**:
 * ```typescript
 * const headers = await getRelayAuthHeaders(); // NEW
 * const intentRes = await fetch(`${relayUrl}/message/${chatId}`, {
 *   method: 'POST',
 *   headers,
 *   body: JSON.stringify({ to: peer, from: username }),
 * });
 * 
 * if (intentRes.status === 401 || intentRes.status === 403) {
 *   relayAuthController.markFailed('Intent registration failed', intentRes.status);
 *   machine.transition(HandshakeState.FAILED, 'Auth failure');
 *   throw new Error('Cannot register intent: Authentication failed');
 * }
 * ```
 * 
 * **Action**: ⚠️ NEEDS UPDATE
 * 
 * ---
 * 
 * ### 4. Handshake Message Sending (apps/web/lib/ratchet-refresh.ts)
 * 
 * **Location**: `autoRefreshRatchetOnAADMismatch()`
 * 
 * **Current (WRONG)**:
 * ```typescript
 * if (handshakeRes.status === 403) {
 *   logWarn('Relay returned 403 - continuing in DEV mode'); // ❌ WRONG
 * }
 * ```
 * 
 * **Required**:
 * ```typescript
 * const headers = await getRelayAuthHeaders(); // NEW
 * const sendRes = await fetch(`${relayUrl}/message/${chatId}`, {
 *   method: 'POST',
 *   headers,
 *   body: JSON.stringify(handshakeMessage),
 * });
 * 
 * if (sendRes.status === 401 || sendRes.status === 403) {
 *   relayAuthController.markFailed('Handshake send failed', sendRes.status);
 *   machine.transition(HandshakeState.FAILED, 'Auth failure');
 *   throw new Error('Cannot send handshake: Authentication failed');
 * }
 * ```
 * 
 * **Action**: ⚠️ NEEDS UPDATE
 * 
 * ---
 * 
 * ### 5. Message Sending (all send paths)
 * 
 * **Locations**:
 * - Any code that calls `POST /api/relay/message/:chatId`
 * 
 * **Required**:
 * ```typescript
 * const headers = await getRelayAuthHeaders(); // NEW
 * const res = await fetch(`/api/relay/message/${chatId}`, {
 *   method: 'POST',
 *   headers,
 *   body: JSON.stringify(encryptedMessage),
 * });
 * 
 * if (res.status === 401 || res.status === 403) {
 *   relayAuthController.markFailed('Message send failed', res.status);
 *   throw new Error('Cannot send message: Authentication failed');
 * }
 * ```
 * 
 * **Action**: ⚠️ NEEDS UPDATE
 * 
 * ---
 * 
 * ### 6. Sync Polling (apps/web/lib/sync.ts or similar)
 * 
 * **Location**: Message polling loop
 * 
 * **Current (WRONG)**:
 * ```typescript
 * setInterval(async () => {
 *   const res = await fetch(`/api/relay/sync/${chatId}`);
 *   // Retries infinitely even on 403 ❌
 * }, 1000);
 * ```
 * 
 * **Required**:
 * ```typescript
 * async function pollMessages(chatId: string) {
 *   while (relayAuthController.isRelayAuthenticated()) {
 *     const headers = await getRelayAuthHeaders();
 *     const res = await fetch(`/api/relay/sync/${chatId}`, { headers });
 *     
 *     if (res.status === 401 || res.status === 403) {
 *       relayAuthController.markFailed('Sync polling failed', res.status);
 *       console.error('[Sync] Authentication failed, stopping polling');
 *       break; // STOP POLLING
 *     }
 *     
 *     if (res.ok) {
 *       const messages = await res.json();
 *       // Process messages...
 *     }
 *     
 *     await sleep(1000);
 *   }
 * }
 * ```
 * 
 * **Action**: ⚠️ NEEDS UPDATE
 * 
 * =============================================================================
 * 
 * ## MINIMAL PSEUDO-CODE
 * 
 * ### Relay JWT Issuance (Backend)
 * 
 * ```typescript
 * // File: apps/web/app/api/relay/session/route.ts
 * 
 * import { auth, clerkClient } from '@clerk/nextjs/server';
 * import jwt from 'jsonwebtoken';
 * 
 * export async function POST() {
 *   // 1. Verify Clerk authentication
 *   const { userId } = await auth();
 *   if (!userId) {
 *     return json({ error: 'Not authenticated' }, { status: 401 });
 *   }
 * 
 *   // 2. Get username
 *   const user = await clerkClient.users.getUser(userId);
 *   const username = user.username || user.primaryEmailAddress?.emailAddress;
 *   if (!username) {
 *     return json({ error: 'No username' }, { status: 400 });
 *   }
 * 
 *   // 3. Sign JWT
 *   const secret = process.env.RELAY_JWT_SECRET!;
 *   const token = jwt.sign(
 *     { username, userId, iss: 'ilyazh-web', aud: 'ilyazh-relay' },
 *     secret,
 *     { expiresIn: '24h' }
 *   );
 * 
 *   return json({
 *     relayJWT: token,
 *     username,
 *     expiresAt: Date.now() + 24 * 60 * 60 * 1000,
 *   });
 * }
 * ```
 * 
 * ### Relay JWT Validation (Relay Server)
 * 
 * ```typescript
 * // File: apps/relay/src/middleware/auth.ts
 * 
 * import jwt from 'jsonwebtoken';
 * 
 * interface RelayJWTPayload {
 *   username: string;
 *   userId: string;
 *   iss: string;
 *   aud: string;
 * }
 * 
 * export function verifyRelayJWT(authHeader: string | null): RelayJWTPayload | null {
 *   if (!authHeader?.startsWith('Bearer ')) {
 *     return null;
 *   }
 * 
 *   const token = authHeader.slice(7);
 *   const secret = process.env.RELAY_JWT_SECRET!;
 * 
 *   try {
 *     const payload = jwt.verify(token, secret, {
 *       audience: 'ilyazh-relay',
 *       issuer: 'ilyazh-web',
 *     }) as RelayJWTPayload;
 * 
 *     return payload;
 *   } catch (err) {
 *     console.error('[Auth] JWT verification failed:', err);
 *     return null;
 *   }
 * }
 * 
 * // Usage in relay endpoints
 * app.post('/message/:chatId', (req, res) => {
 *   const payload = verifyRelayJWT(req.headers.authorization);
 *   
 *   if (!payload) {
 *     return res.status(401).json({ error: 'Unauthorized' });
 *   }
 * 
 *   const { username } = payload;
 *   
 *   // Enforce membership
 *   if (!isMemberOfChat(username, req.params.chatId)) {
 *     return res.status(403).json({ error: 'Forbidden: Not a member' });
 *   }
 * 
 *   // Process message...
 * });
 * ```
 * 
 * ### Client Usage (Frontend)
 * 
 * ```typescript
 * // File: apps/web/lib/relay-jwt-manager.ts
 * 
 * interface RelayJWT {
 *   token: string;
 *   expiresAt: number;
 * }
 * 
 * let cachedJWT: RelayJWT | null = null;
 * 
 * export async function getRelayJWT(): Promise<string> {
 *   // Check cache
 *   if (cachedJWT && Date.now() < cachedJWT.expiresAt - 60000) {
 *     return cachedJWT.token;
 *   }
 * 
 *   // Fetch new JWT
 *   const res = await fetch('/api/relay/session', {
 *     method: 'POST',
 *     credentials: 'include', // Send Clerk cookie
 *   });
 * 
 *   if (!res.ok) {
 *     const { relayAuthController } = await import('./relay-auth-controller');
 *     relayAuthController.markFailed('Cannot obtain relay JWT', res.status);
 *     throw new Error('Relay authentication failed');
 *   }
 * 
 *   const { relayJWT, expiresAt } = await res.json();
 *   cachedJWT = { token: relayJWT, expiresAt };
 * 
 *   // Mark auth as verified
 *   const { relayAuthController } = await import('./relay-auth-controller');
 *   relayAuthController.markAuthenticated();
 * 
 *   return relayJWT;
 * }
 * 
 * export async function getRelayAuthHeaders(): Promise<HeadersInit> {
 *   const token = await getRelayJWT();
 *   return {
 *     'Authorization': `Bearer ${token}`,
 *     'Content-Type': 'application/json',
 *   };
 * }
 * ```
 * 
 * =============================================================================
 * 
 * ## DEPLOYMENT CHECKLIST
 * 
 * - [ ] Create `/api/relay/session` endpoint (issues relay JWT)
 * - [ ] Add `RELAY_JWT_SECRET` to env vars (must match relay)
 * - [ ] Create `relay-jwt-manager.ts` (client-side JWT caching)
 * - [ ] Update `identity.ts`: use `getRelayAuthHeaders()` (DONE)
 * - [ ] Update `prekeys.ts`: use `getRelayAuthHeaders()`
 * - [ ] Update `ratchet-refresh.ts`: remove "DEV mode continue", use JWT
 * - [ ] Update sync polling: abort on 403, use JWT
 * - [ ] Update relay server: implement `verifyRelayJWT()` middleware
 * - [ ] Test: Verify 401 → red banner → no messages sent
 * - [ ] Test: Verify handshake completes with valid JWT
 * 
 * =============================================================================
 * 
 * END OF DOCUMENT
 */
