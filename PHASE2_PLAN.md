# Phase 2: Group Chat Implementation Plan

## Objective
Enable end-to-end encrypted group messaging with same security guarantees as 1-on-1 chats.

## Architecture: Pairwise-with-Group-Agreement

### Key Principle
**Each participant encrypts independently to all group members** (like sending individual encrypted messages, but efficient).

### How It Works

```
Alice wants to send "Hello" to group {Alice, Bob, Charlie}

1. SYMMETRIC PHASE (once):
   plaintext = "Hello"
   messageKey = derive from Alice's sendChainKey
   nonce = [ratchetId || counter]
   aad = [version | suiteId | groupSessionId | sequence | ratchetId | flags]
   ciphertext = ChaCha20-Poly1305(plaintext, messageKey, nonce, aad)

2. ASYMMETRIC PHASE (once per recipient):
   For Bob:
     recipientKey = derive("chain-key/bob", groupRootKey)
     recipientNonce = randomBytes(12)
     recipientAAD = [aad + FLAG_RECIPIENT_WRAP + "bob"]
     wrappedForBob = ChaCha20-Poly1305(ciphertext, recipientKey, recipientNonce, recipientAAD)

   For Charlie:
     (same process with Charlie's keys)

3. SEND TO RELAY (single message with wrapped variants):
   POST /group/:groupId/message {
     type: "group_message",
     sender: "alice",
     message: {
       aad: base64(aad),              # Shared AAD
       nonce: base64(nonce),          # Shared nonce
       ciphertext: base64(...),       # Shared symmetric ciphertext
       recipients: {
         bob: {
           nonce: base64(...),        # Bob-specific wrap nonce
           ciphertext: base64(...)    # Bob-specific wrapped ciphertext
         },
         charlie: { ... }
       }
     }
   }

4. RELAY ROUTING:
   - Store message in group message queue
   - For each recipient with WebSocket connection: send to them
   - For offline recipients: store in mailbox

5. BOB RECEIVES:
   a) Unwrap recipient-specific ciphertext:
      recipientKey = derive("chain-key/bob", groupRootKey)  # Same as sender
      plaintext = ChaCha20-Poly1305.decrypt(
        recipientKey,
        recipient_nonce,
        wrappedForBob,
        recipient_aad
      )  # Result: shared ciphertext

   b) Decrypt group message:
      messageKey = derive from Alice's groupChainKey
      messageText = ChaCha20-Poly1305.decrypt(
        messageKey,
        nonce,
        plaintext,  # The shared ciphertext from step (a)
        aad
      )

   c) Update Alice's chain key for next message from her
      newAliceChainKey = HKDF(aliceChainKey, "ck", ...)
```

## Implementation Tasks

### Task 1: Update Relay for Group Messages
**File:** `apps/relay/src/index.ts`

```typescript
// New endpoint: POST /group/:groupId/message
// Input format (from browser):
interface GroupMessageInput {
  type: 'group_message';
  sender: string;
  message: {
    aad: string;                    // base64
    nonce: string;                  // base64
    ciphertext: string;             // base64
    recipients: {
      [username: string]: {
        nonce: string;              // base64
        ciphertext: string;         // base64
      };
    };
  };
}

// Implementation steps:
// 1. Validate groupId format (same as chatId)
// 2. Authenticate sender (JWT or username)
// 3. Verify sender is group member
// 4. For each recipient:
//    - If connected via WebSocket: send instantly
//    - Else: store in group message queue
// 5. Return success + delivery status
```

### Task 2: Store Group Message State
**File:** `apps/relay/src/index.ts`

Add in-memory group tracking:

```typescript
// Group metadata storage
interface GroupMetadata {
  groupId: string;
  groupName: string;
  creatorUsername: string;
  participants: string[];
  createdAt: number;
  version: number;  // Increments on rekey
}

// Group sessions (parallel to CHAT_SESSIONS for 1-on-1)
const GROUP_SESSIONS = new Map<string, GroupMetadata>();

// Group messages (for offline delivery)
const GROUP_MESSAGE_QUEUES = new Map<string, any[]>();
```

### Task 3: Update WebSocket Manager
**File:** `apps/relay/src/websocket.ts`

Extend WebSocketManager to handle group messages:

```typescript
// New message type in handleMessage()
case 'group_message':
  return this.handleGroupMessage(senderUsername, message);

// New method
private handleGroupMessage(sender: string, msg: WSMessage) {
  const groupId = msg.chatId;  // Reuse chatId for group ID
  const groupMessage = msg.content;  // Contains recipients, wrapped ciphertexts

  // For each recipient:
  for (const [recipientUsername, wrappedData] of Object.entries(groupMessage.recipients)) {
    // Send to recipient if connected
    const recipientClient = this.clients.get(recipientUsername);
    if (recipientClient) {
      this.sendToClient(recipientUsername, {
        type: 'message',
        chatId: groupId,
        senderId: sender,
        content: {
          aad: groupMessage.aad,
          nonce: groupMessage.nonce,
          ciphertext: groupMessage.ciphertext,
          recipient: wrappedData
        }
      });
    } else {
      // Queue for offline delivery
      if (!GROUP_MESSAGE_QUEUES.has(groupId)) {
        GROUP_MESSAGE_QUEUES.set(groupId, []);
      }
      GROUP_MESSAGE_QUEUES.get(groupId)!.push({
        sender,
        recipient: recipientUsername,
        wrappedData,
        groupMessage,
        timestamp: Date.now()
      });
    }
  }

  return { delivered: recipientCount };
}
```

### Task 4: Create Group Chat Types
**File:** `apps/web/lib/group-chat.ts` (new file)

```typescript
// Group chat state management
export interface GroupChat {
  groupId: string;
  groupName: string;
  participants: string[];
  createdAt: number;
  myRole: 'admin' | 'member';
  // Session state (parallel to 1-on-1)
  groupSessionId?: string;
  groupRootKey?: Uint8Array;
  participantChainKeys: Map<string, Uint8Array>;  // username -> chain key
  ratchetId: bigint;
  messageCounter: number;
}

// Group creation input
export interface CreateGroupInput {
  groupName: string;
  participants: string[];  // Exclude self
}

// Establish group session
export async function establishGroupSession(
  groupId: string,
  groupName: string,
  myUsername: string,
  myIdentity: IdentityKeyPair,
  participantIdentities: Map<string, { ed25519: Uint8Array; mldsa: Uint8Array }>
): Promise<GroupChat> {
  // 1. For each participant, fetch their prekey and do pairwise handshake
  const pairwiseHandshakes = [];
  for (const [participant, identity] of participantIdentities) {
    const prekey = await fetchPeerBundle(participant);
    const { message, ...ephemeralSecrets } = await initiateHandshake(
      myIdentity,
      identity.ed25519,
      identity.mldsa,
      prekey
    );

    pairwiseHandshakes.push({
      participantUsername: participant,
      transcript: buildTranscript(message, /* ... */),
      ...ephemeralSecrets
    });
  }

  // 2. Derive group session from all pairwise transcripts
  const groupState = deriveGroupSession(
    groupId,
    groupName,
    myUsername,
    myIdentity,
    pairwiseHandshakes
  );

  // 3. Convert to GroupChat and store
  const groupChat: GroupChat = {
    groupId,
    groupName,
    participants: Array.from(participantIdentities.keys()),
    createdAt: Date.now(),
    myRole: 'admin',  // Creator is admin
    groupSessionId: groupState.sessionId,
    groupRootKey: groupState.rootKey,
    participantChainKeys: new Map(
      groupState.participants.map(p => [p.username, p.groupChainKey])
    ),
    ratchetId: groupState.sendRatchetId,
    messageCounter: 0
  };

  // Store to IndexedDB (similar to 1-on-1 sessions)
  await storeGroupChat(groupChat);

  return groupChat;
}

// Encrypt for group
export async function encryptGroupMessageForSending(
  groupChat: GroupChat,
  plaintext: Uint8Array
): Promise<{
  sharedMessage: { aad: string; nonce: string; ciphertext: string };
  recipientWraps: Map<string, { nonce: string; ciphertext: string }>;
}> {
  // Follow protocol above:
  // 1. Single symmetric encryption
  // 2. Per-recipient AEAD wraps
  // Return both
}

// Decrypt for group
export async function decryptGroupMessage(
  groupChat: GroupChat,
  senderUsername: string,
  sharedMessage: { aad: string; nonce: string; ciphertext: string },
  myRecipientWrap: { nonce: string; ciphertext: string }
): Promise<Uint8Array> {
  // Follow protocol above:
  // 1. Unwrap with my recipient key
  // 2. Decrypt shared message with sender's chain key
  // 3. Update sender's chain key
  // Return plaintext
}
```

### Task 5: Create Group Chat UI Page
**File:** `apps/web/app/groups/[groupId]/page.tsx` (new page)

Similar to `/chat/page.tsx` but:
- Display all group members with online status
- Show group typing indicators ("alice and bob are typing...")
- Use `encryptGroupMessageForSending()` instead of `encryptMessage()`
- Use `decryptGroupMessage()` for incoming
- Subscribe to group via WebSocket: `subscribeToChat(groupId)`

### Task 6: Create Group List Page
**File:** `apps/web/app/groups/page.tsx` (new page)

- List all groups user is member of
- Show member count, last message, last activity
- "Create Group" button → dialog
- Click group → navigate to `/groups/[groupId]`

### Task 7: Create Group Dialog
**Component:** `apps/web/components/CreateGroupDialog.tsx` (new)

- Search and select participants (multiselect)
- Input group name
- Show selected members
- "Create" button
  - Call `establishGroupSession()`
  - Store in IndexedDB
  - Navigate to group page

## Testing Checklist

### Manual Testing
- [ ] Create group with 3 members
- [ ] Member 1 sends message → both 2 and 3 receive
- [ ] Member 2 sends → both 1 and 3 receive
- [ ] Member 3 sends → both 1 and 2 receive
- [ ] Typing indicators in group (show all typing users)
- [ ] Read receipts show per-member status
- [ ] Group member becomes offline → presence updates
- [ ] Offline member rejoins → receives queued messages

### Load Testing
- [ ] 10-person group, rapid message sending
- [ ] 50-person group, typing indicators
- [ ] Message delivery latency < 100ms

## Phase 2 Effort Estimate
- Task 1-2: Relay updates = 2 hours
- Task 3: WebSocket integration = 1 hour
- Task 4: Crypto integration = 2 hours
- Task 5-7: UI components = 3 hours
- Testing & fixes = 2 hours

**Total: ~10 hours** for MVP group chat

## Success Criteria
✅ Create group with N participants
✅ Send encrypted message to entire group
✅ All members receive and decrypt message
✅ Typing indicators work in group
✅ Read receipts show per-member status
✅ Offline member joins → gets previous messages
✅ All messages end-to-end encrypted
✅ Performance: < 100ms delivery, < 10MB per group per hour

---

**Next Phase:** Phase 3 - Security Hardening (JWT auth, rate limiting, audit logs)
