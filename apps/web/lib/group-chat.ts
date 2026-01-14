'use client';

/**
 * Group Chat Management
 * Handles group creation, session establishment, and message encryption
 */

import type { GroupRatchetState, GroupParticipant, IdentityKeyPair, PrekeyBundle } from '@/lib/crypto';
import * as protocolCrypto from '@/lib/crypto';
import { getSecureRandomBytes } from '@/lib/runtime/secure-random';

/**
 * Group chat state stored in IndexedDB
 */
export interface StoredGroupChat {
  groupId: string;
  groupName: string;
  participants: string[]; // usernames
  createdAt: number;
  myRole: 'admin' | 'member';
  // Encrypted session state
  groupSessionId?: string;
  groupRootKey?: string; // base64 encoded
  participantChainKeys?: Record<string, string>; // base64 encoded
  ratchetId: number;
  messageCounter: number;
}

const DB_NAME = 'ilyazh-groupchat-v1';
const STORE_NAME = 'groups';

/**
 * Open IndexedDB for group chats
 */
async function getGroupChatDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'groupId' });
      }
    };
  });
}

/**
 * Save group chat to IndexedDB
 */
export async function storeGroupChat(group: StoredGroupChat): Promise<void> {
  const db = await getGroupChatDB();
  const transaction = db.transaction([STORE_NAME], 'readwrite');
  const store = transaction.objectStore(STORE_NAME);

  return new Promise((resolve, reject) => {
    const request = store.put(group);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();
  });
}

/**
 * Load group chat from IndexedDB
 */
export async function loadGroupChat(groupId: string): Promise<StoredGroupChat | null> {
  const db = await getGroupChatDB();
  const transaction = db.transaction([STORE_NAME], 'readonly');
  const store = transaction.objectStore(STORE_NAME);

  return new Promise((resolve, reject) => {
    const request = store.get(groupId);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result || null);
  });
}

/**
 * List all group chats
 */
export async function listGroupChats(): Promise<StoredGroupChat[]> {
  const db = await getGroupChatDB();
  const transaction = db.transaction([STORE_NAME], 'readonly');
  const store = transaction.objectStore(STORE_NAME);

  return new Promise((resolve, reject) => {
    const request = store.getAll();
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
}

/**
 * Delete group chat
 */
export async function deleteGroupChat(groupId: string): Promise<void> {
  const db = await getGroupChatDB();
  const transaction = db.transaction([STORE_NAME], 'readwrite');
  const store = transaction.objectStore(STORE_NAME);

  return new Promise((resolve, reject) => {
    const request = store.delete(groupId);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();
  });
}

/**
 * Create a new group chat
 */
export async function createGroupChat(
  groupId: string,
  groupName: string,
  myUsername: string,
  myIdentity: IdentityKeyPair,
  participantIdentities: Map<string, { ed25519: Uint8Array; mldsa: Uint8Array }>
): Promise<StoredGroupChat> {
  // Create mock pairwise handshakes for each participant
  // In production, would do real X3DH handshakes
  const pairwiseHandshakes = Array.from(participantIdentities.entries()).map(([username, identity]) => ({
    participantUsername: username,
    transcript: new Uint8Array(64), // Mock transcript
    ephemeralX25519Secret: new Uint8Array(32),
    ephemeralMLKEMSecret: new Uint8Array(2400),
  }));

  // Derive group session
  const groupState = protocolCrypto.deriveGroupSession(groupId, groupName, myUsername, myIdentity, pairwiseHandshakes);

  // Store as StoredGroupChat
  const storedGroup: StoredGroupChat = {
    groupId,
    groupName,
    participants: Array.from(participantIdentities.keys()),
    createdAt: Date.now(),
    myRole: 'admin',
    groupSessionId: Buffer.from(groupState.sessionId).toString('hex'),
    groupRootKey: Buffer.from(groupState.rootKey).toString('base64'),
    participantChainKeys: Object.fromEntries(
      groupState.participants.map((p) => [p.username, Buffer.from(p.groupChainKey).toString('base64')])
    ),
    ratchetId: Number(groupState.sendRatchetId),
    messageCounter: 0,
  };

  await storeGroupChat(storedGroup);

  console.log(`[GroupChat] ✅ Created group: ${groupName} (${groupId.slice(0, 12)}...)`);

  return storedGroup;
}

/**
 * Helper: Convert base64 to Uint8Array
 */
function base64ToUint8(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Helper: Convert Uint8Array to base64
 */
function uint8ToBase64(arr: Uint8Array): string {
  const binary = String.fromCharCode.apply(null, Array.from(arr));
  return btoa(binary);
}

/**
 * Encrypt message for group sending
 */
export async function encryptForGroup(
  groupChat: StoredGroupChat,
  plaintext: Uint8Array
): Promise<{
  aad: string;
  nonce: string;
  ciphertext: string;
  recipients: Record<string, { nonce: string; ciphertext: string }>;
}> {
  // Convert stored group to GroupRatchetState format
  const groupState: any = {
    groupId: groupChat.groupId,
    groupName: groupChat.groupName,
    groupCreatedAt: groupChat.createdAt,
    groupVersion: 1,
    sessionId: base64ToUint8(groupChat.groupSessionId || ''),
    rootKey: base64ToUint8(groupChat.groupRootKey || ''),
    sendRatchetId: BigInt(groupChat.ratchetId),
    sendChainKey: new Uint8Array(), // Would be derived in full impl
    sendCounter: groupChat.messageCounter,
    groupTotalMessages: groupChat.messageCounter,
    participants: groupChat.participants.map((username) => ({
      username,
      groupChainKey: base64ToUint8(groupChat.participantChainKeys?.[username] || ''),
    })),
  };

  const result = await protocolCrypto.encryptGroupMessage(groupState, plaintext);

  // Convert to base64 for transmission
  return {
    aad: uint8ToBase64(result.aad),
    nonce: uint8ToBase64(result.nonce),
    ciphertext: uint8ToBase64(result.ciphertext),
    recipients: Object.fromEntries(
      Array.from(result.perRecipientWraps.entries()).map(([username, wrap]) => [
        username,
        {
          nonce: uint8ToBase64(wrap.nonce),
          ciphertext: uint8ToBase64(wrap.ciphertext),
        },
      ])
    ),
  };
}

/**
 * Decrypt message from group
 */
export async function decryptFromGroup(
  groupChat: StoredGroupChat,
  senderUsername: string,
  message: {
    aad: string;
    nonce: string;
    ciphertext: string;
    recipient: { nonce: string; ciphertext: string };
  }
): Promise<Uint8Array> {
  // Convert to expected format
  const sharedMessage = {
    ciphertext: base64ToUint8(message.ciphertext),
    nonce: base64ToUint8(message.nonce),
    aad: base64ToUint8(message.aad),
  };

  const myRecipientWrap = {
    nonce: base64ToUint8(message.recipient.nonce),
    ciphertext: base64ToUint8(message.recipient.ciphertext),
  };

  // For MVP, just return the plaintext directly
  // In production, would do full decryption with chain keys
  return sharedMessage.ciphertext;
}

/**
 * Generate deterministic group ID from participant list
 */
export function generateGroupId(groupName: string, participants: string[]): string {
  // Sort participants for determinism
  const sorted = [groupName, ...participants].sort();
  const message = sorted.join(':');

  // Synchronous hash using base64 (deterministic but not cryptographic for browser)
  // Use Node.js crypto for server-side, base64 for browser
  if (typeof window === 'undefined') {
    // Node.js environment
    try {
      const { createHash } = require('crypto');
      return createHash('sha256').update(message).digest('hex');
    } catch {
      return Buffer.from(message).toString('hex');
    }
  } else {
    // Browser environment - use deterministic base64 hash for now
    // TODO: Use crypto.subtle.digest() but would need to be async
    return Buffer.from(message).toString('base64').slice(0, 64);
  }
}

/**
 * Generate random group ID (SYNCHRONOUS).
 * Uses cryptographically secure random bytes from secure-random abstraction.
 * 
 * @returns 64-character hex string (32 bytes)
 */
export function generateRandomGroupId(): string {
  const bytes = getSecureRandomBytes(32);
  
  // Convert to hex string
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('hex');
  }
  
  // Browser fallback
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}
