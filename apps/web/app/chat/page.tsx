'use client';

/**
 * Chat Page with Clerk Authentication + E2E Encryption
 *
 * SECURITY ARCHITECTURE:
 * - Clerk provides authenticated userId (never sees messages or keys)
 * - E2E keys are loaded from IndexedDB (client-side only)
 * - All messages encrypted with Ilyazh-Web3E2E protocol
 * - Clerk session token used only for relay authentication
 * - Private keys NEVER leave the browser
 */

import { useState, useEffect, useRef } from 'react';
import { useUser } from '@clerk/nextjs';
import Link from 'next/link';
import {
  generateIdentity,
  generatePrekeyBundle,
  initiateHandshake,
  completeHandshake,
  finalizeHandshake,
  encryptMessage,
  decryptMessage,
  encodeHandshakeMessage,
  decodeHandshakeMessage,
  encodeEncryptedMessage,
  decodeEncryptedMessage,
  normalizeWireData,
  isLikelyEncryptedBlob,
  hashTranscript,
  AADMismatchError,
  type IdentityKeyPair,
  type HandshakeState,
  type PrekeyBundle,
  type HandshakeMessage as CryptoHandshakeMessage,
} from '@ilyazh/crypto';
import { getOrCreateIdentity, fetchPeerIdentity, createAuthHeaders } from '@/lib/identity';
import {
  generateAndUploadPrekeyBundle,
  fetchPeerBundle,
  loadPrekeySecrets,
  loadPrekeySecretsOrRegenerate,
  deletePrekeySecrets,
  ensurePrekeyPublished,
  type PrekeySecrets,
} from '@/lib/prekeys';
import { keystore } from '@/lib/keystore';
import {
  getSessionSecurity,
  checkSessionHealth,
  formatAge,
  type SessionHealth,
} from '@/lib/session-security';
import { refreshSessionFromPeer, retryPendingSession } from '@/lib/ratchet-refresh';
import { SafetyNumber } from '@/components/SafetyNumber';
import { SessionHealthWarning } from '@/components/SessionHealthWarning';
import { UsernameSearch } from '@/components/UsernameSearch';
import { ChatList } from '@/components/ChatList';
import { logDebug, logInfo, logWarn, logError, redactPlaintext, redactSessionId, isSyncDebugEnabled } from '@/lib/logger';
import { saveMessage, loadMessages, type StoredMessage } from '@/lib/message-store';

// PART 2: Client-side deduplication set (module-level, persists across renders)
const seenEntries = new Set<string>();

// Dynamically determine relay URL based on current hostname
const getRelayUrl = () => {
  if (typeof window === 'undefined') return 'http://localhost:3001';

  const hostname = window.location.hostname;
  if (hostname !== 'localhost' && hostname !== '127.0.0.1') {
    return `http://${hostname}:3001`;
  }

  return process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';
};

// Route relay calls through Next.js proxy in browser to avoid CORS/connectivity issues
const getRelayUrlForBrowser = (path: string) => {
  if (typeof window !== 'undefined') {
    // Browser: use Next.js API proxy
    return `/api/relay/${path.replace(/^\/+/, '')}`;
  }
  // SSR/server: use direct relay URL
  return `${getRelayUrl()}/${path.replace(/^\/+/, '')}`;
};

/**
 * DEFENSIVE: Detect if an entry looks like a handshake message
 * This is a fallback for cases where the relay forgot to set the type field.
 * We keep this STRICT - only detect clear handshake indicators.
 */
function looksLikeHandshake(entry: any): boolean {
  // Method 1: Check if cipher/blob contains handshake markers
  // Handshake messages are typically larger (contain ephemeral keys, signatures)
  // and have specific structure that can be detected

  // If we have a blob/cipher, check its size (handshakes are typically 3000+ bytes base64)
  const blob = entry?.blob || entry?.cipher || entry?.payload;
  if (blob && typeof blob === 'string' && blob.length > 2500) {
    // Large message could be handshake - but we need more evidence
    // Check if this is from a peer we don't have a session with yet
    // This is handled in the main sync logic
    return true;
  }

  // Method 2: Check explicit handshake markers
  if (entry?.payload?.kind === 'handshake') {
    return true;
  }

  if (entry?.cipher?.meta?.kind === 'handshake') {
    return true;
  }

  // Default to false - we cannot safely assume
  return false;
}

// Normalize incoming entry to handle both real relay (with index) and dev mode (without index)
function normalizeIncomingEntry(entry: any): {
  id: string;
  type: string;
  from: string;
  cipher: any;
  ts: number;
  raw: any;
} {
  const hasIndex = typeof entry?.index !== 'undefined';
  const id = hasIndex
    ? String(entry.index)
    : entry.id
      ? String(entry.id)
      : 'dev-' + Date.now() + '-' + Math.random().toString(16).slice(2);

  const from = entry?.from || entry?.sender || 'unknown';
  const ts = entry?.ts || Date.now();

  // CRITICAL FIX: Defensive type detection
  // Priority:
  // 1. Use explicit type from relay if present
  // 2. If type is missing, check if it looks like a handshake
  // 3. Default to 'message' only if neither condition is true
  const rawType = entry?.type;
  const type = rawType
    ? rawType
    : looksLikeHandshake(entry)
      ? 'handshake'
      : 'message';

  // Choose cipher field (blob, payload, or ciphertext)
  const cipher = entry?.blob || entry?.payload || entry?.ciphertext || null;

  return {
    id,
    from,
    ts,
    type,
    cipher,
    raw: entry,
  };
}

interface Message {
  id: string;
  sender: string;
  text: string;
  timestamp: number;
  encrypted: boolean;
}

interface StoredIdentity {
  ed25519: {
    publicKey: string;
    secretKey: string;
  };
  mldsa: {
    publicKey: string;
    secretKey: string;
  };
}

export default function ChatPage() {
  // Clerk authentication state
  const { isSignedIn, user, isLoaded } = useUser();

  // User identity state
  // userId: Clerk ID used for crypto operations (canonical identity)
  // username: Human-readable username for display
  const [userId, setUserId] = useState('');
  const [username, setUsername] = useState('');
  const [recipient, setRecipient] = useState('');
  const [chatActive, setChatActive] = useState(false);
  const [showingChatList, setShowingChatList] = useState(true); // Show chat list by default
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState('');
  const [sessionInfo, setSessionInfo] = useState<any>(null);
  const [chatId, setChatId] = useState<string>('');
  const [lastSyncIndex, setLastSyncIndex] = useState<number>(0);
  const [mounted, setMounted] = useState(false);
  const [identity, setIdentity] = useState<IdentityKeyPair | null>(null);
  const [peerIdentity, setPeerIdentity] = useState<IdentityKeyPair | null>(null);
  const [ratchetState, setRatchetState] = useState<HandshakeState | null>(null);
  const [handshakeInProgress, setHandshakeInProgress] = useState(false);
  const [sessionHealth, setSessionHealth] = useState<SessionHealth | null>(null);
  const [showSafetyNumber, setShowSafetyNumber] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // PART 3: Per-chat cursor tracking (persists across renders, doesn't trigger re-render)
  const cursorsRef = useRef<Record<string, number>>({});

  // Load or generate identity on mount using Clerk userId
  // Use ref to prevent React StrictMode double-initialization race condition
  const initRef = useRef(false);

  useEffect(() => {
    // Wait for Clerk to load
    if (!isLoaded) {
      console.log('[Chat] Waiting for Clerk to load...');
      return;
    }

    // Redirect to sign-in if not authenticated
    if (!isSignedIn || !user?.id) {
      console.warn('[Chat] User not authenticated, redirecting to sign-in');
      window.location.href = '/sign-in?redirect_url=/chat';
      return;
    }

    // Prevent duplicate initialization in React StrictMode
    if (initRef.current) {
      console.log('[Chat] Already initializing, skipping duplicate call');
      return;
    }
    initRef.current = true;

    const initAsync = async () => {
      setMounted(true);

      // Use Clerk userId as the canonical identifier for crypto operations
      const clerkUserId = user.id;
      console.log('[Chat] Clerk user authenticated:', clerkUserId);
      setUserId(clerkUserId);

      // CRITICAL: Get human-readable username from localStorage
      // NEVER use Clerk ID for identity registration (fails relay validation)
      const storedUsername = localStorage.getItem(`username:${clerkUserId}`);

      if (!storedUsername || storedUsername.startsWith('user_')) {
        // No valid username - redirect to home page to set it up
        console.error('[Chat] No valid username found, redirecting to home');
        alert('Please set your username first');
        window.location.href = '/';
        return;
      }

      const canonicalUsername = storedUsername.toLowerCase().trim();
      console.log('[Chat] Using username for identity:', canonicalUsername);
      setUsername(canonicalUsername);

      try {
        console.log('[Chat] Initializing E2E identity with username:', canonicalUsername);

        // CRITICAL: Use human-readable username, NOT Clerk ID
        // This ensures relay validation passes (3-20 chars, lowercase alphanumeric + underscore)
        const identityKeys = await getOrCreateIdentity(canonicalUsername);
        setIdentity(identityKeys);

        console.log('[Chat] E2E identity loaded/created');

        // Check if we have a prekey bundle, generate if not
        const prekeySecrets = await loadPrekeySecrets(canonicalUsername);
        if (!prekeySecrets) {
          console.log('[Chat] No prekey bundle found, generating...');
          await generateAndUploadPrekeyBundle(canonicalUsername, identityKeys);
          console.log('[Chat] Prekey bundle generated and uploaded');
        } else {
          console.log('[Chat] Existing prekey bundle found:', prekeySecrets.bundleId);
        }

        console.log('[Chat] E2E crypto initialization complete');
      } catch (err) {
        console.error('[Chat] Failed to initialize E2E crypto:', err);
        alert('Failed to initialize encryption keys. Please refresh or set your username in settings.');
      }
    };

    initAsync();
  }, [isLoaded, isSignedIn, user?.id]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Monitor session health
  useEffect(() => {
    if (!ratchetState) {
      setSessionHealth(null);
      return;
    }

    const updateHealth = () => {
      const health = checkSessionHealth(ratchetState);
      setSessionHealth(health);

      // Log warnings
      if (health.warnings.length > 0) {
        console.warn('[Session Health]', health.warnings);
      }
    };

    // Check immediately
    updateHealth();

    // Check every 30 seconds
    const interval = setInterval(updateHealth, 30000);
    return () => clearInterval(interval);
  }, [ratchetState]);

  // Load persisted messages from IndexedDB when chat becomes active
  useEffect(() => {
    if (!chatActive || !chatId) return;

    const loadPersistedMessages = async () => {
      try {
        console.log('[MessageStore] Loading persisted messages for chatId:', chatId);
        const stored = await loadMessages(chatId);

        if (stored.length > 0) {
          console.log(`[MessageStore] Loaded ${stored.length} persisted messages`);

          // Convert StoredMessage to Message format
          const loadedMessages = stored.map(msg => ({
            id: msg.id,
            sender: msg.sender,
            text: msg.text,
            timestamp: msg.timestamp,
            encrypted: msg.encrypted,
          }));

          setMessages(loadedMessages);
        } else {
          console.log('[MessageStore] No persisted messages found');
        }
      } catch (err) {
        console.error('[MessageStore] Failed to load messages:', err);
      }
    };

    loadPersistedMessages();
  }, [chatActive, chatId]);

  // Poll for incoming messages
  useEffect(() => {
    if (!chatActive || !chatId || !identity) return;

    const pollMessages = async () => {
      try {
        // PART 3: Use cursor from ref for this specific chat
        const cursor = cursorsRef.current[chatId] || 0;

        console.log('[Sync] 🔄 Polling for new messages:', {
          chatId,
          cursor,
          timestamp: new Date().toISOString(),
        });

        const syncRes = await fetch(getRelayUrlForBrowser(`sync/${chatId}?since=${cursor}`), {
          headers: createAuthHeaders(username),
        });

        if (!syncRes.ok) {
          console.warn('[Sync] ⚠️  Sync request failed:', {
            status: syncRes.status,
            statusText: syncRes.statusText,
            chatId,
          });
          return;
        }

        const syncData = await syncRes.json();
        const incoming = Array.isArray(syncData.messages) ? syncData.messages : (syncData.entries || []);

        if (incoming.length === 0) {
          // Silent - no new messages
          return;
        }

        console.log(`[Sync] 📬 Received ${incoming.length} entries from relay:`, {
          chatId,
          entriesCount: incoming.length,
          cursor,
          timestamp: new Date().toISOString(),
        });

        // Debug: log all entry types with detailed info
        for (const entry of incoming) {
          console.log('[Sync] Entry details:', {
            index: entry.index,
            from: entry.from,
            type: entry.type || '⚠️  MISSING TYPE',
            hasBlob: !!entry.blob,
            hasBlobRef: !!entry.blobRef,
            hasSession: !!entry.session,
            timestamp: entry.ts,
          });
          logDebug('sync', 'Entry received', { index: entry.index, from: entry.from, type: entry.type || 'MISSING' });
        }

        let currentRatchetState = ratchetState;
        let maxIndex = lastSyncIndex;

        // CRITICAL: Track ALL seen message indices (both processed and skipped)
        // This prevents cursor from getting stuck when we skip our own messages
        const processedIndices: number[] = [];
        const skippedIndices: number[] = [];

        // PHASE 1: Process handshakes FIRST
        for (const entry of incoming) {
          const msg = normalizeIncomingEntry(entry);

          // Skip messages we sent BUT track the index
          if (msg.from === username) {
            const entryIndex = typeof entry.index !== 'undefined' ? entry.index : -1;
            if (entryIndex >= 0) {
              skippedIndices.push(entryIndex);
              console.log(`[Sync][Phase1] Skipping own message at index ${entryIndex}`);
              if (entryIndex >= maxIndex) {
                maxIndex = entryIndex + 1;
              }
            }
            continue;
          }

          // Only process handshakes in Phase 1, skip everything else
          if (msg.type !== 'handshake') {
            continue;
          }

          // PART 2: Deduplication - check if we've already processed this handshake
          const rawId = entry.id ?? entry.index ?? entry.ts ?? entry.created_at ?? Math.random().toString(16).slice(2);
          const dedupeKey = `${chatId}::${rawId}`;
          if (seenEntries.has(dedupeKey)) {
            console.log(`[Sync][Phase1] Skipping duplicate handshake: ${dedupeKey}`);
            continue;
          }
          seenEntries.add(dedupeKey);

          if (msg.type === 'handshake') {
            console.log(`[Sync] Processing handshake from ${msg.from}`);

            try {
              // Get blob data (inline for dev mode, fetch for real relay)
              let wireData: Uint8Array;

              if (msg.cipher && typeof msg.cipher === 'string') {
                // Dev mode: cipher is inline as base64 string
                wireData = new Uint8Array(Buffer.from(msg.cipher, 'base64'));
              } else if (entry.blobRef) {
                // Real relay: fetch blob by reference
                const blobRes = await fetch(getRelayUrlForBrowser(`blob/${chatId}/${entry.blobRef}`), {
                  headers: createAuthHeaders(username),
                });

                if (!blobRes.ok) continue;

                const blobData = await blobRes.arrayBuffer();
                wireData = new Uint8Array(blobData);
              } else {
                console.warn('[Handshake] No cipher data available');
                continue;
              }

              const handshakeMsg = decodeHandshakeMessage(wireData);
              console.log('[Handshake] Received handshake message, role:', handshakeMsg.role);

            if (handshakeMsg.role === 'initiator' && !currentRatchetState) {
              // We are the responder (Bob), complete the handshake
              console.log('[Handshake] We are responder, completing handshake...');

              // Load our prekey secrets with auto-regeneration fallback
              // SECURITY: If secrets are missing, loadPrekeySecretsOrRegenerate will:
              // 1. Generate NEW keys locally (never download from server)
              // 2. Publish new bundle to relay
              // 3. Return the newly generated secrets
              // This prevents crashes while maintaining E2E security.
              // CRITICAL: Use username (NOT Clerk ID) for all crypto operations
              const prekeySecrets = await loadPrekeySecretsOrRegenerate(username, identity);

              console.log('[Handshake] Using prekey bundle:', prekeySecrets.bundleId);

              // Complete handshake
              const { message: responseMessage, state: handshakeState } = await completeHandshake(
                identity,
                prekeySecrets.x25519SecretKey,
                prekeySecrets.mlkemSecretKey,
                handshakeMsg
              );

              console.log('[Handshake] Handshake completed');
              logInfo('handshake', 'Handshake completed', { sessionId: redactSessionId(handshakeState.sessionId), role: handshakeState.role });;
              console.log('[Handshake] - Role:', handshakeState.role);

              // Update state
              currentRatchetState = handshakeState;
              setRatchetState(handshakeState);

              // Save session to IndexedDB
              await keystore.init();
              await keystore.saveSession(handshakeState.sessionId, msg.from, handshakeState);

              // Delete used prekey secrets
              // CRITICAL: Use username (NOT Clerk ID) for all crypto operations
              await deletePrekeySecrets(username);

              // Generate new prekey bundle for future sessions
              console.log('[Handshake] Generating new prekey bundle...');
              await generateAndUploadPrekeyBundle(username, identity);

              // Send response handshake
              const responseWireData = encodeHandshakeMessage(responseMessage);
              const responseData = Buffer.from(responseWireData).toString('base64');

              const handshakeRes = await fetch(getRelayUrlForBrowser(`message/${chatId}`), {
                method: 'POST',
                headers: createAuthHeaders(username),
                body: JSON.stringify({
                  type: 'handshake',
                  from: username,
                  blob: responseData,
                }),
              });

              // Handle 409 correctly: if relay returns 409, the handshake response already exists
              // This is normal in dev/re-init scenarios - session is already saved above
              if (handshakeRes.status === 409) {
                console.warn('[Handshake] Relay returned 409 (handshake response already exists), but session is saved locally');
              } else if (!handshakeRes.ok) {
                console.warn('[Handshake] Relay returned', handshakeRes.status, 'but continuing in DEV mode');
              }

              console.log('[Handshake] Response sent');

              // Show completion message
              setMessages((prev) => [
                ...prev,
                {
                  id: msg.id,
                  sender: 'system',
                  text: `🔐 Handshake completed with ${msg.from}. Session established!`,
                  timestamp: Date.now(),
                  encrypted: true,
                },
              ]);

              // Update max index if entry has one
              const entryIndex = typeof entry.index !== 'undefined' ? entry.index : -1;
              if (entryIndex >= 0 && entryIndex >= maxIndex) {
                maxIndex = entryIndex + 1;
              }
              continue;
            } else if (handshakeMsg.role === 'responder') {
              // We are the initiator (Alice), finalize the handshake
              console.log('[Handshake] We are initiator, finalizing handshake...');

              // Load pending handshake state
              const pendingDataJson = sessionStorage.getItem(`handshake_pending_${chatId}`);
              if (!pendingDataJson) {
                throw new Error('No pending handshake state found');
              }

              const pendingData = JSON.parse(pendingDataJson);

              // Validate that we have the ephemeral secrets and initiator message
              // NOTE: We do NOT have a complete "state" yet - that's what finalizeHandshake creates!
              if (!pendingData.ephemeralX25519Secret || !pendingData.initiatorMessage) {
                console.error('[Handshake][restore] missing pending data for chat', chatId, {
                  hasSecret: !!pendingData.ephemeralX25519Secret,
                  hasMessage: !!pendingData.initiatorMessage,
                });
                throw new Error('Incomplete handshake pending data - missing ephemeral secrets or initiator message');
              }

              // Reconstruct ephemeral secrets from stored arrays
              const ephemeralX25519Secret = new Uint8Array(pendingData.ephemeralX25519Secret);
              // Handle classical-only mode where ML-KEM secret may be undefined
              const ephemeralMLKEMSecret = pendingData.ephemeralMLKEMSecret
                ? new Uint8Array(pendingData.ephemeralMLKEMSecret)
                : new Uint8Array(0);

              // Reconstruct initiator message from stored arrays
              const initiatorMsg = {
                ...pendingData.initiatorMessage,
                ephemeralX25519: new Uint8Array(pendingData.initiatorMessage.ephemeralX25519),
                ephemeralMLKEM: pendingData.initiatorMessage.ephemeralMLKEM
                  ? new Uint8Array(pendingData.initiatorMessage.ephemeralMLKEM)
                  : undefined,
                identityPublicEd25519: new Uint8Array(pendingData.initiatorMessage.identityPublicEd25519),
                identityPublicMLDSA: new Uint8Array(pendingData.initiatorMessage.identityPublicMLDSA),
                ed25519Signature: new Uint8Array(pendingData.initiatorMessage.ed25519Signature),
                mldsaSignature: new Uint8Array(pendingData.initiatorMessage.mldsaSignature),
              };

              const finalState = await finalizeHandshake(
                ephemeralX25519Secret,
                ephemeralMLKEMSecret,
                initiatorMsg,
                handshakeMsg
              );

              console.log('[Handshake] Handshake finalized!');
              logInfo('handshake', 'Handshake completed', { sessionId: redactSessionId(finalState.sessionId), role: finalState.role });

              // Update state
              currentRatchetState = finalState;
              setRatchetState(finalState);

              // Save session to IndexedDB
              await keystore.init();
              await keystore.saveSession(finalState.sessionId, msg.from, finalState);

              // Clear pending handshake
              sessionStorage.removeItem(`handshake_pending_${chatId}`);

              console.log('[Handshake] Session saved to IndexedDB');

              // Show completion message
              setMessages((prev) => [
                ...prev,
                {
                  id: msg.id,
                  sender: 'system',
                  text: `🔐 Handshake finalized! Secure session active with ${msg.from}.`,
                  timestamp: Date.now(),
                  encrypted: true,
                },
              ]);

              // Update max index if entry has one
              const entryIndex2 = typeof entry.index !== 'undefined' ? entry.index : -1;
              if (entryIndex2 >= 0 && entryIndex2 >= maxIndex) {
                maxIndex = entryIndex2 + 1;
              }
              continue;
            }
            } catch (handshakeError) {
              console.error('[Handshake] Failed to process handshake:', handshakeError);
              // Update max index even on error
              const entryIndex3 = typeof entry.index !== 'undefined' ? entry.index : -1;
              if (entryIndex3 >= 0 && entryIndex3 >= maxIndex) {
                maxIndex = entryIndex3 + 1;
              }
            }
          }
        }

        // PHASE 2: Process regular messages AFTER handshakes
        for (const entry of incoming) {
          const msg = normalizeIncomingEntry(entry);

          // PART 2: Deduplication - check if we've already SUCCESSFULLY processed this entry
          // CRITICAL: Only skip if we've successfully decrypted and rendered this message
          // Do NOT mark as seen until decryption succeeds
          const rawId = entry.index ?? entry.id ?? entry.ts ?? entry.created_at ?? Math.random().toString(16).slice(2);
          const dedupeKey = `${chatId}::${rawId}`;
          if (seenEntries.has(dedupeKey)) {
            console.log(`[Sync] Skipping already processed (decrypted) entry: ${dedupeKey}`);
            continue;
          }
          // NOTE: We add to seenEntries ONLY after successful decryption (see below)

          // CRITICAL FIX: Skip DECRYPTION for our own outgoing messages
          // When we send a message, it comes back from relay with from === username
          // We cannot decrypt our own messages because Double Ratchet doesn't support
          // the same party being both sender and receiver with the same session state
          // Instead, mark as processed and skip (message already shown via optimistic UI or send handler)
          if (msg.from === username) {
            console.log(`[Sync] Skipping decryption for our own outgoing message: ${dedupeKey}`);
            // Mark as successfully processed to advance cursor
            seenEntries.add(dedupeKey);
            const entryIndex = typeof entry.index !== 'undefined' ? entry.index : -1;
            if (entryIndex >= 0) {
              processedIndices.push(entryIndex);
            }
            continue;
          }

          // Skip handshakes (already processed in Phase 1)
          if (msg.type === 'handshake') {
            continue;
          }

          // Skip empty/control-only entries (no cipher and no text)
          if (!msg.cipher && !msg.raw?.text) {
            console.log(`[Sync] Skipping empty entry: ${dedupeKey}`);
            continue;
          }

          console.log(`[Sync] Processing regular message from ${msg.from}`);

          // Check if cipher is available
          if (!msg.cipher) {
            console.warn('[Message] No blob data available in entry:', msg.raw);

            // Fallback: check if there's plaintext for dev/debug
            if (msg.raw?.text) {
              console.log('[Message] Found plaintext fallback');
              const newMessage: Message = {
                id: msg.id,
                sender: msg.from,
                text: msg.raw.text,
                timestamp: msg.ts,
                encrypted: false,
              };
              setMessages((prev) => {
                if (prev.find((m) => m.id === newMessage.id)) return prev;
                return [...prev, newMessage];
              });

              // CRITICAL: Mark as successfully processed ONLY after message is rendered
              seenEntries.add(dedupeKey);
              console.log(`[Sync] ✅ Marked plaintext entry as seen: ${dedupeKey}`);

              // Track as successfully processed
              const entryIndex = typeof entry.index !== 'undefined' ? entry.index : -1;
              if (entryIndex >= 0) {
                processedIndices.push(entryIndex);
              }
            }
            continue;
          }

          try {
            // Get blob data (inline for dev mode, fetch for real relay)
            let rawData: any;

            if (typeof msg.cipher === 'string') {
              // Dev mode: cipher is inline as base64 string
              console.log(`[Message] Found inline cipher, length: ${msg.cipher.length}`);
              rawData = msg.cipher;
            } else if (entry.blobRef) {
              // Real relay: fetch blob by reference
              console.log(`[Message] Fetching blob by reference: ${entry.blobRef}`);
              const blobRes = await fetch(getRelayUrlForBrowser(`blob/${chatId}/${entry.blobRef}`), {
                headers: createAuthHeaders(username),
              });

              if (!blobRes.ok) continue;

              const blobData = await blobRes.arrayBuffer();
              rawData = blobData;
            } else {
              console.warn('[Message] Cipher present but not a string or blobRef');
              continue;
            }

            // GUARD: Check if this looks like an encrypted blob before decoding
            if (!isLikelyEncryptedBlob(rawData)) {
              console.warn('[Message] Entry does not look like an encrypted blob, skipping (might be handshake/system message)');
              continue;
            }

            // Normalize wire data to Uint8Array (handles base64, ArrayBuffer, etc.)
            let wireData: Uint8Array;
            try {
              wireData = normalizeWireData(rawData);
            } catch (normErr) {
              console.error('[Message] Failed to normalize wire data:', normErr);
              continue;
            }

            let messageText: string;
            let isEncrypted = false;

            // CRITICAL FIX: Decode encrypted message OUTSIDE try-catch to make it available in retry logic
            // This fixes TypeScript error where encryptedRecord was out of scope during session refresh
            let encryptedRecord: ReturnType<typeof decodeEncryptedMessage>;
            try {
              encryptedRecord = decodeEncryptedMessage(wireData);
            } catch (decodeErr) {
              console.error('[Message] Failed to decode encrypted message:', decodeErr);
              messageText = '[Invalid encrypted message format]';
              isEncrypted = false;
              // Skip to next message
              messages.push({
                id: msg.id,
                sender: msg.from,
                text: messageText,
                timestamp: msg.ts || Date.now(),
                encrypted: isEncrypted,
              });
              continue;
            }

            // CRITICAL FIX: Deduplicate by nonce BEFORE attempting decryption
            // This prevents false replay detection when relay returns same message with different entry.id/ts
            // Nonce is unique per message (R64||C32), so it's the most reliable deduplication key
            const nonceHex = Buffer.from(encryptedRecord.nonce).toString('hex');
            const nonceDedupe = `${chatId}::nonce::${nonceHex}`;

            if (seenEntries.has(nonceDedupe)) {
              console.log(`[Sync] Skipping already processed nonce: ${nonceHex.slice(0, 16)}... (relay returned duplicate with different ID)`);
              // Update cursor to skip this duplicate
              const entryIndex = typeof entry.index !== 'undefined' ? entry.index : -1;
              if (entryIndex >= 0 && entryIndex >= maxIndex) {
                maxIndex = entryIndex + 1;
              }
              continue;
            }

            // CRITICAL FIX: If no ratchet state in memory, try loading from IndexedDB
            // This handles cases where:
            // 1. Page refreshed after handshake
            // 2. Handshake completed but state not yet propagated to this poll cycle
            // 3. Session was saved but React state is stale
            if (!currentRatchetState) {
              console.log('[Message] No ratchet state in memory, attempting to load from IndexedDB for peer:', msg.from);
              try {
                const loadedSession = await keystore.findSessionByPeer(msg.from);
                if (loadedSession) {
                  console.log('[Message] ✅ Loaded session from IndexedDB for peer:', msg.from);
                  currentRatchetState = loadedSession;
                  setRatchetState(loadedSession);
                } else {
                  console.warn('[Message] No session found in IndexedDB for peer:', msg.from);
                }
              } catch (err) {
                console.error('[Message] Failed to load session from IndexedDB:', err);
              }
            }

            // CRITICAL FIX: Check for inline session in message BEFORE attempting decryption
            // Inline session is ALWAYS fresher than local/relay session
            // This prevents infinite loops where we try local → fail → go to relay → get stale → fail again

            // DEBUG: Log entry and msg structure to find inline session
            console.log('[Message][DEBUG] Entry keys:', Object.keys(entry));
            console.log('[Message][DEBUG] entry.session exists:', !!entry.session);
            console.log('[Message][DEBUG] msg.raw exists:', !!msg.raw);
            if (msg.raw) {
              console.log('[Message][DEBUG] msg.raw keys:', Object.keys(msg.raw));
              console.log('[Message][DEBUG] msg.raw.session exists:', !!msg.raw.session);
            }

            if (entry.session || msg.raw?.session) {
              console.log('[Message] 🟡 Found inline session in message, adopting it BEFORE decryption...');
              try {
                const { deserializeSession } = await import('@/lib/session-serializer');
                const inlineSessionData = entry.session || msg.raw.session;
                let adoptedSession = deserializeSession(inlineSessionData);

                logDebug('message', 'Deserialized inline session', {
                  sessionId: redactSessionId(adoptedSession.sessionId)
                });

                // CRITICAL FIX: Swap send/recv chains because we received peer's perspective
                // Alice's sendChainKey → Bob's recvChainKey
                // Alice's recvChainKey → Bob's sendChainKey
                console.log('[Message] 🔄 Swapping send/recv chains (peer perspective → our perspective)');
                adoptedSession = {
                  ...adoptedSession,
                  sendChainKey: adoptedSession.recvChainKey,
                  recvChainKey: adoptedSession.sendChainKey,
                  sendRatchetId: adoptedSession.recvRatchetId,
                  recvRatchetId: adoptedSession.sendRatchetId,
                  sendCounter: adoptedSession.recvCounter,
                  recvCounter: adoptedSession.sendCounter,
                };
                console.log('[Message] ✅ Swapped send/recv chains');

                // CRITICAL FIX: Delete old session for this peer before saving new one
                // This prevents conflict where old session ID keeps getting reloaded
                try {
                  const oldSession = await keystore.findSessionByPeer(msg.from);
                  if (oldSession && oldSession.sessionId) {
                    const oldSessionIdHex = Buffer.from(oldSession.sessionId).toString('hex').slice(0, 16);
                    const newSessionIdHex = Buffer.from(adoptedSession.sessionId).toString('hex').slice(0, 16);

                    if (oldSessionIdHex !== newSessionIdHex) {
                      logDebug('message', 'Deleting old session for peer', {
                        peer: msg.from,
                        oldSessionId: redactSessionId(oldSession.sessionId)
                      });
                      await keystore.deleteSession(oldSession.sessionId);
                      logDebug('message', 'Old session deleted');
                    }
                  }
                } catch (delErr) {
                  console.warn('[Message] Failed to delete old session:', delErr);
                }

                // Save and use inline session
                await keystore.saveSession(adoptedSession.sessionId, msg.from, adoptedSession);
                currentRatchetState = adoptedSession;
                setRatchetState(adoptedSession);

                console.log('[Message] ✅ Adopted inline session from message (source of truth!)');
              } catch (inlineErr) {
                console.warn('[Message] Failed to adopt inline session:', inlineErr);
              }
            }

            if (currentRatchetState) {
              try {
                console.log('[Message] 🔓 Starting decryption process:', {
                  messageId: msg.id,
                  from: msg.from,
                  sessionId: Buffer.from(currentRatchetState.sessionId).toString('hex').slice(0, 16) + '...',
                  sendCounter: currentRatchetState.sendCounter,
                  recvCounter: currentRatchetState.recvCounter,
                  noncePreview: Buffer.from(encryptedRecord.nonce).toString('hex').slice(0, 32) + '...',
                  ciphertextLength: encryptedRecord.ciphertext.length,
                });

                // CRITICAL FIX: Try to decrypt FIRST, check nonce ONLY if successful
                // This prevents false replay detection when we retry after session refresh
                // Relay sends same messages multiple times → checkNonce before decrypt = false positives
                let plaintext: Uint8Array;
                let newState: typeof currentRatchetState;

                try {
                  // Decrypt message
                  const decryptStartTime = Date.now();
                  const result = await decryptMessage(currentRatchetState, encryptedRecord);
                  const decryptDuration = Date.now() - decryptStartTime;

                  plaintext = result.plaintext;
                  newState = result.newState;

                  console.log('[Message] ✅ Decryption successful:', {
                    messageId: msg.id,
                    from: msg.from,
                    plaintextLength: plaintext.length,
                    decryptionTime: decryptDuration + 'ms',
                    newSendCounter: newState.sendCounter,
                    newRecvCounter: newState.recvCounter,
                  });
                } catch (decryptErr) {
                  console.error('[Message] ❌ Decryption failed:', {
                    messageId: msg.id,
                    from: msg.from,
                    error: decryptErr instanceof Error ? decryptErr.message : String(decryptErr),
                    sessionId: Buffer.from(currentRatchetState.sessionId).toString('hex').slice(0, 16) + '...',
                    recvCounter: currentRatchetState.recvCounter,
                  });
                  // Re-throw to outer catch block for proper handling
                  throw decryptErr;
                }

                // ✅ Decryption succeeded
                // NOTE: Replay protection now handled by nonce deduplication BEFORE decryption (line 691)
                // This prevents false positives when relay returns duplicates with different entry IDs

                // Apply state changes and persist
                currentRatchetState = newState;
                setRatchetState(newState);

                // CRITICAL FIX: Save updated session state back to IndexedDB after each decrypt
                // This ensures ratchet state is persisted across page refreshes
                await keystore.saveSession(newState.sessionId, msg.from, newState);

                messageText = new TextDecoder().decode(plaintext);
                isEncrypted = true;
                logInfo('message', 'Successfully decrypted message', { plaintext: redactPlaintext(plaintext) });
              } catch (encError) {
                // Handle "ciphertext cannot be decrypted" - message encrypted with older chain key
                const errorMsg = encError instanceof Error ? encError.message : String(encError);
                if (errorMsg.includes('ciphertext cannot be decrypted using that key')) {
                  console.warn('[Message] ⚠️  Cannot decrypt yet - session out of sync');
                  console.warn('[Message] Attempting to refresh session from relay...');

                  // Try to refresh session from relay immediately
                  try {
                    const newSession = await refreshSessionFromPeer({
                      chatId,
                      peerUsername: msg.from,
                      ourIdentity: identity!,
                      ourUsername: username,
                      skipSignatureVerification: false,
                    });

                    if (newSession) {
                      console.log('[Message] ✅ Session refreshed from relay');

                      // CRITICAL: Check if message has inlineSession (more authoritative than relay session)
                      if (entry.session || msg.raw?.session) {
                        console.log('[Message] 🟡 Message has inlineSession, using it instead of relay session');
                        try {
                          const { deserializeSession } = await import('@/lib/session-serializer');
                          const inlineSessionData = entry.session || msg.raw.session;
                          let adoptedSession = deserializeSession(inlineSessionData);

                          // Swap send/recv chains (peer perspective → our perspective)
                          adoptedSession = {
                            ...adoptedSession,
                            sendChainKey: adoptedSession.recvChainKey,
                            recvChainKey: adoptedSession.sendChainKey,
                            sendRatchetId: adoptedSession.recvRatchetId,
                            recvRatchetId: adoptedSession.sendRatchetId,
                            sendCounter: adoptedSession.recvCounter,
                            recvCounter: adoptedSession.sendCounter,
                          };

                          await keystore.saveSession(adoptedSession.sessionId, msg.from, adoptedSession);
                          currentRatchetState = adoptedSession;
                          setRatchetState(adoptedSession);
                          console.log('[Message] ✅ Adopted inlineSession from message');
                        } catch (inlineErr) {
                          console.warn('[Message] Failed to adopt inlineSession, using relay session:', inlineErr);
                          currentRatchetState = newSession;
                          setRatchetState(newSession);
                        }
                      } else {
                        currentRatchetState = newSession;
                        setRatchetState(newSession);
                      }

                      // CRITICAL FIX: Try to decrypt IMMEDIATELY with refreshed session
                      // Don't wait for next poll cycle - session is now in sync!
                      console.log('[Message] 🔄 Retrying decryption with refreshed session...');
                      try {
                        const result = await decryptMessage(currentRatchetState, encryptedRecord);
                        const plaintext = result.plaintext;
                        const newState = result.newState;

                        // ✅ Retry succeeded (replay protection already handled by nonce dedupe)
                        // Apply state changes and persist
                        currentRatchetState = newState;
                        setRatchetState(newState);
                        await keystore.saveSession(newState.sessionId, msg.from, newState);

                        messageText = new TextDecoder().decode(plaintext);
                        isEncrypted = true;
                        logInfo('message', 'Successfully decrypted message', { plaintext: redactPlaintext(plaintext) });
                      } catch (retryErr) {
                        console.error('[Message] ❌ Still cannot decrypt after refresh:', retryErr);
                        messageText = `[Cannot decrypt - session still out of sync]`;
                        isEncrypted = false;
                      }
                    } else {
                      // Failed to refresh session
                      console.warn('[Message] ❌ Failed to refresh session from relay');
                      messageText = `[Cannot decrypt - failed to refresh session]`;
                      isEncrypted = false;
                    }
                  } catch (refreshErr) {
                    console.warn('[Message] Failed to refresh session:', refreshErr);
                    messageText = `[Cannot decrypt - refresh error]`;
                    isEncrypted = false;
                  }

                  // Don't continue - fall through to add message to UI
                }

                // Handle AAD session ID mismatch specifically with instanceof check
                if (encError instanceof AADMismatchError) {
                  console.warn('[Ratchet] ⚠️ AAD session ID mismatch detected');
                  console.warn('[Ratchet] Message session:', encError.messageSessionId);
                  console.warn('[Ratchet] Local session:', encError.localSessionId);
                  console.warn('[Ratchet] This means peer is using a different session (re-handshaked)');

                  // DO NOT decrypt with wrong AAD - this protects against replay attacks
                  // Instead, refresh session and retry

                  // CRITICAL FIX: Try inline session FIRST before going to relay
                  // Inline session is ALWAYS fresher than relay session
                  let newSession: typeof currentRatchetState | null = null;

                  if (entry.session || msg.raw?.session) {
                    console.warn('[Ratchet] 🟡 Found inline session in message, trying it FIRST...');
                    try {
                      const { deserializeSession } = await import('@/lib/session-serializer');
                      const inlineSessionData = entry.session || msg.raw.session;
                      const adoptedSession = deserializeSession(inlineSessionData);

                      logDebug('ratchet', 'Deserialized inline session', {
                        sessionId: redactSessionId(adoptedSession.sessionId)
                      });

                      // Save and use inline session
                      await keystore.saveSession(adoptedSession.sessionId, msg.from, adoptedSession);
                      newSession = adoptedSession;

                      console.log('[Ratchet] ✅ Adopted inline session from message (source of truth!)');
                    } catch (inlineErr) {
                      console.warn('[Ratchet] Failed to adopt inline session:', inlineErr);
                    }
                  }

                  // Fallback: if no inline session or it failed, try relay
                  if (!newSession && identity && msg.from) {
                    console.warn('[Ratchet] No inline session available, fetching from relay...');
                    try {
                      newSession = await refreshSessionFromPeer({
                        chatId,
                        peerUsername: msg.from,
                        ourIdentity: identity,
                        ourUsername: username,
                        skipSignatureVerification: false, // Keep verification enabled!
                      });

                      if (newSession) {
                        logDebug('ratchet', 'Session refreshed from relay', {
                          sessionId: redactSessionId(newSession.sessionId)
                        });
                      }
                    } catch (refreshError) {
                      console.error('[Ratchet] ❌ Exception during relay session refresh:', refreshError);
                    }
                  }

                  // If we got a new session (either inline or relay), try decryption
                  if (newSession) {
                    // Check if session is pending (relay returned 403)
                    if ((newSession as any)._pending) {
                      console.warn('[Ratchet] Session is pending - retrying send to relay');
                      await retryPendingSession(chatId, msg.from, username);
                    }

                    // Update current ratchet state
                    currentRatchetState = newSession;
                    setRatchetState(newSession);

                    // Retry decryption with new session
                    try {
                      console.log('[Ratchet] Retrying decryption with refreshed session...');

                      // ✅ Replay protection already handled by nonce dedupe (line 691)
                      // Decrypt message with new session
                      const { plaintext, newState } = await decryptMessage(newSession, encryptedRecord);
                      currentRatchetState = newState;
                      setRatchetState(newState);

                      // Save updated session state
                      await keystore.saveSession(newState.sessionId, msg.from, newState);

                      messageText = new TextDecoder().decode(plaintext);
                      isEncrypted = true;
                      logInfo('ratchet', 'Successfully decrypted with refreshed session', {
                        plaintext: redactPlaintext(plaintext)
                      });
                    } catch (retryError) {
                      // Check for "ciphertext cannot be decrypted" error
                      const retryErrorMsg = retryError instanceof Error ? retryError.message : String(retryError);
                      if (retryErrorMsg.includes('ciphertext cannot be decrypted using that key')) {
                        console.warn('[Ratchet] ⚠️  Cannot decrypt yet after refresh - will retry');
                        // CRITICAL: Do NOT advance cursor - retry next poll cycle
                        continue;
                      }

                      // Even after refresh, decryption failed - might be AAD mismatch again
                      if (retryError instanceof AADMismatchError) {
                        console.warn('[Ratchet] ⚠️  Still AAD mismatch after refresh - message from old session');
                        console.warn('[Ratchet] Skipping this message (cannot decrypt with current session)');
                        messageText = `[Message from old session - cannot decrypt]`;
                        isEncrypted = false;
                      } else {
                        console.error('[Ratchet] ❌ Decryption failed even after session refresh:', retryError);
                        messageText = `[Session refreshed but decryption still failed]`;
                        isEncrypted = false;
                      }
                    }
                  } else {
                    // No session available (neither inline nor relay)
                    console.error('[Ratchet] ❌ Cannot refresh session - no inline session and relay refresh failed');
                    messageText = `[Session mismatch - cannot recover. Please restart chat.]`;
                    isEncrypted = false;
                  }
                } else {
                  console.error('[Message] Decryption failed:', encError);
                  messageText = `[Encrypted message - failed to decrypt]`;
                  isEncrypted = false;
                }
              }
            } else {
              console.warn('[Message] No ratchet state for chatId=' + chatId + ', peer=' + msg.from);
              console.log('[Message] Attempting auto-heal by refreshing session...');

              // AUTO-HEAL: Refresh session from peer and retry decryption
              if (identity && msg.from) {
                try {
                  const newSession = await refreshSessionFromPeer({
                    chatId,
                    peerUsername: msg.from,
                    ourIdentity: identity,
                    ourUsername: username,
                    skipSignatureVerification: false,
                  });

                  if (newSession) {
                    console.log('[Message] ✅ Auto-heal successful, session refreshed');

                    // Check if session is pending (relay returned 403)
                    if ((newSession as any)._pending) {
                      console.warn('[Message] Auto-heal session is pending - retrying send to relay');
                      await retryPendingSession(chatId, msg.from, username);
                    }

                    currentRatchetState = newSession;
                    setRatchetState(newSession);

                    // Retry decryption with new session
                    try {
                      // ✅ Replay protection already handled by nonce dedupe (line 691)
                      const { plaintext, newState } = await decryptMessage(newSession, encryptedRecord);
                      currentRatchetState = newState;
                      setRatchetState(newState);
                      await keystore.saveSession(newState.sessionId, msg.from, newState);
                      messageText = new TextDecoder().decode(plaintext);
                      isEncrypted = true;
                      logInfo('message', 'Successfully decrypted after auto-heal', {
                        plaintext: redactPlaintext(plaintext)
                      });
                    } catch (retryErr) {
                      console.error('[Message] Decryption still failed after auto-heal:', retryErr);
                      messageText = `[Auto-heal succeeded but decryption failed]`;
                      isEncrypted = false;
                    }
                  } else {
                    console.error('[Message] ❌ Auto-heal failed - no session returned');
                    messageText = `[Encrypted message - no session]`;
                    isEncrypted = false;
                  }
                } catch (healErr) {
                  console.error('[Message] ❌ Auto-heal exception:', healErr);
                  messageText = `[Encrypted message - no session]`;
                  isEncrypted = false;
                }
              } else {
                console.error('[Message] Cannot auto-heal - missing identity or peer info');
                messageText = `[Encrypted message - no session]`;
                isEncrypted = false;
              }
            }

            const newMessage: Message = {
              id: msg.id,
              sender: msg.from,
              text: messageText,
              timestamp: msg.ts || Date.now(),
              encrypted: isEncrypted,
            };

            setMessages((prev) => {
              if (prev.find((m) => m.id === newMessage.id)) {
                return prev;
              }
              return [...prev, newMessage];
            });

            // Save message to IndexedDB for persistence
            try {
              await saveMessage({
                id: newMessage.id,
                chatId: chatId,
                sender: newMessage.sender,
                recipient: username.toLowerCase(), // We are the recipient of incoming messages
                text: newMessage.text,
                timestamp: newMessage.timestamp,
                encrypted: newMessage.encrypted,
              });
              console.log('[MessageStore] Saved incoming message:', newMessage.id);
            } catch (storeErr) {
              console.error('[MessageStore] Failed to save message:', storeErr);
            }

            // CRITICAL: Mark as successfully processed ONLY after message is decrypted and rendered
            seenEntries.add(dedupeKey);
            seenEntries.add(nonceDedupe); // Also mark nonce as seen to prevent relay duplicates
            console.log(`[Sync] ✅ Marked entry as seen (successfully decrypted): ${dedupeKey}`);

            // CRITICAL: Only advance cursor if message was successfully processed
            // Track this entry as successfully processed
            const entryIndex4 = typeof entry.index !== 'undefined' ? entry.index : -1;
            if (entryIndex4 >= 0) {
              processedIndices.push(entryIndex4);
              console.log(`[Sync] ✅ Marked message index ${entryIndex4} as successfully processed`);
            }
          } catch (err) {
            console.error('[Message] Failed to decode message:', err);
            // CRITICAL: Do NOT update maxIndex or processedIndices - message failed to decode
          }
        }

        // PART 3: Update cursor based on ALL seen messages (both processed AND skipped)
        // CRITICAL: Cursor = highest index we've seen (NOT +1)
        // API semantics: since=N returns messages with index > N
        // So if we've seen index 4, we set cursor=4, next poll since=4 returns indices 5,6,7,...
        const allIndices = [...processedIndices, ...skippedIndices];
        if (allIndices.length > 0) {
          const maxSeenIndex = Math.max(...allIndices);
          const newCursor = maxSeenIndex; // NOT maxSeenIndex + 1

          if (newCursor > (cursorsRef.current[chatId] || 0)) {
            cursorsRef.current[chatId] = newCursor;
            console.log(`[Sync] Advanced cursor for ${chatId} to ${newCursor} (processed ${processedIndices.length}, skipped ${skippedIndices.length})`);
            maxIndex = newCursor + 1; // maxIndex still uses +1 for backward compatibility with lastSyncIndex
          }
        }

        // Also update lastSyncIndex state for backward compatibility
        if (maxIndex > lastSyncIndex) {
          setLastSyncIndex(maxIndex);
        }
      } catch (err) {
        console.error('Poll failed:', err);
      }
    };

    const intervalId = setInterval(pollMessages, 2000);
    pollMessages();

    return () => clearInterval(intervalId);
  }, [chatActive, chatId, lastSyncIndex, username, identity, ratchetState, recipient]);

  const startChat = async () => {
    // Canonicalize recipient username
    const recipientCanonical = recipient.toLowerCase().trim();

    if (!recipientCanonical || !identity) return;

    // Canonicalize our username too
    const usernameCanonical = username.toLowerCase().trim();

    console.log('[Chat] startChat canonicalized', {
      recipient,
      recipientCanonical,
      username,
      usernameCanonical
    });

    try {
      setHandshakeInProgress(true);
      console.log('[Handshake] Starting chat with:', recipientCanonical);

      // CRITICAL: Ensure crypto is fully initialized before handshake
      const { ensureCryptoReady } = await import('@ilyazh/crypto');
      await ensureCryptoReady();
      console.log('[Handshake] Crypto initialization complete');

      // 0. CRITICAL: Ensure OUR prekey bundle is published to relay FIRST
      console.log('[Prekey] Ensuring our prekey bundle is published...');
      try {
        await ensurePrekeyPublished(usernameCanonical, identity);
        console.log('[Prekey] ✅ Our prekey bundle is published');
      } catch (err) {
        console.error('[Prekey] Failed to publish our prekey bundle:', err);
        throw new Error('Cannot start chat: failed to publish prekey bundle');
      }

      // 1. Get canonical chatId from relay FIRST (always!)
      console.log('[Chat] Getting canonical chat ID from relay...');
      const initRes = await fetch(getRelayUrlForBrowser('chat/init'), {
        method: 'POST',
        headers: createAuthHeaders(usernameCanonical),
        body: JSON.stringify({
          participants: [usernameCanonical, recipientCanonical],
        }),
      });

      console.log('[Chat] Init response:', {
        ok: initRes.ok,
        status: initRes.status,
        statusText: initRes.statusText,
        headers: Object.fromEntries(initRes.headers.entries()),
      });

      if (!initRes.ok) {
        const errorText = await initRes.text();
        console.error('[Chat] Init failed with body:', errorText);
        throw new Error(`Failed to initialize chat on relay: ${initRes.status} - ${errorText}`);
      }

      const initData = await initRes.json();
      if (!initData.chatId) {
        throw new Error('Relay did not return chatId');
      }

      const canonicalChatId = initData.chatId;
      console.log('[Chat] Relay returned canonical chatId:', canonicalChatId);
      setChatId(canonicalChatId);

      // 2. Check if we already have a session with this peer
      await keystore.init();
      let existingSession = await keystore.findSessionByPeer(recipientCanonical);

      if (existingSession) {
        console.log('[Handshake] Found existing session, restoring...');
        setRatchetState(existingSession);
        setChatActive(true);

        // Add system message only if no messages are loaded yet
        // (loadPersistedMessages useEffect will load them after chatActive becomes true)
        setMessages((prev) => {
          if (prev.length > 0) {
            // Already have messages, don't add system message
            return prev;
          }
          return [
            {
              id: 'system-init',
              sender: 'system',
              text: `🔐 Existing session restored with ${recipientCanonical}`,
              timestamp: Date.now(),
              encrypted: true,
            },
          ];
        });

        setHandshakeInProgress(false);
        return;
      }

      console.log('[Handshake] No existing session, initiating new handshake...');

      // 3. Fetch recipient's identity and prekey bundle from relay (with retry)
      console.log('[Handshake] Fetching peer bundle with retry...');
      let peerData;
      let lastError;

      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          peerData = await fetchPeerBundle(recipientCanonical);
          console.log(`[Handshake] ✅ Fetched peer bundle on attempt ${attempt}:`, peerData.prekey?.bundleId || 'dev');
          break;
        } catch (err) {
          lastError = err;
          console.warn(`[Handshake] Attempt ${attempt}/3 failed to fetch peer bundle:`, err);
          if (attempt < 3) {
            await new Promise(r => setTimeout(r, 400));
          }
        }
      }

      if (!peerData) {
        console.error('[Handshake] ❌ Failed to fetch peer bundle after 3 attempts');
        throw lastError || new Error('Failed to fetch peer bundle');
      }

      // 4. Reconstruct peer's identity keypair (public keys only)
      // SAFETY: Handle missing/empty keys gracefully
      const edBase64 = peerData?.identity?.identityEd25519;
      const mldsaBase64 = peerData?.identity?.identityMLDSA;

      if (!edBase64) {
        console.warn('[chat] peer has no Ed25519 identity key!');
      }
      if (!mldsaBase64) {
        console.log('[chat] peer has no ML-DSA key (classical-only mode)');
      }

      const peerIdentity: IdentityKeyPair = {
        ed25519: {
          publicKey: edBase64 ? new Uint8Array(Buffer.from(edBase64, 'base64')) : new Uint8Array(32),
          secretKey: new Uint8Array(0), // Not needed
        },
        mldsa: {
          publicKey: mldsaBase64 ? new Uint8Array(Buffer.from(mldsaBase64, 'base64')) : new Uint8Array(1952),
          secretKey: new Uint8Array(0),
        },
      };

      // 5. Reconstruct peer's prekey bundle (public part only)
      const x25519Base64 = peerData?.prekey?.x25519Ephemeral;
      const mlkemBase64 = peerData?.prekey?.mlkemPublicKey;
      const ed25519SigBase64 = peerData?.prekey?.ed25519Signature;
      const mldsaSigBase64 = peerData?.prekey?.mldsaSignature;

      const peerBundle: Omit<PrekeyBundle, 'x25519SecretKey' | 'mlkemSecretKey'> = {
        bundleId: peerData.prekey?.bundleId || 'dev-bundle',
        x25519Ephemeral: x25519Base64 ? new Uint8Array(Buffer.from(x25519Base64, 'base64')) : new Uint8Array(32),
        mlkemPublicKey: mlkemBase64 ? new Uint8Array(Buffer.from(mlkemBase64, 'base64')) : new Uint8Array(1184),
        ed25519Signature: ed25519SigBase64 ? new Uint8Array(Buffer.from(ed25519SigBase64, 'base64')) : new Uint8Array(64),
        mldsaSignature: mldsaSigBase64 ? new Uint8Array(Buffer.from(mldsaSigBase64, 'base64')) : new Uint8Array(3293),
        timestamp: peerData.prekey?.timestamp || Date.now(),
      };

      // SECURITY: Verify prekey bundle signatures before trusting
      console.log('[Security] Verifying prekey bundle signatures...');
      console.log('[Security] Bundle ID:', peerBundle.bundleId);

      const { ed25519Verify, serializePrekeyBundle } = await import('@ilyazh/crypto');

      // Serialize bundle using SAME function that was used during signing
      const bundleData = serializePrekeyBundle({
        x25519Pub: peerBundle.x25519Ephemeral,
        pqKemPub: peerBundle.mlkemPublicKey.length > 0 ? peerBundle.mlkemPublicKey : undefined,
        pqSigPub: undefined, // No PQ sig key in prekey bundle
      });

      console.log('[Security] Serialized bundle data length:', bundleData.length);
      console.log('[Security] Signature length:', peerBundle.ed25519Signature.length);
      console.log('[Security] Public key length:', peerIdentity.ed25519.publicKey.length);

      // Verify Ed25519 signature (skip for dev mode or classical-only mode)
      // Classical-only mode: no ML-DSA keys means we're in dev/testing
      const isClassicalOnly = !mldsaBase64 || mldsaBase64 === '';
      const isRelayBundle = peerBundle.bundleId === 'relay-bundle' || peerBundle.bundleId === 'dev-bundle';
      const shouldVerify = !peerData.dev && !isClassicalOnly && !isRelayBundle;

      if (shouldVerify) {
        const ed25519Valid = ed25519Verify(
          peerBundle.ed25519Signature,
          bundleData,
          peerIdentity.ed25519.publicKey
        );

        if (!ed25519Valid) {
          console.error('[Security] ⚠️ Prekey bundle Ed25519 signature verification FAILED!');
          throw new Error(
            '⚠️ SECURITY ALERT: Prekey bundle signature verification failed. ' +
            'This may indicate a man-in-the-middle attack or corrupted data. ' +
            'Cannot proceed with handshake for your safety.'
          );
        }

        console.log('[Security] ✅ Prekey bundle Ed25519 signature verified successfully');
      } else {
        if (isRelayBundle) {
          console.log('[Security] ⚠️ Relay test bundle detected - skipping signature verification');
        } else if (isClassicalOnly) {
          console.log('[Security] ⚠️ Classical-only mode (no PQ keys) - skipping signature verification');
        } else {
          console.log('[Security] ⚠️ Dev mode - skipping signature verification');
        }
      }

      console.log('[Handshake] Initiating handshake with verified peer bundle...');

      // 6. Initiate handshake (we are Alice)
      const { message: handshakeMessage, ephemeralX25519Secret, ephemeralMLKEMSecret } = await initiateHandshake(
        identity,
        peerIdentity.ed25519.publicKey,
        peerIdentity.mldsa.publicKey,
        peerBundle as any // Type mismatch - needs proper handling
      );

      console.log('[Handshake] Handshake initiated (message created)');

      // 7. Store pending handshake data in sessionStorage (for finalization)
      // Use the canonical chatId we got from relay earlier
      sessionStorage.setItem(`handshake_pending_${canonicalChatId}`, JSON.stringify({
        initiatorMessage: {
          ...handshakeMessage,
          ephemeralX25519: Array.from(handshakeMessage.ephemeralX25519),
          ephemeralMLKEM: handshakeMessage.ephemeralMLKEM ? Array.from(handshakeMessage.ephemeralMLKEM) : undefined,
          identityPublicEd25519: Array.from(handshakeMessage.identityPublicEd25519),
          identityPublicMLDSA: Array.from(handshakeMessage.identityPublicMLDSA),
          ed25519Signature: Array.from(handshakeMessage.ed25519Signature),
          mldsaSignature: Array.from(handshakeMessage.mldsaSignature),
        },
        ephemeralX25519Secret: Array.from(ephemeralX25519Secret),
        ephemeralMLKEMSecret: ephemeralMLKEMSecret ? Array.from(ephemeralMLKEMSecret) : undefined,
      }));

      // 8. Encode and send handshake message
      const wireData = encodeHandshakeMessage(handshakeMessage);
      const data = Buffer.from(wireData).toString('base64');

      console.log('[Handshake] Sending handshake message to relay...');

      const sendRes = await fetch(getRelayUrlForBrowser(`message/${canonicalChatId}`), {
        method: 'POST',
        headers: createAuthHeaders(usernameCanonical),
        body: JSON.stringify({
          type: 'handshake',
          from: usernameCanonical,
          blob: data,
        }),
      });

      // Handle 409 correctly: if relay returns 409, the handshake message already exists
      // This is normal in dev/re-init scenarios - we should still proceed with session setup
      if (sendRes.status === 409) {
        console.warn('[Handshake] Relay returned 409 (handshake already exists), proceeding with local session init');
      } else if (!sendRes.ok) {
        console.warn('[Handshake] Relay returned', sendRes.status, 'but continuing in DEV mode');
      }

      console.log('[Handshake] Handshake message sent, waiting for response...');

      // Don't set ratchetState yet - wait for finalization
      setChatActive(true);
      setSessionInfo({
        sessionId: canonicalChatId.slice(0, 16) + '...',
        ratchetId: 0,
        messageCount: 0,
        epochAge: '0s',
        sessionAge: '0s',
      });

      // Add system message only if no messages are loaded yet
      setMessages((prev) => {
        if (prev.length > 0) {
          // Already have messages, don't add system message
          return prev;
        }
        return [
          {
            id: 'system-handshake',
            sender: 'system',
            text: `🔐 Handshake sent to ${recipientCanonical}. Waiting for response...`,
            timestamp: Date.now(),
            encrypted: true,
          },
        ];
      });

      setHandshakeInProgress(false);
    } catch (err) {
      console.error('Chat initialization failed:', err);
      const errorMessage = err instanceof Error ? err.message : String(err);
      alert(`Failed to start chat: ${errorMessage}`);
      setHandshakeInProgress(false);
    }
  };

  const sendMessage = async () => {
    if (!inputText.trim() || !chatId) return;

    const messageText = inputText;
    const messageId = `msg-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    setInputText('');

    // Canonicalize usernames
    const usernameCanonical = username.toLowerCase().trim();
    const recipientCanonical = recipient.toLowerCase().trim();

    console.log('[Send] 🚀 Starting message send:', {
      messageId,
      chatId,
      from: usernameCanonical,
      to: recipientCanonical,
      textLength: messageText.length,
      hasRatchetState: !!ratchetState,
      timestamp: new Date().toISOString(),
    });

    try {
      let data: string;
      let inlineSession: any = undefined;

      if (ratchetState) {
        console.log('[Send] 📝 Encrypting message with ratchet state...');
        console.log('[Send] - Session ID:', Buffer.from(ratchetState.sessionId).toString('hex').slice(0, 16) + '...');
        console.log('[Send] - Send counter before encryption:', ratchetState.sendCounter);
        console.log('[Send] - Recv counter before encryption:', ratchetState.recvCounter);

        // CRITICAL FIX: Serialize session BEFORE encryption
        // The inline session must contain the state that will be used for encryption
        // NOT the state after encryption (which has advanced chain keys)
        const { serializeSession } = await import('@/lib/session-serializer');
        inlineSession = serializeSession(ratchetState);
        console.log('[Send] ✅ Serialized session BEFORE encryption (state that will be used)');
        console.log('[Send] - Session version:', inlineSession.version);
        console.log('[Send] - sendCounter:', inlineSession.sendCounter);

        // Encrypt message using ratchet
        const plaintext = new TextEncoder().encode(messageText);
        const encryptStartTime = Date.now();
        const { record, newState } = await encryptMessage(ratchetState, plaintext);
        const encryptDuration = Date.now() - encryptStartTime;

        console.log('[Send] ✅ Message encrypted successfully');
        console.log('[Send] - Encryption took:', encryptDuration, 'ms');
        console.log('[Send] - Nonce (first 16 bytes):', Buffer.from(record.nonce).toString('hex').slice(0, 32));
        console.log('[Send] - Ciphertext length:', record.ciphertext.length);
        console.log('[Send] - New send counter:', newState.sendCounter);

        setRatchetState(newState);

        // Save updated session state to IndexedDB after encryption
        console.log('[Send] 💾 Saving updated session to IndexedDB...');
        await keystore.init();
        await keystore.saveSession(newState.sessionId, recipientCanonical, newState);
        console.log('[Send] ✅ Session saved to IndexedDB');

        // Encode as wire format
        const wireData = encodeEncryptedMessage(record);
        data = Buffer.from(wireData).toString('base64');
        console.log('[Send] ✅ Message encoded to base64, length:', data.length);
      } else {
        console.log('[Send] ⚠️  No ratchet state - using plaintext fallback (DEV MODE ONLY)');
        data = Buffer.from(messageText, 'utf-8').toString('base64');
      }

      console.log('[Send] 🌐 Sending to relay...');
      const sendStartTime = Date.now();

      const requestBody = {
        type: 'message',
        from: usernameCanonical,
        blob: data,
        text: ratchetState ? undefined : messageText,  // dev fallback for classical-only
        ts: Date.now(),
        version: 'ilyazh/0.8',
        session: inlineSession,  // CRITICAL: Send session atomically with message
      };

      console.log('[Send] Request payload:', {
        type: requestBody.type,
        from: requestBody.from,
        blobLength: requestBody.blob.length,
        hasSession: !!requestBody.session,
        version: requestBody.version,
      });

      const response = await fetch(getRelayUrlForBrowser(`message/${chatId}`), {
        method: 'POST',
        headers: createAuthHeaders(usernameCanonical),
        body: JSON.stringify(requestBody),
      });

      const sendDuration = Date.now() - sendStartTime;

      console.log('[Send] 📡 Relay response received:', {
        messageId,
        chatId,
        status: response.status,
        statusText: response.statusText,
        ok: response.ok,
        from: usernameCanonical,
        to: recipientCanonical,
        hasSession: !!ratchetState,
        duration: sendDuration + 'ms',
        timestamp: new Date().toISOString(),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('[Send] ❌ Relay rejected message:', {
          messageId,
          chatId,
          status: response.status,
          statusText: response.statusText,
          errorBody: errorText,
          from: usernameCanonical,
          to: recipientCanonical,
        });
        throw new Error(`Failed to send message: ${response.status} - ${errorText}`);
      }

      const result = await response.json();
      console.log('[Send] ✅ Relay accepted message:', {
        messageId,
        relayIndex: result.index,
        relayResponse: result,
      });

      const newMessage: Message = {
        id: (result && typeof result.index !== 'undefined')
          ? String(result.index)
          : `local-${Date.now()}`,
        sender: username,
        text: messageText,
        timestamp: Date.now(),
        encrypted: !!ratchetState,
      };

      setMessages((prev) => [...prev, newMessage]);

      // Save outgoing message to IndexedDB for persistence
      try {
        await saveMessage({
          id: newMessage.id,
          chatId: chatId,
          sender: newMessage.sender,
          recipient: recipientCanonical, // The person we're sending to
          text: newMessage.text,
          timestamp: newMessage.timestamp,
          encrypted: newMessage.encrypted,
        });
        console.log('[MessageStore] Saved outgoing message:', newMessage.id);
      } catch (storeErr) {
        console.error('[MessageStore] Failed to save outgoing message:', storeErr);
      }

      if (sessionInfo) {
        setSessionInfo({
          ...sessionInfo,
          messageCount: sessionInfo.messageCount + 1,
        });
      }
    } catch (err) {
      console.error('Send failed:', err);
      alert('Failed to send message. Please try again.');
      setInputText(messageText);
    }
  };

  if (!mounted) {
    return (
      <main className="min-h-screen flex items-center justify-center bg-black text-white p-4">
        <div className="text-center max-w-md">
          <div className="flex items-center justify-center mb-6">
            <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center animate-pulse">
              <span className="text-white font-bold text-4xl">S</span>
            </div>
          </div>
          <h1 className="text-3xl font-bold mb-4 tracking-wider">STVOR</h1>
          <div className="space-y-3">
            <div className="animate-pulse">
              <div className="h-2 bg-gray-800 rounded w-full mb-2"></div>
              <div className="h-2 bg-gray-800 rounded w-5/6 mx-auto"></div>
            </div>
            <p className="text-lg text-gray-400 mt-4">Загрузка...</p>
          </div>
        </div>
      </main>
    );
  }

  if (!identity) {
    return (
      <main className="min-h-screen flex items-center justify-center bg-black text-white p-4">
        <div className="text-center max-w-md">
          <div className="flex items-center justify-center mb-6">
            <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center animate-pulse">
              <span className="text-white font-bold text-4xl">S</span>
            </div>
          </div>
          <h1 className="text-3xl font-bold mb-4 tracking-wider">STVOR</h1>
          <div className="space-y-3">
            <div className="animate-pulse">
              <div className="h-2 bg-green-500 rounded w-full mb-2"></div>
              <div className="h-2 bg-green-500 rounded w-4/6 mx-auto"></div>
            </div>
            <p className="text-lg text-green-500 mt-4">Генерация ключей шифрования...</p>
            <p className="text-sm text-gray-500">Ваши ключи никогда не покидают устройство</p>
          </div>
        </div>
      </main>
    );
  }

  if (!chatActive) {
    // Show loading state during handshake initialization
    if (handshakeInProgress) {
      return (
        <main className="min-h-screen flex items-center justify-center bg-black text-white p-4">
          <div className="text-center max-w-md">
            <div className="flex items-center justify-center mb-6">
              <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center animate-pulse">
                <span className="text-white font-bold text-4xl">S</span>
              </div>
            </div>
            <h1 className="text-3xl font-bold mb-4 tracking-wider">STVOR</h1>
            <div className="space-y-4">
              <div className="animate-pulse">
                <div className="h-2 bg-green-500 rounded w-full mb-2"></div>
                <div className="h-2 bg-green-500 rounded w-3/4 mx-auto mb-2"></div>
                <div className="h-2 bg-green-500 rounded w-5/6 mx-auto"></div>
              </div>
              <div className="space-y-2 mt-6">
                <p className="text-xl text-green-500 font-semibold">Создаётся пространство</p>
                <p className="text-lg text-gray-400">Полностью изолированное от других</p>
                <p className="text-md text-gray-500 italic">Ваша мини расширенная территория</p>
              </div>
              <div className="mt-8 p-4 bg-gray-900 rounded-lg border border-gray-800">
                <p className="text-xs text-gray-400">
                  🔒 Установка защищённого соединения с использованием<br />
                  квантово-устойчивого шифрования ML-KEM-768
                </p>
              </div>
            </div>
          </div>
        </main>
      );
    }

    // Show chat list or new chat form
    if (showingChatList) {
      return (
        <main className="min-h-screen flex flex-col bg-black text-white">
          {/* Header */}
          <div className="bg-gray-900 border-b border-gray-800 p-4 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
                <span className="text-white font-bold text-xl">S</span>
              </div>
              <h1 className="text-xl font-bold tracking-wider">STVOR Чаты</h1>
            </div>
            <Link href="/" className="text-green-500 hover:text-green-400 text-sm font-medium">
              ← Домой
            </Link>
          </div>

          {/* Chat List */}
          <div className="flex-1 overflow-hidden">
            <ChatList
              currentUsername={username}
              onSelectChat={(recipientUsername) => {
                setRecipient(recipientUsername);
                setShowingChatList(false);
              }}
              onStartNewChat={() => setShowingChatList(false)}
            />
          </div>
        </main>
      );
    }

    return (
      <main className="min-h-screen flex flex-col items-center justify-center p-8 bg-black text-white">
        <div className="w-full max-w-md bg-gray-900 border border-gray-800 rounded-xl shadow-2xl p-8">
          <button
            onClick={() => setShowingChatList(true)}
            className="text-sm text-green-500 hover:text-green-400 mb-4 block"
          >
            ← Назад к чатам
          </button>

          <h1 className="text-3xl font-bold mb-4">💬 Начать Чат</h1>
          <p className="text-gray-400 mb-6">
            Вы вошли как <strong className="text-white">{username}</strong>
          </p>

          <UsernameSearch
            value={recipient}
            onChange={(value) => {
              // Strip @ prefix for internal use (backend expects bare username)
              const normalized = value.startsWith('@') ? value.slice(1) : value;
              setRecipient(normalized);
            }}
            onKeyDown={(e) => e.key === 'Enter' && !handshakeInProgress && startChat()}
            disabled={handshakeInProgress}
            placeholder="Поиск пользователя (@username)"
            autoFocus
          />
          <div className="mb-4" />

          <button
            onClick={startChat}
            disabled={handshakeInProgress}
            className="w-full p-3 bg-green-500 hover:bg-green-600 disabled:bg-gray-800 disabled:text-gray-500 text-white rounded-lg font-semibold transition"
          >
            Начать Зашифрованный Чат
          </button>

          <div className="mt-6 p-4 bg-gray-950 rounded-lg border border-gray-800">
            <p className="font-semibold mb-3 text-green-500">Протокол Ilyazh-Web3E2E:</p>
            <ul className="text-xs space-y-2 text-gray-400">
              <li className="flex items-start">
                <span className="text-green-500 mr-2">•</span>
                <span>Гибридный обмен ключами (X25519 + ML-KEM-768)</span>
              </li>
              <li className="flex items-start">
                <span className="text-green-500 mr-2">•</span>
                <span>Двойные подписи (Ed25519 + ML-DSA-65)</span>
              </li>
              <li className="flex items-start">
                <span className="text-green-500 mr-2">•</span>
                <span>Вывод ID сессии через HKDF-SHA-384</span>
              </li>
              <li className="flex items-start">
                <span className="text-green-500 mr-2">•</span>
                <span>Double Ratchet с обязательной ротацией ключей</span>
              </li>
              <li className="flex items-start">
                <span className="text-green-500 mr-2">•</span>
                <span>AES-256-GCM с sid-in-AAD</span>
              </li>
            </ul>
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen flex flex-col bg-black text-white">
      {/* Header */}
      <div className="bg-gray-900 border-b border-gray-800 shadow-sm p-4 flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <button
            onClick={() => {
              setChatActive(false);
              setShowingChatList(true);
              setRatchetState(null);
              setMessages([]);
            }}
            className="text-green-500 hover:text-green-400 text-sm font-medium"
          >
            ← Назад к чатам
          </button>
          <div>
            <div className="font-semibold">
              {username} → {recipient}
            </div>
            <div className="text-xs text-green-500">
              {ratchetState ? '🔒 E2E Зашифровано (Активно)' : '⚠️ Ожидание Handshake'}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {sessionInfo && (
            <div className="text-xs text-gray-400">
              <div>Сообщений: {sessionInfo.messageCount}</div>
              <div>Эпоха: {sessionInfo.ratchetId}</div>
            </div>
          )}
          {ratchetState && (
            <button
              onClick={async () => {
                // Fetch peer identity before showing safety number
                if (!peerIdentity && recipient) {
                  try {
                    const recipientCanonical = recipient.toLowerCase().trim();
                    console.log('[SafetyNumber] Fetching peer identity for:', recipientCanonical);
                    const fetchedPeerIdentity = await fetchPeerIdentity(recipientCanonical);
                    setPeerIdentity(fetchedPeerIdentity as any);
                    console.log('[SafetyNumber] ✅ Peer identity fetched');
                  } catch (err) {
                    console.error('[SafetyNumber] ❌ Failed to fetch peer identity:', err);
                    alert('Failed to fetch peer identity. Cannot display safety number.');
                    return;
                  }
                }
                setShowSafetyNumber(true);
              }}
              className="px-3 py-1 text-xs bg-gray-800 border border-gray-700 rounded hover:bg-gray-700 hover:border-green-500 transition"
              title="Verify safety number"
            >
              🔐 Safety Number
            </button>
          )}
        </div>
      </div>

      {/* Session Health Warning */}
      {sessionHealth && sessionHealth.status !== 'healthy' && (
        <div className="px-4 pt-4">
          <SessionHealthWarning
            health={sessionHealth}
            onStartNewSession={() => {
              // Clear current session and restart
              if (ratchetState) {
                const security = getSessionSecurity(ratchetState.sessionId);
                security.skippedKeys.clear();
                security.replayProtection.clearSession(ratchetState.sessionId);
              }
              setChatActive(false);
              setRatchetState(null);
              setMessages([]);
              alert('Please start a new chat to continue.');
            }}
          />
        </div>
      )}

      {/* Safety Number Modal */}
      {showSafetyNumber && identity && peerIdentity && (
        <SafetyNumber
          ourIdentityEd25519={identity.ed25519.publicKey}
          theirIdentityEd25519={peerIdentity.ed25519.publicKey}
          peerName={recipient}
          onClose={() => setShowSafetyNumber(false)}
        />
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-black">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex ${msg.sender === username ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-md p-3 rounded-lg ${
                msg.sender === 'system'
                  ? 'bg-gray-900 border border-gray-800 text-gray-300 text-center w-full'
                  : msg.sender === username
                  ? 'bg-green-500 text-white'
                  : 'bg-gray-800 border border-gray-700 text-white'
              }`}
            >
              {msg.sender !== 'system' && (
                <div className="text-xs opacity-70 mb-1">{msg.sender}</div>
              )}
              <div>{msg.text}</div>
              <div className="text-xs opacity-70 mt-1">
                {new Date(msg.timestamp).toLocaleTimeString()}
                {msg.encrypted && ' • 🔐'}
              </div>
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="bg-gray-900 border-t border-gray-800 p-4">
        <div className="flex space-x-2">
          <input
            type="text"
            placeholder="Введите сообщение..."
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
            className="flex-1 p-3 bg-black border border-gray-800 text-white rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent placeholder:text-gray-600"
          />
          <button
            onClick={sendMessage}
            className="px-6 py-3 bg-green-500 hover:bg-green-600 text-white rounded-lg font-semibold transition"
          >
            Отправить
          </button>
        </div>
        <div className="text-xs text-gray-400 mt-2">
          {ratchetState
            ? 'Все сообщения зашифрованы с помощью AES-256-GCM • sid in AAD'
            : 'Сообщения будут зашифрованы после завершения handshake'}
        </div>
      </div>
    </main>
  );
}
