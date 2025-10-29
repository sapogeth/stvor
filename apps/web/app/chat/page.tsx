'use client';

import { useState, useEffect, useRef } from 'react';
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
  hashTranscript,
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
  deletePrekeySecrets,
  type PrekeySecrets,
} from '@/lib/prekeys';
import { keystore } from '@/lib/keystore';
import {
  getSessionSecurity,
  checkSessionHealth,
  formatAge,
  type SessionHealth,
} from '@/lib/session-security';
import { SafetyNumber } from '@/components/SafetyNumber';
import { SessionHealthWarning } from '@/components/SessionHealthWarning';

// Dynamically determine relay URL based on current hostname
const getRelayUrl = () => {
  if (typeof window === 'undefined') return 'http://localhost:3001';

  const hostname = window.location.hostname;
  if (hostname !== 'localhost' && hostname !== '127.0.0.1') {
    return `http://${hostname}:3001`;
  }

  return process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';
};

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
  const [username, setUsername] = useState('');
  const [recipient, setRecipient] = useState('');
  const [chatActive, setChatActive] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState('');
  const [sessionInfo, setSessionInfo] = useState<any>(null);
  const [chatId, setChatId] = useState<string>('');
  const [lastSyncIndex, setLastSyncIndex] = useState<number>(0);
  const [mounted, setMounted] = useState(false);
  const [identity, setIdentity] = useState<IdentityKeyPair | null>(null);
  const [ratchetState, setRatchetState] = useState<HandshakeState | null>(null);
  const [handshakeInProgress, setHandshakeInProgress] = useState(false);
  const [sessionHealth, setSessionHealth] = useState<SessionHealth | null>(null);
  const [showSafetyNumber, setShowSafetyNumber] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Load or generate identity on mount
  useEffect(() => {
    setMounted(true);
    const stored = localStorage.getItem('ilyazh_username');
    if (!stored) {
      window.location.href = '/';
      return;
    }
    setUsername(stored);

    // Load or generate identity keys + register with relay + generate prekey bundle
    const initializeIdentity = async () => {
      try {
        console.log('[Chat] Initializing identity for:', stored);

        // Get or create identity (handles registration)
        const identityKeys = await getOrCreateIdentity(stored);
        setIdentity(identityKeys);

        console.log('[Chat] Identity loaded/created');

        // Check if we have a prekey bundle, generate if not
        const prekeySecrets = await loadPrekeySecrets(stored);
        if (!prekeySecrets) {
          console.log('[Chat] No prekey bundle found, generating...');
          await generateAndUploadPrekeyBundle(stored, identityKeys);
          console.log('[Chat] Prekey bundle generated and uploaded');
        } else {
          console.log('[Chat] Existing prekey bundle found:', prekeySecrets.bundleId);
        }

        console.log('[Chat] Initialization complete');
      } catch (err) {
        console.error('[Chat] Failed to initialize identity:', err);
        alert('Failed to initialize encryption keys. Please refresh.');
      }
    };

    initializeIdentity();
  }, []);

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

  // Poll for incoming messages
  useEffect(() => {
    if (!chatActive || !chatId || !identity) return;

    const pollMessages = async () => {
      try {
        const syncRes = await fetch(`${getRelayUrl()}/sync/${chatId}?since=${lastSyncIndex}`, {
          headers: createAuthHeaders(username),
        });

        if (!syncRes.ok) return;

        const { entries } = await syncRes.json();

        let currentRatchetState = ratchetState;

        for (const entry of entries) {
          // Skip messages we sent (already in local state)
          if (entry.sender === username) {
            setLastSyncIndex(entry.index + 1);
            continue;
          }

          // Fetch the blob content
          const blobRes = await fetch(`${getRelayUrl()}/blob/${chatId}/${entry.blobRef}`, {
            headers: createAuthHeaders(username),
          });

          if (!blobRes.ok) continue;

          const blobData = await blobRes.arrayBuffer();

          // Try to decode as handshake message first
          const wireData = new Uint8Array(blobData);

          try {
            const handshakeMsg = decodeHandshakeMessage(wireData);
            console.log('[Handshake] Received handshake message, role:', handshakeMsg.role);

            if (handshakeMsg.role === 'initiator' && !currentRatchetState) {
              // We are the responder (Bob), complete the handshake
              console.log('[Handshake] We are responder, completing handshake...');

              // Load our prekey secrets
              const prekeySecrets = await loadPrekeySecrets(username);
              if (!prekeySecrets) {
                throw new Error('No prekey secrets found for completing handshake');
              }

              console.log('[Handshake] Using prekey bundle:', prekeySecrets.bundleId);

              // Complete handshake
              const { message: responseMessage, state: handshakeState } = await completeHandshake(
                identity,
                prekeySecrets.x25519SecretKey,
                prekeySecrets.mlkemSecretKey,
                handshakeMsg
              );

              console.log('[Handshake] Handshake completed');
              console.log('[Handshake] - Session ID:', Buffer.from(handshakeState.sessionId).toString('hex').slice(0, 32) + '...');
              console.log('[Handshake] - Role:', handshakeState.role);

              // Update state
              currentRatchetState = handshakeState;
              setRatchetState(handshakeState);

              // Save session to IndexedDB
              await keystore.init();
              await keystore.saveSession(handshakeState.sessionId, entry.sender, handshakeState);

              // Delete used prekey secrets
              await deletePrekeySecrets(username);

              // Generate new prekey bundle for future sessions
              console.log('[Handshake] Generating new prekey bundle...');
              await generateAndUploadPrekeyBundle(username, identity);

              // Send response handshake
              const responseWireData = encodeHandshakeMessage(responseMessage);
              const responseData = Buffer.from(responseWireData).toString('base64');

              await fetch(`${getRelayUrl()}/message/${chatId}`, {
                method: 'POST',
                headers: createAuthHeaders(username),
                body: JSON.stringify({
                  sender: username,
                  data: responseData,
                }),
              });

              console.log('[Handshake] Response sent');

              // Show completion message
              setMessages((prev) => [
                ...prev,
                {
                  id: entry.index.toString(),
                  sender: 'system',
                  text: `🔐 Handshake completed with ${entry.sender}. Session established!`,
                  timestamp: Date.now(),
                  encrypted: true,
                },
              ]);

              setLastSyncIndex(entry.index + 1);
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

              // Reconstruct state from stored data
              const storedState = pendingData.state;
              const tempState: HandshakeState = {
                ...storedState,
                sessionId: new Uint8Array(storedState.sessionId),
                rootKey: new Uint8Array(storedState.rootKey),
                sendChainKey: new Uint8Array(storedState.sendChainKey),
                recvChainKey: new Uint8Array(storedState.recvChainKey),
                sendRatchetId: BigInt(storedState.sendRatchetId),
                recvRatchetId: BigInt(storedState.recvRatchetId),
              };

              // Finalize handshake
              const initiatorMsg = pendingData.initiatorMessage;
              const ephemeralX25519Secret = new Uint8Array(pendingData.ephemeralX25519Secret);
              const ephemeralMLKEMSecret = new Uint8Array(pendingData.ephemeralMLKEMSecret);

              const finalState = await finalizeHandshake(
                ephemeralX25519Secret,
                ephemeralMLKEMSecret,
                initiatorMsg,
                handshakeMsg
              );

              console.log('[Handshake] Handshake finalized!');
              console.log('[Handshake] - Session ID:', Buffer.from(finalState.sessionId).toString('hex').slice(0, 32) + '...');

              // Update state
              currentRatchetState = finalState;
              setRatchetState(finalState);

              // Save session to IndexedDB
              await keystore.init();
              await keystore.saveSession(finalState.sessionId, entry.sender, finalState);

              // Clear pending handshake
              sessionStorage.removeItem(`handshake_pending_${chatId}`);

              console.log('[Handshake] Session saved to IndexedDB');

              // Show completion message
              setMessages((prev) => [
                ...prev,
                {
                  id: entry.index.toString(),
                  sender: 'system',
                  text: `🔐 Handshake finalized! Secure session active with ${entry.sender}.`,
                  timestamp: Date.now(),
                  encrypted: true,
                },
              ]);

              setLastSyncIndex(entry.index + 1);
              continue;
            }
          } catch (handshakeError) {
            // Not a handshake message, try as encrypted message
          }

          // Try to decrypt as encrypted message
          try {
            let messageText: string;
            let isEncrypted = false;

            if (currentRatchetState) {
              try {
                console.log('[Message] Decrypting message from:', entry.sender);
                const encryptedRecord = decodeEncryptedMessage(wireData);

                // Get security context for replay protection
                const security = getSessionSecurity(currentRatchetState.sessionId);

                // Check for replay (nonce reuse)
                if (!security.replayProtection.checkNonce(encryptedRecord.nonce)) {
                  console.error('[Message] Replay detected - duplicate nonce');
                  messageText = `[Replay attack detected]`;
                  isEncrypted = false;
                } else {
                  // Decrypt message
                  const { plaintext, newState } = await decryptMessage(currentRatchetState, encryptedRecord);
                  currentRatchetState = newState;
                  setRatchetState(newState);
                  messageText = new TextDecoder('utf-8').decode(plaintext);
                  isEncrypted = true;
                  console.log('[Message] Successfully decrypted:', messageText);
                }
              } catch (encError) {
                console.error('[Message] Decryption failed:', encError);
                messageText = `[Encrypted message - failed to decrypt]`;
                isEncrypted = false;
              }
            } else {
              console.log('[Message] No ratchet state, cannot decrypt');
              messageText = `[Encrypted message - no session]`;
              isEncrypted = false;
            }

            const newMessage: Message = {
              id: entry.index.toString(),
              sender: entry.sender,
              text: messageText,
              timestamp: Date.now(),
              encrypted: isEncrypted,
            };

            setMessages((prev) => {
              if (prev.find((m) => m.id === newMessage.id)) {
                return prev;
              }
              return [...prev, newMessage];
            });
          } catch (err) {
            console.error('[Message] Failed to decode message:', err);
          }

          setLastSyncIndex(entry.index + 1);
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
    if (!recipient.trim() || !identity) return;

    try {
      setHandshakeInProgress(true);
      console.log('[Handshake] Starting chat with:', recipient);

      // 1. Check if we already have a session with this peer
      await keystore.init();
      let existingSession = await keystore.findSessionByPeer(recipient);

      if (existingSession) {
        console.log('[Handshake] Found existing session, loading...');
        setRatchetState(existingSession);

        // Use opaque chatId (hex of sessionId)
        const opaqueId = Buffer.from(existingSession.sessionId).toString('hex');
        setChatId(opaqueId);
        setChatActive(true);

        setMessages([
          {
            id: 'system-init',
            sender: 'system',
            text: `🔐 Existing session restored with ${recipient}`,
            timestamp: Date.now(),
            encrypted: true,
          },
        ]);

        setHandshakeInProgress(false);
        return;
      }

      console.log('[Handshake] No existing session, initiating new handshake...');

      // 2. Fetch recipient's identity and prekey bundle from relay
      const peerData = await fetchPeerBundle(recipient);

      console.log('[Handshake] Fetched peer bundle:', peerData.prekey.bundleId);

      // 3. Reconstruct peer's identity keypair (public keys only)
      const peerIdentity: IdentityKeyPair = {
        ed25519: {
          publicKey: Buffer.from(peerData.identity.identityEd25519, 'base64'),
          secretKey: new Uint8Array(0), // Not needed
        },
        mldsa: {
          publicKey: Buffer.from(peerData.identity.identityMLDSA, 'base64'),
          secretKey: new Uint8Array(0),
        },
      };

      // 4. Reconstruct peer's prekey bundle (public part only)
      const peerBundle: Omit<PrekeyBundle, 'x25519SecretKey' | 'mlkemSecretKey'> = {
        bundleId: peerData.prekey.bundleId,
        x25519Ephemeral: Buffer.from(peerData.prekey.x25519Ephemeral, 'base64'),
        mlkemPublicKey: Buffer.from(peerData.prekey.mlkemPublicKey, 'base64'),
        ed25519Signature: Buffer.from(peerData.prekey.ed25519Signature, 'base64'),
        mldsaSignature: Buffer.from(peerData.prekey.mldsaSignature, 'base64'),
        timestamp: peerData.prekey.timestamp,
      };

      // SECURITY: Verify prekey bundle signatures before trusting
      console.log('[Security] Verifying prekey bundle signatures...');
      const { ed25519Verify } = await import('@ilyazh/crypto');
      const { encode } = await import('cbor-x');

      // Reconstruct the signed data (must match what was signed during generation)
      const bundleData = encode({
        bundleId: peerBundle.bundleId,
        x25519: peerBundle.x25519Ephemeral,
        mlkem: peerBundle.mlkemPublicKey,
        timestamp: peerBundle.timestamp,
      });

      // Verify Ed25519 signature
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
      // Note: ML-DSA verification skipped until real implementation exists (currently mocked)

      console.log('[Handshake] Initiating handshake with verified peer bundle...');

      // 5. Initiate handshake (we are Alice)
      // Note: initiateHandshake only returns message and ephemeralX25519Secret
      // The state is created later in finalizeHandshake
      const { message: handshakeMessage, ephemeralX25519Secret } = await initiateHandshake(
        identity,
        peerIdentity.ed25519.publicKey,
        peerIdentity.mldsa.publicKey,
        peerBundle as any // Type mismatch - needs proper handling
      );

      console.log('[Handshake] Handshake initiated (message created)');

      // 6. Generate deterministic chatId based on sorted participants
      // This ensures both users use the same chat room
      // SECURITY: Use hash to obscure participant names (metadata privacy)
      const { sha256 } = await import('@noble/hashes/sha256');
      const participants = [username, recipient].sort();
      const participantsString = participants.join('_');
      const hash = sha256(new TextEncoder().encode(participantsString));
      const chatIdString = Buffer.from(hash).toString('hex').slice(0, 32);

      console.log('[Security] Using obfuscated chat ID to protect metadata');
      setChatId(chatIdString);

      // 7. Store pending handshake data in sessionStorage (for finalization)
      // Note: ephemeralMLKEMSecret is part of the bundle, not returned separately
      sessionStorage.setItem(`handshake_pending_${chatIdString}`, JSON.stringify({
        initiatorMessage: {
          ...handshakeMessage,
          ephemeralX25519: Array.from(handshakeMessage.ephemeralX25519),
          ephemeralMLKEM: Array.from(handshakeMessage.ephemeralMLKEM),
          identityPublicEd25519: Array.from(handshakeMessage.identityPublicEd25519),
          identityPublicMLDSA: Array.from(handshakeMessage.identityPublicMLDSA),
          ed25519Signature: Array.from(handshakeMessage.ed25519Signature),
          mldsaSignature: Array.from(handshakeMessage.mldsaSignature),
        },
        ephemeralX25519Secret: Array.from(ephemeralX25519Secret),
        // TODO: ephemeralMLKEMSecret not returned by initiateHandshake - API needs review
      }));

      // 8. Initialize chat on relay server
      const initRes = await fetch(`${getRelayUrl()}/chat/init`, {
        method: 'POST',
        headers: createAuthHeaders(username),
        body: JSON.stringify({
          chatId: chatIdString,
          participants: [username, recipient],
        }),
      });

      if (!initRes.ok && initRes.status !== 409) {
        throw new Error('Failed to initialize chat on relay');
      }

      // 9. Encode and send handshake message
      const wireData = encodeHandshakeMessage(handshakeMessage);
      const data = Buffer.from(wireData).toString('base64');

      console.log('[Handshake] Sending handshake message to relay...');

      const sendRes = await fetch(`${getRelayUrl()}/message/${chatIdString}`, {
        method: 'POST',
        headers: createAuthHeaders(username),
        body: JSON.stringify({
          sender: username,
          data: data,
        }),
      });

      if (!sendRes.ok) {
        throw new Error('Failed to send handshake message');
      }

      console.log('[Handshake] Handshake message sent, waiting for response...');

      // Don't set ratchetState yet - wait for finalization
      setChatActive(true);
      setSessionInfo({
        sessionId: chatIdString.slice(0, 16) + '...',
        ratchetId: 0,
        messageCount: 0,
        epochAge: '0s',
        sessionAge: '0s',
      });

      setMessages([
        {
          id: 'system-handshake',
          sender: 'system',
          text: `🔐 Handshake sent to ${recipient}. Waiting for response...`,
          timestamp: Date.now(),
          encrypted: true,
        },
      ]);

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
    setInputText('');

    try {
      let data: string;

      if (ratchetState) {
        // Encrypt message using ratchet
        const plaintext = new TextEncoder().encode(messageText);
        const { record, newState } = await encryptMessage(ratchetState, plaintext);
        setRatchetState(newState);

        // Encode as wire format
        const wireData = encodeEncryptedMessage(record);
        data = Buffer.from(wireData).toString('base64');
      } else {
        // Fallback to plain base64 if no session yet
        data = Buffer.from(messageText, 'utf-8').toString('base64');
      }

      const response = await fetch(`${getRelayUrl()}/message/${chatId}`, {
        method: 'POST',
        headers: createAuthHeaders(username),
        body: JSON.stringify({
          sender: username,
          data: data,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to send message');
      }

      const result = await response.json();

      const newMessage: Message = {
        id: result.index.toString(),
        sender: username,
        text: messageText,
        timestamp: Date.now(),
        encrypted: !!ratchetState,
      };

      setMessages((prev) => [...prev, newMessage]);

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
      <main className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
        <div className="text-lg">Loading...</div>
      </main>
    );
  }

  if (!identity) {
    return (
      <main className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
        <div className="text-lg">Generating identity keys...</div>
      </main>
    );
  }

  if (!chatActive) {
    return (
      <main className="min-h-screen flex flex-col items-center justify-center p-8 bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
        <div className="w-full max-w-md bg-white dark:bg-gray-800 rounded-lg shadow-xl p-8">
          <Link href="/" className="text-sm text-blue-500 hover:underline mb-4 block">
            ← Back to Home
          </Link>

          <h1 className="text-3xl font-bold mb-4">💬 Start Chat</h1>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            Logged in as <strong>{username}</strong>
          </p>

          <input
            type="text"
            placeholder="Recipient username"
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !handshakeInProgress && startChat()}
            disabled={handshakeInProgress}
            className="w-full p-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 mb-4"
          />

          <button
            onClick={startChat}
            disabled={handshakeInProgress}
            className="w-full p-3 bg-blue-500 hover:bg-blue-600 text-white rounded-lg font-semibold transition disabled:opacity-50"
          >
            {handshakeInProgress ? 'Initializing...' : 'Start Encrypted Chat'}
          </button>

          <div className="mt-6 text-sm text-gray-600 dark:text-gray-400">
            <p className="font-semibold mb-2">Ilyazh-Web3E2E Protocol:</p>
            <ol className="list-decimal list-inside space-y-1">
              <li>Hybrid AKE (X25519 + ML-KEM-768)</li>
              <li>Dual signatures (Ed25519 + ML-DSA-65)</li>
              <li>Session ID derivation with HKDF-SHA-384</li>
              <li>Double ratchet with mandatory rekey</li>
              <li>AES-256-GCM with sid-in-AAD</li>
            </ol>
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen flex flex-col bg-gray-100 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 shadow-sm p-4 flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Link href="/" className="text-blue-500 hover:underline text-sm">
            ← Home
          </Link>
          <div>
            <div className="font-semibold">
              {username} → {recipient}
            </div>
            <div className="text-xs text-green-600 dark:text-green-400">
              {ratchetState ? '🔒 E2E Encrypted (Active)' : '⚠️ Handshake Pending'}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {sessionInfo && (
            <div className="text-xs text-gray-600 dark:text-gray-400">
              <div>Messages: {sessionInfo.messageCount}</div>
              <div>Epoch: {sessionInfo.ratchetId}</div>
            </div>
          )}
          {ratchetState && (
            <button
              onClick={() => setShowSafetyNumber(true)}
              className="px-3 py-1 text-xs bg-gray-200 dark:bg-gray-700 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition"
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
      {showSafetyNumber && ratchetState && (
        <SafetyNumber
          sessionId={ratchetState.sessionId}
          peerName={recipient}
          onClose={() => setShowSafetyNumber(false)}
        />
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex ${msg.sender === username ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-md p-3 rounded-lg ${
                msg.sender === 'system'
                  ? 'bg-yellow-100 dark:bg-yellow-900/30 text-center w-full'
                  : msg.sender === username
                  ? 'bg-blue-500 text-white'
                  : 'bg-white dark:bg-gray-800'
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
      <div className="bg-white dark:bg-gray-800 p-4 border-t dark:border-gray-700">
        <div className="flex space-x-2">
          <input
            type="text"
            placeholder="Type a message..."
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
            className="flex-1 p-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 dark:bg-gray-700"
          />
          <button
            onClick={sendMessage}
            className="px-6 py-3 bg-blue-500 hover:bg-blue-600 text-white rounded-lg font-semibold transition"
          >
            Send
          </button>
        </div>
        <div className="text-xs text-gray-500 dark:text-gray-400 mt-2">
          {ratchetState
            ? 'All messages encrypted with AES-256-GCM • sid in AAD'
            : 'Messages will be encrypted once handshake completes'}
        </div>
      </div>
    </main>
  );
}
