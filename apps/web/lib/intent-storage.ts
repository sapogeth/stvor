/**
 * Intent Storage
 * 
 * Stores intents to allow secure directory access
 * Intent: "I (alice) am about to chat with (bob)"
 * 
 * Format: key = "alice:bob", value = { identityKey, expiresAt }
 * TTL: 1 hour
 */

interface StoredIntent {
  from: string;
  to: string;
  identityEd25519: string;
  timestamp: number;
  expiresAt: number;
}

// In-memory storage (TODO: persist to KV / DB for production)
const INTENT_MAP = new Map<string, StoredIntent>();

/**
 * Store an intent
 * @param from - Current user ID/username
 * @param to - Target user (peer) username
 * @param identityEd25519 - Our Ed25519 identity key (base64)
 */
export function storeIntent(from: string, to: string, identityEd25519: string): void {
  const key = `${from}:${to}`;
  const intent: StoredIntent = {
    from,
    to,
    identityEd25519,
    timestamp: Date.now(),
    expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour TTL
  };

  INTENT_MAP.set(key, intent);
  console.log('[intent-storage] Stored intent', { from, to, expiresAt: intent.expiresAt });
}

/**
 * Get an intent (verify it exists and is not expired)
 * @param from - User ID who initiated
 * @param to - Target user (peer) username
 * @returns Intent data if valid, null if expired/not found
 */
export function getIntent(from: string, to: string): StoredIntent | null {
  const key = `${from}:${to}`;
  const intent = INTENT_MAP.get(key);

  if (!intent) {
    console.log('[intent-storage] Intent not found', { from, to, key });
    return null;
  }

  // Check if expired
  if (intent.expiresAt < Date.now()) {
    console.log('[intent-storage] Intent expired', { from, to });
    INTENT_MAP.delete(key);
    return null;
  }

  return intent;
}

/**
 * Delete an intent (called after successful handshake)
 */
export function deleteIntent(from: string, to: string): void {
  const key = `${from}:${to}`;
  INTENT_MAP.delete(key);
  console.log('[intent-storage] Deleted intent', { from, to });
}

/**
 * Get all intents (for debugging)
 */
export function getAllIntents(): StoredIntent[] {
  return Array.from(INTENT_MAP.values());
}

/**
 * Clear all intents (for testing)
 */
export function clearAllIntents(): void {
  INTENT_MAP.clear();
  console.log('[intent-storage] Cleared all intents');
}
