/**
 * Message Persistence Layer - IndexedDB Storage
 *
 * ARCHITECTURE:
 * - Stores encrypted messages locally in IndexedDB
 * - Each chat has its own message history
 * - Messages are stored with metadata (timestamp, sender, encryption status)
 * - Supports pagination and efficient querying
 *
 * SECURITY:
 * - Stores messages after decryption (for local display only)
 * - Database is browser-specific and user-specific
 * - No server-side storage of message content
 */

const DB_NAME = 'stvor-messages';
const DB_VERSION = 2; // Incremented: added 'recipient' field to StoredMessage
const STORE_NAME = 'messages';

export interface StoredMessage {
  id: string;
  chatId: string;
  sender: string;
  recipient: string; // Username of the other participant in the chat
  text: string;
  timestamp: number;
  encrypted: boolean;
}

/**
 * Open IndexedDB connection
 */
async function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      // Create object store if it doesn't exist
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'id' });

        // Create indexes for efficient querying
        store.createIndex('chatId', 'chatId', { unique: false });
        store.createIndex('timestamp', 'timestamp', { unique: false });
        store.createIndex('chatId_timestamp', ['chatId', 'timestamp'], { unique: false });
      }
    };
  });
}

/**
 * Save a message to IndexedDB
 */
export async function saveMessage(message: StoredMessage): Promise<void> {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    const request = store.put(message);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();

    transaction.oncomplete = () => db.close();
  });
}

/**
 * Save multiple messages in a batch
 */
export async function saveMessages(messages: StoredMessage[]): Promise<void> {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    let completed = 0;
    const total = messages.length;

    if (total === 0) {
      db.close();
      resolve();
      return;
    }

    messages.forEach((message) => {
      const request = store.put(message);

      request.onsuccess = () => {
        completed++;
        if (completed === total) {
          resolve();
        }
      };

      request.onerror = () => reject(request.error);
    });

    transaction.oncomplete = () => db.close();
  });
}

/**
 * Load all messages for a specific chat
 */
export async function loadMessages(chatId: string): Promise<StoredMessage[]> {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const index = store.index('chatId_timestamp');

    // Get all messages for this chat, ordered by timestamp
    const request = index.getAll(IDBKeyRange.bound([chatId, 0], [chatId, Date.now()]));

    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const messages = request.result as StoredMessage[];
      // Sort by timestamp ascending (oldest first)
      messages.sort((a, b) => a.timestamp - b.timestamp);
      resolve(messages);
    };

    transaction.oncomplete = () => db.close();
  });
}

/**
 * Delete all messages for a specific chat
 */
export async function deleteChat(chatId: string): Promise<void> {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const index = store.index('chatId');

    const request = index.openCursor(IDBKeyRange.only(chatId));

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;
      if (cursor) {
        cursor.delete();
        cursor.continue();
      } else {
        resolve();
      }
    };

    request.onerror = () => reject(request.error);

    transaction.oncomplete = () => db.close();
  });
}

/**
 * Get all chat IDs with at least one message
 */
export async function getAllChatIds(): Promise<string[]> {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const index = store.index('chatId');

    const request = index.openKeyCursor(null, 'nextunique');
    const chatIds: string[] = [];

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;
      if (cursor) {
        const chatId = cursor.key as string;
        chatIds.push(chatId);
        cursor.continue();
      } else {
        resolve(chatIds);
      }
    };

    request.onerror = () => reject(request.error);

    transaction.oncomplete = () => db.close();
  });
}

/**
 * Get the last message for a chat (for preview)
 */
export async function getLastMessage(chatId: string): Promise<StoredMessage | null> {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const index = store.index('chatId_timestamp');

    // Get messages in descending order
    const request = index.openCursor(
      IDBKeyRange.bound([chatId, 0], [chatId, Date.now()]),
      'prev'
    );

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;
      if (cursor) {
        resolve(cursor.value as StoredMessage);
      } else {
        resolve(null);
      }
    };

    request.onerror = () => reject(request.error);

    transaction.oncomplete = () => db.close();
  });
}

/**
 * Clear all message data (for logout/reset)
 */
export async function clearAllMessages(): Promise<void> {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    const request = store.clear();

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();

    transaction.oncomplete = () => db.close();
  });
}
