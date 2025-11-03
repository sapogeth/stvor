/**
 * Storage Abstraction Layer for Horizontal Scalability
 * Enables multiple relay instances to share state via external storage
 */

export interface UserIdentity {
  userId: string;
  username: string;
  identityEd25519: string; // base64
  identityMLDSA: string; // base64
  registeredAt: number;
}

export interface PrekeyBundle {
  userId: string;
  bundleId: string;
  x25519Ephemeral: string; // base64
  mlkemPublicKey: string; // base64
  ed25519Signature: string; // base64
  mldsaSignature: string; // base64
  timestamp: number;
  createdAt: number;
  isOneTime: boolean; // true for one-time prekeys, false for signed prekeys
  consumed: boolean; // only relevant for one-time prekeys
  consumedAt?: number;
  consumedBy?: string; // userId who consumed this prekey
}

export interface MessageBlob {
  chatId: string;
  blobRef: string; // SHA-256 hash of blob
  encryptedBlob: Buffer;
  createdAt: number;
  senderId: string;
  sequence: number; // monotonic sequence per chat
  messageType?: 'handshake' | 'message'; // CRITICAL: handshake vs regular message
}

export interface SyncCursor {
  userId: string;
  chatId: string;
  lastSeenSequence: number;
  updatedAt: number;
}

/**
 * User Repository
 * Manages user identities (long-term public keys)
 */
export interface IUserRepository {
  /**
   * Store a new user identity
   * Returns false if user already exists
   */
  createUser(user: UserIdentity): Promise<boolean>;

  /**
   * Get user identity by userId
   * Returns null if not found
   */
  getUserById(userId: string): Promise<UserIdentity | null>;

  /**
   * Get user identity by username
   * Returns null if not found
   */
  getUserByUsername(username: string): Promise<UserIdentity | null>;

  /**
   * Check if user exists
   */
  userExists(userId: string): Promise<boolean>;
}

/**
 * Prekey Repository
 * Manages signed prekeys and one-time prekeys for X3DH-style handshakes
 */
export interface IPrekeyRepository {
  /**
   * Store a prekey bundle
   * Returns false if bundleId already exists for this user
   */
  storePrekeyBundle(bundle: PrekeyBundle): Promise<boolean>;

  /**
   * Get the current signed prekey for a user
   * Returns the most recent non-consumed, non-one-time prekey
   */
  getSignedPrekey(userId: string): Promise<PrekeyBundle | null>;

  /**
   * Get and consume a one-time prekey for a user
   * Atomically marks the prekey as consumed
   * Returns null if no one-time prekeys available
   */
  consumeOneTimePrekey(userId: string, consumedBy: string): Promise<PrekeyBundle | null>;

  /**
   * List all prekey bundles for a user (for rotation/cleanup)
   */
  listPrekeyBundles(userId: string): Promise<PrekeyBundle[]>;

  /**
   * Delete old/expired prekey bundles
   * Returns count of deleted bundles
   */
  deleteOldPrekeys(userId: string, olderThan: number): Promise<number>;

  /**
   * Get count of available one-time prekeys
   */
  countAvailableOneTimePrekeys(userId: string): Promise<number>;
}

/**
 * Message Repository
 * Manages encrypted message blobs (content-addressed storage)
 */
export interface IMessageRepository {
  /**
   * Store an encrypted message blob
   * blobRef is SHA-256 hash of the blob (content-addressed)
   * Returns false if blob already exists
   */
  storeBlob(blob: MessageBlob): Promise<boolean>;

  /**
   * Get a blob by its reference (hash)
   */
  getBlob(blobRef: string): Promise<MessageBlob | null>;

  /**
   * List blobs for a chat since a sequence number
   * Used for /sync endpoint
   */
  listBlobsSince(chatId: string, sinceSequence: number, limit?: number): Promise<MessageBlob[]>;

  /**
   * Get the latest sequence number for a chat
   */
  getLatestSequence(chatId: string): Promise<number>;

  /**
   * Delete old blobs (for retention policy)
   * Returns count of deleted blobs
   */
  deleteOldBlobs(chatId: string, olderThan: number): Promise<number>;
}

/**
 * Sync Repository
 * Manages per-user sync cursors for message polling
 */
export interface ISyncRepository {
  /**
   * Get sync cursor for a user in a chat
   */
  getCursor(userId: string, chatId: string): Promise<SyncCursor | null>;

  /**
   * Update sync cursor (last seen sequence)
   */
  updateCursor(userId: string, chatId: string, sequence: number): Promise<void>;

  /**
   * List all cursors for a user (for cleanup)
   */
  listCursors(userId: string): Promise<SyncCursor[]>;
}

/**
 * Rate Limit Repository
 * Manages rate limiting state (sliding window)
 */
export interface IRateLimitRepository {
  /**
   * Check if action is allowed under rate limit
   * Returns true if allowed, false if rate limited
   * Automatically increments counter if allowed
   */
  checkAndIncrement(key: string, limit: number, windowMs: number): Promise<boolean>;

  /**
   * Get current count for a key
   */
  getCount(key: string): Promise<number>;

  /**
   * Reset rate limit for a key
   */
  reset(key: string): Promise<void>;
}

/**
 * Storage Factory
 * Creates repository instances based on configuration
 */
export interface IStorageAdapter {
  users: IUserRepository;
  prekeys: IPrekeyRepository;
  messages: IMessageRepository;
  sync: ISyncRepository;
  rateLimit: IRateLimitRepository;

  /**
   * Initialize storage (connect to DB, create tables, etc.)
   */
  init(): Promise<void>;

  /**
   * Close storage connections
   */
  close(): Promise<void>;

  /**
   * Health check
   */
  isHealthy(): Promise<boolean>;
}
