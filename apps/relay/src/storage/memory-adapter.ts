/**
 * In-Memory Storage Adapter
 * For development and testing only
 * NOT suitable for production (data lost on restart, no horizontal scaling)
 */

import type {
  IStorageAdapter,
  IUserRepository,
  IPrekeyRepository,
  IMessageRepository,
  ISyncRepository,
  IRateLimitRepository,
  IPostRepository,
  UserIdentity,
  PrekeyBundle,
  MessageBlob,
  SyncCursor,
  Post,
} from './interfaces.js';

class MemoryUserRepository implements IUserRepository {
  private users = new Map<string, UserIdentity>();
  private usernameIndex = new Map<string, string>(); // username -> userId

  async createUser(user: UserIdentity): Promise<boolean> {
    if (this.users.has(user.userId)) {
      return false;
    }
    this.users.set(user.userId, user);
    this.usernameIndex.set(user.username, user.userId);
    return true;
  }

  async getUserById(userId: string): Promise<UserIdentity | null> {
    return this.users.get(userId) || null;
  }

  async getUserByUsername(username: string): Promise<UserIdentity | null> {
    const userId = this.usernameIndex.get(username);
    if (!userId) return null;
    return this.getUserById(userId);
  }

  async userExists(userId: string): Promise<boolean> {
    return this.users.has(userId);
  }

  async getTotalUserCount(): Promise<number> {
    return this.users.size;
  }
}

class MemoryPrekeyRepository implements IPrekeyRepository {
  private prekeys = new Map<string, PrekeyBundle[]>(); // userId -> bundles

  async storePrekeyBundle(bundle: PrekeyBundle): Promise<boolean> {
    const bundles = this.prekeys.get(bundle.userId) || [];

    // Check for duplicate bundleId
    if (bundles.some(b => b.bundleId === bundle.bundleId)) {
      return false;
    }

    bundles.push(bundle);
    this.prekeys.set(bundle.userId, bundles);
    return true;
  }

  async getSignedPrekey(userId: string): Promise<PrekeyBundle | null> {
    const bundles = this.prekeys.get(userId) || [];

    // Find most recent non-consumed, non-one-time prekey
    const signedPrekeys = bundles
      .filter(b => !b.isOneTime && !b.consumed)
      .sort((a, b) => b.createdAt - a.createdAt);

    return signedPrekeys[0] || null;
  }

  async consumeOneTimePrekey(userId: string, consumedBy: string): Promise<PrekeyBundle | null> {
    const bundles = this.prekeys.get(userId) || [];

    // Find first available one-time prekey
    const oneTimePrekey = bundles.find(b => b.isOneTime && !b.consumed);

    if (!oneTimePrekey) {
      return null;
    }

    // Mark as consumed (atomic in memory)
    oneTimePrekey.consumed = true;
    oneTimePrekey.consumedAt = Date.now();
    oneTimePrekey.consumedBy = consumedBy;

    return oneTimePrekey;
  }

  async listPrekeyBundles(userId: string): Promise<PrekeyBundle[]> {
    return this.prekeys.get(userId) || [];
  }

  async deleteOldPrekeys(userId: string, olderThan: number): Promise<number> {
    const bundles = this.prekeys.get(userId) || [];
    const before = bundles.length;

    const filtered = bundles.filter(b => b.createdAt >= olderThan);
    this.prekeys.set(userId, filtered);

    return before - filtered.length;
  }

  async countAvailableOneTimePrekeys(userId: string): Promise<number> {
    const bundles = this.prekeys.get(userId) || [];
    return bundles.filter(b => b.isOneTime && !b.consumed).length;
  }
}

class MemoryMessageRepository implements IMessageRepository {
  private blobs = new Map<string, MessageBlob>(); // blobRef -> blob
  private chatIndex = new Map<string, string[]>(); // chatId -> blobRefs (ordered)
  private sequences = new Map<string, number>(); // chatId -> latest sequence

  async storeBlob(blob: MessageBlob): Promise<boolean> {
    if (this.blobs.has(blob.blobRef)) {
      return false;
    }

    this.blobs.set(blob.blobRef, blob);

    // Add to chat index
    const chatBlobs = this.chatIndex.get(blob.chatId) || [];
    chatBlobs.push(blob.blobRef);
    this.chatIndex.set(blob.chatId, chatBlobs);

    // Update sequence
    const currentSeq = this.sequences.get(blob.chatId) || 0;
    this.sequences.set(blob.chatId, Math.max(currentSeq, blob.sequence));

    return true;
  }

  async getBlob(blobRef: string): Promise<MessageBlob | null> {
    return this.blobs.get(blobRef) || null;
  }

  async listBlobsSince(chatId: string, sinceSequence: number, limit = 100): Promise<MessageBlob[]> {
    const blobRefs = this.chatIndex.get(chatId) || [];
    const blobs: MessageBlob[] = [];

    for (const ref of blobRefs) {
      const blob = this.blobs.get(ref);
      if (blob && blob.sequence > sinceSequence) {
        blobs.push(blob);
        if (blobs.length >= limit) break;
      }
    }

    return blobs.sort((a, b) => a.sequence - b.sequence);
  }

  async getLatestSequence(chatId: string): Promise<number> {
    return this.sequences.get(chatId) || 0;
  }

  async deleteOldBlobs(chatId: string, olderThan: number): Promise<number> {
    const blobRefs = this.chatIndex.get(chatId) || [];
    let deleted = 0;

    const remaining: string[] = [];
    for (const ref of blobRefs) {
      const blob = this.blobs.get(ref);
      if (blob && blob.createdAt < olderThan) {
        this.blobs.delete(ref);
        deleted++;
      } else {
        remaining.push(ref);
      }
    }

    this.chatIndex.set(chatId, remaining);
    return deleted;
  }
}

class MemorySyncRepository implements ISyncRepository {
  private cursors = new Map<string, SyncCursor>(); // userId:chatId -> cursor

  private makeKey(userId: string, chatId: string): string {
    return `${userId}:${chatId}`;
  }

  async getCursor(userId: string, chatId: string): Promise<SyncCursor | null> {
    return this.cursors.get(this.makeKey(userId, chatId)) || null;
  }

  async updateCursor(userId: string, chatId: string, sequence: number): Promise<void> {
    const key = this.makeKey(userId, chatId);
    const existing = this.cursors.get(key);

    if (existing) {
      existing.lastSeenSequence = sequence;
      existing.updatedAt = Date.now();
    } else {
      this.cursors.set(key, {
        userId,
        chatId,
        lastSeenSequence: sequence,
        updatedAt: Date.now(),
      });
    }
  }

  async listCursors(userId: string): Promise<SyncCursor[]> {
    const result: SyncCursor[] = [];
    for (const [key, cursor] of this.cursors) {
      if (cursor.userId === userId) {
        result.push(cursor);
      }
    }
    return result;
  }
}

class MemoryRateLimitRepository implements IRateLimitRepository {
  private counters = new Map<string, { count: number; timestamps: number[] }>();

  async checkAndIncrement(key: string, limit: number, windowMs: number): Promise<boolean> {
    const now = Date.now();
    const entry = this.counters.get(key) || { count: 0, timestamps: [] };

    // Remove expired timestamps
    entry.timestamps = entry.timestamps.filter(ts => now - ts < windowMs);
    entry.count = entry.timestamps.length;

    if (entry.count >= limit) {
      this.counters.set(key, entry);
      return false;
    }

    // Increment
    entry.timestamps.push(now);
    entry.count++;
    this.counters.set(key, entry);
    return true;
  }

  async getCount(key: string): Promise<number> {
    return this.counters.get(key)?.count || 0;
  }

  async reset(key: string): Promise<void> {
    this.counters.delete(key);
  }
}

class MemoryPostRepository implements IPostRepository {
  private posts = new Map<string, Post>(); // postId -> post
  private userPostsIndex = new Map<string, string[]>(); // userId -> postIds

  async createPost(post: Post): Promise<boolean> {
    if (this.posts.has(post.postId)) {
      return false;
    }

    this.posts.set(post.postId, post);

    // Add to user index
    const userPosts = this.userPostsIndex.get(post.authorId) || [];
    userPosts.push(post.postId);
    this.userPostsIndex.set(post.authorId, userPosts);

    return true;
  }

  async getPost(postId: string): Promise<Post | null> {
    return this.posts.get(postId) || null;
  }

  async getFeed(limit: number, beforeTimestamp?: number): Promise<Post[]> {
    const allPosts = Array.from(this.posts.values());

    // Filter by timestamp if provided
    const filtered = beforeTimestamp
      ? allPosts.filter(p => p.createdAt < beforeTimestamp)
      : allPosts;

    // Sort by creation time (newest first)
    filtered.sort((a, b) => b.createdAt - a.createdAt);

    return filtered.slice(0, limit);
  }

  async getUserPosts(userId: string, limit: number): Promise<Post[]> {
    const postIds = this.userPostsIndex.get(userId) || [];
    const posts: Post[] = [];

    for (const postId of postIds) {
      const post = this.posts.get(postId);
      if (post) {
        posts.push(post);
      }
    }

    // Sort by creation time (newest first)
    posts.sort((a, b) => b.createdAt - a.createdAt);

    return posts.slice(0, limit);
  }

  async deletePost(postId: string, userId: string): Promise<boolean> {
    const post = this.posts.get(postId);
    if (!post || post.authorId !== userId) {
      return false;
    }

    this.posts.delete(postId);

    // Remove from user index
    const userPosts = this.userPostsIndex.get(userId) || [];
    const filtered = userPosts.filter(id => id !== postId);
    this.userPostsIndex.set(userId, filtered);

    return true;
  }

  async incrementLikes(postId: string): Promise<void> {
    const post = this.posts.get(postId);
    if (post) {
      post.likesCount++;
    }
  }

  async getTotalPostCount(): Promise<number> {
    return this.posts.size;
  }
}

export class MemoryStorageAdapter implements IStorageAdapter {
  users: IUserRepository;
  prekeys: IPrekeyRepository;
  messages: IMessageRepository;
  sync: ISyncRepository;
  rateLimit: IRateLimitRepository;
  posts: IPostRepository;

  constructor() {
    this.users = new MemoryUserRepository();
    this.prekeys = new MemoryPrekeyRepository();
    this.messages = new MemoryMessageRepository();
    this.sync = new MemorySyncRepository();
    this.rateLimit = new MemoryRateLimitRepository();
    this.posts = new MemoryPostRepository();
  }

  async init(): Promise<void> {
    console.log('[MemoryStorageAdapter] Initialized (in-memory storage)');
  }

  async close(): Promise<void> {
    console.log('[MemoryStorageAdapter] Closed');
  }

  async isHealthy(): Promise<boolean> {
    return true;
  }
}
