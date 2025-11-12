/**
 * PostgreSQL Storage Adapter
 * Production-ready, horizontally scalable storage backend
 * Supports multiple relay instances sharing the same database
 */

import pg from 'pg';
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

const { Pool } = pg;

class PostgresUserRepository implements IUserRepository {
  constructor(private pool: pg.Pool) {}

  async createUser(user: UserIdentity): Promise<boolean> {
    try {
      await this.pool.query(
        `INSERT INTO users (user_id, username, identity_ed25519, identity_mldsa, registered_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [user.userId, user.username, user.identityEd25519, user.identityMLDSA, user.registeredAt]
      );
      return true;
    } catch (err: any) {
      // Unique constraint violation
      if (err.code === '23505') {
        return false;
      }
      throw err;
    }
  }

  async getUserById(userId: string): Promise<UserIdentity | null> {
    const result = await this.pool.query(
      `SELECT user_id, username, identity_ed25519, identity_mldsa, registered_at
       FROM users WHERE user_id = $1`,
      [userId]
    );

    if (result.rows.length === 0) return null;

    const row = result.rows[0];
    return {
      userId: row.user_id,
      username: row.username,
      identityEd25519: row.identity_ed25519,
      identityMLDSA: row.identity_mldsa,
      registeredAt: parseInt(row.registered_at),
    };
  }

  async getUserByUsername(username: string): Promise<UserIdentity | null> {
    const result = await this.pool.query(
      `SELECT user_id, username, identity_ed25519, identity_mldsa, registered_at
       FROM users WHERE username = $1`,
      [username]
    );

    if (result.rows.length === 0) return null;

    const row = result.rows[0];
    return {
      userId: row.user_id,
      username: row.username,
      identityEd25519: row.identity_ed25519,
      identityMLDSA: row.identity_mldsa,
      registeredAt: parseInt(row.registered_at),
    };
  }

  async userExists(userId: string): Promise<boolean> {
    const result = await this.pool.query(
      `SELECT 1 FROM users WHERE user_id = $1`,
      [userId]
    );
    return result.rows.length > 0;
  }

  async getTotalUserCount(): Promise<number> {
    const result = await this.pool.query(
      `SELECT COUNT(*) as count FROM users`
    );
    return parseInt(result.rows[0].count);
  }
}

class PostgresPrekeyRepository implements IPrekeyRepository {
  constructor(private pool: pg.Pool) {}

  async storePrekeyBundle(bundle: PrekeyBundle): Promise<boolean> {
    try {
      await this.pool.query(
        `INSERT INTO prekey_bundles (
          user_id, bundle_id, x25519_ephemeral, mlkem_public_key,
          ed25519_signature, mldsa_signature, timestamp, created_at,
          is_one_time, consumed, consumed_at, consumed_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
        [
          bundle.userId, bundle.bundleId, bundle.x25519Ephemeral, bundle.mlkemPublicKey,
          bundle.ed25519Signature, bundle.mldsaSignature, bundle.timestamp, bundle.createdAt,
          bundle.isOneTime, bundle.consumed, bundle.consumedAt || null, bundle.consumedBy || null
        ]
      );
      return true;
    } catch (err: any) {
      if (err.code === '23505') {
        return false;
      }
      throw err;
    }
  }

  async getSignedPrekey(userId: string): Promise<PrekeyBundle | null> {
    const result = await this.pool.query(
      `SELECT * FROM prekey_bundles
       WHERE user_id = $1 AND is_one_time = false AND consumed = false
       ORDER BY created_at DESC
       LIMIT 1`,
      [userId]
    );

    if (result.rows.length === 0) return null;
    return this.rowToBundle(result.rows[0]);
  }

  async consumeOneTimePrekey(userId: string, consumedBy: string): Promise<PrekeyBundle | null> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Select and lock
      const selectResult = await client.query(
        `SELECT * FROM prekey_bundles
         WHERE user_id = $1 AND is_one_time = true AND consumed = false
         ORDER BY created_at ASC
         LIMIT 1
         FOR UPDATE SKIP LOCKED`,
        [userId]
      );

      if (selectResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return null;
      }

      const bundle = this.rowToBundle(selectResult.rows[0]);

      // Mark as consumed
      await client.query(
        `UPDATE prekey_bundles
         SET consumed = true, consumed_at = $1, consumed_by = $2
         WHERE bundle_id = $3 AND user_id = $4`,
        [Date.now(), consumedBy, bundle.bundleId, userId]
      );

      await client.query('COMMIT');

      bundle.consumed = true;
      bundle.consumedAt = Date.now();
      bundle.consumedBy = consumedBy;

      return bundle;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async listPrekeyBundles(userId: string): Promise<PrekeyBundle[]> {
    const result = await this.pool.query(
      `SELECT * FROM prekey_bundles WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId]
    );
    return result.rows.map(row => this.rowToBundle(row));
  }

  async deleteOldPrekeys(userId: string, olderThan: number): Promise<number> {
    const result = await this.pool.query(
      `DELETE FROM prekey_bundles WHERE user_id = $1 AND created_at < $2`,
      [userId, olderThan]
    );
    return result.rowCount || 0;
  }

  async countAvailableOneTimePrekeys(userId: string): Promise<number> {
    const result = await this.pool.query(
      `SELECT COUNT(*) as count FROM prekey_bundles
       WHERE user_id = $1 AND is_one_time = true AND consumed = false`,
      [userId]
    );
    return parseInt(result.rows[0].count);
  }

  private rowToBundle(row: any): PrekeyBundle {
    return {
      userId: row.user_id,
      bundleId: row.bundle_id,
      x25519Ephemeral: row.x25519_ephemeral,
      mlkemPublicKey: row.mlkem_public_key,
      ed25519Signature: row.ed25519_signature,
      mldsaSignature: row.mldsa_signature,
      timestamp: parseInt(row.timestamp),
      createdAt: parseInt(row.created_at),
      isOneTime: row.is_one_time,
      consumed: row.consumed,
      consumedAt: row.consumed_at ? parseInt(row.consumed_at) : undefined,
      consumedBy: row.consumed_by || undefined,
    };
  }
}

class PostgresMessageRepository implements IMessageRepository {
  constructor(private pool: pg.Pool) {}

  async storeBlob(blob: MessageBlob): Promise<boolean> {
    try {
      await this.pool.query(
        `INSERT INTO message_blobs (chat_id, blob_ref, encrypted_blob, created_at, sender_id, sequence, message_type)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [blob.chatId, blob.blobRef, blob.encryptedBlob, blob.createdAt, blob.senderId, blob.sequence, blob.messageType || 'message']
      );
      return true;
    } catch (err: any) {
      if (err.code === '23505') {
        return false;
      }
      throw err;
    }
  }

  async getBlob(blobRef: string): Promise<MessageBlob | null> {
    const result = await this.pool.query(
      `SELECT * FROM message_blobs WHERE blob_ref = $1`,
      [blobRef]
    );

    if (result.rows.length === 0) return null;
    return this.rowToBlob(result.rows[0]);
  }

  async listBlobsSince(chatId: string, sinceSequence: number, limit = 100): Promise<MessageBlob[]> {
    const result = await this.pool.query(
      `SELECT * FROM message_blobs
       WHERE chat_id = $1 AND sequence > $2
       ORDER BY sequence ASC
       LIMIT $3`,
      [chatId, sinceSequence, limit]
    );

    return result.rows.map(row => this.rowToBlob(row));
  }

  async getLatestSequence(chatId: string): Promise<number> {
    const result = await this.pool.query(
      `SELECT COALESCE(MAX(sequence), 0) as max_seq FROM message_blobs WHERE chat_id = $1`,
      [chatId]
    );
    return parseInt(result.rows[0].max_seq);
  }

  async deleteOldBlobs(chatId: string, olderThan: number): Promise<number> {
    const result = await this.pool.query(
      `DELETE FROM message_blobs WHERE chat_id = $1 AND created_at < $2`,
      [chatId, olderThan]
    );
    return result.rowCount || 0;
  }

  private rowToBlob(row: any): MessageBlob {
    return {
      chatId: row.chat_id,
      blobRef: row.blob_ref,
      encryptedBlob: row.encrypted_blob,
      createdAt: parseInt(row.created_at),
      senderId: row.sender_id,
      sequence: parseInt(row.sequence),
      messageType: (row.message_type as 'handshake' | 'message') || 'message',
    };
  }
}

class PostgresSyncRepository implements ISyncRepository {
  constructor(private pool: pg.Pool) {}

  async getCursor(userId: string, chatId: string): Promise<SyncCursor | null> {
    const result = await this.pool.query(
      `SELECT * FROM sync_cursors WHERE user_id = $1 AND chat_id = $2`,
      [userId, chatId]
    );

    if (result.rows.length === 0) return null;

    const row = result.rows[0];
    return {
      userId: row.user_id,
      chatId: row.chat_id,
      lastSeenSequence: parseInt(row.last_seen_sequence),
      updatedAt: parseInt(row.updated_at),
    };
  }

  async updateCursor(userId: string, chatId: string, sequence: number): Promise<void> {
    await this.pool.query(
      `INSERT INTO sync_cursors (user_id, chat_id, last_seen_sequence, updated_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, chat_id)
       DO UPDATE SET last_seen_sequence = $3, updated_at = $4`,
      [userId, chatId, sequence, Date.now()]
    );
  }

  async listCursors(userId: string): Promise<SyncCursor[]> {
    const result = await this.pool.query(
      `SELECT * FROM sync_cursors WHERE user_id = $1`,
      [userId]
    );

    return result.rows.map(row => ({
      userId: row.user_id,
      chatId: row.chat_id,
      lastSeenSequence: parseInt(row.last_seen_sequence),
      updatedAt: parseInt(row.updated_at),
    }));
  }
}

class PostgresRateLimitRepository implements IRateLimitRepository {
  constructor(private pool: pg.Pool) {}

  async checkAndIncrement(key: string, limit: number, windowMs: number): Promise<boolean> {
    const now = Date.now();
    const windowStart = now - windowMs;

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Clean old entries
      await client.query(
        `DELETE FROM rate_limit_entries WHERE key = $1 AND timestamp < $2`,
        [key, windowStart]
      );

      // Count current entries
      const countResult = await client.query(
        `SELECT COUNT(*) as count FROM rate_limit_entries WHERE key = $1`,
        [key]
      );

      const count = parseInt(countResult.rows[0].count);

      if (count >= limit) {
        await client.query('ROLLBACK');
        return false;
      }

      // Insert new entry
      await client.query(
        `INSERT INTO rate_limit_entries (key, timestamp) VALUES ($1, $2)`,
        [key, now]
      );

      await client.query('COMMIT');
      return true;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async getCount(key: string): Promise<number> {
    const result = await this.pool.query(
      `SELECT COUNT(*) as count FROM rate_limit_entries WHERE key = $1`,
      [key]
    );
    return parseInt(result.rows[0].count);
  }

  async reset(key: string): Promise<void> {
    await this.pool.query(
      `DELETE FROM rate_limit_entries WHERE key = $1`,
      [key]
    );
  }
}

class PostgresPostRepository implements IPostRepository {
  constructor(private pool: pg.Pool) {}

  async createPost(post: Post): Promise<boolean> {
    try {
      await this.pool.query(
        `INSERT INTO posts (post_id, author_id, author_username, content, image_url, created_at, likes_count, comments_count, shares_count)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [post.postId, post.authorId, post.authorUsername, post.content, post.imageUrl || null, post.createdAt, post.likesCount, post.commentsCount, post.sharesCount]
      );
      return true;
    } catch (err: any) {
      if (err.code === '23505') {
        return false;
      }
      throw err;
    }
  }

  async getPost(postId: string): Promise<Post | null> {
    const result = await this.pool.query(
      `SELECT * FROM posts WHERE post_id = $1`,
      [postId]
    );

    if (result.rows.length === 0) return null;
    return this.rowToPost(result.rows[0]);
  }

  async getFeed(limit: number, beforeTimestamp?: number): Promise<Post[]> {
    const query = beforeTimestamp
      ? `SELECT * FROM posts WHERE created_at < $2 ORDER BY created_at DESC LIMIT $1`
      : `SELECT * FROM posts ORDER BY created_at DESC LIMIT $1`;

    const params = beforeTimestamp ? [limit, beforeTimestamp] : [limit];
    const result = await this.pool.query(query, params);

    return result.rows.map(row => this.rowToPost(row));
  }

  async getUserPosts(userId: string, limit: number): Promise<Post[]> {
    const result = await this.pool.query(
      `SELECT * FROM posts WHERE author_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [userId, limit]
    );

    return result.rows.map(row => this.rowToPost(row));
  }

  async deletePost(postId: string, userId: string): Promise<boolean> {
    const result = await this.pool.query(
      `DELETE FROM posts WHERE post_id = $1 AND author_id = $2`,
      [postId, userId]
    );

    return (result.rowCount || 0) > 0;
  }

  async incrementLikes(postId: string): Promise<void> {
    await this.pool.query(
      `UPDATE posts SET likes_count = likes_count + 1 WHERE post_id = $1`,
      [postId]
    );
  }

  async getTotalPostCount(): Promise<number> {
    const result = await this.pool.query(`SELECT COUNT(*) as count FROM posts`);
    return parseInt(result.rows[0].count);
  }

  private rowToPost(row: any): Post {
    return {
      postId: row.post_id,
      authorId: row.author_id,
      authorUsername: row.author_username,
      content: row.content,
      imageUrl: row.image_url || undefined,
      createdAt: parseInt(row.created_at),
      likesCount: parseInt(row.likes_count),
      commentsCount: parseInt(row.comments_count),
      sharesCount: parseInt(row.shares_count),
    };
  }
}

export class PostgresStorageAdapter implements IStorageAdapter {
  private pool: pg.Pool;
  users: IUserRepository;
  prekeys: IPrekeyRepository;
  messages: IMessageRepository;
  sync: ISyncRepository;
  rateLimit: IRateLimitRepository;
  posts: IPostRepository;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString });
    this.users = new PostgresUserRepository(this.pool);
    this.prekeys = new PostgresPrekeyRepository(this.pool);
    this.messages = new PostgresMessageRepository(this.pool);
    this.sync = new PostgresSyncRepository(this.pool);
    this.rateLimit = new PostgresRateLimitRepository(this.pool);
    this.posts = new PostgresPostRepository(this.pool);
  }

  async init(): Promise<void> {
    // Create tables if they don't exist
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        identity_ed25519 TEXT NOT NULL,
        identity_mldsa TEXT NOT NULL,
        registered_at BIGINT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

      CREATE TABLE IF NOT EXISTS prekey_bundles (
        user_id TEXT NOT NULL,
        bundle_id TEXT NOT NULL,
        x25519_ephemeral TEXT NOT NULL,
        mlkem_public_key TEXT NOT NULL,
        ed25519_signature TEXT NOT NULL,
        mldsa_signature TEXT NOT NULL,
        timestamp BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        is_one_time BOOLEAN NOT NULL,
        consumed BOOLEAN NOT NULL DEFAULT false,
        consumed_at BIGINT,
        consumed_by TEXT,
        PRIMARY KEY (user_id, bundle_id)
      );

      CREATE INDEX IF NOT EXISTS idx_prekeys_user_type ON prekey_bundles(user_id, is_one_time, consumed);

      CREATE TABLE IF NOT EXISTS message_blobs (
        chat_id TEXT NOT NULL,
        blob_ref TEXT PRIMARY KEY,
        encrypted_blob BYTEA NOT NULL,
        created_at BIGINT NOT NULL,
        sender_id TEXT NOT NULL,
        sequence BIGINT NOT NULL,
        message_type TEXT DEFAULT 'message'
      );

      CREATE INDEX IF NOT EXISTS idx_blobs_chat_sequence ON message_blobs(chat_id, sequence);

      -- Migration: Add message_type column if it doesn't exist (idempotent)
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name = 'message_blobs' AND column_name = 'message_type'
        ) THEN
          ALTER TABLE message_blobs ADD COLUMN message_type TEXT DEFAULT 'message';
        END IF;
      END $$;

      CREATE TABLE IF NOT EXISTS sync_cursors (
        user_id TEXT NOT NULL,
        chat_id TEXT NOT NULL,
        last_seen_sequence BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (user_id, chat_id)
      );

      CREATE TABLE IF NOT EXISTS rate_limit_entries (
        key TEXT NOT NULL,
        timestamp BIGINT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_rate_limit_key_timestamp ON rate_limit_entries(key, timestamp);

      CREATE TABLE IF NOT EXISTS posts (
        post_id TEXT PRIMARY KEY,
        author_id TEXT NOT NULL,
        author_username TEXT NOT NULL,
        content TEXT NOT NULL,
        image_url TEXT,
        created_at BIGINT NOT NULL,
        likes_count INTEGER DEFAULT 0,
        comments_count INTEGER DEFAULT 0,
        shares_count INTEGER DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_posts_author_id ON posts(author_id);
    `);

    console.log('[PostgresStorageAdapter] Initialized (PostgreSQL storage)');
  }

  async close(): Promise<void> {
    await this.pool.end();
    console.log('[PostgresStorageAdapter] Closed');
  }

  async isHealthy(): Promise<boolean> {
    try {
      await this.pool.query('SELECT 1');
      return true;
    } catch (err) {
      return false;
    }
  }
}
