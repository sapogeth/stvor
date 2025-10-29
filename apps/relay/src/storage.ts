/**
 * Database-free storage layer
 * Content-addressed blobs + JSON manifests
 * Supports filesystem or S3-compatible storage
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';

export interface StorageConfig {
  type: 'filesystem' | 's3';
  dataDir?: string; // for filesystem
  s3Bucket?: string;
  s3Endpoint?: string;
  s3AccessKey?: string;
  s3SecretKey?: string;
}

export interface ManifestEntry {
  index: number;
  type: 'handshake' | 'message' | 'rekey';
  blobRef: string; // SHA-256 hash
  timestamp: number;
  sender?: string;
}

export interface ChatManifest {
  chatId: string;
  participants: string[];
  entries: ManifestEntry[];
  version: number;
}

export class Storage {
  private config: StorageConfig;
  private s3Client?: S3Client;

  constructor(config: StorageConfig) {
    this.config = config;

    if (config.type === 's3') {
      this.s3Client = new S3Client({
        endpoint: config.s3Endpoint,
        region: 'auto',
        credentials: {
          accessKeyId: config.s3AccessKey!,
          secretAccessKey: config.s3SecretKey!,
        },
      });
    }
  }

  private async ensureDir(dirPath: string): Promise<void> {
    if (this.config.type === 'filesystem') {
      await fs.mkdir(dirPath, { recursive: true });
    }
  }

  private hashContent(data: Uint8Array): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  // ==================== User Identity Storage ====================

  async storeUserIdentity(userId: string, identity: any): Promise<void> {
    const key = `users/${userId}/identity.json`;

    if (this.config.type === 'filesystem') {
      const filePath = path.join(this.config.dataDir!, key);
      await this.ensureDir(path.dirname(filePath));
      await fs.writeFile(filePath, JSON.stringify(identity, null, 2));
    } else {
      const command = new PutObjectCommand({
        Bucket: this.config.s3Bucket,
        Key: key,
        Body: JSON.stringify(identity),
        ContentType: 'application/json',
      });
      await this.s3Client!.send(command);
    }
  }

  async getUserIdentity(userId: string): Promise<any | null> {
    const key = `users/${userId}/identity.json`;

    try {
      if (this.config.type === 'filesystem') {
        const filePath = path.join(this.config.dataDir!, key);
        const data = await fs.readFile(filePath, 'utf-8');
        return JSON.parse(data);
      } else {
        const command = new GetObjectCommand({
          Bucket: this.config.s3Bucket,
          Key: key,
        });
        const response = await this.s3Client!.send(command);
        const data = await response.Body!.transformToString();
        return JSON.parse(data);
      }
    } catch (err: any) {
      if (err.code === 'ENOENT' || err.name === 'NoSuchKey') {
        return null;
      }
      throw err;
    }
  }

  // ==================== Prekey Bundle Storage ====================

  async storePrekeyBundle(userId: string, bundleId: string, bundle: any): Promise<void> {
    const key = `prekeys/${userId}/${bundleId}.json`;

    if (this.config.type === 'filesystem') {
      const filePath = path.join(this.config.dataDir!, key);
      await this.ensureDir(path.dirname(filePath));
      await fs.writeFile(filePath, JSON.stringify(bundle, null, 2));
    } else {
      const command = new PutObjectCommand({
        Bucket: this.config.s3Bucket,
        Key: key,
        Body: JSON.stringify(bundle),
        ContentType: 'application/json',
      });
      await this.s3Client!.send(command);
    }
  }

  async getPrekeyBundle(userId: string): Promise<any | null> {
    // Get latest bundle (simplified: just return first found)
    const key = `prekeys/${userId}/`;

    try {
      if (this.config.type === 'filesystem') {
        const dirPath = path.join(this.config.dataDir!, key);
        const files = await fs.readdir(dirPath);
        if (files.length === 0) return null;

        const latestFile = files.sort().reverse()[0];
        const data = await fs.readFile(path.join(dirPath, latestFile), 'utf-8');
        return JSON.parse(data);
      }
      // S3 implementation would list objects and pick latest
      return null;
    } catch (err: any) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  // ==================== Blob Storage (Content-Addressed) ====================

  async storeBlob(chatId: string, data: Uint8Array): Promise<string> {
    const hash = this.hashContent(data);
    const key = `chats/${chatId}/blobs/${hash}.bin`;

    if (this.config.type === 'filesystem') {
      const filePath = path.join(this.config.dataDir!, key);
      await this.ensureDir(path.dirname(filePath));
      await fs.writeFile(filePath, data);
    } else {
      const command = new PutObjectCommand({
        Bucket: this.config.s3Bucket,
        Key: key,
        Body: data,
        ContentType: 'application/octet-stream',
      });
      await this.s3Client!.send(command);
    }

    return hash;
  }

  async getBlob(chatId: string, blobRef: string): Promise<Uint8Array | null> {
    const key = `chats/${chatId}/blobs/${blobRef}.bin`;

    try {
      if (this.config.type === 'filesystem') {
        const filePath = path.join(this.config.dataDir!, key);
        return await fs.readFile(filePath);
      } else {
        const command = new GetObjectCommand({
          Bucket: this.config.s3Bucket,
          Key: key,
        });
        const response = await this.s3Client!.send(command);
        const buffer = await response.Body!.transformToByteArray();
        return buffer;
      }
    } catch (err: any) {
      if (err.code === 'ENOENT' || err.name === 'NoSuchKey') {
        return null;
      }
      throw err;
    }
  }

  // ==================== Manifest Storage (Append-Only) ====================

  private manifestLocks = new Map<string, Promise<void>>();

  private async withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    // Simple in-memory lock (for single-instance relay)
    while (this.manifestLocks.has(key)) {
      await this.manifestLocks.get(key);
    }

    let resolve: () => void;
    const lock = new Promise<void>((res) => {
      resolve = res;
    });
    this.manifestLocks.set(key, lock);

    try {
      return await fn();
    } finally {
      this.manifestLocks.delete(key);
      resolve!();
    }
  }

  async initChatManifest(chatId: string, participants: string[]): Promise<void> {
    await this.withLock(`manifest:${chatId}`, async () => {
      const manifest: ChatManifest = {
        chatId,
        participants,
        entries: [],
        version: 1,
      };

      const key = `chats/${chatId}/manifest.json`;

      if (this.config.type === 'filesystem') {
        const filePath = path.join(this.config.dataDir!, key);
        await this.ensureDir(path.dirname(filePath));
        await fs.writeFile(filePath, JSON.stringify(manifest, null, 2));
      } else {
        const command = new PutObjectCommand({
          Bucket: this.config.s3Bucket,
          Key: key,
          Body: JSON.stringify(manifest),
          ContentType: 'application/json',
        });
        await this.s3Client!.send(command);
      }
    });
  }

  async appendToManifest(
    chatId: string,
    entry: Omit<ManifestEntry, 'index' | 'timestamp'>
  ): Promise<number> {
    return this.withLock(`manifest:${chatId}`, async () => {
      const key = `chats/${chatId}/manifest.json`;
      let manifest: ChatManifest;

      try {
        if (this.config.type === 'filesystem') {
          const filePath = path.join(this.config.dataDir!, key);
          const data = await fs.readFile(filePath, 'utf-8');
          manifest = JSON.parse(data);
        } else {
          const command = new GetObjectCommand({
            Bucket: this.config.s3Bucket,
            Key: key,
          });
          const response = await this.s3Client!.send(command);
          const data = await response.Body!.transformToString();
          manifest = JSON.parse(data);
        }
      } catch (err: any) {
        if (err.code === 'ENOENT' || err.name === 'NoSuchKey') {
          throw new Error('Chat manifest not found');
        }
        throw err;
      }

      const index = manifest.entries.length;
      const fullEntry: ManifestEntry = {
        ...entry,
        index,
        timestamp: Date.now(),
      };

      manifest.entries.push(fullEntry);

      if (this.config.type === 'filesystem') {
        const filePath = path.join(this.config.dataDir!, key);
        await fs.writeFile(filePath, JSON.stringify(manifest, null, 2));
      } else {
        const command = new PutObjectCommand({
          Bucket: this.config.s3Bucket,
          Key: key,
          Body: JSON.stringify(manifest),
          ContentType: 'application/json',
        });
        await this.s3Client!.send(command);
      }

      return index;
    });
  }

  async getManifest(chatId: string): Promise<ChatManifest | null> {
    const key = `chats/${chatId}/manifest.json`;

    try {
      if (this.config.type === 'filesystem') {
        const filePath = path.join(this.config.dataDir!, key);
        const data = await fs.readFile(filePath, 'utf-8');
        return JSON.parse(data);
      } else {
        const command = new GetObjectCommand({
          Bucket: this.config.s3Bucket,
          Key: key,
        });
        const response = await this.s3Client!.send(command);
        const data = await response.Body!.transformToString();
        return JSON.parse(data);
      }
    } catch (err: any) {
      if (err.code === 'ENOENT' || err.name === 'NoSuchKey') {
        return null;
      }
      throw err;
    }
  }

  async getManifestSince(chatId: string, since: number): Promise<ManifestEntry[]> {
    const manifest = await this.getManifest(chatId);
    if (!manifest) return [];
    return manifest.entries.filter((e) => e.index >= since);
  }
}
