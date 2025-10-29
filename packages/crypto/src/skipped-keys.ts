/**
 * Skipped Message Key Storage for Out-of-Order Decryption
 * Bounded cache with automatic eviction
 */

import * as constants from './constants.js';

export interface SkippedKey {
  ratchetId: bigint;
  counter: number;
  messageKey: Uint8Array;
  timestamp: number;
}

export interface ReplayState {
  lastSeenSequence: Map<string, bigint>; // sessionId -> last seq
  recentNonces: Set<string>; // nonce hashes for dup detection
}

const MAX_SKIPPED_KEYS = 1000; // Bounded cache
const MAX_SKIP = 1000; // Max messages to skip
const REPLAY_WINDOW_SIZE = 100; // Recent messages to track

/**
 * Skipped key storage per session
 */
export class SkippedKeyStore {
  private keys: Map<string, SkippedKey> = new Map();

  /**
   * Generate key ID from ratchet + counter
   */
  private keyId(ratchetId: bigint, counter: number): string {
    return `${ratchetId}:${counter}`;
  }

  /**
   * Store skipped message key
   */
  store(ratchetId: bigint, counter: number, messageKey: Uint8Array): void {
    // Enforce bounded cache
    if (this.keys.size >= MAX_SKIPPED_KEYS) {
      // Evict oldest entry
      const oldestKey = Array.from(this.keys.entries())
        .sort((a, b) => a[1].timestamp - b[1].timestamp)[0];
      if (oldestKey) {
        // Zeroize before removing
        oldestKey[1].messageKey.fill(0);
        this.keys.delete(oldestKey[0]);
      }
    }

    const id = this.keyId(ratchetId, counter);
    this.keys.set(id, {
      ratchetId,
      counter,
      messageKey: new Uint8Array(messageKey), // Copy
      timestamp: Date.now(),
    });
  }

  /**
   * Retrieve and remove skipped key
   */
  retrieve(ratchetId: bigint, counter: number): Uint8Array | null {
    const id = this.keyId(ratchetId, counter);
    const entry = this.keys.get(id);
    if (!entry) return null;

    this.keys.delete(id);
    return entry.messageKey;
  }

  /**
   * Check if we have a skipped key
   */
  has(ratchetId: bigint, counter: number): boolean {
    return this.keys.has(this.keyId(ratchetId, counter));
  }

  /**
   * Count skipped keys
   */
  count(): number {
    return this.keys.size;
  }

  /**
   * Clear all skipped keys (zeroize first)
   */
  clear(): void {
    for (const entry of this.keys.values()) {
      entry.messageKey.fill(0);
    }
    this.keys.clear();
  }
}

/**
 * Replay protection using sequence numbers
 */
export class ReplayProtection {
  private lastSeenSequence = new Map<string, bigint>();
  private recentNonces = new Set<string>();
  private nonceQueue: string[] = [];

  /**
   * Check if message is a replay
   * Returns true if message should be accepted
   */
  checkSequence(sessionId: Uint8Array, sequence: bigint): boolean {
    const sid = Buffer.from(sessionId).toString('hex');
    const lastSeen = this.lastSeenSequence.get(sid) ?? -1n;

    // Sequence must be strictly increasing
    if (sequence <= lastSeen) {
      return false; // Replay or duplicate
    }

    this.lastSeenSequence.set(sid, sequence);
    return true;
  }

  /**
   * Check if nonce was already seen (duplicate detection)
   */
  checkNonce(nonce: Uint8Array): boolean {
    const nonceHex = Buffer.from(nonce).toString('hex');

    if (this.recentNonces.has(nonceHex)) {
      return false; // Duplicate nonce
    }

    // Add to recent set
    this.recentNonces.add(nonceHex);
    this.nonceQueue.push(nonceHex);

    // Enforce bounded window
    if (this.nonceQueue.length > REPLAY_WINDOW_SIZE) {
      const oldNonce = this.nonceQueue.shift();
      if (oldNonce) {
        this.recentNonces.delete(oldNonce);
      }
    }

    return true;
  }

  /**
   * Clear replay state for session
   */
  clearSession(sessionId: Uint8Array): void {
    const sid = Buffer.from(sessionId).toString('hex');
    this.lastSeenSequence.delete(sid);
  }
}

/**
 * Calculate skip distance
 */
export function calculateSkip(current: number, target: number): number {
  if (target <= current) {
    throw new Error('Target counter must be greater than current');
  }
  const skip = target - current - 1;
  if (skip > MAX_SKIP) {
    throw new Error(`Too many skipped messages: ${skip} (max ${MAX_SKIP})`);
  }
  return skip;
}
