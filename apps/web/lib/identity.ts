/**
 * Identity Management for Ilyazh-Web3E2E v0.8
 *
 * Handles:
 * - Long-term identity keypair generation (Ed25519 + ML-DSA-65)
 * - Registration with relay server
 * - Loading existing identities from IndexedDB
 */

import { generateIdentity, type IdentityKeyPair } from '@ilyazh/crypto';
import { keystore } from './keystore';

const RELAY_URL = process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';

/**
 * Get authentication token for a user
 * Returns JWT token from localStorage
 */
export function getAuthToken(username: string): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(`jwt_token_${username}`);
}

/**
 * Create authenticated headers with JWT token
 */
export function createAuthHeaders(username: string): HeadersInit {
  const token = getAuthToken(username);
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

/**
 * Get or create identity for the current user
 * - Checks IndexedDB first
 * - Generates new identity if not found
 * - Registers with relay server
 * - Stores in IndexedDB
 */
export async function getOrCreateIdentity(username: string): Promise<IdentityKeyPair> {
  console.log('[Identity] Getting or creating identity for:', username);

  try {
    console.log('[Identity] Initializing keystore...');
    await keystore.init();
    console.log('[Identity] Keystore initialized successfully');
  } catch (err) {
    console.error('[Identity] Keystore initialization failed:', err);
    // If VersionError, delete old database and retry
    if (err instanceof Error && err.name === 'VersionError') {
      console.warn('[Identity] VersionError detected, deleting old database...');
      await keystore.deleteDatabase();
      console.log('[Identity] Old database deleted, retrying init...');
      await keystore.init();
      console.log('[Identity] Database recreated successfully');
    } else {
      console.error('[Identity] Fatal error during keystore init:', err);
      throw err;
    }
  }

  // Try to load existing identity
  let identity = await keystore.loadIdentity(username);

  if (identity) {
    console.log('[Identity] Loaded existing identity from IndexedDB');
    return identity;
  }

  console.log('[Identity] No existing identity found, generating new one...');

  // Generate new identity keypair
  identity = await generateIdentity();

  console.log('[Identity] Generated new identity keypair');
  console.log('[Identity] - Ed25519 public key:', Buffer.from(identity.ed25519.publicKey).toString('hex').slice(0, 32) + '...');
  console.log('[Identity] - ML-DSA-65 public key:', Buffer.from(identity.mldsa.publicKey).toString('hex').slice(0, 32) + '...');

  // Save to IndexedDB
  await keystore.saveIdentity(username, identity);
  console.log('[Identity] Saved identity to IndexedDB');

  // Register with relay server
  try {
    await registerWithRelay(username, identity);
    console.log('[Identity] Successfully registered with relay server');
  } catch (err) {
    console.error('[Identity] Failed to register with relay:', err);
    // Continue anyway - registration might have happened before
  }

  return identity;
}

/**
 * Register identity with relay server
 * Uploads public keys for directory lookup
 */
async function registerWithRelay(username: string, identity: IdentityKeyPair): Promise<void> {
  console.log('[Identity] Registering with relay server...');

  const response = await fetch(`${RELAY_URL}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      userId: username,
      username: username,
      identityEd25519: Buffer.from(identity.ed25519.publicKey).toString('base64'),
      identityMLDSA: Buffer.from(identity.mldsa.publicKey).toString('base64'),
    }),
  });

  // 409 = already registered (OK)
  if (!response.ok && response.status !== 409) {
    const error = await response.text();
    throw new Error(`Failed to register: ${response.status} - ${error}`);
  }

  if (response.status === 409) {
    console.log('[Identity] User already registered (409 - OK)');
    return;
  }

  // SECURITY: Store JWT token for authenticated requests
  const data = await response.json();
  if (data.token) {
    localStorage.setItem(`jwt_token_${username}`, data.token);
    console.log('[Identity] JWT token stored');
  }
}

/**
 * Fetch a peer's identity from the relay directory
 * Returns their public identity keys
 */
export async function fetchPeerIdentity(username: string): Promise<{
  identityEd25519: Uint8Array;
  identityMLDSA: Uint8Array;
}> {
  console.log('[Identity] Fetching peer identity for:', username);

  const response = await fetch(`${RELAY_URL}/directory/${username}`);

  if (!response.ok) {
    throw new Error(`User not found: ${username}`);
  }

  const data = await response.json();

  if (!data.identity) {
    throw new Error(`No identity found for user: ${username}`);
  }

  return {
    identityEd25519: Buffer.from(data.identity.identityEd25519, 'base64'),
    identityMLDSA: Buffer.from(data.identity.identityMLDSA, 'base64'),
  };
}

/**
 * Delete identity for a user
 * WARNING: This will permanently delete the identity keypair
 */
export async function deleteIdentity(username: string): Promise<void> {
  console.log('[Identity] Deleting identity for:', username);
  await keystore.init();

  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('ilyazh-keystore-v3', 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(['identities'], 'readwrite');
    const store = tx.objectStore('identities');
    const request = store.delete(username);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });

  db.close();
  console.log('[Identity] Identity deleted');
}
