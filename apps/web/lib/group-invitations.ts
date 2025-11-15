/**
 * Group Invitations Management
 * Handles storing and retrieving group invitations
 */

export interface GroupInvitation {
  invitationId: string;
  groupId: string;
  groupName: string;
  creatorUsername: string;
  creatorDisplayName?: string;
  recipientUsername: string;
  createdAt: number;
  status: 'pending' | 'accepted' | 'rejected';
  expiresAt?: number; // Optional expiration
}

const DB_NAME = 'ilyazh-groupinvitations-v1';
const STORE_NAME = 'invitations';

/**
 * Open IndexedDB for group invitations
 */
async function getInvitationsDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'invitationId' });
        // Index by recipient for quick lookup
        store.createIndex('recipientUsername', 'recipientUsername', { unique: false });
        // Index by status for filtering
        store.createIndex('status', 'status', { unique: false });
        // Index by group for finding invitations for a group
        store.createIndex('groupId', 'groupId', { unique: false });
      }
    };
  });
}

/**
 * Store a new group invitation
 */
export async function storeGroupInvitation(invitation: GroupInvitation): Promise<void> {
  const db = await getInvitationsDB();
  const transaction = db.transaction([STORE_NAME], 'readwrite');
  const store = transaction.objectStore(STORE_NAME);

  return new Promise((resolve, reject) => {
    const request = store.add(invitation);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();
  });
}

/**
 * Get all pending invitations for a user
 */
export async function getPendingInvitations(username: string): Promise<GroupInvitation[]> {
  const db = await getInvitationsDB();
  const transaction = db.transaction([STORE_NAME], 'readonly');
  const store = transaction.objectStore(STORE_NAME);
  const index = store.index('recipientUsername');

  return new Promise((resolve, reject) => {
    const request = index.getAll(username);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const invitations = (request.result as GroupInvitation[]).filter(
        (inv) => inv.status === 'pending'
      );
      resolve(invitations.sort((a, b) => b.createdAt - a.createdAt));
    };
  });
}

/**
 * Get all invitations for a user (pending, accepted, rejected)
 */
export async function getAllInvitations(username: string): Promise<GroupInvitation[]> {
  const db = await getInvitationsDB();
  const transaction = db.transaction([STORE_NAME], 'readonly');
  const store = transaction.objectStore(STORE_NAME);
  const index = store.index('recipientUsername');

  return new Promise((resolve, reject) => {
    const request = index.getAll(username);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const invitations = request.result as GroupInvitation[];
      resolve(invitations.sort((a, b) => b.createdAt - a.createdAt));
    };
  });
}

/**
 * Accept a group invitation
 */
export async function acceptGroupInvitation(invitationId: string): Promise<GroupInvitation> {
  const db = await getInvitationsDB();
  const transaction = db.transaction([STORE_NAME], 'readwrite');
  const store = transaction.objectStore(STORE_NAME);

  return new Promise((resolve, reject) => {
    const getRequest = store.get(invitationId);

    getRequest.onsuccess = () => {
      const invitation = getRequest.result as GroupInvitation;
      if (!invitation) {
        reject(new Error('Invitation not found'));
        return;
      }

      invitation.status = 'accepted';
      const updateRequest = store.put(invitation);

      updateRequest.onsuccess = () => resolve(invitation);
      updateRequest.onerror = () => reject(updateRequest.error);
    };

    getRequest.onerror = () => reject(getRequest.error);
  });
}

/**
 * Reject a group invitation
 */
export async function rejectGroupInvitation(invitationId: string): Promise<GroupInvitation> {
  const db = await getInvitationsDB();
  const transaction = db.transaction([STORE_NAME], 'readwrite');
  const store = transaction.objectStore(STORE_NAME);

  return new Promise((resolve, reject) => {
    const getRequest = store.get(invitationId);

    getRequest.onsuccess = () => {
      const invitation = getRequest.result as GroupInvitation;
      if (!invitation) {
        reject(new Error('Invitation not found'));
        return;
      }

      invitation.status = 'rejected';
      const updateRequest = store.put(invitation);

      updateRequest.onsuccess = () => resolve(invitation);
      updateRequest.onerror = () => reject(updateRequest.error);
    };

    getRequest.onerror = () => reject(getRequest.error);
  });
}

/**
 * Check if user has pending invitation for a group
 */
export async function hasGroupInvitation(username: string, groupId: string): Promise<boolean> {
  const db = await getInvitationsDB();
  const transaction = db.transaction([STORE_NAME], 'readonly');
  const store = transaction.objectStore(STORE_NAME);
  const index = store.index('groupId');

  return new Promise((resolve, reject) => {
    const request = index.getAll(groupId);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const invitations = request.result as GroupInvitation[];
      const hasInvitation = invitations.some(
        (inv) => inv.recipientUsername === username && inv.status === 'pending'
      );
      resolve(hasInvitation);
    };
  });
}

/**
 * Check if user has ACCEPTED invitation for a group (can chat)
 */
export async function hasAcceptedInvitation(username: string, groupId: string): Promise<boolean> {
  const db = await getInvitationsDB();
  const transaction = db.transaction([STORE_NAME], 'readonly');
  const store = transaction.objectStore(STORE_NAME);
  const index = store.index('groupId');

  return new Promise((resolve, reject) => {
    const request = index.getAll(groupId);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const invitations = request.result as GroupInvitation[];
      const hasAccepted = invitations.some(
        (inv) => inv.recipientUsername === username && inv.status === 'accepted'
      );
      resolve(hasAccepted);
    };
  });
}

/**
 * Delete invitation after accepting/rejecting
 */
export async function deleteGroupInvitation(invitationId: string): Promise<void> {
  const db = await getInvitationsDB();
  const transaction = db.transaction([STORE_NAME], 'readwrite');
  const store = transaction.objectStore(STORE_NAME);

  return new Promise((resolve, reject) => {
    const request = store.delete(invitationId);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();
  });
}

/**
 * Generate invitation ID (deterministic from group + recipient)
 */
export function generateInvitationId(groupId: string, recipientUsername: string): string {
  // Simple deterministic ID based on group and recipient
  return `inv_${groupId}_${recipientUsername}_${Date.now()}`;
}
