'use client';

/**
 * Groups List Page
 * View and manage all group chats
 */

import { useState, useEffect } from 'react';
import { useUser } from '@clerk/nextjs';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { listGroupChats, deleteGroupChat, generateRandomGroupId, createGroupChat, StoredGroupChat } from '@/lib/group-chat';
import { getOrCreateIdentity } from '@/lib/identity';
import { storeGroupInvitation, generateInvitationId } from '@/lib/group-invitations';
import type { IdentityKeyPair } from '@ilyazh/crypto';

export default function GroupsPage() {
  const { user } = useUser();
  const router = useRouter();

  const [groups, setGroups] = useState<StoredGroupChat[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [groupName, setGroupName] = useState('');
  const [selectedMembers, setSelectedMembers] = useState<string[]>([]);
  const [newMember, setNewMember] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const username = user?.username || user?.firstName || 'unknown';

  // Load groups on mount
  useEffect(() => {
    const load = async () => {
      try {
        const allGroups = await listGroupChats();
        setGroups(allGroups);
      } catch (err) {
        console.error('[Groups] Failed to load groups:', err);
        setError('Failed to load groups');
      } finally {
        setLoading(false);
      }
    };

    load();
  }, []);

  // Handle create group
  const handleCreateGroup = async () => {
    if (!groupName.trim() || selectedMembers.length === 0) {
      setError('Group name and members required');
      return;
    }

    setCreating(true);
    setError(null);

    try {
      // Get user identity
      const identity = await getOrCreateIdentity(username);

      // Get all member identities (mocked for MVP)
      const memberIdentities = new Map<string, { ed25519: Uint8Array; mldsa: Uint8Array }>();
      for (const member of selectedMembers) {
        memberIdentities.set(member, {
          ed25519: new Uint8Array(32),
          mldsa: new Uint8Array(1952),
        });
      }

      // Generate group ID
      const groupId = await generateRandomGroupId();

      // Create group
      const newGroup = await createGroupChat(
        groupId,
        groupName,
        username,
        identity,
        memberIdentities
      );

      // Send invitations to all selected members
      console.log(`[Groups] Sending invitations to ${selectedMembers.length} members...`);
      for (const member of selectedMembers) {
        try {
          const invitationId = generateInvitationId(groupId, member);

          // Store in IndexedDB for local fallback
          await storeGroupInvitation({
            invitationId,
            groupId,
            groupName,
            creatorUsername: username,
            creatorDisplayName: user?.firstName || username,
            recipientUsername: member,
            createdAt: Date.now(),
            status: 'pending',
          });

          // Also store on server so other devices/browsers can see it
          try {
            const serverRes = await fetch('/api/invitations/store', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                invitationId,
                groupId,
                groupName,
                creatorUsername: username,
                creatorDisplayName: user?.firstName || username,
                recipientUsername: member,
              }),
            });

            if (serverRes.ok) {
              console.log(`[Groups] ✅ Invitation stored on server for ${member}`);
            } else {
              console.warn(`[Groups] ⚠️ Failed to store on server for ${member}:`, serverRes.status);
            }
          } catch (serverErr) {
            console.error(`[Groups] Server error storing invitation for ${member}:`, serverErr);
          }

          console.log(`[Groups] ✅ Invitation created for ${member}`);
        } catch (err) {
          console.error(`[Groups] Failed to create invitation for ${member}:`, err);
        }
      }

      // Add to list and close dialog
      setGroups((prev) => [newGroup, ...prev]);
      setGroupName('');
      setSelectedMembers([]);
      setShowCreateDialog(false);

      // Show success message
      alert(`Group created! Invitations sent to ${selectedMembers.length} members.`);

      // Navigate to new group
      router.push(`/groups/${groupId}`);
    } catch (err) {
      console.error('[Groups] Failed to create group:', err);
      setError('Failed to create group');
    } finally {
      setCreating(false);
    }
  };

  // Handle delete group
  const handleDeleteGroup = async (groupId: string) => {
    if (!confirm('Are you sure you want to delete this group?')) {
      return;
    }

    try {
      await deleteGroupChat(groupId);
      setGroups((prev) => prev.filter((g) => g.groupId !== groupId));
    } catch (err) {
      console.error('[Groups] Failed to delete group:', err);
      setError('Failed to delete group');
    }
  };

  // Handle add member
  const handleAddMember = () => {
    if (newMember.trim() && !selectedMembers.includes(newMember)) {
      setSelectedMembers((prev) => [...prev, newMember]);
      setNewMember('');
    }
  };

  // Handle remove member
  const handleRemoveMember = (member: string) => {
    setSelectedMembers((prev) => prev.filter((m) => m !== member));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading groups...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shadow-sm">
        <div className="max-w-6xl mx-auto px-4 py-6">
          <div className="flex items-center justify-between">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Groups</h1>
            <div className="flex gap-4">
              <Link
                href="/(dashboard)/chats"
                className="px-4 py-2 text-blue-600 hover:bg-blue-50 dark:hover:bg-gray-700 rounded-lg transition"
              >
                1-on-1 Chat
              </Link>
              <button
                onClick={() => setShowCreateDialog(true)}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition"
              >
                + Create Group
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Groups List */}
      <div className="max-w-6xl mx-auto px-4 py-8">
        {error && (
          <div className="mb-6 p-4 bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded-lg">
            {error}
          </div>
        )}

        {groups.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-gray-600 dark:text-gray-400 mb-4">No groups yet</p>
            <button
              onClick={() => setShowCreateDialog(true)}
              className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition"
            >
              Create your first group
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {groups.map((group) => (
              <div
                key={group.groupId}
                className="bg-white dark:bg-gray-800 rounded-lg shadow hover:shadow-lg transition border border-gray-200 dark:border-gray-700 overflow-hidden"
              >
                <Link href={`/(dashboard)/groups/${group.groupId}`} className="block p-6 hover:bg-gray-50 dark:hover:bg-gray-700">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                    {group.groupName}
                  </h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                    {group.participants.length} members
                  </p>
                  <div className="flex flex-wrap gap-2 mb-4">
                    {group.participants.slice(0, 3).map((member) => (
                      <span
                        key={member}
                        className="px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 text-xs rounded"
                      >
                        {member}
                      </span>
                    ))}
                    {group.participants.length > 3 && (
                      <span className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 text-xs rounded">
                        +{group.participants.length - 3}
                      </span>
                    )}
                  </div>
                </Link>
                <div className="border-t border-gray-200 dark:border-gray-700 px-6 py-3 flex gap-2">
                  <Link
                    href={`/(dashboard)/groups/${group.groupId}`}
                    className="flex-1 text-center px-3 py-2 text-blue-600 hover:bg-blue-50 dark:hover:bg-gray-700 rounded transition text-sm"
                  >
                    Open
                  </Link>
                  <button
                    onClick={() => handleDeleteGroup(group.groupId)}
                    className="px-3 py-2 text-red-600 hover:bg-red-50 dark:hover:bg-gray-700 rounded transition text-sm"
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Create Group Dialog */}
      {showCreateDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full mx-4 p-6">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">Create Group</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Group Name
                </label>
                <input
                  type="text"
                  value={groupName}
                  onChange={(e) => setGroupName(e.target.value)}
                  placeholder="e.g., Project Team"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Add Members
                </label>
                <div className="flex gap-2 mb-2">
                  <input
                    type="text"
                    value={newMember}
                    onChange={(e) => setNewMember(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        handleAddMember();
                      }
                    }}
                    placeholder="Username"
                    className="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 focus:ring-2 focus:ring-blue-500"
                  />
                  <button
                    onClick={handleAddMember}
                    className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition"
                  >
                    Add
                  </button>
                </div>

                {selectedMembers.length > 0 && (
                  <div className="space-y-2">
                    {selectedMembers.map((member) => (
                      <div
                        key={member}
                        className="flex items-center justify-between bg-blue-50 dark:bg-blue-900 px-3 py-2 rounded-lg"
                      >
                        <span className="text-sm text-blue-900 dark:text-blue-100">{member}</span>
                        <button
                          onClick={() => handleRemoveMember(member)}
                          className="text-red-600 dark:text-red-400 hover:text-red-800 text-sm"
                        >
                          ✕
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {error && (
                <div className="p-3 bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded-lg text-sm">
                  {error}
                </div>
              )}

              <div className="flex gap-2 pt-4">
                <button
                  onClick={() => {
                    setShowCreateDialog(false);
                    setError(null);
                    setGroupName('');
                    setSelectedMembers([]);
                  }}
                  disabled={creating}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateGroup}
                  disabled={creating || !groupName.trim() || selectedMembers.length === 0}
                  className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition disabled:bg-gray-400 disabled:cursor-not-allowed"
                >
                  {creating ? 'Creating...' : 'Create'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
