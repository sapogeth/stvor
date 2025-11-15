import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// In-memory storage for invitations (will be persisted to DB later)
const invitationsDb = new Map<string, any>();

/**
 * Store group invitation on server
 * POST /api/invitations/store
 */
export async function POST(req: NextRequest) {
  try {
    const { invitationId, groupId, groupName, creatorUsername, creatorDisplayName, recipientUsername } = await req.json();

    if (!invitationId || !groupId || !recipientUsername) {
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
    }

    const invitation = {
      invitationId,
      groupId,
      groupName,
      creatorUsername,
      creatorDisplayName,
      recipientUsername,
      createdAt: Date.now(),
      status: 'pending',
    };

    // Store invitation
    invitationsDb.set(invitationId, invitation);

    console.log(`[API] ✅ Invitation stored: ${invitationId} for ${recipientUsername}`);

    return NextResponse.json({ success: true, invitation });
  } catch (error) {
    console.error('[API] Failed to store invitation:', error);
    return NextResponse.json({ error: 'Failed to store invitation' }, { status: 500 });
  }
}
