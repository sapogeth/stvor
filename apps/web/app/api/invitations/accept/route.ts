import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// In-memory storage for invitations
const invitationsDb = new Map<string, any>();

/**
 * Accept group invitation
 * POST /api/invitations/accept
 */
export async function POST(req: NextRequest) {
  try {
    const { invitationId } = await req.json();

    if (!invitationId) {
      return NextResponse.json({ error: 'Missing invitationId' }, { status: 400 });
    }

    const invitation = invitationsDb.get(invitationId);

    if (!invitation) {
      return NextResponse.json({ error: 'Invitation not found' }, { status: 404 });
    }

    // Mark as accepted
    invitation.status = 'accepted';
    invitationsDb.set(invitationId, invitation);

    console.log(`[API] ✅ Invitation accepted: ${invitationId}`);

    return NextResponse.json({ success: true, invitation });
  } catch (error) {
    console.error('[API] Failed to accept invitation:', error);
    return NextResponse.json({ error: 'Failed to accept invitation' }, { status: 500 });
  }
}
