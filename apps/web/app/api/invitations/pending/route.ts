import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// In-memory storage for invitations
const invitationsDb = new Map<string, any>();

/**
 * Get pending invitations for user
 * GET /api/invitations/pending?username=alice
 */
export async function GET(req: NextRequest) {
  try {
    const username = req.nextUrl.searchParams.get('username');

    if (!username) {
      return NextResponse.json({ error: 'Missing username parameter' }, { status: 400 });
    }

    // Get all pending invitations for this user
    const pending = Array.from(invitationsDb.values()).filter(
      (inv) => inv.recipientUsername === username && inv.status === 'pending'
    );

    console.log(`[API] Found ${pending.length} pending invitations for ${username}`);

    return NextResponse.json({ invitations: pending });
  } catch (error) {
    console.error('[API] Failed to get invitations:', error);
    return NextResponse.json({ error: 'Failed to get invitations' }, { status: 500 });
  }
}
