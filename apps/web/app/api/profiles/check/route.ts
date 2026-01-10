import { NextResponse } from 'next/server';
import { getProfileByUsername } from '../storage';

// Force Node.js runtime (Clerk/Supabase compatible)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * GET /api/profiles/check?username=foo
 * Returns availability of the username. Public endpoint.
 */
export async function GET(req: Request) {
  try {
    const { searchParams } = new URL(req.url);
    const username = (searchParams.get('username') || '').toLowerCase().trim();

    if (!username) {
      return NextResponse.json({ error: 'Missing username' }, { status: 400 });
    }

    const profile = await getProfileByUsername(username);
    const available = !profile;

    return NextResponse.json({ available }, { status: 200 });
  } catch (error) {
    console.error('[API] profiles/check GET error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
