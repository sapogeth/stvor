import { currentUser } from '@clerk/nextjs/server';
import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function rand(n: number) {
  const c = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let r = '';
  for (let i = 0; i < n; i++) r += c[Math.floor(Math.random() * c.length)];
  return r;
}

export async function POST(req: NextRequest) {
  try {
    const user = await currentUser();
    if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    const body = await req.json().catch(() => ({ name: 'API Key' }));
    const key = 'sk_live_' + rand(32);
    return NextResponse.json({ id: 'key_' + rand(8), name: body.name, key, createdAt: new Date().toISOString(), active: true });
  } catch (e) {
    console.error('[subscription/generate-key] Error:', e);
    return NextResponse.json({ error: 'Failed to generate API key' }, { status: 500 });
  }
}
