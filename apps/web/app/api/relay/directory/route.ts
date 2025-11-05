// apps/web/app/api/relay/directory/route.ts
import { NextResponse } from 'next/server';

// Force Node.js runtime (not Edge)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELAY_BASE =
  process.env.RELAY_BASE_URL ||
  'http://localhost:3001';

export async function GET() {
  return NextResponse.json({ error: 'Use /directory/:username endpoint' }, { status: 404 });
}

export async function POST(req: Request) {
  const body = await req.json();
  const username = (body.username || body.user || '').toLowerCase();

  const res = await fetch(`${RELAY_BASE}/directory/${username}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  const data = await res.json().catch(() => ({}));
  console.log(`[Proxy] Directory POST /${username} -> ${res.status}`);
  return NextResponse.json(data, { status: res.status });
}

export const dynamic = 'force-dynamic';
