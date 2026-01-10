// apps/web/app/api/relay/directory/route.ts
import { NextResponse } from 'next/server';

// Force Node.js runtime (not Edge)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELAY_BASE =
  process.env.NEXT_PUBLIC_RELAY_URL ||
  'http://localhost:3001';

export async function GET() {
  return NextResponse.json({ error: 'Use /directory/:username endpoint' }, { status: 404 });
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const username = (body.username || body.user || '').toLowerCase();

    const res = await fetch(`${RELAY_BASE}/directory/${username}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    const text = await res.text();
    const data = (() => {
      try {
        return JSON.parse(text);
      } catch {
        return { error: 'INVALID_RESPONSE', detail: 'Relay returned non-JSON response' };
      }
    })();
    
    console.log(`[Proxy] Directory POST /${username} -> ${res.status}`);
    return NextResponse.json(data, { status: res.status });
  } catch (error) {
    console.error('[API] directory POST error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
