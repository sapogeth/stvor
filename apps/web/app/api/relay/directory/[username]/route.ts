// apps/web/app/api/relay/directory/[username]/route.ts
import { NextResponse } from 'next/server';

// Force Node.js runtime (not Edge)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELAY_BASE =
  process.env.RELAY_BASE_URL || 'http://localhost:3001';

// READ prekey bundle / identity
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ username: string }> }
) {
  const resolvedParams = await params;
  const raw = resolvedParams.username || '';
  const username = raw.toLowerCase().trim();

  const url = `${RELAY_BASE}/directory/${username}`;
  const res = await fetch(url, {
    method: 'GET',
    headers: {
      'content-type': 'application/json',
    },
  });

  if (!res.ok) {
    console.warn(`[Proxy] Directory GET /${username} -> ${res.status}`);
    return NextResponse.json(
      {
        error: 'directory_not_found',
        message: `No directory entry for ${username}`,
      },
      { status: res.status }
    );
  }

  const data = await res.json();

  console.log(`[Proxy] Directory GET /${username} -> 200`);

  return NextResponse.json({
    username,
    identityPublicKey:
      data.identityPublicKey || data.identityEd25519 || data.ed25519,
    identityEd25519:
      data.identityEd25519 || data.identityPublicKey || data.ed25519,
    identityMLDSA: data.identityMLDSA || '',
    prekeyBundle: data.prekeyBundle ?? data.prekeys ?? null,
    prekeySignature:
      data.prekeySignature ||
      data.signature ||
      data.prekeyBundle?.signature ||
      null,
  });
}

// PUBLISH / UPDATE prekey bundle
export async function POST(
  req: Request,
  { params }: { params: Promise<{ username: string }> }
) {
  const resolvedParams = await params;
  const raw = resolvedParams.username || '';
  const username = raw.toLowerCase().trim();
  const body = await req.json();

  const url = `${RELAY_BASE}/directory/${username}`;

  console.log(`[Proxy] Directory POST /${username}`);

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      // normalize username to prevent case mismatches
      username,
      ...body,
    }),
  });

  const text = await res.text();
  const maybeJson = (() => {
    try {
      return JSON.parse(text);
    } catch {
      return { raw: text };
    }
  })();

  console.log(`[Proxy] Directory POST /${username} -> ${res.status}`);

  return NextResponse.json(maybeJson, { status: res.status });
}

// some relays use PUT for updates
export async function PUT(
  req: Request,
  { params }: { params: Promise<{ username: string }> }
) {
  const resolvedParams = await params;
  const raw = resolvedParams.username || '';
  const username = raw.toLowerCase().trim();
  const body = await req.json();

  const url = `${RELAY_BASE}/directory/${username}`;

  console.log(`[Proxy] Directory PUT /${username}`);

  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      username,
      ...body,
    }),
  });

  const text = await res.text();
  const maybeJson = (() => {
    try {
      return JSON.parse(text);
    } catch {
      return { raw: text };
    }
  })();

  console.log(`[Proxy] Directory PUT /${username} -> ${res.status}`);

  return NextResponse.json(maybeJson, { status: res.status });
}
