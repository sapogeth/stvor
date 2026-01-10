// apps/web/app/api/relay/directory/[username]/route.ts
import { NextResponse } from 'next/server';

// Force Node.js runtime (not Edge)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELAY_BASE =
  process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';

// READ prekey bundle / identity
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ username: string }> }
) {
  try {
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

    const ed25519 = data.identityPublicKey || data.identityEd25519 || data.ed25519;
    const mldsa = data.identityMLDSA || '';
    const relayPublicKey = data.relayPublicKey || null;

    return NextResponse.json({
      username,
      // Nested identity object for client code compatibility
      identity: {
        ed25519,
        identityEd25519: ed25519,
        identityMLDSA: mldsa,
        relayPublicKey,
      },
      // Flat fields for backward compatibility
      identityPublicKey: ed25519,
      identityEd25519: ed25519,
      identityMLDSA: mldsa,
      prekeyBundle: data.prekeyBundle ?? data.prekeys ?? null,
      prekeySignature:
        data.prekeySignature ||
        data.signature ||
        data.prekeyBundle?.signature ||
        null,
    });
  } catch (error) {
    console.error('[API] directory GET error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// PUBLISH / UPDATE prekey bundle
export async function POST(
  req: Request,
  { params }: { params: Promise<{ username: string }> }
) {
  try {
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
        return { error: 'INVALID_RESPONSE', detail: 'Relay returned non-JSON response' };
      }
    })();

    console.log(`[Proxy] Directory POST /${username} -> ${res.status}`);

    return NextResponse.json(maybeJson, { status: res.status });
  } catch (error) {
    console.error('[API] directory POST error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// some relays use PUT for updates
export async function PUT(
  req: Request,
  { params }: { params: Promise<{ username: string }> }
) {
  try {
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
        return { error: 'INVALID_RESPONSE', detail: 'Relay returned non-JSON response' };
      }
    })();

    console.log(`[Proxy] Directory PUT /${username} -> ${res.status}`);

    return NextResponse.json(maybeJson, { status: res.status });
  } catch (error) {
    console.error('[API] directory PUT error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
