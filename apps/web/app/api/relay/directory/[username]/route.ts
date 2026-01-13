// apps/web/app/api/relay/directory/[username]/route.ts
import { NextResponse } from 'next/server';

// Force Node.js runtime (not Edge)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELAY_URL =
  process.env.RELAY_URL ||
  process.env.RELAY_BASE_URL ||
  process.env.NEXT_PUBLIC_RELAY_URL ||
  'http://localhost:3001';
const RELAY_API_KEY = process.env.RELAY_API_KEY || 'dev-key-change-in-production';

// READ prekey bundle / identity
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ username: string }> }
) {
  try {
    const resolvedParams = await params;
    const raw = resolvedParams.username || '';
    const username = raw.toLowerCase().trim();

    const url = `${RELAY_URL}/directory/${username}`;
    console.error(`[Proxy/directory] ======================================`);
    console.error(`[Proxy/directory] ENV VARS CHECK:`);
    console.error(`[Proxy/directory]   RELAY_URL: ${process.env.RELAY_URL || 'NOT SET'}`);
    console.error(`[Proxy/directory]   RELAY_BASE_URL: ${process.env.RELAY_BASE_URL || 'NOT SET'}`);
    console.error(`[Proxy/directory]   NEXT_PUBLIC_RELAY_URL: ${process.env.NEXT_PUBLIC_RELAY_URL || 'NOT SET'}`);
    console.error(`[Proxy/directory]   RELAY_API_KEY: ${process.env.RELAY_API_KEY ? '***SET***' : 'NOT SET (using default)'}`);
    console.error(`[Proxy/directory]   Final RELAY_URL: ${RELAY_URL}`);
    console.error(`[Proxy/directory] GET /directory/${username} -> ${url}`);
    
    const res = await fetch(url, {
      signal: AbortSignal.timeout(10000),
      method: 'GET',
      headers: {
        'content-type': 'application/json',
        'Authorization': `Bearer ${RELAY_API_KEY}`,
      },
    });

    console.error(`[Proxy/directory] Relay response: ${res.status} ${res.statusText}`);
    
    if (!res.ok) {
      return NextResponse.json(
        {
          error: 'directory_not_found',
          message: `No directory entry for ${username}`,
        },
        { status: res.status }
      );
    }

    const data = await res.json();
    console.error(`[Proxy/directory] Successfully fetched directory for ${username}`);

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
  } catch (error: any) {
    console.error('[Proxy/directory] GET error:', {
      username: (await params).username,
      error: error.message,
      code: error.code,
      cause: error.cause?.message
    });
    
    // Check if it's a network error (ECONNREFUSED = relay down)
    if (error.cause?.code === 'ECONNREFUSED' || error.code === 'ECONNREFUSED') {
      return NextResponse.json(
        { 
          error: 'relay_unavailable',
          message: 'Relay server is not responding. Check RELAY_URL environment variable.' 
        },
        { status: 502 }
      );
    }
    
    return NextResponse.json(
      { error: 'Internal server error', details: error.message },
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

    const url = `${RELAY_URL}/directory/${username}`;

    console.error(`[Proxy/directory] POST /directory/${username} -> ${url}`);

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

    console.error(`[Proxy/directory] POST response: ${res.status}`);

    return NextResponse.json(maybeJson, { status: res.status });
  } catch (error: any) {
    console.error('[Proxy/directory] POST error:', {
      username: (await params).username,
      error: error.message,
      code: error.code
    });
    
    if (error.cause?.code === 'ECONNREFUSED' || error.code === 'ECONNREFUSED') {
      return NextResponse.json(
        { error: 'relay_unavailable', message: 'Relay server is not responding' },
        { status: 502 }
      );
    }
    
    return NextResponse.json(
      { error: 'Internal server error', details: error.message },
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

    const url = `${RELAY_URL}/directory/${username}`;

    console.error(`[Proxy/directory] PUT /directory/${username} -> ${url}`);

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
