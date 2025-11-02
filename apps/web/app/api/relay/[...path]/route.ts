import { NextRequest, NextResponse } from "next/server";

const RELAY_URL =
  process.env.RELAY_INTERNAL_URL ||
  process.env.NEXT_PUBLIC_RELAY_URL ||
  'http://localhost:3001';

/**
 * Transparent API proxy to relay server
 * Forwards all /api/relay/* requests to the real relay
 * NO synthetic responses, NO dev mode auto-create
 */

export async function POST(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolvedParams = await params;
  const path = resolvedParams.path.join("/");

  try {
    const bodyText = await req.text();
    const url = `${RELAY_URL}/${path}`;

    console.log(`[Proxy] POST /${path}`);

    // Forward all headers, especially Authorization
    const headers: Record<string, string> = {};
    req.headers.forEach((value, key) => {
      // Skip host and connection headers
      if (!['host', 'connection', 'content-length'].includes(key.toLowerCase())) {
        headers[key] = value;
      }
    });

    const res = await fetch(url, {
      method: "POST",
      headers,
      body: bodyText,
    });

    const responseText = await res.text();
    console.log(`[Proxy] POST /${path} -> ${res.status}`);

    return new Response(responseText, {
      status: res.status,
      headers: {
        'content-type': res.headers.get('content-type') || 'application/json',
      },
    });
  } catch (e) {
    console.error(`[Proxy] Relay unreachable for POST ${path}:`, e);
    return NextResponse.json({ error: 'RELAY_UNAVAILABLE' }, { status: 503 });
  }
}

export async function GET(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolvedParams = await params;
  const path = resolvedParams.path.join("/");

  try {
    const searchParams = req.nextUrl.searchParams.toString();
    const target = `${RELAY_URL}/${path}${searchParams ? "?" + searchParams : ""}`;

    console.log(`[Proxy] GET /${path}${searchParams ? "?" + searchParams : ""}`);

    // Forward all headers, especially Authorization
    const headers: Record<string, string> = {};
    req.headers.forEach((value, key) => {
      // Skip host and connection headers
      if (!['host', 'connection', 'content-length'].includes(key.toLowerCase())) {
        headers[key] = value;
      }
    });

    const res = await fetch(target, {
      method: "GET",
      headers,
    });

    const responseText = await res.text();
    console.log(`[Proxy] GET /${path} -> ${res.status}`);

    return new Response(responseText, {
      status: res.status,
      headers: {
        'content-type': res.headers.get('content-type') || 'application/json',
      },
    });
  } catch (e) {
    console.error(`[Proxy] Relay unreachable for GET ${path}:`, e);
    return NextResponse.json({ error: 'RELAY_UNAVAILABLE' }, { status: 503 });
  }
}

export async function PUT(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolvedParams = await params;
  const path = resolvedParams.path.join("/");

  try {
    const bodyText = await req.text();
    const url = `${RELAY_URL}/${path}`;

    console.log(`[Proxy] PUT /${path}`);

    // Forward all headers, especially Authorization
    const headers: Record<string, string> = {};
    req.headers.forEach((value, key) => {
      // Skip host and connection headers
      if (!['host', 'connection', 'content-length'].includes(key.toLowerCase())) {
        headers[key] = value;
      }
    });

    const res = await fetch(url, {
      method: "PUT",
      headers,
      body: bodyText,
    });

    const responseText = await res.text();
    console.log(`[Proxy] PUT /${path} -> ${res.status}`);

    return new Response(responseText, {
      status: res.status,
      headers: {
        'content-type': res.headers.get('content-type') || 'application/json',
      },
    });
  } catch (e) {
    console.error(`[Proxy] Relay unreachable for PUT ${path}:`, e);
    return NextResponse.json({ error: 'RELAY_UNAVAILABLE' }, { status: 503 });
  }
}
