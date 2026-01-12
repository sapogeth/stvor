import { NextRequest, NextResponse } from "next/server";

// Force Node.js runtime (not Edge) for full fetch API support
export const runtime = 'nodejs';
// Force dynamic rendering (no static optimization)
export const dynamic = 'force-dynamic';

const RELAY_URL =
  process.env.RELAY_URL ||
  process.env.RELAY_BASE_URL ||
  process.env.NEXT_PUBLIC_RELAY_URL ||
  'http://localhost:3001';

const RELAY_API_KEY = process.env.RELAY_API_KEY || 'dev-key-change-in-production';

/**
 * Transparent API proxy to relay server
 * Forwards all /api/relay/* requests to the real relay
 * Adds RELAY_API_KEY server-side for authentication
 * NO synthetic responses, NO dev mode auto-create
 */

export async function POST(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolvedParams = await params;
  const path = resolvedParams.path.join("/");

  try {
    const bodyText = await req.text();
    const url = `${RELAY_URL}/${path}`;

    console.log(`[Proxy] POST /${path}`);

    // Forward all headers, especially Authorization from client
    const clientAuth = req.headers.get('authorization');
    const headers: Record<string, string> = {
      'Authorization': clientAuth || `Bearer ${RELAY_API_KEY}`, // Forward client JWT, fallback to API key
    };
    req.headers.forEach((value, key) => {
      // Skip host, connection, and authorization (already handled above)
      if (!['host', 'connection', 'content-length', 'authorization'].includes(key.toLowerCase())) {
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

    // Try to parse as JSON, always return JSON even on error
    let responseData;
    try {
      responseData = JSON.parse(responseText);
    } catch {
      console.warn(`[Proxy] POST /${path} response is not JSON, wrapping:`, responseText.substring(0, 100));
      responseData = { error: 'INVALID_RESPONSE', detail: 'Relay returned non-JSON response' };
    }

    return NextResponse.json(responseData, {
      status: res.status,
      headers: {
        'content-type': 'application/json',
      },
    });
  } catch (e) {
    console.error(`[Proxy] Relay unreachable for POST ${path}:`, e);
    return NextResponse.json(
      { error: 'RELAY_UNAVAILABLE', detail: String((e as Error)?.message ?? e) },
      { status: 502 }
    );
  }
}

export async function GET(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolvedParams = await params;
  const path = resolvedParams.path.join("/");

  try {
    const searchParams = req.nextUrl.searchParams.toString();
    const target = `${RELAY_URL}/${path}${searchParams ? "?" + searchParams : ""}`;

    console.log(`[Proxy] GET /${path}${searchParams ? "?" + searchParams : ""}`);

    // Forward all headers, especially Authorization from client
    const clientAuth = req.headers.get('authorization');
    const headers: Record<string, string> = {
      'Authorization': clientAuth || `Bearer ${RELAY_API_KEY}`, // Forward client JWT, fallback to API key
    };
    req.headers.forEach((value, key) => {
      // Skip host, connection, and authorization (already handled above)
      if (!['host', 'connection', 'content-length', 'authorization'].includes(key.toLowerCase())) {
        headers[key] = value;
      }
    });

    const res = await fetch(target, {
      method: "GET",
      headers,
    });

    const responseText = await res.text();
    console.log(`[Proxy] GET /${path} -> ${res.status}`);

    // Try to parse as JSON, always return JSON even on error
    let responseData;
    try {
      responseData = JSON.parse(responseText);
    } catch {
      console.warn(`[Proxy] GET /${path} response is not JSON, wrapping:`, responseText.substring(0, 100));
      responseData = { error: 'INVALID_RESPONSE', detail: 'Relay returned non-JSON response' };
    }

    return NextResponse.json(responseData, {
      status: res.status,
      headers: {
        'content-type': 'application/json',
      },
    });
  } catch (e) {
    console.error(`[Proxy] Relay unreachable for GET ${path}:`, e);
    return NextResponse.json(
      { error: 'RELAY_UNAVAILABLE', detail: String((e as Error)?.message ?? e) },
      { status: 502 }
    );
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

    // Try to parse as JSON, always return JSON even on error
    let responseData;
    try {
      responseData = JSON.parse(responseText);
    } catch {
      console.warn(`[Proxy] PUT /${path} response is not JSON, wrapping:`, responseText.substring(0, 100));
      responseData = { error: 'INVALID_RESPONSE', detail: 'Relay returned non-JSON response' };
    }

    return NextResponse.json(responseData, {
      status: res.status,
      headers: {
        'content-type': 'application/json',
      },
    });
  } catch (e) {
    console.error(`[Proxy] Relay unreachable for PUT ${path}:`, e);
    return NextResponse.json(
      { error: 'RELAY_UNAVAILABLE', detail: String((e as Error)?.message ?? e) },
      { status: 502 }
    );
  }
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolvedParams = await params;
  const path = resolvedParams.path.join("/");

  try {
    const url = `${RELAY_URL}/${path}`;

    console.log(`[Proxy] DELETE /${path}`);

    // Forward all headers, especially Authorization
    const headers: Record<string, string> = {};
    req.headers.forEach((value, key) => {
      // Skip host and connection headers
      if (!['host', 'connection', 'content-length'].includes(key.toLowerCase())) {
        headers[key] = value;
      }
    });

    const res = await fetch(url, {
      method: "DELETE",
      headers,
    });

    const responseText = await res.text();
    console.log(`[Proxy] DELETE /${path} -> ${res.status}`);

    // Try to parse as JSON, always return JSON even on error
    let responseData;
    try {
      responseData = JSON.parse(responseText);
    } catch {
      console.warn(`[Proxy] DELETE /${path} response is not JSON, wrapping:`, responseText.substring(0, 100));
      responseData = { error: 'INVALID_RESPONSE', detail: 'Relay returned non-JSON response' };
    }

    return NextResponse.json(responseData, {
      status: res.status,
      headers: {
        'content-type': 'application/json',
      },
    });
  } catch (e) {
    console.error(`[Proxy] Relay unreachable for DELETE ${path}:`, e);
    return NextResponse.json(
      { error: 'RELAY_UNAVAILABLE', detail: String((e as Error)?.message ?? e) },
      { status: 502 }
    );
  }
}
