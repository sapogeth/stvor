// apps/web/app/api/relay/message/[chatId]/route.ts
import { NextRequest, NextResponse } from 'next/server';

// Force Node.js runtime (not Edge)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELAY_API_KEY = process.env.RELAY_API_KEY || 'dev-key-change-in-production';

const RELAY_BASE = process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';

/**
 * POST /api/relay/message/:chatId
 * Forwards message (handshake or encrypted) to relay server
 * CRITICAL: Must forward Authorization header for relay authentication
 */
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ chatId: string }> }
) {
  try {
    const resolvedParams = await params;
    const chatId = resolvedParams.chatId;

    // Read body as text to forward raw JSON
    const body = await req.text();

    // Extract headers - CRITICAL: Forward JWT from client
    const auth = req.headers.get('authorization') || '';
    const contentType = req.headers.get('content-type') || 'application/json';
    const origin = req.headers.get('origin') || '';

    console.log(`[Proxy] POST /message/${chatId}`, { hasAuth: !!auth });

    // Forward to relay with authentication
    const url = `${RELAY_BASE}/message/${chatId}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': auth || `Bearer ${RELAY_API_KEY}`,  // Forward JWT, fallback to API key
        'Content-Type': contentType,
        'Origin': origin,
      },
      body,
    });

    const responseText = await res.text();

    // Try to parse as JSON, otherwise return error
    let responseData;
    try {
      responseData = JSON.parse(responseText);
    } catch {
      console.warn(`[Proxy] POST /message/${chatId} response is not JSON`);
      responseData = { error: 'INVALID_RESPONSE', detail: 'Relay returned non-JSON response' };
    }

    console.log(`[Proxy] POST /message/${chatId} -> ${res.status}`);

    if (!res.ok) {
      console.error(`[Proxy] Message POST failed: ${res.status}`, responseData);
    }

    return NextResponse.json(responseData, {
      status: res.status,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  } catch (error) {
    console.error('[API] message POST error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * GET /api/relay/message/:chatId
 * Fetch messages for a chat
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ chatId: string }> }
) {
  try {
    const resolvedParams = await params;
    const chatId = resolvedParams.chatId;

    const auth = req.headers.get('authorization') || '';

    console.log(`[Proxy] GET /message/${chatId}`, { hasAuth: !!auth });

    const url = `${RELAY_BASE}/message/${chatId}`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': auth || `Bearer ${RELAY_API_KEY}`,  // Forward JWT, fallback to API key
        'Content-Type': 'application/json',
      },
    });

    const text = await res.text();
    const data = (() => {
      try {
        return JSON.parse(text);
      } catch {
        console.warn(`[Proxy] GET /message/${chatId} response is not JSON`);
        return { error: 'INVALID_RESPONSE', detail: 'Relay returned non-JSON response' };
      }
    })();

    console.log(`[Proxy] GET /message/${chatId} -> ${res.status}`);

    return NextResponse.json(data, {
      status: res.status,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  } catch (error) {
    console.error('[API] message GET error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
