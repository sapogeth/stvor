// apps/web/app/api/relay/message/[chatId]/route.ts
import { NextRequest, NextResponse } from 'next/server';

const RELAY_BASE = process.env.RELAY_BASE_URL || 'http://localhost:3001';

/**
 * POST /api/relay/message/:chatId
 * Forwards message (handshake or encrypted) to relay server
 * CRITICAL: Must forward Authorization header for relay authentication
 */
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ chatId: string }> }
) {
  const resolvedParams = await params;
  const chatId = resolvedParams.chatId;

  // Read body as text to forward raw JSON
  const body = await req.text();

  // Extract headers
  const auth = req.headers.get('authorization') || '';
  const contentType = req.headers.get('content-type') || 'application/json';
  const origin = req.headers.get('origin') || '';

  console.log(`[Proxy] POST /message/${chatId}`);

  // Forward to relay with authentication
  const url = `${RELAY_BASE}/message/${chatId}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': auth,
      'Content-Type': contentType,
      'Origin': origin,
    },
    body,
  });

  const responseText = await res.text();

  // Try to parse as JSON, otherwise return raw text
  let responseData;
  try {
    responseData = JSON.parse(responseText);
  } catch {
    responseData = { raw: responseText };
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
}

/**
 * GET /api/relay/message/:chatId
 * Fetch messages for a chat
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ chatId: string }> }
) {
  const resolvedParams = await params;
  const chatId = resolvedParams.chatId;

  const auth = req.headers.get('authorization') || '';

  console.log(`[Proxy] GET /message/${chatId}`);

  const url = `${RELAY_BASE}/message/${chatId}`;
  const res = await fetch(url, {
    method: 'GET',
    headers: {
      'Authorization': auth,
      'Content-Type': 'application/json',
    },
  });

  const data = await res.json().catch(() => ({}));

  console.log(`[Proxy] GET /message/${chatId} -> ${res.status}`);

  return NextResponse.json(data, {
    status: res.status,
    headers: {
      'Content-Type': 'application/json',
    },
  });
}
