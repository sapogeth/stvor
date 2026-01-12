// apps/web/app/api/relay/sync/[chatId]/route.ts
import { NextRequest, NextResponse } from 'next/server';

// Force Node.js runtime (not Edge)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELAY_API_KEY = process.env.RELAY_API_KEY || 'dev-key-change-in-production';
const RELAY_BASE = process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';

/**
 * GET /api/relay/sync/:chatId
 * Fetch sync messages for a chat
 * CRITICAL: Must forward Authorization header (JWT) for relay authentication
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ chatId: string }> }
) {
  try {
    const resolvedParams = await params;
    const chatId = resolvedParams.chatId;

    // Extract JWT from request
    const auth = req.headers.get('authorization') || '';
    const searchParams = req.nextUrl.searchParams;
    const since = searchParams.get('since') || '0';
    const limit = searchParams.get('limit') || '10';

    console.log(`[Proxy] GET /sync/${chatId}`, { since, limit, hasAuth: !!auth });

    // Build relay URL with query params
    const url = `${RELAY_BASE}/sync/${chatId}?since=${since}&limit=${limit}`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': auth || `Bearer ${RELAY_API_KEY}`,  // Forward JWT, fallback to API key
        'Content-Type': 'application/json',
      },
    });

    const responseText = await res.text();

    // Try to parse as JSON
    let responseData;
    try {
      responseData = JSON.parse(responseText);
    } catch {
      console.warn(`[Proxy] GET /sync/${chatId} response is not JSON`);
      responseData = { error: 'INVALID_RESPONSE', detail: 'Relay returned non-JSON response' };
    }

    console.log(`[Proxy] GET /sync/${chatId} -> ${res.status}`);

    if (!res.ok) {
      console.error(`[Proxy] Sync GET failed: ${res.status}`, responseData);
    }

    return NextResponse.json(responseData, {
      status: res.status,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  } catch (error) {
    console.error('[API] sync GET error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
