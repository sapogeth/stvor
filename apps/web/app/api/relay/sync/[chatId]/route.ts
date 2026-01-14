// apps/web/app/api/relay/sync/[chatId]/route.ts
import { NextRequest, NextResponse } from 'next/server';

// Force Node.js runtime (not Edge)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELAY_BASE = process.env.RELAY_URL || process.env.RELAY_BASE_URL || process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';

/**
 * GET /api/relay/sync/:chatId
 * CRITICAL: Transparent proxy - forwards Authorization header from client
 * Does NOT verify Clerk session, does NOT use httpOnly cookies
 * Client sends: Authorization: Bearer <relay_jwt>
 * Relay verifies JWT with RELAY_JWT_SECRET
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ chatId: string }> }
) {
  try {
    const resolvedParams = await params;
    const chatId = resolvedParams.chatId;

    // CRITICAL: Forward Authorization header from client
    const authHeader = req.headers.get('authorization');
    
    const searchParams = req.nextUrl.searchParams;
    const since = searchParams.get('since') || '0';
    const limit = searchParams.get('limit') || '10';

    console.log(`[Proxy/sync] GET /sync/${chatId}`, { 
      since, 
      limit, 
      hasAuth: !!authHeader,
    });

    // Build relay URL with query params
    const url = `${RELAY_BASE}/sync/${chatId}?since=${since}&limit=${limit}`;
    
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    };
    
    // Forward Authorization header if present
    if (authHeader) {
      headers['Authorization'] = authHeader;
    }
    
    const res = await fetch(url, {
      method: 'GET',
      headers,
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
