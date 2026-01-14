// apps/web/app/api/relay/sync/[chatId]/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { extractJWTFromRequest } from '@/lib/auth-cookies';

// Force Node.js runtime (not Edge)
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELAY_API_KEY = process.env.RELAY_API_KEY || 'dev-key-change-in-production';
const RELAY_BASE = process.env.RELAY_URL || process.env.RELAY_BASE_URL || process.env.NEXT_PUBLIC_RELAY_URL || 'http://localhost:3001';

/**
 * GET /api/relay/sync/:chatId
 * Fetch sync messages for a chat
 * SECURITY: JWT extracted from httpOnly cookie (XSS-resistant when accessed via Next.js API routes - see ARCHITECTURAL_ASSUMPTIONS.md §A1)
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ chatId: string }> }
) {
  try {
    const resolvedParams = await params;
    const chatId = resolvedParams.chatId;

    // SECURITY: Extract JWT from httpOnly cookie (NOT from JavaScript-accessible storage)
    const jwt = await extractJWTFromRequest(req);
    
    const searchParams = req.nextUrl.searchParams;
    const since = searchParams.get('since') || '0';
    const limit = searchParams.get('limit') || '10';

    console.error(`[Proxy/sync] GET /sync/${chatId}`, { 
      since, 
      limit, 
      hasJWT: !!jwt,
    });

    // Build relay URL with query params
    const url = `${RELAY_BASE}/sync/${chatId}?since=${since}&limit=${limit}`;
    
    // SECURITY: Use JWT from cookie or fallback to API key
    const authHeader = jwt ? `Bearer ${jwt}` : `Bearer ${RELAY_API_KEY}`;
    
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json',
      },
    });

    console.error(`[Proxy/sync] Relay response:`, {
      status: res.status,
      statusText: res.statusText,
      sentAuth: jwt ? 'JWT' : 'API_KEY'
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
