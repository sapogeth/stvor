// Minimal test route - NO imports from /lib
import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELAY_URL =
  process.env.RELAY_URL ||
  process.env.RELAY_BASE_URL ||
  process.env.NEXT_PUBLIC_RELAY_URL ||
  'http://localhost:3001';

const RELAY_API_KEY = process.env.RELAY_API_KEY || 'dev-key-change-in-production';

export async function GET() {
  console.error('[TEST] ==========================================');
  console.error('[TEST] ENV VARS:');
  console.error(`[TEST]   RELAY_URL: ${process.env.RELAY_URL || 'NOT SET'}`);
  console.error(`[TEST]   RELAY_BASE_URL: ${process.env.RELAY_BASE_URL || 'NOT SET'}`);
  console.error(`[TEST]   NEXT_PUBLIC_RELAY_URL: ${process.env.NEXT_PUBLIC_RELAY_URL || 'NOT SET'}`);
  console.error(`[TEST]   RELAY_API_KEY: ${process.env.RELAY_API_KEY ? 'SET' : 'NOT SET'}`);
  console.error(`[TEST]   Final RELAY_URL: ${RELAY_URL}`);
  
  try {
    const url = `${RELAY_URL}/healthz`;
    console.error(`[TEST] Fetching: ${url}`);
    
    const res = await fetch(url, {
      signal: AbortSignal.timeout(5000),
      headers: {
        'Authorization': `Bearer ${RELAY_API_KEY}`,
      },
    });
    
    console.error(`[TEST] Response: ${res.status} ${res.statusText}`);
    
    const data = await res.json();
    
    return NextResponse.json({
      success: true,
      relay_url: RELAY_URL,
      relay_response: data,
      status: res.status,
    });
  } catch (error: any) {
    console.error('[TEST] ERROR:', error.message);
    return NextResponse.json({
      success: false,
      error: error.message,
      relay_url: RELAY_URL,
      env_vars: {
        RELAY_URL: process.env.RELAY_URL || 'NOT SET',
        RELAY_BASE_URL: process.env.RELAY_BASE_URL || 'NOT SET',
        NEXT_PUBLIC_RELAY_URL: process.env.NEXT_PUBLIC_RELAY_URL || 'NOT SET',
      }
    }, { status: 500 });
  }
}
