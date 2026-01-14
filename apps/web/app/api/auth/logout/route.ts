/**
 * POST /api/auth/logout
 * 
 * SECURITY: Clears httpOnly authentication cookie
 */

import { NextResponse } from 'next/server';
import { clearAuthCookie } from '@/lib/auth-cookies';

export async function POST() {
  try {
    await clearAuthCookie();
    
    console.log('[Auth/Logout] Cleared httpOnly cookie');
    
    return NextResponse.json({ 
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('[Auth/Logout] Error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
