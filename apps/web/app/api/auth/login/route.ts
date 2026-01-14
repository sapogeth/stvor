/**
 * POST /api/auth/login
 * 
 * SECURITY: Sets httpOnly cookie with JWT token
 * This is the ONLY secure way to store authentication tokens
 * 
 * Called after relay registration returns JWT
 */

import { NextRequest, NextResponse } from 'next/server';
import { setAuthCookie } from '@/lib/auth-cookies';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { username, token } = body;
    
    if (!username || !token) {
      return NextResponse.json(
        { error: 'Missing username or token' },
        { status: 400 }
      );
    }
    
    // Set httpOnly cookie (NOT accessible to JavaScript)
    await setAuthCookie(username, token);
    
    console.log(`[Auth/Login] Set httpOnly cookie for user: ${username}`);
    
    return NextResponse.json({ 
      success: true,
      message: 'Authentication cookie set successfully'
    });
  } catch (error) {
    console.error('[Auth/Login] Error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
