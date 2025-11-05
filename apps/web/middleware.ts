/**
 * Next.js Middleware for Clerk Authentication + Security Headers
 *
 * SECURITY ARCHITECTURE:
 * - Clerk handles ONLY identity and session management
 * - Clerk NEVER sees or stores private encryption keys
 * - E2E crypto operations remain 100% client-side
 * - Middleware validates session but NEVER decrypts messages
 * - /api/relay/* is COMPLETELY BYPASSED (direct server-to-server proxy)
 */

import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * Content-Security-Policy Configuration
 *
 * SECURITY: Minimal whitelist of external domains required for functionality
 * - Clerk: Authentication provider (*.clerk.accounts.dev, api.clerk.dev)
 * - Cloudflare: CAPTCHA challenges (challenges.cloudflare.com)
 * - Supabase: Relay backend (*.supabase.co)
 * - Localhost: Development relay server
 *
 * WASM Support: 'unsafe-eval' required for PQ crypto (ML-KEM-768, ML-DSA-65)
 * Next.js: 'unsafe-inline' required for hydration and Tailwind
 *
 * CAPTCHA Support: Cloudflare CAPTCHA requires:
 * - script-src-elem: For dynamically injected <script> tags
 * - worker-src: For Web Workers (including blob: URLs)
 * - child-src: Fallback for older browsers (same as worker-src)
 */
const CSP = [
  "default-src 'self'",
  // Scripts: Clerk + Cloudflare CAPTCHA + WASM support
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*.clerk.accounts.dev https://challenges.cloudflare.com",
  // Script elements: CRITICAL for CAPTCHA - must include challenges.cloudflare.com
  "script-src-elem 'self' 'unsafe-inline' https://*.clerk.accounts.dev https://challenges.cloudflare.com",
  // Connections: Clerk API + Supabase relay + localhost dev
  "connect-src 'self' https://*.clerk.accounts.dev https://api.clerk.com https://api.clerk.dev https://*.supabase.co https://challenges.cloudflare.com http://localhost:* ws://localhost:*",
  // Web Workers: CRITICAL for CAPTCHA - allows blob: URLs and Cloudflare workers
  "worker-src 'self' blob: https://*.clerk.accounts.dev https://challenges.cloudflare.com",
  // Child contexts: Fallback for older browsers (same as worker-src)
  "child-src 'self' blob: https://*.clerk.accounts.dev https://challenges.cloudflare.com",
  // Images: Clerk avatars + data URIs + blobs
  "img-src 'self' data: blob: https://img.clerk.com https://*.clerk.com",
  // Styles: Tailwind requires inline styles
  "style-src 'self' 'unsafe-inline'",
  // Frames: Clerk OAuth + Cloudflare CAPTCHA
  "frame-src 'self' https://*.clerk.accounts.dev https://challenges.cloudflare.com",
  // Fonts: Local + data URIs
  "font-src 'self' data:",
  // Media: Blobs for WASM modules
  "media-src 'self' blob:",
  // Security: Block all objects (Flash, Java applets)
  "object-src 'none'",
  // Security: Prevent base tag hijacking
  "base-uri 'self'",
  // Forms: Self + Clerk OAuth callbacks
  "form-action 'self' https://*.clerk.accounts.dev",
  // Security: Prevent iframe embedding (clickjacking protection)
  "frame-ancestors 'none'",
].join('; ');

// Define public routes that don't require authentication
const isPublicRoute = createRouteMatcher([
  '/',
  '/sign-in(.*)',
  '/sign-up(.*)',
  '/benchmarks',
  '/security',
  '/debug(.*)',
  '/test(.*)',
  '/reset(.*)',
]);

/**
 * Main middleware with early bypass for /api/relay/*
 * CRITICAL: /api/relay/* routes MUST NOT be processed by Clerk at all
 */
export default clerkMiddleware(async (auth, request) => {
  const url = new URL(request.url);

  // HARD BYPASS: /api/relay/* goes directly to route handlers
  // This ensures no Clerk SDK initialization, no auth checks, no interference
  if (url.pathname.startsWith('/api/relay/')) {
    return NextResponse.next();
  }

  // Protect non-public routes by redirecting to sign-in
  const { userId } = await auth();

  if (!isPublicRoute(request) && !userId) {
    const signInUrl = new URL('/sign-in', request.url);
    signInUrl.searchParams.set('redirect_url', request.url);
    return NextResponse.redirect(signInUrl);
  }

  // Create response with security headers
  const res = NextResponse.next();

  // SECURITY: Force HTTPS in production
  if (
    process.env.NODE_ENV === 'production' &&
    request.headers.get('x-forwarded-proto') !== 'https'
  ) {
    const httpsUrl = `https://${request.headers.get('host')}${request.nextUrl.pathname}${request.nextUrl.search}`;
    return NextResponse.redirect(httpsUrl, 301);
  }

  // Add CSP header
  res.headers.set('Content-Security-Policy', CSP);

  // HSTS: Force HTTPS for 1 year including subdomains
  res.headers.set(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains; preload'
  );

  // Prevent MIME-type sniffing
  res.headers.set('X-Content-Type-Options', 'nosniff');

  // Prevent clickjacking (allow SAMEORIGIN for Clerk iframes)
  res.headers.set('X-Frame-Options', 'SAMEORIGIN');

  // Enable XSS protection
  res.headers.set('X-XSS-Protection', '1; mode=block');

  // Referrer policy
  res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Permissions policy (disable unnecessary features)
  res.headers.set(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), interest-cohort=()'
  );

  // CRITICAL: Middleware only validates session existence
  // It NEVER decrypts messages or accesses private keys
  // All E2E crypto operations happen client-side only

  return res;
});

export const config = {
  // Exclude static files and Next.js internals
  // NOTE: We DON'T exclude /api/* because some API routes need Clerk (e.g. /api/profiles)
  // We only bypass /api/relay/* via early return in middleware function
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
