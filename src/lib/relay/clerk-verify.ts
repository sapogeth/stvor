import { createRemoteJWKSet, jwtVerify } from 'jose';

const CLERK_ISSUER = process.env.NEXT_PUBLIC_CLERK_ISSUER_URL || 
  `https://${process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY?.split('_')[1]}.clerk.accounts.dev`;

// Clerk JWKS endpoint
const JWKS = createRemoteJWKSet(new URL(`${CLERK_ISSUER}/.well-known/jwks.json`));

export interface ClerkJwtPayload {
  sub: string;      // User ID
  azp?: string;     // Authorized party
  exp: number;
  iat: number;
  iss: string;
}

export async function verifyClerkJwt(token: string): Promise<ClerkJwtPayload | null> {
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: CLERK_ISSUER,
    });

    // Validate required claims
    if (!payload.sub || typeof payload.sub !== 'string') {
      console.error('[CLERK] Missing or invalid sub claim');
      return null;
    }

    return payload as ClerkJwtPayload;
  } catch (error) {
    console.error('[CLERK] JWT verification failed:', error);
    return null;
  }
}
