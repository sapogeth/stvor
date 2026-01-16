export interface RelaySession {
  sessionId: string;
  clerkUserId: string;
  username: string;
  createdAt: Date;
  expiresAt: Date;
  identityRegistered: boolean;
  identityPublicKey?: string;
}

export interface RelayJwtPayload {
  sub: string;
  sid: string;
  username: string;
  iat: number;
  exp: number;
}

export interface DirectoryEntry {
  username: string;
  clerkUserId: string;
  publicKeys: {
    identity: string;
    signedPreKey: string;
    kyberPreKey: string;
  };
  signature: string;
  registeredAt: Date;
  updatedAt: Date;
}

export type AuthErrorCode =
  | 'MISSING_AUTH'
  | 'INVALID_CLERK_TOKEN'
  | 'INVALID_RELAY_TOKEN'
  | 'SESSION_EXPIRED'
  | 'SESSION_NOT_FOUND'
  | 'FORBIDDEN'
  | 'USERNAME_TAKEN'
  | 'IDENTITY_NOT_FOUND'
  | 'RELAY_UNAVAILABLE'
  | 'INTERNAL_ERROR';

export interface AuthError {
  code: AuthErrorCode;
  message: string;
}
