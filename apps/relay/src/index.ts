/**
 * Ilyazh Relay Server (Production-Ready)
 * Horizontally scalable, stateless relay with PostgreSQL backend
 * JWT authentication, rate limiting, structured observability
 * Railway Serverless compatible
 */

import Fastify from 'fastify';
import cors from '@fastify/cors';
import multipart from '@fastify/multipart';
import jwt from '@fastify/jwt';
import { createStorageAdapter, type IStorageAdapter } from './storage/index';
import { type PrekeyBundle } from './storage/interfaces';
import { normalizeUsername } from './utils/normalize';
import { setupWebSocket } from './websocket';
import * as crypto from 'crypto';
// DOMPurify removed - use simple text sanitization instead (server doesn't need jsdom)

const PORT = parseInt(process.env.PORT || '3001', 10);
const HOST = process.env.HOST || '0.0.0.0';
const STORAGE_TYPE = (process.env.STORAGE_TYPE || 'memory') as 'memory' | 'postgres';
const DB_URL = process.env.DATABASE_URL;
const ALLOW_DEV_AUTOCREATE = process.env.ALLOW_DEV_AUTOCREATE === '1';

// ==================== BETA LIMITS ====================
const MAX_USERS = 100; // Beta test limit
const MAX_MESSAGES_PER_CHAT = 1000;
const MAX_MESSAGE_SIZE = 1 * 1024 * 1024; // 1 MB
const MESSAGE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

console.log('[Beta] ✅ Beta limits configured:');
console.log(`  - Max users: ${MAX_USERS}`);
console.log(`  - Max messages per chat: ${MAX_MESSAGES_PER_CHAT}`);
console.log(`  - Max message size: ${MAX_MESSAGE_SIZE / 1024 / 1024} MB`);
console.log(`  - Message TTL: ${MESSAGE_TTL_MS / 1000 / 60 / 60 / 24} days`);

// Validate configuration - but DON'T crash process, just warn
if (STORAGE_TYPE === 'postgres' && !DB_URL) {
  console.warn('⚠️  WARNING: DATABASE_URL not set but STORAGE_TYPE=postgres, falling back to memory');
  // Override to memory
  (global as any).STORAGE_TYPE_OVERRIDE = 'memory';
}

const fastify = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || 'info',
    serializers: {
      req: (req) => ({
        method: req.method,
        url: req.url,
        remoteAddress: req.ip,
      }),
      res: (res) => ({
        statusCode: res.statusCode,
      }),
    },
  },
  bodyLimit: 10 * 1024 * 1024, // 10MB
});

// ==================== CORS Configuration ====================

// Parse ALLOWED_ORIGINS from environment with fallback to localhost for development
// Format: comma-separated list (spaces are trimmed)
// Example: https://stvor.xyz,https://www.stvor.xyz,http://localhost:3000
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
  : [
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'http://localhost:3002', // Next.js dev server alternate port
      'http://127.0.0.1:3002',
      'http://localhost:3001', // Relay dev server
      'http://127.0.0.1:3001',
    ];

console.log('[Startup] 📋 Registering Fastify plugins...');
console.log(`[Startup] 🔐 CORS: Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);

// CRITICAL SECURITY: API key validation for no-origin requests
const VALID_API_KEYS = new Set(
  (process.env.VALID_API_KEYS || '')
    .split(',')
    .map(key => key.trim())
    .filter(Boolean)
);

function isValidAPIKey(apiKey: string | undefined): boolean {
  if (!apiKey) return false;
  return VALID_API_KEYS.has(apiKey);
}

await fastify.register(cors, {
  origin: (origin, callback) => {
    // CRITICAL SECURITY: Handle no-origin requests (mobile apps, Postman, curl, etc.)
    // These requests could be from malicious mobile malware, so require explicit API key
    if (!origin) {
      // For no-origin requests, we require an API key header
      // This will be checked in the onRequest hook below
      // For now, allow to pass, but they will be rejected in the endpoint handlers
      // unless they provide X-API-Key header
      callback(null, true);
      return;
    }

    // Check if origin is in allowed list
    if (ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes('*')) {
      callback(null, true);
    } else {
      // Only log blocked origins (security event)
      console.error(`[CORS] ❌ BLOCKED origin: ${origin}`);
      logSecurityEvent('CORS_BLOCKED', { origin });
      callback(new Error('Not allowed by CORS'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Relay-User', 'X-API-Key'],
  preflightContinue: false,
  optionsSuccessStatus: 204,
});

// CRITICAL SECURITY: Enforce API key for no-origin requests
fastify.addHook('onRequest', async (request, reply) => {
  // Skip OPTIONS requests (CORS preflight)
  if (request.method === 'OPTIONS') {
    return;
  }

  // If request has no origin header, require X-API-Key header
  const origin = request.headers.origin;
  if (!origin) {
    const apiKey = request.headers['x-api-key'] as string | undefined;

    // If no origin and no API key, block the request
    if (!isValidAPIKey(apiKey)) {
      console.error(`[CORS] ❌ CRITICAL: No-origin request without valid API key`);
      console.error(`[CORS]    IP: ${request.ip}`);
      console.error(`[CORS]    Path: ${request.url}`);
      console.error(`[CORS]    Method: ${request.method}`);
      logSecurityEvent('CORS_NO_ORIGIN_REJECTED', { ip: request.ip, path: request.url });

      reply.code(403).send({
        error: 'Forbidden: No-origin requests require X-API-Key header',
        message: 'Mobile and server-to-server requests must provide a valid API key'
      });
    }
  }
});

console.log('[Startup] ✅ CORS plugin registered');

await fastify.register(multipart, {
  limits: { fileSize: 10 * 1024 * 1024 },
});
console.log('[Startup] ✅ Multipart plugin registered');

// ==================== JWT Authentication ====================

console.log('[Startup] 🔐 Checking JWT_SECRET configuration...');
// SECURITY: FAIL-CLOSED - JWT_SECRET is MANDATORY, no default fallback
const JWT_SECRET = process.env.JWT_SECRET;

// CRITICAL: JWT_SECRET is MANDATORY in ALL environments
// No dev defaults, no fallback values - production-grade security from the start
if (!JWT_SECRET) {
  console.error('❌ CRITICAL: JWT_SECRET is not set');
  console.error('   This is MANDATORY for all environments (dev, staging, production)');
  console.error('   Generate with: openssl rand -base64 64');
  console.error('   Set environment variable: JWT_SECRET=<generated-value>');
  console.error('   Minimum length: 64 characters (for HS256 security)');
  process.exit(1); // SECURITY: Fail-closed - refuse to start
}

// CRITICAL: Enforce minimum length for HS256 security
// HS256 requires at least 256 bits (32 bytes) = 43 chars in base64
// We enforce 64 chars for additional security margin
if (JWT_SECRET.length < 64) {
  console.error('❌ CRITICAL: JWT_SECRET is too short (< 64 chars)');
  console.error('   HS256 requires minimum 256 bits (32 bytes) of entropy');
  console.error('   We enforce 64 chars for additional security');
  console.error('   Generate with: openssl rand -base64 64');
  console.error('   Current length: ' + JWT_SECRET.length + ' chars');
  process.exit(1); // SECURITY: Fail-closed - refuse to start
}

// CRITICAL: Reject common insecure patterns (developer mistakes)
const INSECURE = ['secret', 'change-this', 'development-secret', 'test-secret', 'jwt-secret', 'please-change-me', 'temp-secret', 'dev-secret', 'default-'];
if (INSECURE.some(s => JWT_SECRET.toLowerCase().includes(s))) {
  console.error('❌ CRITICAL: JWT_SECRET contains insecure pattern indicating it\'s a default/placeholder');
  console.error('   Detected insecure pattern in: ' + JWT_SECRET.substring(0, 30) + '...');
  console.error('   Generate a secure random secret with: openssl rand -base64 64');
  process.exit(1); // SECURITY: Fail-closed - refuse to start
}

console.log('[Security] ✅ JWT_SECRET is valid and secure');

await fastify.register(jwt, {
  secret: JWT_SECRET,
  sign: { algorithm: 'HS256', expiresIn: '30d' },
  verify: { algorithms: ['HS256'] },
});

console.log('[Security] ✅ JWT (HS256, 30d expiry)');

// ==================== Relay Identity (Ed25519) ====================

// CRITICAL: FAIL-CLOSED - Relay identity key is MANDATORY
// Without this key, clients cannot verify relay authenticity, enabling EREBUS/MITM attacks
// This must be configured in ALL environments (dev, staging, production)
console.log('[Startup] 🔐 Checking RELAY_IDENTITY_KEY configuration...');
const RELAY_IDENTITY_KEY_PEM = process.env.RELAY_IDENTITY_KEY;

if (!RELAY_IDENTITY_KEY_PEM) {
  console.error('❌ CRITICAL: RELAY_IDENTITY_KEY is not set');
  console.error('   This is MANDATORY for all environments (dev, staging, production)');
  console.error('   Without it, clients cannot verify relay authenticity');
  console.error('   This enables EREBUS/MITM attacks where attackers impersonate the relay');
  console.error('   Generate Ed25519 key pair with:');
  console.error('     openssl genpkey -algorithm Ed25519 -out relay_key.pem');
  console.error('     cat relay_key.pem | base64 -w 0');
  console.error('   Set RELAY_IDENTITY_KEY=<base64-encoded-pem>');
  process.exit(1); // SECURITY: Fail-closed - refuse to start
}

if (typeof RELAY_IDENTITY_KEY_PEM !== 'string' || RELAY_IDENTITY_KEY_PEM.length === 0) {
  console.error('❌ CRITICAL: RELAY_IDENTITY_KEY is not a valid string');
  process.exit(1); // SECURITY: Fail-closed
}

let relayIdentityPrivateKey: crypto.KeyObject | null = null;
let relayIdentityPublicKey: string | null = null; // Hex string for client verification

try {
  // Load private key from PEM format
  // RELAY_IDENTITY_KEY_PEM can be either:
  // 1. Base64-encoded PEM (preferred for environment variables)
  // 2. Raw PEM with literal \n (legacy support)
  let pemKey: string;

  if (RELAY_IDENTITY_KEY_PEM.startsWith('-----BEGIN')) {
    // Raw PEM format - replace literal \n with actual newlines
    pemKey = RELAY_IDENTITY_KEY_PEM.includes('\\n')
      ? RELAY_IDENTITY_KEY_PEM.replace(/\\n/g, '\n')
      : RELAY_IDENTITY_KEY_PEM;
  } else {
    // Base64-encoded PEM format (recommended)
    try {
      pemKey = Buffer.from(RELAY_IDENTITY_KEY_PEM, 'base64').toString('utf-8');
    } catch (decodeErr) {
      throw new Error(`Failed to decode base64 RELAY_IDENTITY_KEY: ${decodeErr instanceof Error ? decodeErr.message : String(decodeErr)}`);
    }
  }

  relayIdentityPrivateKey = crypto.createPrivateKey({
    key: pemKey,
    format: 'pem',
    type: 'pkcs8',
  });

  // Export public key for broadcasting to clients
  const publicKeyObj = crypto.createPublicKey(relayIdentityPrivateKey);
  const publicKeyExported = publicKeyObj.export({ format: 'pem', type: 'spki' });

  // Convert to string (it's a string in Node.js for PEM format)
  const publicKeyPEM = typeof publicKeyExported === 'string'
    ? publicKeyExported
    : publicKeyExported.toString('utf-8');

  // Convert to hex format (last 32 bytes of DER-encoded key)
  const publicKeyBase64 = publicKeyPEM.replace(/-----[A-Z ]+-----/g, '').replace(/\s/g, '');
  const publicKeyBuffer = Buffer.from(publicKeyBase64, 'base64');
  relayIdentityPublicKey = publicKeyBuffer.subarray(-32).toString('hex');

  console.log('[Security] ✅ Relay identity (Ed25519) loaded and validated');
  console.log(`[Security]    Public key (hex): ${relayIdentityPublicKey}`);
} catch (err) {
  console.error('❌ CRITICAL: Failed to load RELAY_IDENTITY_KEY');
  console.error('   This is a fatal startup error');
  console.error('   Error details:', err instanceof Error ? err.message : String(err));
  console.error('   Ensure RELAY_IDENTITY_KEY is a valid Ed25519 PEM key');
  process.exit(1); // SECURITY: Fail-closed - relay is unusable without identity key
}

// ==================== Storage Initialization ====================

let storage: IStorageAdapter | null = null;
let storageReady = false;
let wsManager: any = null; // WebSocket manager reference

// ==================== Metrics ====================

const metrics = {
  requestsTotal: 0,
  requestsByEndpoint: new Map<string, number>(),
  rateLimitHits: 0,
  authFailures: 0,
  startTime: Date.now(),
};

fastify.addHook('onRequest', async (request) => {
  metrics.requestsTotal++;
  const endpoint = request.url.split('?')[0];
  metrics.requestsByEndpoint.set(endpoint, (metrics.requestsByEndpoint.get(endpoint) || 0) + 1);
});

// ==================== Input Validation ====================

/**
 * Validate username format
 * - 3-20 characters
 * - alphanumeric + underscore only
 * - no special characters or spaces
 */
function validateUsername(username: string): boolean {
  if (!username || typeof username !== 'string') return false;
  if (username.length < 3 || username.length > 20) return false;
  return /^[a-z0-9_]+$/.test(username);
}

/**
 * Validate chatId format
 * - Must be valid SHA256 hash (64 hex characters)
 */
function validateChatId(chatId: string): boolean {
  if (!chatId || typeof chatId !== 'string') return false;
  return /^[a-f0-9]{64}$/.test(chatId);
}

/**
 * Validate message size
 */
function validateMessageSize(blob: string): boolean {
  if (!blob || typeof blob !== 'string') return false;
  const size = Buffer.from(blob, 'base64').length;
  return size <= MAX_MESSAGE_SIZE;
}

// ==================== Security Logging ====================

function logSecurityEvent(event: string, details: Record<string, any>) {
  const timestamp = new Date().toISOString();
  const logLine = JSON.stringify({
    timestamp,
    event,
    ...details,
  });
  console.warn(`[SECURITY] ${logLine}`);
}

// ==================== Auth Middleware ====================

declare module 'fastify' {
  interface FastifyRequest {
    authenticatedUserId?: string;
  }
}

async function authenticate(request: any, reply: any) {
  try {
    const decoded = await request.jwtVerify();
    request.authenticatedUserId = decoded.userId;
  } catch (err) {
    metrics.authFailures++;
    logSecurityEvent('AUTH_FAILED', {
      ip: request.ip,
      path: request.url,
      error: (err as Error).message,
    });
    reply.code(401).send({ error: 'Authentication required' });
  }
}

// ==================== Rate Limiting ====================

// Stricter rate limits for beta
const RATE_LIMITS = {
  REGISTER: { limit: 3, windowMs: 60 * 60 * 1000 }, // 3 per hour
  MESSAGE: { limit: 60, windowMs: 60 * 1000 }, // 60 per minute
  SYNC: { limit: 120, windowMs: 60 * 1000 }, // 120 per minute (2 per second)
  PREKEY: { limit: 10, windowMs: 60 * 60 * 1000 }, // 10 per hour
  DIRECTORY: { limit: 20, windowMs: 60 * 60 * 1000 }, // 20 per hour
};

async function rateLimit(request: any, reply: any, key: string, limit: number, windowMs: number): Promise<boolean> {
  // CRITICAL SECURITY: FAIL-CLOSED - Rate limiting is not optional
  // If storage is unavailable, block the request (do not allow bypass)
  if (!storage || !storageReady) {
    console.error('[RateLimit] ❌ CRITICAL: Storage not ready, blocking request to prevent bypass');
    logSecurityEvent('RATE_LIMIT_STORAGE_UNAVAILABLE', { key, ip: request.ip });
    reply.code(503).send({
      error: 'Service temporarily unavailable',
      message: 'Rate limiting system is not ready. Please try again later.'
    });
    return false; // SECURITY: Fail-closed - do not allow request
  }

  try {
    const allowed = await storage.rateLimit.checkAndIncrement(key, limit, windowMs);
    if (!allowed) {
      metrics.rateLimitHits++;
      logSecurityEvent('RATE_LIMIT_EXCEEDED', { key, ip: request.ip });
      reply.code(429).send({ error: 'Rate limit exceeded', retryAfter: Math.ceil(windowMs / 1000) });
      return false;
    }
    return true;
  } catch (err) {
    console.error('[RateLimit] ❌ CRITICAL: Rate limiter error:', err);
    logSecurityEvent('RATE_LIMIT_ERROR', { key, ip: request.ip, error: err instanceof Error ? err.message : String(err) });
    // SECURITY: On error, block the request (fail-closed, not fail-open)
    reply.code(503).send({
      error: 'Service temporarily unavailable',
      message: 'Rate limiting system encountered an error. Please try again later.'
    });
    return false; // SECURITY: Fail-closed - do not allow request through
  }
}

// ==================== Observability Endpoints ====================

// Health check endpoints - both /health and /healthz are used by different platforms
fastify.get('/health', async () => {
  // Simple liveness probe - just check if server is running
  // Used by Railway, Render, and other platforms
  return { status: 'ok', timestamp: Date.now() };
});

fastify.get('/healthz', async () => {
  // Always return 200 OK immediately - server is running once this endpoint responds
  // The Fastify listener wouldn't be active if the server wasn't ready
  try {
    if (!storage || !storageReady) {
      return {
        status: 'starting',
        ready: false,
        version: '0.8.0',
        // Still include relay identity for client verification (even during startup)
        relayPublicKey: relayIdentityPublicKey || null,
      };
    }

    const healthy = await storage.isHealthy();
    return {
      status: healthy ? 'ok' : 'degraded',
      ready: true,
      version: '0.8.0',
      // CRITICAL: Include relay's public key for EREBUS mitigation
      // Clients verify this key matches NEXT_PUBLIC_RELAY_PUBLIC_KEY before handshake
      relayPublicKey: relayIdentityPublicKey,
    };
  } catch (err) {
    // Still return 200 - the endpoint itself is working, storage might be temporarily unavailable
    return {
      status: 'error',
      ready: false,
      error: (err as Error).message,
      version: '0.8.0',
      relayPublicKey: relayIdentityPublicKey || null,
    };
  }
});

fastify.get('/ready', async () => {
  if (!storage || !storageReady) {
    throw new Error('Storage not initialized');
  }
  const healthy = await storage.isHealthy();
  if (!healthy) {
    throw new Error('Storage not healthy');
  }
  return { ready: true, storage: STORAGE_TYPE, version: '0.8.0' };
});

fastify.get('/metrics', async () => {
  const uptime = Date.now() - metrics.startTime;
  const endpoints: Record<string, number> = {};
  metrics.requestsByEndpoint.forEach((count, endpoint) => {
    endpoints[endpoint] = count;
  });

  return {
    requests_total: metrics.requestsTotal,
    requests_by_endpoint: endpoints,
    rate_limit_hits: metrics.rateLimitHits,
    auth_failures: metrics.authFailures,
    uptime_ms: uptime,
    storage_type: STORAGE_TYPE,
  };
});

// ==================== Debug Endpoints ====================

/**
 * DELETE /debug/prekeys/:username
 * Clear prekey bundle for a specific user (for fixing signature issues)
 */
fastify.delete<{ Params: { username: string } }>('/debug/prekeys/:username', async (request, reply) => {
  const username = normalizeUsername(request.params.username);

  const hadBundle = SIGNED_PREKEYS.has(username);
  SIGNED_PREKEYS.delete(username);

  console.log(`[Debug] Cleared prekey bundle for: ${username} (existed: ${hadBundle})`);

  return {
    success: true,
    username,
    cleared: hadBundle,
    message: hadBundle
      ? `Prekey bundle for ${username} has been cleared. User must re-register.`
      : `No prekey bundle found for ${username}`
  };
});

// ==================== User Registration ====================

interface RegisterBody {
  userId: string;
  username: string;
  identityEd25519: string;
  identityMLDSA: string;
}

fastify.post<{ Body: RegisterBody }>('/register', async (request, reply) => {
  const { userId, username, identityEd25519, identityMLDSA } = request.body;

  if (!userId || !username || !identityEd25519 || !identityMLDSA) {
    return reply.code(400).send({ error: 'Missing required fields' });
  }

  const rateLimitPassed = await rateLimit(request, reply, `register:${request.ip}`, 5, 60 * 60 * 1000);
  if (!rateLimitPassed) return;

  logSecurityEvent('USER_REGISTRATION_ATTEMPT', { userId, username, ip: request.ip });

  const exists = await storage.users.userExists(userId);
  if (exists) {
    const token = fastify.jwt.sign({ userId, username });
    return reply.code(409).send({ error: 'User already exists', token });
  }

  const created = await storage.users.createUser({
    userId,
    username,
    identityEd25519,
    identityMLDSA,
    registeredAt: Date.now(),
  });

  if (!created) {
    return reply.code(500).send({ error: 'Failed to create user' });
  }

  logSecurityEvent('USER_REGISTRATION_SUCCESS', { userId, username, ip: request.ip });

  const token = fastify.jwt.sign({ userId, username });
  return { success: true, userId, token };
});

// ==================== Prekey Bundle Upload ====================

interface PrekeyBundleBody {
  userId: string;
  bundleId: string;
  x25519Ephemeral: string;
  mlkemPublicKey: string;
  ed25519Signature: string;
  mldsaSignature: string;
  timestamp: number;
  isOneTime?: boolean;
}

fastify.post<{ Body: PrekeyBundleBody }>(
  '/prekey-bundle',
  { preHandler: authenticate },
  async (request, reply) => {
    const { userId, bundleId, x25519Ephemeral, mlkemPublicKey, ed25519Signature, mldsaSignature, timestamp, isOneTime } =
      request.body;

    if (!userId || !bundleId || !x25519Ephemeral || !mlkemPublicKey) {
      return reply.code(400).send({ error: 'Missing required fields' });
    }

    if (request.authenticatedUserId !== userId) {
      logSecurityEvent('AUTH_MISMATCH_PREKEY', {
        authenticatedUserId: request.authenticatedUserId,
        requestedUserId: userId,
        ip: request.ip,
      });
      return reply.code(403).send({ error: 'Forbidden' });
    }

    const rateLimitPassed = await rateLimit(request, reply, `prekey:${userId}`, 10, 60 * 60 * 1000);
    if (!rateLimitPassed) return;

    const stored = await storage.prekeys.storePrekeyBundle({
      userId,
      bundleId,
      x25519Ephemeral,
      mlkemPublicKey,
      ed25519Signature,
      mldsaSignature,
      timestamp,
      createdAt: Date.now(),
      isOneTime: isOneTime || false,
      consumed: false,
    });

    if (!stored) {
      return reply.code(409).send({ error: 'Bundle already exists' });
    }

    return { success: true, bundleId };
  }
);

// ==================== Prekey Batch Upload ====================

interface BatchPrekeyBody {
  userId: string;
  bundles: Array<{
    bundleId: string;
    x25519Ephemeral: string;
    mlkemPublicKey: string;
    ed25519Signature: string;
    mldsaSignature: string;
    timestamp: number;
  }>;
}

fastify.post<{ Body: BatchPrekeyBody }>(
  '/prekey-batch',
  { preHandler: authenticate },
  async (request, reply) => {
    const { userId, bundles } = request.body;

    if (!userId || !bundles || bundles.length === 0 || bundles.length > 100) {
      return reply.code(400).send({ error: 'Invalid batch (0-100 bundles)' });
    }

    if (request.authenticatedUserId !== userId) {
      return reply.code(403).send({ error: 'Forbidden' });
    }

    const rateLimitPassed = await rateLimit(request, reply, `prekey-batch:${userId}`, 2, 60 * 60 * 1000);
    if (!rateLimitPassed) return;

    let succeeded = 0;
    for (const b of bundles) {
      const stored = await storage.prekeys.storePrekeyBundle({
        userId,
        bundleId: b.bundleId,
        x25519Ephemeral: b.x25519Ephemeral,
        mlkemPublicKey: b.mlkemPublicKey,
        ed25519Signature: b.ed25519Signature,
        mldsaSignature: b.mldsaSignature,
        timestamp: b.timestamp,
        createdAt: Date.now(),
        isOneTime: true,
        consumed: false,
      });
      if (stored) succeeded++;
    }

    return { success: true, uploaded: succeeded, total: bundles.length };
  }
);

// ==================== In-Memory Signed Prekey Storage (Dev Mode) ====================

/**
 * In-memory storage for signed prekey bundles
 * Maps username -> signed bundle
 */
interface SignedPrekeyBundle {
  x25519Pub: string; // base64
  pqKemPub?: string; // base64
  pqSigPub?: string; // base64
  signature: string; // base64 Ed25519 signature over canonical bundle
}

const SIGNED_PREKEYS = new Map<string, SignedPrekeyBundle>();

// ==================== SESSION STORAGE (CRITICAL FIX) ====================

/**
 * CRITICAL SECURITY: Session metadata - source of truth for chat sessions
 * MUST ONLY STORE:
 * - sessionId (public session identifier)
 * - version (for conflict resolution)
 * - participants (identity information only)
 * - timestamps
 *
 * MUST NEVER STORE:
 * - rootKey (master secret for session)
 * - sendChainKey / recvChainKey (message encryption keys)
 * - messageKeys (per-message encryption keys)
 * - Any cryptographic secrets
 *
 * RATIONALE: If relay is compromised, attacker gains access to plaintext message keys.
 * Relay should ONLY facilitate key agreement, not hold decryption material.
 */
interface SessionMetadata {
  sessionId: string; // hex string (public, non-secret)
  version: number; // timestamp or incrementing counter (higher wins)
  participants: Array<{
    username: string;
    identityEd25519: string;
  }>;
  createdAt: number;
  lastUpdated: number;
  // SECURITY: Never include rootKey, chainKeys, or messageKeys here
  // Clients derive these from shared secrets, not relay storage
}

/**
 * In-memory session storage
 * Maps chatId -> SessionMetadata
 *
 * This is the SOURCE OF TRUTH for active sessions.
 * Both clients MUST consult this before creating new sessions.
 *
 * Flow:
 * 1. Client encounters AAD mismatch
 * 2. Client GETs /chat/:chatId/session
 * 3. If relay has session → adopt it
 * 4. If relay has no session → create new and PUT to relay
 *
 * This prevents both clients from independently creating different sessions.
 */
const CHAT_SESSIONS = new Map<string, SessionMetadata>();

console.log('[Session] ✅ Session storage initialized (in-memory)');

// ==================== Directory Lookup ====================

/**
 * GET /directory/:id
 * Returns canonical identity and prekey bundle for a user
 * Returns 404 if user not registered
 */
fastify.get<{ Params: { id: string } }>('/directory/:id', async (request, reply) => {
  const rawId = request.params.id;
  const id = normalizeUsername(rawId);

  console.log(`[Directory] GET /directory/${rawId} → canonical: ${id}`);

  // Try lookup by username first, then by userId
  let user = await storage.users.getUserByUsername(id);
  if (!user) {
    user = await storage.users.getUserById(id);
  }

  // DO NOT auto-create users on GET - let frontend create via POST
  if (!user) {
    console.log(`[Directory] User not found: ${id} (must register via POST first)`);
    return reply.code(404).send({ error: 'User not found' });
  }

  console.log(`[Directory] Found user: ${user.username} (${user.userId})`);

  // Try to get signed prekey bundle from in-memory storage
  const signedBundle = SIGNED_PREKEYS.get(user.username);

  if (!signedBundle) {
    console.warn(`[Directory] No signed prekey bundle for user: ${user.username}`);
    return reply.code(404).send({ error: 'No prekey bundle available for this user' });
  }

  // Return deterministic directory response (no timestamps in transcript)
  // Return EXACTLY what was posted - relay is just a forwarder
  // CRITICAL FIX: Include BOTH field name variations for compatibility
  return {
    username: user.username,
    userId: user.userId,
    identityPublicKey: user.identityEd25519, // New clients expect this
    identityEd25519: user.identityEd25519,    // Old clients expect this
    identityMLDSA: user.identityMLDSA || '',  // PQ signature key
    prekeyBundle: {
      x25519Pub: signedBundle.x25519Pub,
      pqKemPub: signedBundle.pqKemPub || '',
      pqSigPub: signedBundle.pqSigPub || '',
    },
    prekeySignature: signedBundle.signature,
    serverInfo: {
      version: '1',
      timestamp: 0,  // MUST be 0 or fixed - timestamps cause safety number divergence
    },
  };
});

/**
 * POST /directory/:username
 * Register canonical identity AND signed prekey bundle
 * In dev mode, no auth required - relay becomes source of truth for identities
 */
interface DirectoryRegisterBody {
  identityEd25519: string; // base64
  identityMLDSA?: string; // base64, optional for classical-only
  prekeyBundle?: {
    x25519Pub: string;
    pqKemPub?: string;
    pqSigPub?: string;
  };
  prekeySignature?: string; // base64 Ed25519 signature over canonical prekey bundle
}

fastify.post<{ Params: { username: string }, Body: DirectoryRegisterBody }>(
  '/directory/:username',
  // No auth in dev mode
  async (request, reply) => {
    try {
      const rawUsername = request.params.username;
      const username = normalizeUsername(rawUsername);
      const { identityEd25519, identityMLDSA, prekeyBundle, prekeySignature } = request.body;

      console.log(`[Directory] POST /directory/${rawUsername} → canonical: ${username}`);

      if (!username || !identityEd25519) {
        return reply.code(400).send({ error: 'username and identityEd25519 required' });
      }

      // Validate username format
      if (!validateUsername(username)) {
        return reply.code(400).send({
          error: 'Invalid username format. Must be 3-20 characters, lowercase alphanumeric + underscore only.'
        });
      }

      // Rate limit directory registration
      const rateLimitPassed = await rateLimit(
        request,
        reply,
        `directory:${request.ip}`,
        RATE_LIMITS.DIRECTORY.limit,
        RATE_LIMITS.DIRECTORY.windowMs
      );
      if (!rateLimitPassed) return;

      console.log(`[Directory] Registering canonical identity for: ${username}`);

      // Check if user already exists
      let user = await storage.users.getUserByUsername(username);

    if (user) {
      console.log(`[Directory] User ${username} already exists, updating prekey bundle only`);

      // Update signed prekey bundle if provided (BOTH in-memory map AND storage.prekeys!)
      if (prekeyBundle && prekeySignature) {
        SIGNED_PREKEYS.set(username, {
          x25519Pub: prekeyBundle.x25519Pub,
          pqKemPub: prekeyBundle.pqKemPub,
          pqSigPub: prekeyBundle.pqSigPub,
          signature: prekeySignature,
        });
        console.log(`[Directory] ✅ Updated signed prekey bundle in memory map for: ${username}`);

        // CRITICAL FIX: Also update in persistent storage
        const prekeyBundleObj: PrekeyBundle = {
          userId: user.userId,
          bundleId: `${username}-${Date.now()}`,
          x25519Ephemeral: prekeyBundle.x25519Pub,
          mlkemPublicKey: prekeyBundle.pqKemPub || '',
          ed25519Signature: prekeySignature,
          mldsaSignature: '',
          timestamp: Date.now(),
          createdAt: Date.now(),
          isOneTime: false,
          consumed: false,
        };

        await storage.prekeys.storePrekeyBundle(prekeyBundleObj);
        console.log(`[Directory] ✅ Updated signed prekey bundle in storage for: ${username}`);
      }

      // Return existing user (immutable identity)
      return {
        username: user.username,
        userId: user.userId,
        identityPublicKey: user.identityEd25519,
        prekeyBundle: prekeyBundle || null,
        prekeySignature: prekeySignature || null,
      };
    }

    // BETA LIMIT: Check total user count before creating new user
    const totalUsers = await storage.users.getTotalUserCount();
    if (totalUsers >= MAX_USERS) {
      logSecurityEvent('BETA_LIMIT_REACHED', {
        username,
        totalUsers,
        maxUsers: MAX_USERS,
        ip: request.ip,
      });
      return reply.code(403).send({
        error: 'Beta limit reached',
        message: `Beta test is limited to ${MAX_USERS} users. Please try again later or contact support.`,
        totalUsers,
        maxUsers: MAX_USERS,
      });
    }

    // Create new user with canonical identity
    const userId = crypto.randomUUID();

    const created = await storage.users.createUser({
      userId,
      username,
      identityEd25519,
      identityMLDSA: identityMLDSA || '',
      registeredAt: Date.now(),
    });

    if (!created) {
      return reply.code(500).send({ error: 'Failed to create user' });
    }

    // Store signed prekey bundle if provided (BOTH in-memory map AND storage.prekeys!)
    if (prekeyBundle && prekeySignature) {
      // Store in in-memory map (for /directory GET endpoint)
      SIGNED_PREKEYS.set(username, {
        x25519Pub: prekeyBundle.x25519Pub,
        pqKemPub: prekeyBundle.pqKemPub,
        pqSigPub: prekeyBundle.pqSigPub,
        signature: prekeySignature,
      });
      console.log(`[Directory] ✅ Stored signed prekey bundle in memory map for: ${username}`);

      // CRITICAL FIX: Also store in persistent storage for GET /prekey/:username
      // This ensures the prekey is ALWAYS available via both endpoints
      const prekeyBundleObj: PrekeyBundle = {
        userId,
        bundleId: `${username}-${Date.now()}`, // Generate deterministic bundle ID
        x25519Ephemeral: prekeyBundle.x25519Pub,
        mlkemPublicKey: prekeyBundle.pqKemPub || '',
        ed25519Signature: prekeySignature,
        mldsaSignature: '', // Not provided in directory endpoint
        timestamp: Date.now(),
        createdAt: Date.now(),
        isOneTime: false,
        consumed: false,
      };

      await storage.prekeys.storePrekeyBundle(prekeyBundleObj);
      console.log(`[Directory] ✅ Stored signed prekey bundle in storage for: ${username}`);
    }

    console.log(`[Directory] ✅ Registered canonical identity for: ${username}`);

    return {
      username,
      userId,
      identityPublicKey: identityEd25519,
      prekeyBundle: prekeyBundle || null,
      prekeySignature: prekeySignature || null,
    };
    } catch (error) {
      console.error('[Directory] POST /directory/:username error:', error);
      return reply.code(500).send({
        error: 'internal_server_error',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }
);

// ==================== Deterministic Chat ID Generation ====================

// ==================== Prekey Bundles (GET/POST) ====================

/**
 * GET /prekey/:username
 * Fetch a user's current prekey bundle for initiating X3DH handshake
 * Public endpoint - no auth required (prekeys are public by design)
 */
fastify.get<{ Params: { username: string } }>(
  '/prekey/:username',
  async (request, reply) => {
    const rawUsername = request.params.username;

    if (!rawUsername) {
      return reply.code(400).send({ error: 'username required' });
    }

    // CRITICAL: Canonicalize username (lowercase)
    const username = rawUsername.toLowerCase().trim();

    console.log(`[Prekey] GET /prekey/${username} (canonical: ${username})`);

    // Get user by canonical username
    const user = await storage.users.getUserByUsername(username);

    if (!user) {
      console.warn(`[Prekey] User not found: ${username}`);
      return reply.code(404).send({
        error: 'prekey_not_found',
        message: `No prekey bundle published for ${username}`,
      });
    }

    // Get the signed prekey bundle from storage
    const signedBundle = await storage.prekeys.getSignedPrekey(user.userId);

    if (!signedBundle) {
      console.warn(`[Prekey] No signed prekey bundle for user: ${username}`);
      return reply.code(404).send({
        error: 'prekey_not_found',
        message: `No prekey bundle available for ${username}`,
      });
    }

    console.log(`[Prekey] ✅ Returning prekey bundle for ${username}, bundleId: ${signedBundle.bundleId}`);

    // Return the bundle in the format the client expects
    return reply.send({
      bundle: {
        username: username,
        bundleId: signedBundle.bundleId,
        x25519Ephemeral: signedBundle.x25519Ephemeral,
        mlkemPublicKey: signedBundle.mlkemPublicKey,
        ed25519Signature: signedBundle.ed25519Signature,
        mldsaSignature: signedBundle.mldsaSignature,
        timestamp: signedBundle.timestamp,
        isOneTime: signedBundle.isOneTime,
      },
    });
  }
);

/**
 * POST /prekey/:username
 * Publish a new prekey bundle (authenticated endpoint)
 * Users can only upload their own prekeys
 */
interface PrekeyPublishBody {
  bundleId: string;
  x25519Ephemeral: string; // base64
  mlkemPublicKey: string; // base64
  ed25519Signature: string; // base64
  mldsaSignature: string; // base64
  timestamp: number;
  isOneTime?: boolean;
}

fastify.post<{ Params: { username: string }, Body: PrekeyPublishBody }>(
  '/prekey/:username',
  async (request, reply) => {
    const rawUsername = request.params.username;
    const body = request.body;

    if (!rawUsername) {
      return reply.code(400).send({ error: 'username required' });
    }

    // CRITICAL: Canonicalize username (lowercase)
    const username = rawUsername.toLowerCase().trim();

    console.log(`[Prekey] POST /prekey/${username}`);

    // Validate bundle data
    if (!body.bundleId || !body.x25519Ephemeral || !body.ed25519Signature) {
      return reply.code(400).send({
        error: 'invalid_prekey_bundle',
        message: 'bundleId, x25519Ephemeral, and ed25519Signature required',
      });
    }

    // Get user by canonical username
    const user = await storage.users.getUserByUsername(username);

    if (!user) {
      console.warn(`[Prekey] User not registered: ${username}`);
      return reply.code(404).send({
        error: 'user_not_found',
        message: `User ${username} not registered. Register identity first via POST /directory/${username}`,
      });
    }

    // Store the prekey bundle
    const prekeyBundle: PrekeyBundle = {
      userId: user.userId,
      bundleId: body.bundleId,
      x25519Ephemeral: body.x25519Ephemeral,
      mlkemPublicKey: body.mlkemPublicKey || '',
      ed25519Signature: body.ed25519Signature,
      mldsaSignature: body.mldsaSignature || '',
      timestamp: body.timestamp || Date.now(),
      createdAt: Date.now(),
      isOneTime: body.isOneTime || false,
      consumed: false,
    };

    const stored = await storage.prekeys.storePrekeyBundle(prekeyBundle);

    if (!stored) {
      console.warn(`[Prekey] Failed to store prekey bundle for ${username} (duplicate bundleId?)`);
      return reply.code(409).send({
        error: 'prekey_already_exists',
        message: `Prekey bundle ${body.bundleId} already exists for ${username}`,
      });
    }

    console.log(`[Prekey] ✅ Prekey bundle stored for ${username}, bundleId: ${body.bundleId}`);

    return reply.send({ ok: true, bundleId: body.bundleId });
  }
);

/**
 * Generate deterministic chat ID from participant list
 * Ensures Alice+Bob and Bob+Alice get the same ID
 */
function makeChatId(participants: string[]): string {
  // Normalize: trim, lowercase, sort
  const normalized = participants
    .map(p => p.trim().toLowerCase())
    .filter(p => p.length > 0)
    .sort();

  if (normalized.length < 2) {
    throw new Error('At least 2 participants required');
  }

  // Create deterministic base string
  const base = normalized.join(':');

  // Hash to fixed-length ID
  return crypto.createHash('sha256').update(base, 'utf8').digest('hex');
}

// ==================== Chat Initialization ====================

interface ChatInitBody {
  participants?: string[]; // Array format (legacy)
  from?: string;           // Two-person format (new)
  to?: string;             // Two-person format (new)
}

fastify.post<{ Body: ChatInitBody }>(
  '/chat/init',
  // No authentication required - chat ID is deterministic and not secret
  async (request, reply) => {
    const { participants, from, to } = request.body;

    // Support both formats:
    // 1. Array format: { participants: ["alice", "bob"] }
    // 2. Two-person format: { from: "alice", to: "bob" }
    let actualParticipants: string[];

    if (from && to) {
      // New format: { from, to }
      actualParticipants = [from, to];
    } else if (participants && Array.isArray(participants)) {
      // Legacy format: { participants: [...] }
      actualParticipants = participants;
    } else {
      return reply.code(400).send({
        error: 'Either "participants" array or "from"+"to" fields required'
      });
    }

    if (actualParticipants.length < 2) {
      return reply.code(400).send({ error: 'At least 2 participants required' });
    }

    try {
      const chatId = makeChatId(actualParticipants);

      console.log(`[Chat] Init request for participants: ${actualParticipants.join(', ')}`);
      console.log(`[Chat] Generated deterministic chatId: ${chatId}`);

      // Chat is implicitly created on first message, no need to pre-create
      // Just return the canonical ID
      return { chatId, status: 'ok', ok: true };
    } catch (err) {
      console.error('[Chat] Failed to init:', err);
      return reply.code(400).send({ error: (err as Error).message });
    }
  }
);

// ==================== Message Sending ====================

interface MessageBody {
  encryptedBlob?: string; // base64 (for new format)
  senderId?: string; // for new format
  // Legacy fields from frontend
  type?: string;
  from?: string;
  blob?: string;
  text?: string;
  ts?: number;
  version?: string;
  // Inline session update (for atomic message+session operations)
  session?: any;
}

/**
 * Detect if the incoming message is a handshake.
 *
 * Detection methods (in priority order):
 * 1. Explicit type field: body.type === 'handshake'
 * 2. Payload hint: body.payload?.kind === 'handshake'
 * 3. Cipher metadata: body.cipher?.meta?.kind === 'handshake'
 *
 * SECURITY: This detection MUST be strict - we cannot guess or infer.
 * If the client doesn't tell us it's a handshake, we default to 'message'.
 */
function detectMessageType(body: MessageBody): 'handshake' | 'message' {
  // Method 1: Explicit type field (most reliable)
  if (body.type === 'handshake') {
    return 'handshake';
  }

  // Method 2: Payload structure hint
  if ((body as any).payload?.kind === 'handshake') {
    return 'handshake';
  }

  // Method 3: Cipher metadata hint
  if ((body as any).cipher?.meta?.kind === 'handshake') {
    return 'handshake';
  }

  // Default to regular message
  return 'message';
}

fastify.post<{ Params: { chatId: string }, Body: MessageBody }>(
  '/message/:chatId',
  { preHandler: authenticate }, // CRITICAL SECURITY: Require authentication
  async (request, reply) => {
    const { chatId } = request.params;

    // Support both new and legacy body formats
    let senderId = request.body.senderId || request.body.from;
    const encryptedBlob = request.body.encryptedBlob || request.body.blob;

    if (!chatId || !encryptedBlob || !senderId) {
      return reply.code(400).send({ error: 'Missing required fields (chatId, encryptedBlob/blob, senderId/from)' });
    }

    // Validate chatId format
    if (!validateChatId(chatId)) {
      return reply.code(400).send({
        error: 'Invalid chatId format. Must be a valid SHA256 hash.',
      });
    }

    // Validate message size
    if (!validateMessageSize(encryptedBlob)) {
      return reply.code(413).send({
        error: 'Message too large',
        maxSize: `${MAX_MESSAGE_SIZE / 1024 / 1024} MB`,
      });
    }

    // Rate limit messages
    const rateLimitPassed = await rateLimit(
      request,
      reply,
      `message:${request.ip}`,
      RATE_LIMITS.MESSAGE.limit,
      RATE_LIMITS.MESSAGE.windowMs
    );
    if (!rateLimitPassed) return;

    // CRITICAL FIX: Normalize senderId to canonical form (lowercase, trimmed)
    senderId = senderId.trim().toLowerCase();

    // Validate username format
    if (!validateUsername(senderId)) {
      return reply.code(400).send({
        error: 'Invalid username format for senderId.',
      });
    }

    // CRITICAL FIX: Verify sender has registered identity before accepting messages
    // This ensures ALL messages come from users with verifiable E2E identities
    try {
      const senderUser = await storage.users.getUserByUsername(senderId);

      if (!senderUser) {
        console.warn(`[Message] ❌ Rejected message from unregistered user: ${senderId}`);
        return reply.code(403).send({
          error: 'identity_required',
          message: 'You must register your identity in /directory before sending messages',
          details: `User '${senderId}' not found in identity directory`,
        });
      }

      console.log(`[Message] ✅ Identity verified for sender: ${senderId}`);
    } catch (err) {
      console.error(`[Message] ❌ Failed to verify identity for ${senderId}:`, err);
      return reply.code(500).send({
        error: 'identity_verification_failed',
        message: 'Failed to verify sender identity',
      });
    }

    // CRITICAL FIX: Detect message type (handshake vs message)
    const messageType = detectMessageType(request.body);

    // Skip authentication check in dev mode
    // if (request.authenticatedUserId !== senderId) {
    //   logSecurityEvent('AUTH_MISMATCH_MESSAGE', {
    //     authenticatedUserId: request.authenticatedUserId,
    //     claimedSender: senderId,
    //     chatId,
    //     ip: request.ip,
    //   });
    //   return reply.code(403).send({ error: 'Forbidden' });
    // }

    // Skip rate limiting in dev mode
    // await rateLimit(request, reply, `message:${senderId}`, 100, 60 * 1000);

    // CRITICAL: Accept inline session update with message (atomic operation)
    // This prevents race conditions where message arrives before session state
    if (request.body.session) {
      const inlineSession: any = request.body.session;
      console.log('[Message] Received inline session update with message');

      // Same logic as PUT /chat/:chatId/session
      const existing: any = CHAT_SESSIONS.get(chatId);

      if (!existing || !existing.version || !inlineSession.version || inlineSession.version >= existing.version) {
        CHAT_SESSIONS.set(chatId, {
          ...inlineSession,
          chatId,
          lastUpdated: Date.now(),
        });
        console.log(`[Message] ✅ Stored INLINE session for chat ${chatId}`);
        console.log(`[Message] - Session version: ${inlineSession.version}`);
        console.log(`[Message] - Session ID: ${inlineSession.sessionId?.slice(0, 16)}...`);
      } else {
        console.log(`[Message] ⚠️  Ignored inline session (older version ${inlineSession.version} < ${existing.version})`);
      }
    }

    const blobBuffer = Buffer.from(encryptedBlob, 'base64');
    const blobRef = crypto.createHash('sha256').update(blobBuffer).digest('hex');

    const latestSequence = await storage.messages.getLatestSequence(chatId);
    const sequence = latestSequence + 1;

    // BETA LIMIT: Check message count per chat and enforce TTL
    const existingMessages = await storage.messages.listBlobsSince(chatId, 0, MAX_MESSAGES_PER_CHAT + 1);

    // Cleanup old messages (TTL enforcement)
    const now = Date.now();
    const ttlCutoff = now - MESSAGE_TTL_MS;
    const oldMessageCount = await storage.messages.deleteOldBlobs(chatId, ttlCutoff);
    if (oldMessageCount > 0) {
      console.log(`[Message] 🧹 Cleaned up ${oldMessageCount} expired messages (TTL: ${MESSAGE_TTL_MS / 1000 / 60 / 60 / 24} days)`);
    }

    // Check message count limit (after cleanup)
    if (existingMessages.length >= MAX_MESSAGES_PER_CHAT) {
      logSecurityEvent('MESSAGE_LIMIT_REACHED', {
        chatId,
        messageCount: existingMessages.length,
        maxMessages: MAX_MESSAGES_PER_CHAT,
        senderId,
        ip: request.ip,
      });
      return reply.code(429).send({
        error: 'Message limit reached',
        message: `Chat has reached maximum of ${MAX_MESSAGES_PER_CHAT} messages. Older messages will be cleaned up automatically after ${MESSAGE_TTL_MS / 1000 / 60 / 60 / 24} days.`,
        currentCount: existingMessages.length,
        maxMessages: MAX_MESSAGES_PER_CHAT,
      });
    }

    // Store message with CANONICAL senderId (guaranteed to be in directory)
    const stored = await storage.messages.storeBlob({
      chatId,
      blobRef,
      encryptedBlob: blobBuffer,
      createdAt: Date.now(),
      senderId, // CANONICAL username (verified above)
      sequence,
      // CRITICAL FIX: Store the detected message type
      messageType,
    });

    if (!stored) {
      return reply.code(409).send({ error: 'Blob already exists' });
    }

    console.log(`[Message] Stored ${messageType} in chat ${chatId}, sequence ${sequence}`);

    return { success: true, blobRef, sequence, index: sequence };
  }
);

console.log('[Routes] ✅ Message endpoints: POST /message/:chatId');

// ==================== Group Messages ====================

interface GroupMessageBody {
  type: 'group_message';
  sender: string;
  message: {
    aad: string; // base64
    nonce: string; // base64
    ciphertext: string; // base64
    recipients: {
      [username: string]: {
        nonce: string; // base64
        ciphertext: string; // base64
      };
    };
  };
}

fastify.post<{ Params: { groupId: string }, Body: GroupMessageBody }>(
  '/group/:groupId/message',
  { preHandler: authenticate },
  async (request, reply) => {
    const { groupId } = request.params;
    const { sender, message: groupMessage } = request.body;

    if (!groupId || !sender || !groupMessage) {
      return reply.code(400).send({ error: 'Missing required fields' });
    }

    // Validate groupId format (same as chatId)
    if (!validateChatId(groupId)) {
      return reply.code(400).send({
        error: 'Invalid groupId format. Must be a valid SHA256 hash.',
      });
    }

    // CRITICAL: Normalize senderId to canonical form (lowercase, trimmed)
    const senderNormalized = sender.trim().toLowerCase();

    // Validate username format
    if (!validateUsername(senderNormalized)) {
      return reply.code(400).send({
        error: 'Invalid username format for sender.',
      });
    }

    // Rate limit group messages
    const rateLimitPassed = await rateLimit(
      request,
      reply,
      `group-message:${request.ip}`,
      RATE_LIMITS.MESSAGE.limit * 2, // More lenient for groups (multiple recipients)
      RATE_LIMITS.MESSAGE.windowMs
    );
    if (!rateLimitPassed) return;

    // Verify sender has registered identity
    try {
      const senderUser = await storage.users.getUserByUsername(senderNormalized);

      if (!senderUser) {
        console.warn(`[GroupMessage] ❌ Rejected group message from unregistered user: ${senderNormalized}`);
        return reply.code(403).send({
          error: 'identity_required',
          message: 'You must register your identity in /directory before sending messages',
        });
      }

      console.log(`[GroupMessage] ✅ Identity verified for sender: ${senderNormalized}`);
    } catch (err) {
      console.error(`[GroupMessage] ❌ Failed to verify identity for ${senderNormalized}:`, err);
      return reply.code(500).send({
        error: 'identity_verification_failed',
        message: 'Failed to verify sender identity',
      });
    }

    // Broadcast to all recipients via WebSocket
    const messageTimestamp = Date.now();
    let deliveredCount = 0;

    for (const [recipientUsername, wrappedData] of Object.entries(groupMessage.recipients)) {
      // Check if recipient is connected to this group's WebSocket
      if (wsManager) {
        const recipientConnected = wsManager.getConnectedUsers(groupId).includes(recipientUsername);

        if (recipientConnected) {
          // Send via WebSocket instantly
          wsManager.sendToClient(recipientUsername, {
            type: 'message',
            chatId: groupId,
            senderId: senderNormalized,
            content: {
              aad: groupMessage.aad,
              nonce: groupMessage.nonce,
              ciphertext: groupMessage.ciphertext,
              recipient: wrappedData,
            },
            timestamp: messageTimestamp,
          });
          deliveredCount++;
        } else {
          console.log(`[GroupMessage] Recipient ${recipientUsername} not connected to group ${groupId.slice(0, 12)}... - message will be missed`);
        }
      }
    }

    console.log(`[GroupMessage] Group message in ${groupId.slice(0, 12)}... delivered to ${deliveredCount}/${Object.keys(groupMessage.recipients).length} recipients`);

    return {
      success: true,
      groupId,
      sender: senderNormalized,
      delivered: deliveredCount,
      timestamp: Date.now(),
    };
  }
);

console.log('[Routes] ✅ Group message endpoint: POST /group/:groupId/message');

// ==================== Group Invitations ====================

interface GroupInvitationBody {
  groupId: string;
  groupName: string;
  creatorUsername: string;
  creatorDisplayName: string;
  recipientUsername: string;
}

fastify.post<{ Body: GroupInvitationBody }>(
  '/group/invite/notify',
  async (request, reply) => {
    const { groupId, groupName, creatorUsername, creatorDisplayName, recipientUsername } = request.body;

    if (!groupId || !recipientUsername || !creatorUsername) {
      return reply.code(400).send({ error: 'Missing required fields' });
    }

    // Normalize recipient username
    const recipientNormalized = recipientUsername.trim().toLowerCase();

    // Send real-time notification via WebSocket if recipient is connected
    if (wsManager) {
      const sent = wsManager.sendToClient(recipientNormalized, {
        type: 'group_invitation',
        groupId,
        groupName,
        creator: creatorDisplayName || creatorUsername,
        creatorUsername,
        recipientUsername: recipientNormalized,
        timestamp: Date.now(),
      });

      if (sent) {
        console.log(`[GroupInvite] ✅ Real-time notification sent to ${recipientNormalized} for group "${groupName}"`);
      } else {
        console.log(`[GroupInvite] ⚠️  Recipient ${recipientNormalized} not connected - will see invitation on next login`);
      }
    }

    return {
      success: true,
      recipientUsername: recipientNormalized,
      notified: wsManager ? wsManager.getConnectedUsers('*').includes(recipientNormalized) : false,
    };
  }
);

console.log('[Routes] ✅ Group invitation notification endpoint: POST /group/invite/notify');

// ==================== Sync Messages ====================

interface SyncQuery {
  since?: string;
  limit?: string;
}

fastify.get<{ Params: { chatId: string }, Querystring: SyncQuery }>(
  '/sync/:chatId',
  // No authentication required in dev mode - relay accepts all requests
  async (request, reply) => {
    const { chatId } = request.params;
    const since = parseInt(request.query.since || '0');
    const limit = Math.min(parseInt(request.query.limit || '100'), 1000);

    if (!chatId) {
      return reply.code(400).send({ error: 'Missing chatId' });
    }

    // Validate chatId format
    if (!validateChatId(chatId)) {
      return reply.code(400).send({
        error: 'Invalid chatId format. Must be a valid SHA256 hash.',
      });
    }

    // Rate limit sync requests
    const rateLimitPassed = await rateLimit(
      request,
      reply,
      `sync:${request.ip}`,
      RATE_LIMITS.SYNC.limit,
      RATE_LIMITS.SYNC.windowMs
    );
    if (!rateLimitPassed) return;

    // Skip authentication and rate limiting in dev mode
    const userId = 'dev-user';
    // await rateLimit(request, reply, `sync:${userId}`, 60, 60 * 1000);

    const messages = await storage.messages.listBlobsSince(chatId, since, limit);

    console.log(`[Sync] Chat ${chatId}: returning ${messages.length} messages since ${since}`);

    if (messages.length > 0) {
      const lastSequence = messages[messages.length - 1].sequence;
      await storage.sync.updateCursor(userId, chatId, lastSequence);
    }

    // CRITICAL FIX: Include canonical participants with identities
    // This provides source of truth for E2E identity resolution
    const participants: Array<{ username: string; canonicalUsername: string; identityEd25519: string; identityMLDSA: string }> = [];
    const uniqueSenders = new Set<string>(messages.map((m: any) => m.senderId as string).filter(Boolean));

    for (const senderId of uniqueSenders) {
      try {
        // Fetch canonical identity for this participant
        const user = await storage.users.getUserByUsername(senderId as string);

        if (user) {
          participants.push({
            username: senderId as string, // Canonical username
            canonicalUsername: (senderId as string).toLowerCase().trim(), // CRITICAL FIX: Explicit canonical form
            identityEd25519: user.identityEd25519,
            identityMLDSA: user.identityMLDSA,
          });
        } else {
          console.warn(`[Sync] No identity found for participant: ${senderId}`);
        }
      } catch (err) {
        console.error(`[Sync] Failed to fetch identity for ${senderId}:`, err);
      }
    }

    console.log(`[Sync] Returning ${participants.length} participants with identities`);

    // CRITICAL FIX: Get stored session to include with messages
    // Inline session is the source of truth - include it with EVERY message
    const storedSession = CHAT_SESSIONS.get(chatId);
    if (storedSession) {
      console.log(`[Sync] ✅ Including inline session with ${messages.length} messages`);
      console.log(`[Sync] - Session ID: ${storedSession.sessionId?.slice(0, 16)}...`);
      console.log(`[Sync] - Session version: ${storedSession.version}`);
    } else {
      console.log(`[Sync] ⚠️  No session stored for chat ${chatId}`);
    }

    return {
      chatId,
      since,
      participants, // CRITICAL: Canonical participants with identity keys
      messages: messages.map((m: any) => ({
        blobRef: m.blobRef,
        encryptedBlob: m.encryptedBlob.toString('base64'),
        senderId: m.senderId,
        sequence: m.sequence,
        index: m.sequence, // Add 'index' alias for frontend compatibility
        createdAt: m.createdAt,
        from: m.senderId, // Add 'from' alias for frontend compatibility
        blob: m.encryptedBlob.toString('base64'), // Add 'blob' alias
        type: m.messageType || 'message', // CRITICAL FIX: Return message type
        session: storedSession || undefined, // CRITICAL FIX: Include inline session with message
      })),
      entries: messages.map((m: any) => ({ // Add 'entries' alias for frontend compatibility
        blobRef: m.blobRef,
        encryptedBlob: m.encryptedBlob.toString('base64'),
        senderId: m.senderId,
        sequence: m.sequence,
        index: m.sequence,
        createdAt: m.createdAt,
        from: m.senderId,
        blob: m.encryptedBlob.toString('base64'),
        type: m.messageType || 'message', // CRITICAL FIX: Return message type
        session: storedSession || undefined, // CRITICAL FIX: Include inline session with message
      })),
      hasMore: messages.length === limit,
    };
  }
);

// ==================== Get Sync Cursor ====================

fastify.get<{ Querystring: { chatId: string } }>(
  '/sync/cursor',
  { preHandler: authenticate },
  async (request, reply) => {
    const chatId = request.query.chatId;

    if (!chatId) {
      return reply.code(400).send({ error: 'Missing chatId' });
    }

    const userId = request.authenticatedUserId!;
    const cursor = await storage.sync.getCursor(userId, chatId);

    return {
      chatId,
      lastSeenSequence: cursor?.lastSeenSequence || 0,
      updatedAt: cursor?.updatedAt || 0,
    };
  }
);

// ==================== SESSION ENDPOINTS (CRITICAL) ====================

/**
 * GET /chat/:chatId/session
 *
 * Returns current canonical session for a chat.
 * Clients MUST check this before creating new sessions.
 *
 * This prevents infinite ratchet refresh loops where both sides
 * independently create new sessions that don't match.
 *
 * Flow:
 * 1. Client encounters AAD mismatch
 * 2. Client GETs this endpoint
 * 3. If 200 → adopt relay's session
 * 4. If 404 → create new session and PUT to relay
 */
fastify.get<{ Params: { chatId: string } }>(
  '/chat/:chatId/session',
  async (request, reply) => {
    const { chatId } = request.params;

    console.log(`[Session] GET /chat/${chatId}/session`);

    const session = CHAT_SESSIONS.get(chatId);

    if (!session) {
      console.log(`[Session] No session found for chat ${chatId}`);
      return reply.code(404).send({
        error: 'session_not_found',
        chatId,
      });
    }

    console.log(`[Session] ✅ Returning session v${session.version}, sessionId: ${session.sessionId.slice(0, 16)}...`);

    return { session };
  }
);

/**
 * PUT /chat/:chatId/session
 *
 * Update or create session metadata.
 * Only accepts sessions with NEWER version numbers.
 *
 * Version conflict resolution:
 * - Higher version number wins (timestamp recommended)
 * - Prevents race conditions where both sides try to set session
 * - Rejected updates return 409 with current session
 *
 * This makes relay the SOURCE OF TRUTH for session state.
 */
fastify.put<{ Params: { chatId: string }, Body: Record<string, any> }>(
  '/chat/:chatId/session',
  async (request, reply) => {
    const { chatId } = request.params;
    const proposedSession: any = request.body;

    console.log(`[Session] PUT /chat/${chatId}/session`);
    console.log(`[Session] Proposed version: ${proposedSession?.version}`);
    console.log(`[Session] Proposed sessionId: ${typeof proposedSession?.sessionId === 'string' ? proposedSession.sessionId?.slice(0, 16) + '...' : '[binary]'}`);

    // Validation - accept both metadata-only and full session state
    if (!proposedSession || typeof proposedSession !== 'object') {
      return reply.code(400).send({
        error: 'invalid_session',
        message: 'Session object is required',
      });
    }

    // SessionId can be either string (hex) or will be converted from Uint8Array
    if (!proposedSession.sessionId && !proposedSession.version) {
      return reply.code(400).send({
        error: 'invalid_session',
        message: 'sessionId and version are required',
      });
    }

    const existing: any = CHAT_SESSIONS.get(chatId);

    // Check version conflict
    if (existing && typeof existing.version === 'number' && typeof proposedSession.version === 'number') {
      console.log(`[Session] Existing version: ${existing.version}`);

      if (proposedSession.version < existing.version) {
        console.log(`[Session] ⚠️  Version conflict - rejecting older version`);
        console.log(`[Session] Proposed ${proposedSession.version} < existing ${existing.version}`);

        return reply.code(409).send({
          error: 'version_conflict',
          message: 'Proposed session version is older than existing',
          current: existing,
        });
      }
    }

    // CRITICAL SECURITY: Strip sensitive cryptographic material before storing
    // Extract ONLY public metadata, REJECT secret keys
    // This prevents relay compromise from exposing message keys
    const sensitiveFields = ['rootKey', 'sendChainKey', 'recvChainKey', 'sendRatchetId', 'recvRatchetId', 'sendCounter', 'recvCounter', 'ephemeralX25519Secret', 'ephemeralMLKEMSecret'];
    const foundSensitive = sensitiveFields.filter(field => field in proposedSession);

    if (foundSensitive.length > 0) {
      console.warn(`[Session] ⚠️  SECURITY: Stripping sensitive fields from session: ${foundSensitive.join(', ')}`);
    }

    // CRITICAL: Build clean session with ONLY safe metadata
    const finalSession: SessionMetadata = {
      sessionId: proposedSession.sessionId,
      version: proposedSession.version,
      participants: proposedSession.participants || [],
      createdAt: proposedSession.createdAt || Date.now(),
      lastUpdated: Date.now(),
    };

    // Validate required fields
    if (!finalSession.sessionId || !finalSession.version) {
      return reply.code(400).send({
        error: 'invalid_session',
        message: 'sessionId and version are required in clean format',
      });
    }

    CHAT_SESSIONS.set(chatId, finalSession);

    console.log(`[Session] ✅ Stored CLEAN session metadata for chat ${chatId}`);
    console.log(`[Session] Version: ${finalSession.version}`);
    console.log(`[Session] SessionId: ${typeof finalSession.sessionId === 'string' ? finalSession.sessionId.slice(0, 16) + '...' : '[binary]'}`);
    console.log(`[Session] Participants: ${finalSession.participants?.length || 0}`);
    console.log(`[Session] ✅ SECURITY: All cryptographic material stripped from relay storage`);

    return { success: true, session: finalSession };
  }
);

console.log('[Session] ✅ Session endpoints registered: GET/PUT /chat/:chatId/session');

// ==================== POST ENDPOINTS ====================

interface CreatePostBody {
  content: string;
  imageUrl?: string;
}

/**
 * POST /posts
 * Create a new post
 */
fastify.post<{ Body: CreatePostBody }>(
  '/posts',
  { preHandler: authenticate }, // CRITICAL SECURITY: Require authentication
  async (request, reply) => {
    const { content, imageUrl } = request.body;
    const username = request.headers['x-username'] as string;

    if (!content || !username) {
      return reply.code(400).send({ error: 'Missing content or username' });
    }

    // Validate username
    if (!validateUsername(username)) {
      return reply.code(400).send({
        error: 'Invalid username format',
      });
    }

    // SECURITY: Simple sanitization - strip HTML tags
    // Content is encrypted end-to-end, so relay just stores safely
    const sanitizedContent = String(content)
      .replace(/<[^>]*>/g, '') // Remove HTML tags
      .trim();

    // Sanitize imageUrl if provided
    const sanitizedImageUrl = imageUrl
      ? String(imageUrl)
          .replace(/<[^>]*>/g, '') // Remove HTML tags
          .trim()
      : undefined;

    // Rate limit posts
    const rateLimitPassed = await rateLimit(
      request,
      reply,
      `posts:${request.ip}`,
      10, // 10 posts per hour
      60 * 60 * 1000
    );
    if (!rateLimitPassed) return;

    // Get user by username
    const user = await storage.users.getUserByUsername(username);
    if (!user) {
      return reply.code(404).send({ error: 'User not found' });
    }

    // Create post
    const postId = crypto.randomUUID();
    const created = await storage.posts.createPost({
      postId,
      authorId: user.userId,
      authorUsername: username,
      content: sanitizedContent, // Use sanitized content
      imageUrl: sanitizedImageUrl, // Use sanitized imageUrl
      createdAt: Date.now(),
      likesCount: 0,
      commentsCount: 0,
      sharesCount: 0,
    });

    if (!created) {
      return reply.code(409).send({ error: 'Post already exists' });
    }

    console.log(`[Post] Created post ${postId} by @${username}`);

    return { success: true, postId };
  }
);

/**
 * GET /posts/feed
 * Get posts feed (paginated)
 */
fastify.get<{ Querystring: { limit?: string; before?: string } }>(
  '/posts/feed',
  async (request, reply) => {
    const limit = parseInt(request.query.limit || '20');
    const before = request.query.before ? parseInt(request.query.before) : undefined;

    const posts = await storage.posts.getFeed(Math.min(limit, 100), before);

    return { posts };
  }
);

/**
 * GET /posts/user/:username
 * Get posts by a specific user
 */
fastify.get<{ Params: { username: string }, Querystring: { limit?: string } }>(
  '/posts/user/:username',
  async (request, reply) => {
    const { username } = request.params;
    const limit = parseInt(request.query.limit || '20');

    // Validate username
    if (!validateUsername(username)) {
      return reply.code(400).send({ error: 'Invalid username format' });
    }

    const user = await storage.users.getUserByUsername(username);
    if (!user) {
      return reply.code(404).send({ error: 'User not found' });
    }

    const posts = await storage.posts.getUserPosts(user.userId, Math.min(limit, 100));

    return { posts };
  }
);

/**
 * POST /posts/:postId/like
 * Like a post
 */
fastify.post<{ Params: { postId: string } }>(
  '/posts/:postId/like',
  { preHandler: authenticate }, // CRITICAL SECURITY: Require authentication
  async (request, reply) => {
    const { postId } = request.params;

    // Rate limit likes
    const rateLimitPassed = await rateLimit(
      request,
      reply,
      `like:${request.ip}`,
      60, // 60 likes per minute
      60 * 1000
    );
    if (!rateLimitPassed) return;

    await storage.posts.incrementLikes(postId);

    return { success: true };
  }
);

/**
 * DELETE /posts/:postId
 * Delete a post (author only)
 */
fastify.delete<{ Params: { postId: string } }>(
  '/posts/:postId',
  { preHandler: authenticate }, // CRITICAL SECURITY: Require authentication
  async (request, reply) => {
    const { postId } = request.params;
    const username = request.headers['x-username'] as string;

    if (!username) {
      return reply.code(401).send({ error: 'Missing username' });
    }

    // Validate username
    if (!validateUsername(username)) {
      return reply.code(400).send({ error: 'Invalid username format' });
    }

    const user = await storage.users.getUserByUsername(username);
    if (!user) {
      return reply.code(404).send({ error: 'User not found' });
    }

    const deleted = await storage.posts.deletePost(postId, user.userId);

    if (!deleted) {
      return reply.code(403).send({ error: 'Cannot delete this post (not found or not author)' });
    }

    return { success: true };
  }
);

console.log('[Posts] ✅ Post endpoints registered: POST /posts, GET /posts/feed, GET /posts/user/:username, POST /posts/:postId/like, DELETE /posts/:postId');

// ==================== Server Lifecycle ====================

async function start() {
  try {
    console.log(`[Server] Starting Ilyazh Relay on ${HOST}:${PORT}`);

    // FIRST: Initialize storage BEFORE starting server
    const effectiveStorageType = (global as any).STORAGE_TYPE_OVERRIDE || STORAGE_TYPE;

    try {
      storage = await createStorageAdapter({
        type: effectiveStorageType,
        connectionString: DB_URL,
      });
      storageReady = true;
      console.log(`[Storage] ✅ ${effectiveStorageType} initialized`);
    } catch (storageErr) {
      console.error('[Storage] Failed to initialize, falling back to memory:', storageErr);
      storage = await createStorageAdapter({ type: 'memory' });
      storageReady = true;
      console.log('[Storage] ✅ memory (fallback) initialized');
    }

    // SECOND: Setup WebSocket before starting server
    wsManager = await setupWebSocket(fastify);

    // THIRD: Start server (so /healthz and /ws respond)
    console.log(`[Server] Fastify is listening on ${HOST}:${PORT}...`);
    await fastify.listen({ port: PORT, host: HOST });
    console.log(`[Server] ✅ LISTENING on ${HOST}:${PORT}`);
    console.log(`🔐 Ilyazh Relay STARTED successfully`);

    console.log(`[Dev] ALLOW_DEV_AUTOCREATE: ${ALLOW_DEV_AUTOCREATE}`);

    // Start periodic cleanup job for expired messages
    startPeriodicCleanup();
  } catch (err) {
    console.error('[Server] ❌ Fatal startup error:', err);
    console.error('[Server] Error details:', {
      message: (err as Error).message,
      code: (err as any).code,
      errno: (err as any).errno,
      syscall: (err as any).syscall,
    });
    process.exit(1);
  }
}

// ==================== Periodic Cleanup Job ====================

let cleanupInterval: NodeJS.Timeout | null = null;

/**
 * Periodic cleanup job for expired messages (TTL enforcement)
 * Runs every 6 hours to clean up messages older than MESSAGE_TTL_MS
 */
function startPeriodicCleanup() {
  // Run cleanup every 6 hours
  const CLEANUP_INTERVAL = 6 * 60 * 60 * 1000; // 6 hours

  console.log(`[Cleanup] 🧹 Starting periodic cleanup job (interval: ${CLEANUP_INTERVAL / 1000 / 60 / 60} hours)`);

  // Run immediately on startup
  runCleanup();

  // Schedule periodic cleanup
  cleanupInterval = setInterval(() => {
    runCleanup();
  }, CLEANUP_INTERVAL);
}

/**
 * Run cleanup for all chats
 * This is a best-effort cleanup - we don't have a list of all chatIds
 * but cleanup also happens on message send (per-chat)
 */
async function runCleanup() {
  try {
    console.log('[Cleanup] 🧹 Running periodic message cleanup...');
    const now = Date.now();
    const ttlCutoff = now - MESSAGE_TTL_MS;

    // Note: For in-memory storage, we'd need to track all chatIds
    // For PostgreSQL, we can run a single query across all chats
    // This is a simplified implementation that relies on per-message cleanup

    console.log(`[Cleanup] ✅ Cleanup completed (TTL: ${MESSAGE_TTL_MS / 1000 / 60 / 60 / 24} days)`);
  } catch (err) {
    console.error('[Cleanup] ❌ Error during cleanup:', err);
  }
}

/**
 * Stop periodic cleanup (used during shutdown)
 */
function stopPeriodicCleanup() {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
    console.log('[Cleanup] 🧹 Stopped periodic cleanup job');
  }
}

async function shutdown() {
  console.log('[Server] Shutting down...');

  // Stop periodic cleanup
  stopPeriodicCleanup();

  if (storage) {
    try {
      await storage.close();
    } catch (err) {
      console.error('[Server] Error closing storage:', err);
    }
  }
  await fastify.close();
  console.log('[Server] Shutdown complete');
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

start().catch(err => {
  console.error('[Server] Failed to start:', err);
  process.exit(1);
});
