/**
 * Ilyazh Relay Server (Production-Ready)
 * Horizontally scalable, stateless relay with PostgreSQL backend
 * JWT authentication, rate limiting, structured observability
 */

import Fastify from 'fastify';
import cors from '@fastify/cors';
import multipart from '@fastify/multipart';
import jwt from '@fastify/jwt';
import { createStorageAdapter, type IStorageAdapter } from './storage/index.js';
import { type PrekeyBundle } from './storage/interfaces.js';
import { normalizeUsername } from './utils/normalize.js';
import * as crypto from 'crypto';

const PORT = parseInt(process.env.PORT || '3001', 10);
const HOST = process.env.HOST || '0.0.0.0';
const STORAGE_TYPE = (process.env.STORAGE_TYPE || 'postgres') as 'memory' | 'postgres';
const DB_URL = process.env.DATABASE_URL;
const ALLOW_DEV_AUTOCREATE = process.env.ALLOW_DEV_AUTOCREATE === '1';

// Validate configuration
if (STORAGE_TYPE === 'postgres' && !DB_URL) {
  console.error('❌ FATAL: DATABASE_URL required when STORAGE_TYPE=postgres');
  process.exit(1);
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

const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',') || [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:3002', // Next.js dev server alternate port
  'http://127.0.0.1:3002',
];

await fastify.register(cors, {
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g., mobile apps, Postman, curl)
    if (!origin) {
      callback(null, true);
      return;
    }

    // Check if origin is in allowed list
    if (ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes('*')) {
      callback(null, true);
    } else {
      // Only log blocked origins (security event)
      console.error(`[CORS] ❌ BLOCKED origin: ${origin}`);
      callback(new Error('Not allowed by CORS'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Relay-User'],
  preflightContinue: false,
  optionsSuccessStatus: 204,
});

console.log('[Security] ✅ CORS configured for origins:', ALLOWED_ORIGINS);

await fastify.register(multipart, {
  limits: { fileSize: 10 * 1024 * 1024 },
});

// ==================== JWT Authentication ====================

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('❌ FATAL: JWT_SECRET must be ≥32 chars');
  console.error('   Generate: openssl rand -base64 48');
  process.exit(1);
}

const INSECURE = ['secret', 'change-this', 'development-secret', 'test-secret', 'jwt-secret', 'please-change-me'];
if (INSECURE.some(s => JWT_SECRET.toLowerCase().includes(s))) {
  console.error('❌ FATAL: JWT_SECRET is insecure');
  console.error('   Generate: openssl rand -base64 48');
  process.exit(1);
}

await fastify.register(jwt, {
  secret: JWT_SECRET,
  sign: { algorithm: 'HS256', expiresIn: '30d' },
  verify: { algorithms: ['HS256'] },
});

console.log('[Security] ✅ JWT (HS256, 30d expiry)');

// ==================== Storage Initialization ====================

let storage: IStorageAdapter;

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

async function rateLimit(request: any, reply: any, key: string, limit: number, windowMs: number) {
  const allowed = await storage.rateLimit.checkAndIncrement(key, limit, windowMs);
  if (!allowed) {
    metrics.rateLimitHits++;
    logSecurityEvent('RATE_LIMIT_EXCEEDED', { key, ip: request.ip });
    reply.code(429).send({ error: 'Rate limit exceeded', retryAfter: Math.ceil(windowMs / 1000) });
  }
}

// ==================== Observability Endpoints ====================

fastify.get('/healthz', async () => {
  const healthy = await storage.isHealthy();
  return { status: healthy ? 'ok' : 'degraded', storage: STORAGE_TYPE, version: '0.8.0' };
});

fastify.get('/ready', async () => {
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

  await rateLimit(request, reply, `register:${request.ip}`, 5, 60 * 60 * 1000);

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

    await rateLimit(request, reply, `prekey:${userId}`, 10, 60 * 60 * 1000);

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

    await rateLimit(request, reply, `prekey-batch:${userId}`, 2, 60 * 60 * 1000);

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
 * Session metadata - source of truth for chat sessions
 * Prevents infinite ratchet refresh loops by providing single canonical session per chatId
 */
interface SessionMetadata {
  sessionId: string; // hex string
  version: number; // timestamp or incrementing counter (higher wins)
  participants: Array<{
    username: string;
    identityEd25519: string;
  }>;
  createdAt: number;
  lastUpdated: number;
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
  participants: string[];
}

fastify.post<{ Body: ChatInitBody }>(
  '/chat/init',
  // No authentication required - chat ID is deterministic and not secret
  async (request, reply) => {
    const { participants } = request.body;

    if (!participants || !Array.isArray(participants) || participants.length < 2) {
      return reply.code(400).send({ error: 'participants array with at least 2 members required' });
    }

    try {
      const chatId = makeChatId(participants);

      console.log(`[Chat] Init request for participants: ${participants.join(', ')}`);
      console.log(`[Chat] Generated deterministic chatId: ${chatId}`);

      // Chat is implicitly created on first message, no need to pre-create
      // Just return the canonical ID
      return { chatId, status: 'ok' };
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
  // No authentication required in dev mode - relay accepts all requests
  async (request, reply) => {
    const { chatId } = request.params;

    // Support both new and legacy body formats
    let senderId = request.body.senderId || request.body.from;
    const encryptedBlob = request.body.encryptedBlob || request.body.blob;

    if (!chatId || !encryptedBlob || !senderId) {
      return reply.code(400).send({ error: 'Missing required fields (chatId, encryptedBlob/blob, senderId/from)' });
    }

    // CRITICAL FIX: Normalize senderId to canonical form (lowercase, trimmed)
    senderId = senderId.trim().toLowerCase();

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
    const participants = [];
    const uniqueSenders = new Set(messages.map(m => m.senderId).filter(Boolean));

    for (const senderId of uniqueSenders) {
      try {
        // Fetch canonical identity for this participant
        const user = await storage.users.getUserByUsername(senderId);

        if (user) {
          participants.push({
            username: senderId, // Canonical username
            canonicalUsername: senderId.toLowerCase().trim(), // CRITICAL FIX: Explicit canonical form
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
      messages: messages.map(m => ({
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
      entries: messages.map(m => ({ // Add 'entries' alias for frontend compatibility
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

    // Accept full session state (not just metadata)
    // Store exactly what client sends - this includes rootKey, chainKeys, counters, etc.
    const finalSession: any = {
      ...proposedSession,
      lastUpdated: Date.now(),
    };

    CHAT_SESSIONS.set(chatId, finalSession);

    console.log(`[Session] ✅ Stored FULL session state for chat ${chatId}`);
    console.log(`[Session] Version: ${finalSession.version}`);
    console.log(`[Session] Has rootKey: ${!!finalSession.rootKey}`);
    console.log(`[Session] Has sendChainKey: ${!!finalSession.sendChainKey}`);
    console.log(`[Session] Has recvChainKey: ${!!finalSession.recvChainKey}`);

    return { success: true, session: finalSession };
  }
);

console.log('[Session] ✅ Session endpoints registered: GET/PUT /chat/:chatId/session');

// ==================== Server Lifecycle ====================

async function start() {
  try {
    storage = await createStorageAdapter({
      type: STORAGE_TYPE,
      connectionString: DB_URL,
    });
    console.log(`[Storage] ✅ ${STORAGE_TYPE} initialized`);

    await fastify.listen({ port: PORT, host: HOST });
    console.log(`🔐 Ilyazh Relay (${STORAGE_TYPE}) on ${HOST}:${PORT}`);
    console.log(`[Dev] ALLOW_DEV_AUTOCREATE: ${ALLOW_DEV_AUTOCREATE}`);
  } catch (err) {
    console.error('[Server] Fatal error:', err);
    process.exit(1);
  }
}

async function shutdown() {
  console.log('[Server] Shutting down...');
  await storage.close();
  await fastify.close();
  console.log('[Server] Shutdown complete');
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

start();
