/**
 * Ilyazh Relay Server
 * Database-free stateless relay for encrypted messages
 */

import Fastify from 'fastify';
import cors from '@fastify/cors';
import multipart from '@fastify/multipart';
import rateLimit from '@fastify/rate-limit';
import jwt from '@fastify/jwt';
import { Storage } from './storage.js';

const PORT = parseInt(process.env.PORT || '3001', 10);
const HOST = process.env.HOST || '0.0.0.0';

const DATA_DIR = process.env.DATA_DIR || './storage';
const STORAGE_TYPE = (process.env.STORAGE_TYPE || 'filesystem') as 'filesystem' | 's3';

const storage = new Storage({
  type: STORAGE_TYPE,
  dataDir: DATA_DIR,
  s3Bucket: process.env.S3_BUCKET,
  s3Endpoint: process.env.S3_ENDPOINT,
  s3AccessKey: process.env.S3_ACCESS_KEY,
  s3SecretKey: process.env.S3_SECRET_KEY,
});

const fastify = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || 'info',
  },
});

// SECURITY: Configure CORS with allowed origins
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',') || [
  'http://localhost:3000',
  'http://localhost:3001',
];

await fastify.register(cors, {
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) {
      callback(null, true);
      return;
    }

    // Check if origin is in allowed list
    if (ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes('*')) {
      callback(null, true);
    } else {
      console.warn(`[CORS] Blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Length', 'Content-Type'],
  preflightContinue: false,
  optionsSuccessStatus: 204,
});

console.log('[Security] ✅ CORS configured with allowed origins:', ALLOWED_ORIGINS);

await fastify.register(multipart);

// SECURITY: Add JWT authentication with secure secret management
const JWT_SECRET = process.env.JWT_SECRET;

// CRITICAL: Always require JWT_SECRET to be explicitly set
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('❌ FATAL: JWT_SECRET environment variable must be set and at least 32 characters long!');
  console.error('   Generate a secure secret with: openssl rand -base64 48');
  process.exit(1);
}

// Warn about common insecure values
const INSECURE_SECRETS = [
  'secret',
  'change-this',
  'development-secret',
  'test-secret',
  'your-secret-here',
  'jwt-secret',
  'please-change-me'
];

if (INSECURE_SECRETS.some(insecure => JWT_SECRET.toLowerCase().includes(insecure))) {
  console.error('❌ FATAL: JWT_SECRET appears to be a placeholder or insecure value!');
  console.error('   Generate a secure secret with: openssl rand -base64 48');
  process.exit(1);
}

await fastify.register(jwt, {
  secret: JWT_SECRET,
  sign: {
    algorithm: 'HS256', // Explicitly set algorithm to prevent algorithm confusion attacks
    expiresIn: '30d',   // 30-day token expiry
  },
  verify: {
    algorithms: ['HS256'], // Only accept HS256 to prevent algorithm substitution
  },
});

console.log('[Security] ✅ JWT authentication enabled (HS256, 30d expiry)');

// SECURITY: Add rate limiting to prevent DoS attacks
await fastify.register(rateLimit, {
  global: true,
  max: 100, // 100 requests
  timeWindow: '1 minute',
  errorResponseBuilder: (req, context) => ({
    error: 'Rate limit exceeded. Too many requests.',
    statusCode: 429,
    retryAfter: context.after,
  }),
});

console.log('[Security] ✅ Rate limiting enabled (100 req/min global)');

// ==================== Security Event Logging ====================

function logSecurityEvent(event: string, details: Record<string, any>) {
  const timestamp = new Date().toISOString();
  const ip = details.ip || 'unknown';

  console.warn(`[SECURITY] ${timestamp} - ${event}`, {
    ...details,
    ip,
  });

  // In production, send to SIEM/monitoring service
  // Example: sendToSentry({ event, details, timestamp });
}

// ==================== Authentication Middleware ====================

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
    logSecurityEvent('AUTH_FAILED', {
      ip: request.ip,
      path: request.url,
      error: (err as Error).message,
    });
    reply.code(401).send({ error: 'Authentication required' });
  }
}

// ==================== Health Check ====================

fastify.get('/health', async () => {
  return {
    status: 'ok',
    storage: STORAGE_TYPE,
    version: '0.8.0',
  };
});

// ==================== User Registration ====================

interface RegisterBody {
  userId: string;
  username: string;
  identityEd25519: string; // base64
  identityMLDSA: string;
}

fastify.post<{ Body: RegisterBody }>('/register', async (request, reply) => {
  const { userId, username, identityEd25519, identityMLDSA } = request.body;

  if (!userId || !username || !identityEd25519 || !identityMLDSA) {
    return reply.code(400).send({ error: 'Missing required fields' });
  }

  // SECURITY: Log registration attempt
  logSecurityEvent('USER_REGISTRATION_ATTEMPT', {
    userId,
    username,
    ip: request.ip,
  });

  // Check if user already exists
  const existing = await storage.getUserIdentity(userId);
  if (existing) {
    logSecurityEvent('USER_REGISTRATION_DUPLICATE', {
      userId,
      username,
      ip: request.ip,
    });
    // SECURITY: Issue new JWT token even for existing users
    const token = fastify.jwt.sign(
      { userId, username },
      { expiresIn: '30d' }
    );
    return reply.code(409).send({ error: 'User already exists', token });
  }

  await storage.storeUserIdentity(userId, {
    userId,
    username,
    identityEd25519,
    identityMLDSA,
    registeredAt: Date.now(),
  });

  logSecurityEvent('USER_REGISTRATION_SUCCESS', {
    userId,
    username,
    ip: request.ip,
  });

  // SECURITY: Issue JWT token for authenticated requests
  const token = fastify.jwt.sign(
    { userId, username },
    { expiresIn: '30d' } // 30 day expiration
  );

  return { success: true, userId, token };
});

// ==================== Prekey Bundle ====================

interface PrekeyBundleBody {
  userId: string;
  bundleId: string;
  x25519Ephemeral: string; // base64
  mlkemPublicKey: string;
  ed25519Signature: string;
  mldsaSignature: string;
  timestamp: number;
}

fastify.post<{ Body: PrekeyBundleBody }>(
  '/prekey-bundle',
  { preHandler: authenticate },
  async (request, reply) => {
    const { userId, bundleId, x25519Ephemeral, mlkemPublicKey, ed25519Signature, mldsaSignature, timestamp } =
      request.body;

    if (!userId || !bundleId || !x25519Ephemeral || !mlkemPublicKey || !timestamp) {
      return reply.code(400).send({ error: 'Missing required fields' });
    }

    // SECURITY: Verify authenticated user matches userId in request
    if (request.authenticatedUserId !== userId) {
      logSecurityEvent('AUTH_MISMATCH_PREKEY', {
        authenticatedUserId: request.authenticatedUserId,
        requestedUserId: userId,
        ip: request.ip,
      });
      return reply.code(403).send({ error: 'Forbidden: userId mismatch' });
    }

    await storage.storePrekeyBundle(userId, bundleId, {
      bundleId,
      x25519Ephemeral,
      mlkemPublicKey,
      ed25519Signature,
      mldsaSignature,
      timestamp, // Use client's timestamp (which was signed)
    });

    return { success: true, bundleId };
  }
);

// ==================== Directory Lookup ====================

fastify.get<{ Params: { username: string } }>('/directory/:username', async (request, reply) => {
  const { username } = request.params;

  // Simple linear search (in production, use indexing)
  // For now, assume userId = username for simplicity
  const identity = await storage.getUserIdentity(username);
  if (!identity) {
    return reply.code(404).send({ error: 'User not found' });
  }

  const prekey = await storage.getPrekeyBundle(username);

  return {
    identity,
    prekey,
  };
});

// ==================== Chat Initialization ====================

interface InitChatBody {
  chatId: string;
  participants: string[];
}

fastify.post<{ Body: InitChatBody }>(
  '/chat/init',
  { preHandler: authenticate },
  async (request, reply) => {
    const { chatId, participants } = request.body;

    if (!chatId || !participants || participants.length !== 2) {
      return reply.code(400).send({ error: 'Invalid chat initialization' });
    }

    // SECURITY: Verify authenticated user is one of the participants
    if (!participants.includes(request.authenticatedUserId!)) {
      logSecurityEvent('AUTH_MISMATCH_CHAT_INIT', {
        authenticatedUserId: request.authenticatedUserId,
        participants,
        ip: request.ip,
      });
      return reply.code(403).send({ error: 'Forbidden: not a participant' });
    }

    // Check if chat already exists
    const existing = await storage.getManifest(chatId);
    if (existing) {
      return reply.code(409).send({ error: 'Chat already exists' });
    }

    await storage.initChatManifest(chatId, participants);

    return { success: true, chatId };
  }
);

// ==================== Handshake Message ====================

interface HandshakeBody {
  chatId: string;
  sender: string;
  data: string; // base64 encoded wire message
}

fastify.post<{ Body: HandshakeBody; Params: { chatId: string } }>(
  '/handshake/:chatId',
  { preHandler: authenticate },
  async (request, reply) => {
    const { chatId } = request.params;
    const { sender, data } = request.body;

    if (!data || !sender) {
      return reply.code(400).send({ error: 'Missing data or sender' });
    }

    // SECURITY: Verify sender matches authenticated user
    if (request.authenticatedUserId !== sender) {
      logSecurityEvent('AUTH_MISMATCH_HANDSHAKE', {
        authenticatedUserId: request.authenticatedUserId,
        claimedSender: sender,
        ip: request.ip,
      });
      return reply.code(403).send({ error: 'Forbidden: sender mismatch' });
    }

    // Store as blob
    const blob = Buffer.from(data, 'base64');
    const blobRef = await storage.storeBlob(chatId, blob);

    // Append to manifest
    const index = await storage.appendToManifest(chatId, {
      type: 'handshake',
      blobRef,
      sender,
    });

    return { success: true, index, blobRef };
  }
);

// ==================== Message Sending ====================

interface MessageBody {
  chatId: string;
  sender: string;
  data: string; // base64 encoded wire message
}

fastify.post<{ Body: MessageBody; Params: { chatId: string } }>(
  '/message/:chatId',
  { preHandler: authenticate },
  async (request, reply) => {
    const { chatId } = request.params;
    const { sender, data } = request.body;

    if (!data || !sender) {
      return reply.code(400).send({ error: 'Missing data or sender' });
    }

    // SECURITY: Verify sender matches authenticated user
    if (request.authenticatedUserId !== sender) {
      logSecurityEvent('AUTH_MISMATCH_MESSAGE', {
        authenticatedUserId: request.authenticatedUserId,
        claimedSender: sender,
        chatId,
        ip: request.ip,
      });
      return reply.code(403).send({ error: 'Forbidden: sender mismatch' });
    }

    // Store as blob
    const blob = Buffer.from(data, 'base64');
    const blobRef = await storage.storeBlob(chatId, blob);

    // Append to manifest
    const index = await storage.appendToManifest(chatId, {
      type: 'message',
      blobRef,
      sender,
    });

    return { success: true, index, blobRef };
  }
);

// ==================== Rekey Signal ====================

fastify.post<{ Body: MessageBody; Params: { chatId: string } }>(
  '/rekey/:chatId',
  { preHandler: authenticate },
  async (request, reply) => {
    const { chatId } = request.params;
    const { sender, data } = request.body;

    if (!data || !sender) {
      return reply.code(400).send({ error: 'Missing data or sender' });
    }

    // SECURITY: Verify sender matches authenticated user
    if (request.authenticatedUserId !== sender) {
      logSecurityEvent('AUTH_MISMATCH_REKEY', {
        authenticatedUserId: request.authenticatedUserId,
        claimedSender: sender,
        chatId,
        ip: request.ip,
      });
      return reply.code(403).send({ error: 'Forbidden: sender mismatch' });
    }

    const blob = Buffer.from(data, 'base64');
    const blobRef = await storage.storeBlob(chatId, blob);

    const index = await storage.appendToManifest(chatId, {
      type: 'rekey',
      blobRef,
      sender,
    });

    return { success: true, index, blobRef };
  }
);

// ==================== Sync (Get Updates) ====================

interface SyncQuery {
  since?: string;
}

fastify.get<{ Params: { chatId: string }; Querystring: SyncQuery }>(
  '/sync/:chatId',
  { preHandler: authenticate },
  async (request, reply) => {
    const { chatId } = request.params;
    const since = parseInt(request.query.since || '0', 10);

    const entries = await storage.getManifestSince(chatId, since);

    return { chatId, entries, count: entries.length };
  }
);

// ==================== Blob Retrieval ====================

fastify.get<{ Params: { chatId: string; ref: string } }>(
  '/blob/:chatId/:ref',
  { preHandler: authenticate },
  async (request, reply) => {
    const { chatId, ref } = request.params;

    const blob = await storage.getBlob(chatId, ref);
    if (!blob) {
      return reply.code(404).send({ error: 'Blob not found' });
    }

    reply.header('Content-Type', 'application/octet-stream');
    return Buffer.from(blob);
  }
);

// ==================== Start Server ====================

try {
  await fastify.listen({ port: PORT, host: HOST });
  console.log(`🔐 Ilyazh Relay listening on ${HOST}:${PORT}`);
  console.log(`📁 Storage: ${STORAGE_TYPE} ${STORAGE_TYPE === 'filesystem' ? `(${DATA_DIR})` : ''}`);
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}
