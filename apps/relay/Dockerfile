# ==============================================================================
# Ilyazh Relay Server - Production Dockerfile
# ==============================================================================
# Multi-stage build for minimal production image
# Optimized for Railway, Render, Fly.io, or any Docker platform
# NOTE: Cache mounts removed for Railway compatibility

FROM node:20-alpine AS base

# Install pnpm
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable && corepack prepare pnpm@9.0.0 --activate

# ==============================================================================
# Build stage - TypeScript compilation
# ==============================================================================
FROM base AS builder
WORKDIR /app

# Copy workspace configuration
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY turbo.json ./

# Copy source code for both relay and crypto package
COPY packages ./packages
COPY apps/relay ./apps/relay

# Install ALL dependencies (including devDependencies for build)
# No cache mount - Railway compatible
RUN pnpm install --frozen-lockfile

# Build both crypto package and relay
RUN pnpm --filter @ilyazh/crypto build && \
    pnpm --filter @ilyazh/relay build

# ==============================================================================
# Production stage - Minimal runtime image
# ==============================================================================
FROM base AS runner
WORKDIR /app

# Set production environment
ENV NODE_ENV=production
ENV HOST=0.0.0.0

# Copy built JavaScript artifacts (NOT TypeScript source)
COPY --from=builder /app/apps/relay/dist ./apps/relay/dist
COPY --from=builder /app/apps/relay/package.json ./apps/relay/
COPY --from=builder /app/packages/crypto/dist ./packages/crypto/dist
COPY --from=builder /app/packages/crypto/package.json ./packages/crypto/

# Copy workspace files for pnpm (including lockfile for frozen install)
COPY --from=builder /app/package.json /app/pnpm-workspace.yaml /app/pnpm-lock.yaml ./

# Install ONLY production dependencies (no devDependencies)
# No cache mount - Railway compatible
RUN pnpm install --prod --frozen-lockfile

# Install curl for health checks (Railway/Render monitoring)
RUN apk add --no-cache curl

# Security: Run as non-root user
# Create relay user if not exists (node user is default in node:alpine)
RUN addgroup -S relay 2>/dev/null || true && \
    adduser -S -G relay relay 2>/dev/null || true
USER node

# Expose port (Railway/Render will set $PORT dynamically)
# Default to 3001 if not set
EXPOSE ${PORT:-3001}

# Health check endpoint for production monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:${PORT:-3001}/healthz || exit 1

# Start relay server
CMD ["node", "apps/relay/dist/index.js"]
