# ==============================================================================
# Ilyazh Web Client - Production Dockerfile
# ==============================================================================
# Multi-stage build for minimal production image
# Supports Railway, Render, Fly.io, or any Docker platform

FROM node:20-alpine AS base

# Railway-specific: Accept service ID for cache mount prefixing
ARG RAILWAY_SERVICE_ID=web

# Install pnpm
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable && corepack prepare pnpm@latest --activate

# ==============================================================================
# Dependencies stage - Install all dependencies
# ==============================================================================
FROM base AS deps
ARG RAILWAY_SERVICE_ID=web
WORKDIR /app

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages ./packages
COPY apps/web/package.json ./apps/web/

# Install ALL dependencies with Railway-compatible cache mount
# Railway-compatible cache mount: id=s/${RAILWAY_SERVICE_ID}-pnpm-store
RUN --mount=type=cache,id=s/${RAILWAY_SERVICE_ID}-pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile

# ==============================================================================
# Build stage - TypeScript compilation and Next.js build
# ==============================================================================
FROM base AS builder
ARG RAILWAY_SERVICE_ID=web
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages ./packages
COPY . .

# Build crypto library
RUN pnpm --filter @ilyazh/crypto build

# Build web app
WORKDIR /app/apps/web
RUN pnpm build

# ==============================================================================
# Production stage - Minimal runtime image
# ==============================================================================
FROM base AS runner
ARG RAILWAY_SERVICE_ID=web
WORKDIR /app

# Set production environment
ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/apps/web/public ./public

# Set permissions for prerender cache
RUN mkdir .next
RUN chown nextjs:nodejs .next

COPY --from=builder --chown=nextjs:nodejs /app/apps/web/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/.next/static ./.next/static

# Install curl for healthcheck
USER root
RUN apk add --no-cache curl
USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:3000 || exit 1

CMD ["node", "server.js"]
