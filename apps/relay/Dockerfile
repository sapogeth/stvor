# Relay Server Dockerfile
FROM node:20-alpine AS base

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

# Build stage
FROM base AS builder
WORKDIR /app

# Copy workspace files
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY turbo.json ./

# Copy all packages
COPY packages ./packages
COPY apps/relay ./apps/relay

# Install dependencies
RUN pnpm install --frozen-lockfile

# Build
RUN pnpm --filter @ilyazh/crypto build
RUN pnpm --filter @ilyazh/relay build

# Production stage
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production

# Copy built artifacts
COPY --from=builder /app/apps/relay/dist ./apps/relay/dist
COPY --from=builder /app/apps/relay/package.json ./apps/relay/
COPY --from=builder /app/packages/crypto/dist ./packages/crypto/dist
COPY --from=builder /app/packages/crypto/package.json ./packages/crypto/

# Copy workspace files
COPY --from=builder /app/package.json /app/pnpm-workspace.yaml ./

# Install production dependencies only
RUN pnpm install --prod --frozen-lockfile

# Create data directory
RUN mkdir -p /data && chown -R node:node /data

USER node

EXPOSE 3001

CMD ["node", "apps/relay/dist/index.js"]
