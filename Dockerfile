# ============================================================================
# Dang! SIEM — Multi-stage Docker build
# Target: Linux x86_64 (Ubuntu 22.04, kernel 6.8.0-100-generic)
# ============================================================================

# ── Stage 1: Dependencies ────────────────────────────────────────────────────
FROM node:22-slim AS deps

RUN corepack enable && corepack prepare pnpm@10.4.1 --activate

WORKDIR /app

# Copy dependency manifests first for layer caching
COPY package.json pnpm-lock.yaml ./
COPY patches/ ./patches/

RUN pnpm install --frozen-lockfile

# ── Stage 2: Build ───────────────────────────────────────────────────────────
FROM node:22-slim AS builder

RUN corepack enable && corepack prepare pnpm@10.4.1 --activate

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build frontend (Vite) and backend (esbuild)
RUN pnpm run build

# ── Stage 3: Production ─────────────────────────────────────────────────────
FROM node:22-slim AS production

RUN corepack enable && corepack prepare pnpm@10.4.1 --activate

# Install curl for health checks and tini for proper signal handling
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy full node_modules from deps stage (--prod would strip vite which
# the built server still imports at runtime for static file serving)
COPY --from=deps /app/node_modules ./node_modules

# Copy built artifacts from builder
COPY --from=builder /app/dist ./dist

# Copy drizzle migrations for runtime migration support
COPY drizzle/ ./drizzle/
COPY drizzle.config.ts ./

# Copy entrypoint script
COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

# Non-root user for security
RUN groupadd -r dang && useradd -r -g dang -d /app dang
RUN chown -R dang:dang /app
USER dang

# Default environment
ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

# Health check — hits the /api/health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

# Use tini as init system for proper signal handling
ENTRYPOINT ["tini", "--"]
CMD ["./docker-entrypoint.sh"]
