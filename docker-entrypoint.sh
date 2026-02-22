#!/bin/sh
# ============================================================================
# Dang! SIEM — Docker Entrypoint
# Handles: DB readiness wait, optional migrations, server start
# ============================================================================

set -e

echo "╔══════════════════════════════════════════════════╗"
echo "║  Dang! SIEM — Starting Production Server        ║"
echo "╚══════════════════════════════════════════════════╝"

# ── Wait for database if DATABASE_URL is set ─────────────────────────────────
if [ -n "$DATABASE_URL" ]; then
  echo "[entrypoint] DATABASE_URL detected, waiting for database..."

  # Extract host:port from mysql://user:pass@host:port/db
  DB_HOST=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:/]*\).*|\1|p')
  DB_PORT=$(echo "$DATABASE_URL" | sed -n 's|.*:\([0-9]*\)/.*|\1|p')
  DB_PORT=${DB_PORT:-3306}

  MAX_RETRIES=30
  RETRY_COUNT=0

  while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -sf "http://${DB_HOST}:${DB_PORT}" > /dev/null 2>&1 || \
       node -e "const net=require('net');const s=net.createConnection({host:'${DB_HOST}',port:${DB_PORT}},()=>{s.end();process.exit(0)});s.on('error',()=>process.exit(1))" 2>/dev/null; then
      echo "[entrypoint] Database is reachable at ${DB_HOST}:${DB_PORT}"
      break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo "[entrypoint] Waiting for database... (${RETRY_COUNT}/${MAX_RETRIES})"
    sleep 2
  done

  if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "[entrypoint] WARNING: Database not reachable after ${MAX_RETRIES} attempts, starting anyway..."
  fi
fi

# ── Run migrations if requested ──────────────────────────────────────────────
if [ "$RUN_MIGRATIONS" = "true" ] && [ -n "$DATABASE_URL" ]; then
  echo "[entrypoint] Running database migrations..."
  npx drizzle-kit migrate 2>&1 || echo "[entrypoint] WARNING: Migration failed, continuing..."
  echo "[entrypoint] Migrations complete."
fi

# ── Start the production server ──────────────────────────────────────────────
echo "[entrypoint] Starting Node.js server on port ${PORT:-3000}..."
exec node dist/index.js
