#!/usr/bin/env bash
# ============================================================================
# Dang! SIEM — Deployment Script
# Target: Linux x86_64 (Ubuntu 22.04+, kernel 6.8+)
#
# Usage:
#   chmod +x deploy.sh
#   ./deploy.sh              # Full build + start
#   ./deploy.sh --rebuild    # Force rebuild without cache
#   ./deploy.sh --stop       # Stop all services
#   ./deploy.sh --logs       # Follow logs
#   ./deploy.sh --status     # Show service status
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

log()   { echo -e "${PURPLE}[dang]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[✗]${NC} $1"; }

# ── Pre-flight checks ───────────────────────────────────────────────────────
preflight() {
  log "Running pre-flight checks..."

  if ! command -v docker &> /dev/null; then
    err "Docker is not installed. Install with: sudo apt install docker.io docker-compose-plugin"
    exit 1
  fi
  ok "Docker found: $(docker --version)"

  if ! docker compose version &> /dev/null; then
    err "Docker Compose V2 not found. Install with: sudo apt install docker-compose-plugin"
    exit 1
  fi
  ok "Docker Compose found: $(docker compose version --short)"

  if ! docker info &> /dev/null 2>&1; then
    err "Docker daemon is not running or current user lacks permissions."
    err "Try: sudo systemctl start docker && sudo usermod -aG docker \$USER"
    exit 1
  fi
  ok "Docker daemon is running"

  if [ ! -f ".env" ]; then
    if [ -f "env.docker.template" ]; then
      warn "No .env file found. Creating from template..."
      cp env.docker.template .env
      warn "IMPORTANT: Edit .env with your actual credentials before starting!"
      warn "  Required: JWT_SECRET, WAZUH_HOST, WAZUH_USER, WAZUH_PASS"
      warn "  Generate JWT_SECRET with: openssl rand -hex 32"
      exit 1
    else
      err "No .env file and no env.docker.template found."
      exit 1
    fi
  fi
  ok ".env file found"

  # Validate required variables
  local missing=0
  for var in JWT_SECRET WAZUH_HOST WAZUH_USER WAZUH_PASS; do
    val=$(grep "^${var}=" .env 2>/dev/null | cut -d'=' -f2-)
    if [ -z "$val" ] || [[ "$val" == *"CHANGE_ME"* ]]; then
      err "Required variable ${var} is not set or still has placeholder value"
      missing=1
    fi
  done

  if [ $missing -eq 1 ]; then
    err "Please update .env with your actual credentials."
    exit 1
  fi
  ok "Required environment variables are set"
}

# ── Commands ─────────────────────────────────────────────────────────────────
cmd_start() {
  preflight
  log "Building and starting Dang! SIEM..."

  local build_args=""
  if [ "${1:-}" = "--rebuild" ]; then
    build_args="--no-cache"
    log "Forcing rebuild without cache..."
  fi

  docker compose build $build_args
  ok "Docker image built successfully"

  docker compose up -d
  ok "Services started"

  log "Waiting for health check..."
  sleep 10

  local retries=0
  local max_retries=12
  while [ $retries -lt $max_retries ]; do
    if docker compose exec -T app curl -sf http://localhost:3000/api/health > /dev/null 2>&1; then
      ok "Application is healthy!"
      break
    fi
    retries=$((retries + 1))
    sleep 5
  done

  if [ $retries -eq $max_retries ]; then
    warn "Health check did not pass within 60s. Check logs with: ./deploy.sh --logs"
  fi

  echo ""
  echo -e "${PURPLE}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${PURPLE}║${NC}  ${GREEN}Dang! SIEM is running${NC}                          ${PURPLE}║${NC}"
  echo -e "${PURPLE}║${NC}                                                  ${PURPLE}║${NC}"
  local port=$(grep "^APP_PORT=" .env 2>/dev/null | cut -d'=' -f2-)
  port=${port:-3000}
  echo -e "${PURPLE}║${NC}  Web UI:  ${GREEN}http://localhost:${port}${NC}                ${PURPLE}║${NC}"
  echo -e "${PURPLE}║${NC}  Health:  ${GREEN}http://localhost:${port}/api/health${NC}     ${PURPLE}║${NC}"
  echo -e "${PURPLE}╚══════════════════════════════════════════════════╝${NC}"
}

cmd_stop() {
  log "Stopping Dang! SIEM..."
  docker compose down
  ok "All services stopped"
}

cmd_logs() {
  docker compose logs -f --tail=100
}

cmd_status() {
  echo ""
  log "Service Status:"
  docker compose ps
  echo ""
  log "Health Check:"
  local port=$(grep "^APP_PORT=" .env 2>/dev/null | cut -d'=' -f2-)
  port=${port:-3000}
  curl -s "http://localhost:${port}/api/health" 2>/dev/null | python3 -m json.tool 2>/dev/null || warn "App not reachable"
}

# ── Main ─────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --stop)
    cmd_stop
    ;;
  --logs)
    cmd_logs
    ;;
  --status)
    cmd_status
    ;;
  --rebuild)
    cmd_start --rebuild
    ;;
  *)
    cmd_start
    ;;
esac
