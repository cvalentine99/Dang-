#!/usr/bin/env bash
# ============================================================================
# Dang! SIEM — Deployment Script (Co-located with Wazuh)
# Target: Linux x86_64 (Ubuntu 22.04+, kernel 6.8+)
#
# Usage:
#   chmod +x deploy.sh
#   ./deploy.sh                     # Co-located with Wazuh Docker (default)
#   ./deploy.sh --wazuh-host        # Wazuh installed via packages (no Docker)
#   ./deploy.sh --proxy caddy       # Add HTTPS via Caddy (auto Let's Encrypt)
#   ./deploy.sh --proxy nginx       # Add HTTPS via Nginx (bring your own certs)
#   ./deploy.sh --rebuild           # Force rebuild without cache
#   ./deploy.sh --stop              # Stop all services
#   ./deploy.sh --logs              # Follow logs
#   ./deploy.sh --status            # Show service status
#   ./deploy.sh --generate-certs    # Generate self-signed certs for Nginx
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log()   { echo -e "${PURPLE}[dang]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[✗]${NC} $1"; }
info()  { echo -e "${CYAN}[i]${NC} $1"; }

PROXY_MODE=""
WAZUH_HOST_MODE=false
COMPOSE_FILES="-f docker-compose.yml"

# ── Parse arguments ─────────────────────────────────────────────────────────
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --proxy)
        PROXY_MODE="${2:-}"
        if [[ "$PROXY_MODE" != "caddy" && "$PROXY_MODE" != "nginx" ]]; then
          err "Invalid proxy mode: '$PROXY_MODE'. Use 'caddy' or 'nginx'."
          exit 1
        fi
        shift 2
        ;;
      --wazuh-host)
        WAZUH_HOST_MODE=true
        shift
        ;;
      --rebuild|--stop|--logs|--status|--generate-certs)
        # These are handled by the case statement in main
        break
        ;;
      *)
        break
        ;;
    esac
  done
}

# ── Build compose file list based on deployment mode ─────────────────────
setup_compose_files() {
  COMPOSE_FILES="-f docker-compose.yml"
  if [ "$WAZUH_HOST_MODE" = "true" ]; then
    COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.standalone.yml"
    log "Wazuh mode: ${CYAN}package-based (host network)${NC}"
  else
    log "Wazuh mode: ${CYAN}Docker co-located${NC}"
  fi
  if [ -n "$PROXY_MODE" ]; then
    COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.${PROXY_MODE}.yml"
    log "Proxy mode: ${CYAN}${PROXY_MODE}${NC}"
  fi
}

# ── Pre-flight checks ──────────────────────────────────────────────────────
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
  for var in JWT_SECRET; do
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

  # Warn about optional but recommended variables
  local wazuh_host=$(grep "^WAZUH_HOST=" .env 2>/dev/null | cut -d'=' -f2-)
  if [ -z "$wazuh_host" ]; then
    warn "WAZUH_HOST not set — app will start but Wazuh features will be unavailable"
    info "Set WAZUH_HOST, WAZUH_USER, and WAZUH_PASS to enable Wazuh integration"
  fi

  # Check local auth credentials
  local admin_pass=$(grep "^LOCAL_ADMIN_PASS=" .env 2>/dev/null | cut -d'=' -f2-)
  if [ -n "$admin_pass" ] && [[ "$admin_pass" == *"CHANGE_ME"* ]]; then
    warn "LOCAL_ADMIN_PASS still has placeholder value — change it or remove it"
  fi

  # ── Wazuh co-located checks ──────────────────────────────────────────────
  if [ "$WAZUH_HOST_MODE" = "true" ]; then
    info "Package-based Wazuh mode — using standalone network override"
    if [ -n "$wazuh_host" ] && [ "$wazuh_host" != "host.docker.internal" ]; then
      warn "WAZUH_HOST='${wazuh_host}' — for package-based Wazuh, consider using 'host.docker.internal'"
    fi
  else
    # Docker co-located mode — verify Wazuh Docker network exists
    local wazuh_net=$(grep "^WAZUH_NETWORK=" .env 2>/dev/null | cut -d'=' -f2-)
    wazuh_net=${wazuh_net:-single-node_default}

    if docker network inspect "$wazuh_net" > /dev/null 2>&1; then
      ok "Wazuh Docker network found: ${wazuh_net}"
    else
      err "Wazuh Docker network '${wazuh_net}' not found."
      info "Ensure the Wazuh Docker stack is running on this server."
      info "Find your network with: docker network ls | grep -i wazuh"
      info "Then set WAZUH_NETWORK=<name> in .env"
      info "If Wazuh is installed via packages (not Docker), use: ./deploy.sh --wazuh-host"
      exit 1
    fi

    # Check if Wazuh containers are running
    local wazuh_containers=$(docker ps --format '{{.Names}}' | grep -ci 'wazuh' 2>/dev/null || echo "0")
    if [ "$wazuh_containers" -gt 0 ]; then
      ok "Found ${wazuh_containers} running Wazuh container(s)"
    else
      warn "No running Wazuh containers detected — Dang! may fail to connect"
    fi
  fi

  # ── Port conflict checks ─────────────────────────────────────────────────
  if [ -n "$PROXY_MODE" ]; then
    if ss -tlnp 2>/dev/null | grep -q ':443 ' || docker ps --format '{{.Ports}}' 2>/dev/null | grep -q '0.0.0.0:443'; then
      warn "Port 443 is already in use (likely by Wazuh Dashboard)."
      info "Set DANG_HTTPS_PORT=8443 in .env to use an alternate port."
    fi
  fi

  # Proxy-specific checks
  if [ "$PROXY_MODE" = "caddy" ]; then
    local domain=$(grep "^DANG_DOMAIN=" .env 2>/dev/null | cut -d'=' -f2-)
    if [ -z "$domain" ]; then
      warn "DANG_DOMAIN not set in .env — defaulting to 'localhost' (self-signed)"
      info "For production, set DANG_DOMAIN=your.domain.com and ACME_EMAIL=you@email.com"
    else
      ok "Caddy domain: ${domain}"
    fi
  fi

  if [ "$PROXY_MODE" = "nginx" ]; then
    if [ ! -f "proxy/nginx/ssl/dang.crt" ] || [ ! -f "proxy/nginx/ssl/dang.key" ]; then
      warn "SSL certificates not found in proxy/nginx/ssl/"
      warn "Generate self-signed certs with: ./deploy.sh --generate-certs"
      warn "Or place your own dang.crt and dang.key in proxy/nginx/ssl/"
      err "Cannot start Nginx without certificates."
      exit 1
    fi
    ok "SSL certificates found"
  fi
}

# ── Generate self-signed certificates ──────────────────────────────────────
cmd_generate_certs() {
  log "Generating self-signed SSL certificates for Nginx..."

  mkdir -p proxy/nginx/ssl

  local cn="${1:-dang.local}"

  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout proxy/nginx/ssl/dang.key \
    -out proxy/nginx/ssl/dang.crt \
    -subj "/C=US/ST=Security/L=SOC/O=Dang SIEM/CN=${cn}" \
    2>/dev/null

  ok "Self-signed certificate generated for CN=${cn}"
  info "Certificate: proxy/nginx/ssl/dang.crt"
  info "Private key: proxy/nginx/ssl/dang.key"
  info "Valid for: 365 days"
  echo ""
  warn "Self-signed certs will show browser warnings. For production, use Let's Encrypt."
  info "Consider using Caddy instead (--proxy caddy) for automatic Let's Encrypt certs."
}

# ── Commands ────────────────────────────────────────────────────────────────
cmd_start() {
  preflight
  setup_compose_files

  log "Building and starting Dang! SIEM..."
  if [ -n "$PROXY_MODE" ]; then
    info "HTTPS proxy: ${PROXY_MODE}"
  fi

  local build_args=""
  if [ "${1:-}" = "--rebuild" ]; then
    build_args="--no-cache"
    log "Forcing rebuild without cache..."
  fi

  docker compose $COMPOSE_FILES build $build_args
  ok "Docker image built successfully"

  docker compose $COMPOSE_FILES up -d
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
  echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${PURPLE}║${NC}  ${GREEN}Dang! SIEM is running${NC}                                      ${PURPLE}║${NC}"
  echo -e "${PURPLE}║${NC}                                                              ${PURPLE}║${NC}"

  if [ "$PROXY_MODE" = "caddy" ]; then
    local domain=$(grep "^DANG_DOMAIN=" .env 2>/dev/null | cut -d'=' -f2-)
    domain=${domain:-localhost}
    echo -e "${PURPLE}║${NC}  Web UI:  ${GREEN}https://${domain}${NC}                            ${PURPLE}║${NC}"
    echo -e "${PURPLE}║${NC}  Proxy:   ${CYAN}Caddy (auto TLS)${NC}                               ${PURPLE}║${NC}"
  elif [ "$PROXY_MODE" = "nginx" ]; then
    echo -e "${PURPLE}║${NC}  Web UI:  ${GREEN}https://localhost${NC}                              ${PURPLE}║${NC}"
    echo -e "${PURPLE}║${NC}  Proxy:   ${CYAN}Nginx (TLS)${NC}                                    ${PURPLE}║${NC}"
  else
    local port=$(grep "^APP_PORT=" .env 2>/dev/null | cut -d'=' -f2-)
    port=${port:-3000}
    echo -e "${PURPLE}║${NC}  Web UI:  ${GREEN}http://localhost:${port}${NC}                            ${PURPLE}║${NC}"
    echo -e "${PURPLE}║${NC}  Proxy:   ${YELLOW}None (HTTP only)${NC}                               ${PURPLE}║${NC}"
  fi

  if [ "$WAZUH_HOST_MODE" = "true" ]; then
    echo -e "${PURPLE}║${NC}  Wazuh:   ${CYAN}Package-based (host network)${NC}                   ${PURPLE}║${NC}"
  else
    local wnet=$(grep "^WAZUH_NETWORK=" .env 2>/dev/null | cut -d'=' -f2-)
    wnet=${wnet:-single-node_default}
    echo -e "${PURPLE}║${NC}  Wazuh:   ${CYAN}Docker network (${wnet})${NC}         ${PURPLE}║${NC}"
  fi

  echo -e "${PURPLE}║${NC}  Health:  ${GREEN}http://localhost:3000/api/health${NC} (internal)     ${PURPLE}║${NC}"
  echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"

  if [ -z "$PROXY_MODE" ]; then
    echo ""
    info "For HTTPS, re-run with: ./deploy.sh --proxy caddy"
  fi
}

cmd_stop() {
  setup_compose_files
  log "Stopping Dang! SIEM..."
  docker compose $COMPOSE_FILES down
  ok "All services stopped"
}

cmd_logs() {
  setup_compose_files
  docker compose $COMPOSE_FILES logs -f --tail=100
}

cmd_status() {
  setup_compose_files
  echo ""
  log "Service Status:"
  docker compose $COMPOSE_FILES ps
  echo ""
  log "Health Check:"
  local port=$(grep "^APP_PORT=" .env 2>/dev/null | cut -d'=' -f2-)
  port=${port:-3000}
  curl -s "http://localhost:${port}/api/health" 2>/dev/null | python3 -m json.tool 2>/dev/null || warn "App not reachable on port ${port}"

  if [ "$PROXY_MODE" = "caddy" ]; then
    echo ""
    log "Caddy Status:"
    docker compose $COMPOSE_FILES exec caddy caddy version 2>/dev/null || warn "Caddy not reachable"
  fi

  if [ "$PROXY_MODE" = "nginx" ]; then
    echo ""
    log "Nginx Status:"
    docker compose $COMPOSE_FILES exec nginx nginx -t 2>/dev/null || warn "Nginx not reachable"
  fi
}

# ── Main ────────────────────────────────────────────────────────────────────
# Extract --proxy before other args
ALL_ARGS=("$@")
parse_args "$@"

# Find the command arg (skip --proxy and its value)
CMD=""
for arg in "${ALL_ARGS[@]}"; do
  case "$arg" in
    --proxy|caddy|nginx|--wazuh-host) continue ;;
    --*) CMD="$arg"; break ;;
  esac
done

case "${CMD:-start}" in
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
  --generate-certs)
    cmd_generate_certs "${2:-dang.local}"
    ;;
  *)
    cmd_start
    ;;
esac
