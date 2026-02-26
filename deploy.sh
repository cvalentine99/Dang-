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
#   ./deploy.sh --update            # Pull latest code, rebuild, and restart
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
      --update|--rebuild|--stop|--logs|--status|--generate-certs)
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

# ── Helper: set a value in .env ────────────────────────────────────────────
set_env() {
  local key="$1" val="$2"
  if grep -q "^${key}=" .env 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${val}|" .env
  else
    echo "${key}=${val}" >> .env
  fi
}

# ── Helper: read a value from .env ────────────────────────────────────────
get_env() {
  grep "^${1}=" .env 2>/dev/null | cut -d'=' -f2-
}

# ── Helper: prompt with default ───────────────────────────────────────────
prompt() {
  local prompt_text="$1" default="${2:-}"
  local input
  if [ -n "$default" ]; then
    echo -en "  ${CYAN}${prompt_text}${NC} [${GREEN}${default}${NC}]: " >&2
  else
    echo -en "  ${CYAN}${prompt_text}${NC}: " >&2
  fi
  read -r input
  echo "${input:-$default}"
}

# ── Helper: prompt for password (hidden input) ────────────────────────────
prompt_secret() {
  local prompt_text="$1" default="${2:-}"
  local input
  if [ -n "$default" ]; then
    echo -en "  ${CYAN}${prompt_text}${NC} [${YELLOW}press Enter to keep current${NC}]: " >&2
  else
    echo -en "  ${CYAN}${prompt_text}${NC}: " >&2
  fi
  read -rs input
  echo "" >&2
  echo "${input:-$default}"
}

# ── Interactive first-run setup ───────────────────────────────────────────
first_run_setup() {
  echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${PURPLE}║${NC}  ${GREEN}Dang! SIEM — First-Run Setup${NC}                                ${PURPLE}║${NC}"
  echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""

  # Start from template
  cp env.docker.template .env

  # ── 1. Auto-generate JWT_SECRET ────────────────────────────────────────
  local jwt_secret
  if command -v openssl &> /dev/null; then
    jwt_secret=$(openssl rand -hex 32)
  else
    jwt_secret=$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 64)
  fi
  set_env "JWT_SECRET" "$jwt_secret"
  ok "JWT_SECRET auto-generated"

  # ── 2. Auto-generate DB passwords ─────────────────────────────────────
  local db_root_pw db_user_pw
  if command -v openssl &> /dev/null; then
    db_root_pw=$(openssl rand -hex 16)
    db_user_pw=$(openssl rand -hex 16)
  else
    db_root_pw=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 32)
    db_user_pw=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 32)
  fi
  set_env "MYSQL_ROOT_PASSWORD" "$db_root_pw"
  set_env "MYSQL_PASSWORD" "$db_user_pw"
  ok "MySQL passwords auto-generated"

  # ── 3. Admin account ──────────────────────────────────────────────────
  echo ""
  log "Admin Account"
  info "This is the login for the Dang! SIEM web UI."
  local admin_user admin_pass
  admin_user=$(prompt "Admin username" "admin")
  admin_pass=$(prompt_secret "Admin password")
  while [ -z "$admin_pass" ]; do
    warn "Password cannot be empty."
    admin_pass=$(prompt_secret "Admin password")
  done
  set_env "LOCAL_ADMIN_USER" "$admin_user"
  set_env "LOCAL_ADMIN_PASS" "$admin_pass"
  ok "Admin account configured"

  # ── 4. Wazuh connection ───────────────────────────────────────────────
  echo ""
  log "Wazuh Connection"
  if [ "$WAZUH_HOST_MODE" = "true" ]; then
    info "Package-based mode: connecting to Wazuh on this host via Docker bridge"
    set_env "WAZUH_HOST" "host.docker.internal"
    set_env "WAZUH_INDEXER_HOST" "host.docker.internal"
    ok "WAZUH_HOST set to host.docker.internal"
  else
    info "Docker mode: connecting to Wazuh containers on shared network"
    # Auto-detect Wazuh network
    local detected_net=""
    detected_net=$(docker network ls --format '{{.Name}}' 2>/dev/null | grep -i 'wazuh\|single-node' | head -1 || true)
    if [ -n "$detected_net" ]; then
      ok "Auto-detected Wazuh network: ${detected_net}"
      set_env "WAZUH_NETWORK" "$detected_net"
    else
      local wazuh_net
      wazuh_net=$(prompt "Wazuh Docker network name" "single-node_default")
      set_env "WAZUH_NETWORK" "$wazuh_net"
    fi

    # Auto-detect Wazuh manager container name
    local detected_mgr=""
    detected_mgr=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i 'wazuh.*manager\|wazuh\.manager' | head -1 || true)
    if [ -n "$detected_mgr" ]; then
      ok "Auto-detected Wazuh Manager container: ${detected_mgr}"
      set_env "WAZUH_HOST" "$detected_mgr"
    else
      local wazuh_host
      wazuh_host=$(prompt "Wazuh Manager hostname" "wazuh.manager")
      set_env "WAZUH_HOST" "$wazuh_host"
    fi

    # Auto-detect Wazuh indexer container name
    local detected_idx=""
    detected_idx=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i 'wazuh.*indexer\|wazuh\.indexer' | head -1 || true)
    if [ -n "$detected_idx" ]; then
      ok "Auto-detected Wazuh Indexer container: ${detected_idx}"
      set_env "WAZUH_INDEXER_HOST" "$detected_idx"
    else
      local wazuh_idx_host
      wazuh_idx_host=$(prompt "Wazuh Indexer hostname" "wazuh.indexer")
      set_env "WAZUH_INDEXER_HOST" "$wazuh_idx_host"
    fi
  fi

  echo ""
  log "Wazuh API Credentials"
  info "These are the credentials for the Wazuh Manager API (port 55000)."
  local wazuh_user wazuh_pass
  wazuh_user=$(prompt "Wazuh API username" "wazuh-wui")
  wazuh_pass=$(prompt_secret "Wazuh API password")
  if [ -n "$wazuh_pass" ]; then
    set_env "WAZUH_USER" "$wazuh_user"
    set_env "WAZUH_PASS" "$wazuh_pass"
    ok "Wazuh Manager credentials set"
  else
    warn "No Wazuh password provided — you can set WAZUH_PASS in .env later"
  fi

  echo ""
  log "Wazuh Indexer Credentials"
  info "These are the credentials for the Wazuh Indexer / OpenSearch (port 9200)."
  local idx_user idx_pass
  idx_user=$(prompt "Indexer username" "admin")
  idx_pass=$(prompt_secret "Indexer password")
  if [ -n "$idx_pass" ]; then
    set_env "WAZUH_INDEXER_USER" "$idx_user"
    set_env "WAZUH_INDEXER_PASS" "$idx_pass"
    ok "Wazuh Indexer credentials set"
  else
    warn "No Indexer password provided — you can set WAZUH_INDEXER_PASS in .env later"
  fi

  echo ""
  ok "Setup complete! Configuration saved to .env"
}

# ── Fix placeholder values in existing .env ───────────────────────────────
fix_placeholders() {
  log "Fixing placeholder values..."

  # Auto-fix JWT_SECRET
  local jwt_val=$(get_env "JWT_SECRET")
  if [ -z "$jwt_val" ] || [[ "$jwt_val" == *"CHANGE_ME"* ]]; then
    local jwt_secret
    if command -v openssl &> /dev/null; then
      jwt_secret=$(openssl rand -hex 32)
    else
      jwt_secret=$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 64)
    fi
    set_env "JWT_SECRET" "$jwt_secret"
    ok "JWT_SECRET auto-generated"
  fi

  # Auto-fix MySQL passwords
  local db_root=$(get_env "MYSQL_ROOT_PASSWORD")
  if [[ "$db_root" == *"change_me"* ]]; then
    local pw
    if command -v openssl &> /dev/null; then pw=$(openssl rand -hex 16); else pw=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 32); fi
    set_env "MYSQL_ROOT_PASSWORD" "$pw"
    ok "MYSQL_ROOT_PASSWORD auto-generated"
  fi

  local db_user=$(get_env "MYSQL_PASSWORD")
  if [[ "$db_user" == *"change_me"* ]]; then
    local pw
    if command -v openssl &> /dev/null; then pw=$(openssl rand -hex 16); else pw=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 32); fi
    set_env "MYSQL_PASSWORD" "$pw"
    ok "MYSQL_PASSWORD auto-generated"
  fi

  # Prompt for Wazuh/admin passwords that are still CHANGE_ME
  local wazuh_pass=$(get_env "WAZUH_PASS")
  if [[ "$wazuh_pass" == *"CHANGE_ME"* ]]; then
    echo ""
    info "Wazuh Manager API password is still a placeholder."
    local new_pass
    new_pass=$(prompt_secret "Wazuh API password (WAZUH_PASS)")
    if [ -n "$new_pass" ]; then
      set_env "WAZUH_PASS" "$new_pass"
      ok "WAZUH_PASS updated"
    else
      warn "Skipped — WAZUH_PASS left as placeholder"
    fi
  fi

  local idx_pass=$(get_env "WAZUH_INDEXER_PASS")
  if [[ "$idx_pass" == *"CHANGE_ME"* ]]; then
    info "Wazuh Indexer password is still a placeholder."
    local new_pass
    new_pass=$(prompt_secret "Wazuh Indexer password (WAZUH_INDEXER_PASS)")
    if [ -n "$new_pass" ]; then
      set_env "WAZUH_INDEXER_PASS" "$new_pass"
      ok "WAZUH_INDEXER_PASS updated"
    else
      warn "Skipped — WAZUH_INDEXER_PASS left as placeholder"
    fi
  fi

  local admin_pass=$(get_env "LOCAL_ADMIN_PASS")
  if [[ "$admin_pass" == *"CHANGE_ME"* ]]; then
    info "Admin UI password is still a placeholder."
    local new_pass
    new_pass=$(prompt_secret "Admin password (LOCAL_ADMIN_PASS)")
    if [ -n "$new_pass" ]; then
      set_env "LOCAL_ADMIN_PASS" "$new_pass"
      ok "LOCAL_ADMIN_PASS updated"
    else
      warn "Skipped — LOCAL_ADMIN_PASS left as placeholder"
    fi
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

  # ── First-run or stale-template setup ────────────────────────────────────
  local run_setup=false

  if [ ! -f ".env" ]; then
    if [ ! -f "env.docker.template" ]; then
      err "No .env file and no env.docker.template found."
      exit 1
    fi
    run_setup=true
  else
    # Detect if .env is an unmodified template copy (e.g., from a previous failed run)
    local jwt_val=$(grep "^JWT_SECRET=" .env 2>/dev/null | cut -d'=' -f2-)
    if [ -z "$jwt_val" ] || [[ "$jwt_val" == *"CHANGE_ME"* ]]; then
      warn ".env exists but has placeholder credentials — re-running setup..."
      run_setup=true
    fi
  fi

  if [ "$run_setup" = "true" ]; then
    echo ""
    first_run_setup
    echo ""
  fi
  ok ".env file found"

  # ── Validate critical values (should be set by now) ────────────────────
  local jwt_val=$(grep "^JWT_SECRET=" .env 2>/dev/null | cut -d'=' -f2-)
  if [ -z "$jwt_val" ] || [[ "$jwt_val" == *"CHANGE_ME"* ]]; then
    err "JWT_SECRET is still not set. Cannot continue."
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

cmd_update() {
  setup_compose_files

  echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${PURPLE}║${NC}  ${GREEN}Dang! SIEM — Update${NC}                                        ${PURPLE}║${NC}"
  echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""

  # ── 1. Pull latest code ────────────────────────────────────────────────
  log "Pulling latest code..."
  if git rev-parse --is-inside-work-tree &> /dev/null; then
    local branch
    branch=$(git rev-parse --abbrev-ref HEAD)
    local before
    before=$(git rev-parse HEAD)

    git pull origin "$branch" --ff-only 2>&1 || {
      err "git pull failed. Resolve conflicts manually, then re-run ./deploy.sh --update"
      exit 1
    }

    local after
    after=$(git rev-parse HEAD)
    if [ "$before" = "$after" ]; then
      ok "Already up to date (${branch})"
    else
      local count
      count=$(git rev-list --count "${before}..${after}")
      ok "Pulled ${count} new commit(s) on ${branch}"
      echo ""
      git --no-pager log --oneline "${before}..${after}"
      echo ""
    fi
  else
    warn "Not a git repo — skipping code pull"
  fi

  # ── 2. Rebuild the app image ───────────────────────────────────────────
  log "Rebuilding Docker image..."
  docker compose $COMPOSE_FILES build --no-cache app
  ok "Image rebuilt"

  # ── 3. Restart app container (DB stays up) ─────────────────────────────
  log "Restarting app container..."
  docker compose $COMPOSE_FILES up -d --no-deps app
  ok "App container restarted"

  # ── 4. Health check ────────────────────────────────────────────────────
  log "Waiting for health check..."
  local retries=0
  local max_retries=12
  sleep 5
  while [ $retries -lt $max_retries ]; do
    if docker compose $COMPOSE_FILES exec -T app curl -sf http://localhost:3000/api/health > /dev/null 2>&1; then
      ok "Application is healthy!"
      break
    fi
    retries=$((retries + 1))
    sleep 5
  done

  if [ $retries -eq $max_retries ]; then
    warn "Health check did not pass within 60s. Check logs with: ./deploy.sh --logs"
  else
    echo ""
    ok "Update complete!"
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
  --update)
    cmd_update
    ;;
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
