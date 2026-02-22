# Dang! SIEM — Docker Deployment Guide

Self-hosted deployment of Dang! SIEM on Linux x86_64 systems using Docker.

---

## Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 22.04+ x86_64 | Ubuntu 24.04 LTS |
| Kernel | 5.15+ | 6.8+ |
| Docker | 24.0+ | 27.0+ |
| Docker Compose | v2.20+ | v2.30+ |
| RAM | 2 GB | 4 GB |
| Disk | 5 GB | 20 GB |
| Wazuh Manager | 4.7+ | 4.9+ |

The application connects to your **existing Wazuh Manager API** and **Wazuh Indexer (OpenSearch)**. It does not install or manage Wazuh itself.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/cvalentine99/Dang-.git
cd Dang-

# 2. Create environment file from template
cp env.docker.template .env

# 3. Edit .env with your credentials
nano .env
#    Required: JWT_SECRET, WAZUH_HOST, WAZUH_USER, WAZUH_PASS
#    Generate JWT_SECRET: openssl rand -hex 32

# 4. Build and start
chmod +x deploy.sh
./deploy.sh
```

The application will be available at **http://localhost:3000** (or the port configured in `APP_PORT`).

---

## Environment Variables

### Required

| Variable | Description | Example |
|---|---|---|
| `JWT_SECRET` | Session signing key (generate with `openssl rand -hex 32`) | `a1b2c3d4e5f6...` |
| `WAZUH_HOST` | Wazuh Manager hostname or IP | `192.168.50.213` |
| `WAZUH_USER` | Wazuh API username | `wazuh-wui` |
| `WAZUH_PASS` | Wazuh API password | `MySecretPass` |

### Wazuh Indexer (Required for SIEM Events and Threat Hunting)

| Variable | Description | Default |
|---|---|---|
| `WAZUH_INDEXER_HOST` | Indexer hostname or IP | *(none)* |
| `WAZUH_INDEXER_PORT` | Indexer port | `9200` |
| `WAZUH_INDEXER_USER` | Indexer username | *(none)* |
| `WAZUH_INDEXER_PASS` | Indexer password | *(none)* |
| `WAZUH_INDEXER_PROTOCOL` | `https` or `http` | `https` |

### Database

| Variable | Description | Default |
|---|---|---|
| `MYSQL_ROOT_PASSWORD` | MySQL root password | `dang_root_secret` |
| `MYSQL_DATABASE` | Database name | `dang` |
| `MYSQL_USER` | Application DB user | `dang` |
| `MYSQL_PASSWORD` | Application DB password | `dang_db_secret` |

### Optional

| Variable | Description | Default |
|---|---|---|
| `APP_PORT` | External web UI port | `3000` |
| `DB_EXTERNAL_PORT` | External MySQL port | `3306` |
| `RUN_MIGRATIONS` | Run DB migrations on startup | `true` |
| `OTX_API_KEY` | AlienVault OTX API key for threat intel | *(none)* |
| `VITE_APP_TITLE` | Application title | `Dang! SIEM` |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Docker Host (Linux x86_64)                         │
│                                                     │
│  ┌──────────────┐    ┌──────────────┐               │
│  │  dang-app    │    │  dang-db     │               │
│  │  (Node 22)   │───▶│  (MySQL 8)   │               │
│  │  :3000       │    │  :3306       │               │
│  └──────┬───────┘    └──────────────┘               │
│         │                                           │
└─────────┼───────────────────────────────────────────┘
          │
          ▼
┌─────────────────────┐    ┌─────────────────────┐
│  Wazuh Manager API  │    │  Wazuh Indexer       │
│  :55000 (HTTPS)     │    │  :9200 (HTTPS)       │
└─────────────────────┘    └─────────────────────┘
```

The application acts as a **read-only proxy** to Wazuh. All API calls flow through the backend, which enforces authentication, rate limiting, and field filtering. No Wazuh tokens are ever exposed to the browser.

---

## Deploy Script Commands

```bash
./deploy.sh              # Build and start all services
./deploy.sh --rebuild    # Force rebuild without Docker cache
./deploy.sh --stop       # Stop all services
./deploy.sh --logs       # Follow container logs
./deploy.sh --status     # Show service status + health check
```

---

## Manual Docker Commands

```bash
# Build the image
docker compose build

# Start in background
docker compose up -d

# View logs
docker compose logs -f app

# Stop services
docker compose down

# Stop and remove volumes (WARNING: deletes database)
docker compose down -v

# Rebuild after code changes
docker compose build --no-cache && docker compose up -d
```

---

## Database Migrations

Migrations run automatically on startup when `RUN_MIGRATIONS=true`. For manual control:

```bash
# Disable auto-migration
RUN_MIGRATIONS=false

# Run migrations manually
docker compose exec app npx drizzle-kit migrate
```

---

## Health Check

The application exposes a health endpoint at `/api/health`:

```bash
curl http://localhost:3000/api/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2026-02-22T14:00:00.000Z",
  "database": "connected"
}
```

Docker uses this endpoint for automatic health monitoring. Unhealthy containers are restarted automatically with the `unless-stopped` restart policy.

---

## Network Configuration

### Firewall Rules

The application needs outbound access to your Wazuh infrastructure:

```bash
# Allow outbound to Wazuh Manager API
sudo ufw allow out to <WAZUH_HOST> port 55000

# Allow outbound to Wazuh Indexer
sudo ufw allow out to <WAZUH_INDEXER_HOST> port 9200

# Allow inbound to web UI
sudo ufw allow in 3000/tcp
```

### Self-Signed Certificates

The application accepts self-signed TLS certificates from Wazuh Manager and Indexer by default (`rejectUnauthorized: false`). This is standard for internal Wazuh deployments.

---

## Reverse Proxy (Optional)

### Nginx

```nginx
server {
    listen 443 ssl;
    server_name dang.yourdomain.com;

    ssl_certificate     /etc/ssl/certs/dang.crt;
    ssl_certificate_key /etc/ssl/private/dang.key;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Caddy

```
dang.yourdomain.com {
    reverse_proxy localhost:3000
}
```

---

## Troubleshooting

### Application won't start

```bash
# Check logs
docker compose logs app

# Verify database is healthy
docker compose exec db mysqladmin ping -h localhost -u root -p

# Test Wazuh connectivity from inside the container
docker compose exec app curl -k https://<WAZUH_HOST>:55000/ -u <WAZUH_USER>:<WAZUH_PASS>
```

### Database connection errors

```bash
# Check if MySQL is running
docker compose ps db

# Check MySQL logs
docker compose logs db

# Verify DATABASE_URL is correct
docker compose exec app env | grep DATABASE_URL
```

### Build failures

```bash
# Clean Docker build cache
docker builder prune -f

# Rebuild from scratch
docker compose build --no-cache
```

### Port conflicts

If port 3000 or 3306 is already in use, change `APP_PORT` or `DB_EXTERNAL_PORT` in `.env`:

```bash
APP_PORT=8080
DB_EXTERNAL_PORT=3307
```

---

## Updating

```bash
# Pull latest code
git pull origin main

# Rebuild and restart
./deploy.sh --rebuild

# Or manually
docker compose build --no-cache
docker compose up -d
```

---

## Backup & Restore

### Database Backup

```bash
# Backup
docker compose exec db mysqldump -u root -p${MYSQL_ROOT_PASSWORD} ${MYSQL_DATABASE} > backup_$(date +%Y%m%d).sql

# Restore
docker compose exec -T db mysql -u root -p${MYSQL_ROOT_PASSWORD} ${MYSQL_DATABASE} < backup_20260222.sql
```

### Volume Backup

```bash
# Stop services first
docker compose stop

# Backup volume
docker run --rm -v dang_dang-db-data:/data -v $(pwd):/backup alpine tar czf /backup/db-volume-backup.tar.gz -C /data .

# Restore volume
docker run --rm -v dang_dang-db-data:/data -v $(pwd):/backup alpine sh -c "cd /data && tar xzf /backup/db-volume-backup.tar.gz"

# Restart
docker compose start
```

---

## Security Notes

The application follows a strict security model:

1. **Read-only Wazuh access** — Only GET endpoints are used. No agent deletion, rule modification, or active response triggers.
2. **Server-side token handling** — Wazuh API tokens are never exposed to the browser or logged.
3. **Rate limiting** — Per-endpoint rate limits prevent overloading the Wazuh API.
4. **Field stripping** — Sensitive fields (passwords, tokens, secrets) are stripped from all API responses.
5. **Non-root container** — The application runs as a non-root user inside the container.
6. **Fail closed** — Auth or network errors show error states rather than degrading silently.

For production deployments, also consider:
- Running behind a reverse proxy with TLS termination
- Restricting network access to the Wazuh Manager and Indexer
- Using Docker secrets instead of environment variables for sensitive values
- Enabling Docker content trust for image verification
