# Dang! SIEM

[![CI](https://github.com/cvalentine99/Dang-/actions/workflows/ci.yml/badge.svg)](https://github.com/cvalentine99/Dang-/actions/workflows/ci.yml)
[![Docker Build](https://github.com/cvalentine99/Dang-/actions/workflows/docker.yml/badge.svg)](https://github.com/cvalentine99/Dang-/actions/workflows/docker.yml)
[![GHCR](https://img.shields.io/badge/ghcr.io-cvalentine99%2Fdang--latest-purple?logo=github)](https://ghcr.io/cvalentine99/dang-)
[![License: MIT](https://img.shields.io/badge/License-MIT-violet.svg)](LICENSE)

An analyst-grade web application that visualizes and correlates **Wazuh security telemetry** — agents, alerts, vulnerabilities, FIM, CIS compliance, and MITRE ATT&CK mappings — through a read-only proxy architecture. Built for SOC analysts on ultrawide monitors.

---

## Features

| Module | Description |
|---|---|
| **SOC Console** | Real-time KPI cards, threat trend charts, top firing rules, geographic distribution |
| **Fleet Command** | Agent health monitoring, OS breakdown, group management, status tracking |
| **Alerts Timeline** | Filterable alert table with severity heatmap, rule details, raw JSON view |
| **SIEM Events** | Full-text search across Wazuh Indexer with field-level filtering |
| **Vulnerabilities** | CVE tracking, severity distribution, top affected packages and agents |
| **MITRE ATT&CK** | Tactic/technique heatmap mapped from Wazuh alert data |
| **Compliance** | CIS-CAT, PCI DSS, HIPAA, GDPR, NIST posture views |
| **Threat Intel** | AlienVault OTX integration for IOC enrichment |
| **Threat Hunting** | Query builder for Wazuh Indexer with saved searches |
| **Analyst Notes** | Database-backed investigation notes attached to alerts, agents, or CVEs |
| **IT Hygiene** | System inventory — packages, ports, processes, services, users |

All data tables include **CSV/JSON export** buttons for offline compliance reporting.

---

## Architecture

```
Browser → [Caddy/Nginx TLS] → Express (Node 22) → Wazuh Manager API (:55000)
                                    ↓                    Wazuh Indexer (:9200)
                                MySQL 8 (analyst notes, sessions)
```

The application acts as a **read-only proxy** to Wazuh. All API calls flow through the backend, which enforces authentication, rate limiting, and field filtering. No Wazuh tokens are ever exposed to the browser.

---

## Quick Start

```bash
git clone https://github.com/cvalentine99/Dang-.git && cd Dang-
cp env.docker.template .env
# Edit .env with your Wazuh credentials and JWT_SECRET
./deploy.sh                    # HTTP on port 3000
./deploy.sh --proxy caddy      # HTTPS with auto Let's Encrypt
./deploy.sh --proxy nginx      # HTTPS with your own certs
```

Or pull the pre-built image from GHCR:

```bash
docker pull ghcr.io/cvalentine99/dang-:latest
```

See **[DOCKER.md](DOCKER.md)** for full deployment documentation including environment variables, HTTPS proxy setup, health checks, and CI/CD pipeline details.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19, TypeScript, Tailwind CSS 4, Recharts, shadcn/ui |
| Backend | Express 4, tRPC 11, Drizzle ORM |
| Database | MySQL 8 (TiDB compatible) |
| Auth | Manus OAuth (optional) / JWT sessions |
| Container | Docker multi-stage, Node 22 slim, tini init |
| CI/CD | GitHub Actions, GHCR, Dependabot |
| Proxy | Caddy (auto TLS) or Nginx (manual TLS) |

---

## Design Language

The UI follows the **Amethyst Nexus** dark theme — glass-morphism panels, purple/violet accents, OKLCH color space, and threat-level semantic colors. Fonts: Space Grotesk (headings), Inter (UI), JetBrains Mono (hashes, agent IDs, JSON).

---

## Security Model

- **Read-only by default** — Only GET endpoints unless explicitly gated
- **Server-side tokens** — Wazuh credentials never reach the browser
- **Rate limiting** — Per-endpoint limits prevent Wazuh API overload
- **Non-root container** — Application runs as unprivileged user
- **Fail closed** — Auth/network errors show error states, no silent degradation
- **Forensic data integrity** — Timestamps, agent IDs, rule IDs preserved as-is

---

## License

MIT
