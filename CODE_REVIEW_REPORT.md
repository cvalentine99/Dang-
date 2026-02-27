# Dang! SIEM — Multi-Agent Code Review Report

**Date:** February 27, 2026
**Scope:** Full codebase review — architecture, security, code quality, testing, performance, DevOps
**Method:** 3 parallel review agents (Architecture, Code Quality, Security/Testing) + manual verification
**Branch:** `claude/multi-agent-code-review-QAK5D`

---

## Executive Summary

**Overall Assessment: Production-Ready with Strong Security Posture**

Dang! SIEM is a well-architected analyst-grade web application for visualizing and correlating Wazuh security telemetry. The codebase demonstrates mature engineering practices:

- **339/339 tests passing** across 25 test files
- TypeScript strict mode with Drizzle ORM (SQL injection safe by design)
- JWT + bcrypt local authentication with AES-256-GCM encryption for stored credentials
- Non-root Docker container with Tini init, health checks, and multi-stage builds
- Server-side credential management — tokens never reach the browser
- Read-only by default for all Wazuh data access
- Per-endpoint rate limiting on external API calls

Key areas for improvement: frontend testing gap (zero component tests), some code duplication across clients, a few minor bugs, and hardcoded configuration values.

| Review Area | Critical | High | Medium | Low |
|---|---|---|---|---|
| Architecture | 0 | 1 | 2 | 1 |
| Security | 1 | 2 | 3 | 1 |
| Code Quality | 1 | 2 | 3 | 2 |
| Database | 0 | 1 | 1 | 1 |
| Testing | 0 | 1 | 2 | 1 |
| Performance | 0 | 1 | 2 | 0 |
| DevOps | 0 | 0 | 2 | 1 |
| **Total** | **2** | **8** | **15** | **7** |

---

## 1. Architecture Review

### Stack

| Layer | Technology |
|---|---|
| Frontend | React 19.2 + TypeScript 5.9 + Vite 7.3 |
| UI Library | shadcn/ui (50+ Radix primitives) + Tailwind CSS 4 |
| Routing | wouter 3.3 (lightweight, 1.5KB) |
| API Layer | tRPC 11.10 (end-to-end type safety) |
| Server | Express 4.21 + Node 22 |
| Database | MySQL 8 via Drizzle ORM 0.44 |
| Auth | JWT (jose 6.1) + bcrypt (bcryptjs 3.0) |
| Visualization | Recharts 2.15 + D3 7.9 + Leaflet 1.9 |
| AI | Gemini 2.5 Flash (built-in) + custom LLM support |

### Strengths

- **Clean tRPC composition** — 16 routers composed in `server/routers.ts` with clear separation of concerns
- **Read-only Wazuh proxy** — All Wazuh endpoints are GET-only, enforced at the client level (`server/wazuh/wazuhClient.ts:177-224`)
- **Server-side credential management** — Wazuh/Indexer credentials stored server-side; JWT tokens cached in-memory with 60s expiry buffer (`server/wazuh/wazuhClient.ts:42-49`)
- **Encryption at rest** — AES-256-GCM for stored connection settings (`server/admin/encryptionService.ts`)
- **Health infrastructure** — Comprehensive `/api/health` and `/api/status` endpoints with parallel checks for DB, Wazuh Manager, and Wazuh Indexer (`server/_core/index.ts:53-198`)
- **Rate limiting** — Token-bucket rate limiter per endpoint group with configurable limits (`server/wazuh/wazuhClient.ts:52-71`)
- **28 frontend pages** with ErrorBoundary at app root and dark theme ("Amethyst Nexus")

### Areas for Improvement

| Severity | Finding | Location |
|---|---|---|
| HIGH | Module-level global state for token caching and SSE polling creates potential race conditions under concurrent requests | `server/wazuh/wazuhClient.ts:49`, `server/sse/alertStreamService.ts:56-58` |
| MEDIUM | Some page components are very large and should be decomposed | `ITHygiene.tsx` (1555 lines), `SiemEvents.tsx` (1537 lines), `ComponentShowcase.tsx` (1437 lines), `ThreatHunting.tsx` (1110 lines) |
| MEDIUM | No foreign key constraints in Drizzle schema — relying on application-level referential integrity | `drizzle/schema.ts` (all tables) |
| LOW | `passwordHash` stripped manually in the auth.me procedure rather than using a schema-level transform | `server/routers.ts:26` |

---

## 2. Security Analysis

### Positive Security Controls

- **SQL injection**: Mitigated by Drizzle ORM parameterized queries throughout
- **Authentication**: JWT with jose library + bcrypt (SALT_ROUNDS=12) for password hashing
- **Sensitive field stripping**: Recursive removal of password/token/secret/api_key/key/auth/credential fields from all Wazuh responses (`server/wazuh/wazuhClient.ts:74-96`)
- **Non-root Docker**: Container runs as `dang` user (`Dockerfile:71-73`)
- **Health check hardening**: No version/uptime info leakage in health endpoints
- **Boot-time validation**: Environment variables validated at startup with clear diagnostics (`server/_core/envValidation.ts`)
- **Disabled user blocking**: Login rejected for disabled accounts (`server/localAuth/localAuthService.ts:132-134`)
- **Dependency overrides**: Known vulnerable packages pinned to safe versions in `package.json:124-135`

### Findings

| Severity | Finding | Location | Details |
|---|---|---|---|
| CRITICAL | TLS certificate verification disabled | `server/wazuh/wazuhClient.ts:103` | `rejectUnauthorized: false` in HTTPS agent. Required for self-signed Wazuh certs, but should be configurable via env var (e.g., `WAZUH_TLS_VERIFY=false`) so production deployments with proper certs can enable verification. |
| HIGH | Single secret for dual purpose | `server/admin/encryptionService.ts:14-17` | `JWT_SECRET` used for both JWT signing AND AES-256 key derivation via SHA-256. Compromise of this single secret breaks both session integrity and stored credential encryption. Recommend separate `ENCRYPTION_KEY` env var. |
| HIGH | First user auto-promoted to admin | `server/localAuth/localAuthService.ts:47-48` | If registration endpoint is exposed before admin seeds (e.g., `LOCAL_ADMIN_USER` not set), any first visitor becomes admin. Mitigated by Docker's default `LOCAL_ADMIN_USER` seeding but risky in misconfigured deployments. |
| MEDIUM | Body parser limit at 50MB | `server/_core/index.ts:50` | `express.json({ limit: "50mb" })` allows large request payloads. Could enable memory-intensive DoS. Consider reducing to 10MB for most endpoints, with selective increase only for file upload routes. |
| MEDIUM | `dangerouslySetInnerHTML` in chart component | `client/src/components/ui/chart.tsx:80-99` | Used in shadcn/ui `ChartStyle` component to inject CSS variables. Low risk — data comes from application config objects, not user input. |
| MEDIUM | JWT_SECRET length warning but not enforced | `server/_core/envValidation.ts:202-210` | Warns if JWT_SECRET < 32 chars but doesn't block startup. In production, short secrets are a real risk. |
| LOW | In-memory rate limiter not shared across instances | `server/wazuh/wazuhClient.ts:52` | Acceptable for single-instance Docker deployment. Document that multi-instance deployments need Redis-based rate limiting. |

---

## 3. Code Quality

### Bugs Found

| Severity | Bug | Location | Details |
|---|---|---|---|
| CRITICAL | `registerLocalUser` returns `id: 0` | `server/localAuth/localAuthService.ts:87-88` | After `db.insert()`, the function returns `{ id: 0, ... }` with a comment "Will be set by auto-increment". This is incorrect — the caller receives `id: 0` instead of the actual database-generated ID. Should query the inserted row or use `insertId` from the result. |
| HIGH | `getUserCount()` fetches all rows | `server/localAuth/localAuthService.ts:219-225` | `db.select({ id: users.id }).from(users)` loads all user IDs into memory and returns `result.length`. Should use SQL `COUNT(*)` instead: `db.select({ count: sql\`count(*)\` }).from(users)`. |
| HIGH | Silent error swallowing in auth context | `server/_core/context.ts:16-21` | `catch (error) { user = null; }` silently swallows all authentication errors. While auth is optional for public procedures, this hides legitimate errors (e.g., database connection failures) that should be logged. |

### Anti-Patterns

| Severity | Pattern | Locations | Recommendation |
|---|---|---|---|
| MEDIUM | Widespread unsafe type casts | `server/hybridrag/`, `server/graph/`, `server/sse/alertStreamService.ts:169-188` | 8+ instances of `as unknown` / `as Record<string, unknown>` without runtime validation. Add Zod schemas for external API response shapes. |
| MEDIUM | Hardcoded configuration values | `server/_core/llm.ts:283` (`"gemini-2.5-flash"`), `server/sse/alertStreamService.ts:67` (`DEFAULT_SEVERITY_THRESHOLD = 10`) | Extract to env vars or a central config module. |
| MEDIUM | No Zod validation for external API responses | `server/wazuh/wazuhClient.ts`, `server/indexer/indexerClient.ts` | Wazuh and Indexer responses are used raw with type assertions. Runtime schema validation would catch API version mismatches early. |
| LOW | Inconsistent logging prefixes | Various server files | Some use structured prefixes like `[Wazuh Auth]`, `[Database]`, `[LocalAuth]`; others use raw `console.error()`. Recommend a centralized logger utility. |
| LOW | Magic numbers without named constants | `server/sse/alertStreamService.ts`, `server/_core/index.ts` | e.g., `5_000` timeout, `840_000` fallback expiry. Already mostly well-named, but a few scattered literals remain. |

### Code Duplication

| Finding | Files | Recommendation |
|---|---|---|
| `stripSensitiveFields()` duplicated verbatim | `server/wazuh/wazuhClient.ts:84-96` and `server/indexer/indexerClient.ts:49-61` | Extract to `server/_shared/security.ts` |
| `checkRateLimit()` duplicated with identical logic | `server/wazuh/wazuhClient.ts:61-71` and `server/indexer/indexerClient.ts:30-42` | Extract to `server/_shared/rateLimit.ts` |
| Config loading pattern (getConfig / isConfigured / getEffectiveConfig) | `server/wazuh/wazuhClient.ts:227-269` and `server/indexer/indexerClient.ts:72-120` | Similar structure could share a factory function |

---

## 4. Database Design

### Schema Overview

- **25+ tables** across 11 migrations in `drizzle/schema.ts` (544 lines)
- **Core tables**: `users`, `analyst_notes`, `analyst_notes_v2`, `rag_sessions`, `saved_searches`, `config_baselines`, `investigation_sessions`, `investigation_notes`, `connection_settings`, `llm_usage`, `alert_queue`
- **Knowledge Graph** (4-layer Nemotron-3 architecture): `kg_endpoints`, `kg_parameters`, `kg_responses`, `kg_auth_methods`, `kg_resources`, `kg_use_cases`, `kg_indices`, `kg_fields`, `kg_error_patterns`, `kg_trust_history`, `kg_answer_provenance`, `kg_sync_status`

### Strengths

- Good indexing strategy on frequently-queried columns with composite indexes on Knowledge Graph tables
- JSON columns used appropriately for flexible/schemaless telemetry data (tags, evidence, filters, triageResult)
- Proper use of `onUpdateNow()` for `updatedAt` timestamps
- `analyst_notes_v2` has 4 indexes including composite `(entityType, entityId)` for efficient entity lookups

### Findings

| Severity | Finding | Location | Details |
|---|---|---|---|
| HIGH | Inefficient user count query | `server/localAuth/localAuthService.ts:223` | `db.select({ id: users.id }).from(users)` fetches entire table. Use `SELECT COUNT(*)` instead. |
| MEDIUM | No foreign key constraints | `drizzle/schema.ts` | `userId`, `sessionId`, `endpointId` columns reference other tables but have no FK constraints. Application-level integrity only. This may be intentional (Drizzle ORM trade-off) but should be documented. |
| LOW | `isDisabled` and `resolved` use `int` instead of `boolean` | `drizzle/schema.ts:25,57` | MySQL-compatible choice but sacrifices readability. Could use Drizzle's `boolean()` type. |

---

## 5. Testing Coverage

### Current State: 339/339 Tests Passing

**25 test files** covering server-side logic:

| Test File | Domain |
|---|---|
| `localAuth.test.ts` | Registration, login, password hashing, disabled accounts |
| `adminUsers.test.ts` | User management, role changes, self-protection |
| `connectionSettings.test.ts` | AES-256 encryption, setting CRUD |
| `auth.logout.test.ts` | Session termination |
| `notesRouter.test.ts` | Analyst notes CRUD |
| `wazuhRouter.test.ts` | Wazuh API proxy |
| `wazuhConnectivity.test.ts` | Connection testing |
| `wazuhConnection.test.ts` | Connection management |
| `wazuhSpecCoverage.test.ts` | API spec coverage verification |
| `indexerRouter.test.ts` | Indexer queries |
| `hybridragRouter.test.ts` | AI assistant pipeline |
| `otxRouter.test.ts` | AlienVault OTX integration |
| `graph.test.ts` | Knowledge Graph CRUD |
| `baselinesRouter.test.ts` | Configuration baselines |
| `savedSearchesRouter.test.ts` | Saved searches |
| `alertQueueRouter.test.ts` | Alert queue management |
| `queueNotifier.test.ts` | Queue notifications |
| `alertStreamService.test.ts` | SSE alert streaming |
| `splunkConfig.test.ts` | Splunk ES configuration |
| `splunkRouter.test.ts` | Splunk HEC integration |
| `llmConfig.test.ts` | LLM configuration |
| `llmRouter.test.ts` | LLM router endpoints |
| `llmService.test.ts` | LLM service logic |
| `exportUtils.test.ts` | Data export utilities |
| `soundEngine.test.ts` | Audio notification engine |

### Quality Highlights

- Access control tests verify unauthenticated and wrong-role rejections
- Self-protection tests prevent admins from demoting/disabling themselves
- Wazuh API spec coverage tests verify all endpoints are implemented
- Integration tests run against real MySQL in CI

### Gaps

| Severity | Gap | Recommendation |
|---|---|---|
| HIGH | Zero frontend tests | No component tests, integration tests, or E2E tests for 28 pages. At minimum, add tests for auth flows (Login, Register) and critical dashboard components. |
| MEDIUM | No coverage reporting | Add `vitest --coverage` to CI and set minimum thresholds. |
| MEDIUM | No E2E tests | Add Playwright tests for critical user journeys (login → dashboard → alerts → notes). |
| LOW | No performance/load tests | Consider k6 or Artillery for SSE streaming and concurrent API load. |

---

## 6. Performance Considerations

| Severity | Finding | Location | Details |
|---|---|---|---|
| HIGH | SSE polling race condition | `server/sse/alertStreamService.ts:58,111` | Global `isPolling` flag prevents concurrent polls, but under high concurrency the flag check + set is not atomic. For single-instance Docker deployment this is low risk, but worth noting. |
| MEDIUM | Large page components impact bundle | `client/src/pages/ITHygiene.tsx` (1555 lines), `SiemEvents.tsx` (1537 lines) | Components this large may resist effective code splitting. Decompose into smaller sub-components for better lazy-loading. |
| MEDIUM | 50MB body parser on all routes | `server/_core/index.ts:50` | Memory-intensive for a server that mostly handles JSON API calls. Apply route-specific limits. |

### Well-Designed

- Token caching with 60s buffer before expiry avoids unnecessary re-authentication
- SSE heartbeat (15s) with client cleanup on disconnect prevents connection leaks
- Polling auto-starts only when clients connect, auto-stops when all disconnect
- Rate limiting prevents accidental Wazuh API flooding

---

## 7. DevOps & Deployment

### Current State

- **Docker**: Multi-stage build (deps → build → production) with non-root user, Tini init, health checks
- **CI**: GitHub Actions — typecheck → test (MySQL service) → build verification
- **Multi-platform**: Docker builds for amd64 + arm64 with GHCR push
- **Dependabot**: Configured for npm, GitHub Actions, and Docker ecosystems
- **Security overrides**: pnpm overrides for `qs`, `fast-xml-parser`, `tar`, `lodash`, `minimatch` vulnerabilities

### Findings

| Severity | Finding | Recommendation |
|---|---|---|
| MEDIUM | No SAST scanning in CI | Add CodeQL or Semgrep GitHub Action for static analysis. |
| MEDIUM | No container image scanning | Add Trivy or Grype to scan the production Docker image. |
| LOW | `pnpm install --prod=false` in production stage | Dockerfile comment explains this is needed for Vite path resolution, but it bloats the production image with dev dependencies. |

---

## 8. Prioritized Recommendations

### Critical (Fix Now)

1. **Fix `registerLocalUser` returning `id: 0`** — Query the actual inserted ID after `db.insert()` or use the `insertId` from the MySQL result.
   - File: `server/localAuth/localAuthService.ts:87-88`

2. **Make TLS verification configurable** — Add `WAZUH_TLS_VERIFY` env var (default `false` for backward compatibility) to allow production deployments with proper certificates.
   - File: `server/wazuh/wazuhClient.ts:103`

### High (Next Sprint)

3. **Replace `getUserCount()` with SQL COUNT** — Avoid loading all user rows into memory.
   - File: `server/localAuth/localAuthService.ts:219-225`

4. **Log auth context errors** — Add `console.warn` in the auth context catch block to surface database/JWT errors.
   - File: `server/_core/context.ts:16-21`

5. **Extract duplicated utilities** — Move `stripSensitiveFields()` and `checkRateLimit()` to `server/_shared/`.
   - Files: `server/wazuh/wazuhClient.ts`, `server/indexer/indexerClient.ts`

6. **Separate encryption key** — Add `ENCRYPTION_KEY` env var for AES-256 encryption, independent of `JWT_SECRET`.
   - File: `server/admin/encryptionService.ts:14-17`

7. **Add frontend component tests** — Start with Login, Register, and DashboardLayout components using Vitest + Testing Library.

8. **Make hardcoded values configurable** — LLM model name (`"gemini-2.5-flash"`), severity threshold (`10`), body parser limit (`50mb`).
   - Files: `server/_core/llm.ts:283`, `server/sse/alertStreamService.ts:67`, `server/_core/index.ts:50`

### Medium (Backlog)

9. **Add Zod validation for external API responses** — Runtime schema validation for Wazuh Manager and Indexer responses to catch API version mismatches.

10. **Add SAST and container scanning to CI** — CodeQL/Semgrep for static analysis, Trivy for Docker image scanning.

11. **Add coverage reporting** — `vitest --coverage` in CI with minimum thresholds.

12. **Document missing FK constraints** — Add ADR explaining why foreign keys are omitted (Drizzle ORM trade-off).

13. **Decompose large page components** — Break ITHygiene.tsx (1555 lines), SiemEvents.tsx (1537 lines), ThreatHunting.tsx (1110 lines) into sub-components.

14. **Centralized logging utility** — Replace inconsistent `console.log`/`console.error` with structured logger that includes timestamps, levels, and consistent prefixes.

### Low (Nice-to-Have)

15. **Add E2E tests with Playwright** — Critical user journeys: login → dashboard → alerts → notes workflow.

16. **Enforce JWT_SECRET minimum length** — Block startup if JWT_SECRET < 32 chars in production mode.

17. **Remove unused dev dependencies** — `add` (v2.0.6) appears to be an accidental install.

18. **Architecture Decision Records** — Document key design decisions (local-only auth, no FK constraints, in-memory rate limiting, Knowledge Graph 4-layer architecture).

---

## Files Referenced

| File | Lines | Key Findings |
|---|---|---|
| `server/_core/index.ts` | 234 | Server entry point, 50MB body parser, health checks |
| `server/_core/context.ts` | 28 | tRPC auth context, silent error swallowing |
| `server/_core/envValidation.ts` | 233 | Boot-time env validation, JWT_SECRET length warning |
| `server/_core/llm.ts` | ~300 | Hardcoded `"gemini-2.5-flash"` model |
| `server/routers.ts` | 78 | 16-router tRPC composition |
| `server/wazuh/wazuhClient.ts` | 269 | Wazuh proxy, rate limiting, token management, TLS skip |
| `server/indexer/indexerClient.ts` | ~200 | Duplicated rate limiting and field stripping |
| `server/localAuth/localAuthService.ts` | 225 | Auth service, `id: 0` bug, inefficient count |
| `server/admin/encryptionService.ts` | 60 | AES-256-GCM, JWT_SECRET dual use |
| `server/sse/alertStreamService.ts` | 306 | SSE streaming, race condition risk |
| `client/src/App.tsx` | 100 | 28-route frontend, ErrorBoundary |
| `client/src/components/ui/chart.tsx` | ~200 | `dangerouslySetInnerHTML` (low risk) |
| `drizzle/schema.ts` | 544 | 25+ tables, Knowledge Graph, no FK constraints |
| `.github/workflows/ci.yml` | 157 | CI pipeline, MySQL service |
| `Dockerfile` | 87 | Multi-stage build, non-root, Tini, health check |

---

## Previous Review (Feb 22, 2026) — Status

The previous multi-agent review identified and fixed 7 issues:

1. Non-root container user — **FIXED**
2. Tini init system — **FIXED**
3. Static file path resolution — **FIXED**
4. Static asset caching — **FIXED**
5. Database indexes on `analyst_notes_v2` — **FIXED**
6. Health endpoint hardening — **FIXED**
7. MySQL UTC timezone — **FIXED**

This review builds on that work with deeper analysis of code quality, testing coverage, and architectural patterns.
