# Contract Violations Report

**Date:** 2026-03-06
**Scope:** Multi-agent search across API routes, client code, validation/schemas, and runtime/deployment
**Methodology:** Parallel agent analysis of server routes, client API calls, shared schemas, validation logic, deployment configs, and existing audit documentation

---

## Executive Summary

| Category                  | Critical | High | Medium | Low | Total |
|---------------------------|----------|------|--------|-----|-------|
| API Route Violations      | 1        | 2    | 2      | 0   | 5     |
| Client-Side Violations    | 3        | 3    | 3      | 2   | 11    |
| Validation & Schema       | 1        | 2    | 2      | 1   | 6     |
| Runtime & Deployment      | 0        | 1    | 5      | 2   | 8     |
| Environment Configuration | 0        | 1    | 3      | 1   | 5     |
| **Total**                 | **5**    | **9**| **15** | **6**| **35**|

---

## 1. API Route Contract Violations

### 1.1 [CRITICAL] `/vulnerability/{agent_id}` Endpoint Does Not Exist in Wazuh v4.14.3 Spec

**Location:** `server/wazuh/wazuhRouter.ts` — `wazuh.agentVulnerabilities` procedure
**Details:** Calls `proxyGet("/vulnerability/${input.agentId}")` but this endpoint was removed in Wazuh 4.8+. Vulnerability data moved to the Indexer (`wazuh-states-vulnerabilities-*` index). The call returns 404 on Wazuh 4.8+ deployments.
**Evidence:** `audit-findings.md` documents this. The Indexer router (`indexerRouter.ts`) already has the correct queries (`vulnSearch`, `vulnAggBySeverity`, etc.).
**Fix:** Remove the stale REST call or gate it behind a version check. Use Indexer-only queries for vulnerability data.

### 1.2 [HIGH] Deprecated Wazuh Endpoints Still Proxied

**Location:** `server/wazuh/wazuhRouter.ts`
**Details:** `GET /manager/stats/analysisd` and `GET /manager/stats/remoted` are deprecated in v4.14.3 spec but still called from the dashboard (`Home.tsx`). These may be removed in Wazuh 5.0+.
**Fix:** Add deprecation warnings, feature flags, or fallback logic for these endpoints.

### 1.3 [HIGH] Rate Limit Group `"readiness"` Not Defined

**Location:** `server/readiness/readinessService.ts`
**Details:** Calls `wazuhGet` with `rateLimitGroup: "readiness"`, but this group is not registered in `GLOBAL_RATE_LIMITS` or `PER_USER_RATE_LIMITS`. Silently falls back to `default` group.
**Fix:** Add explicit `readiness` group to rate limit configuration.

### 1.4 [MEDIUM] Dashboard-to-tRPC-to-External API Mapping Gaps

**Details:** Based on `audit-findings.md`, the full mapping shows several endpoints where the client calls a tRPC procedure that proxies to an external API, but no contract test validates the full chain (client → tRPC → external).

### 1.5 [MEDIUM] No Versioning Logic for Wazuh API Compatibility

**Details:** The codebase targets Wazuh v4.14.3 but has no runtime version detection. If deployed against a different Wazuh version, endpoints may silently fail or return unexpected schemas.

---

## 2. Client-Side Contract Violations

### 2.1 [CRITICAL] Pervasive `as any` Type Bypasses (56+ instances)

**Locations:**
- `client/src/pages/AgentDetail.tsx` — 12 instances: `(groupSyncItems[0] as any).synced`, `(osQ.data as any)?.data?.affected_items?.[0]`, `(alertsQ.data as any)?.data?.hits?.hits`, etc.
- `client/src/pages/LivingCaseView.tsx` — `reportType: rt.value as any`, `const caseData = row.caseData as any`
- `client/src/pages/AlertQueue.tsx` — `queuedItems={queuedItems as any}`, `item={item as any}`
- `client/src/pages/TriagePipeline.tsx` — `const bd = corr?.bundleData as any`, `const triageData = triage.triageData as any`
- `client/src/pages/TicketArtifactsPanel.tsx` — `{artifacts.map((a: any) => ...}`

**Impact:** Bypasses TypeScript type checking entirely. Runtime errors if server response structures change. Makes refactoring unsafe.
**Fix:** Import and use shared types from `shared/agenticSchemas.ts` (`TriageObject`, `CorrelationBundle`, `LivingCaseObject`).

### 2.2 [CRITICAL] Shared Types Defined but Not Enforced Client-Side

**Location:** `shared/agenticSchemas.ts` defines canonical contracts:
- `TriageObject` (lines 105-223)
- `CorrelationBundle` (lines 230-368)
- `LivingCaseObject` (lines 375-543)

**But client pages use `any` instead:**
- `TriagePipeline.tsx` — uses `as any` instead of `TriageObject`
- `LivingCaseView.tsx` — uses `any` for case data instead of `LivingCaseObject`
- `alert-queue/QueueItemCard.tsx` — no type imports from shared schemas

**Impact:** Shared type contracts exist but provide zero enforcement. Schema changes won't produce compile errors.

### 2.3 [CRITICAL] Unsafe Response Structure Access Without Validation

**Location:** `client/src/pages/DataPipeline.tsx` (lines 102-104, 128-132)
- `setSyncResults(data.results as Record<string, { success: boolean; count: number; error?: string }>)` — `data.results` accessed without existence check, response typed as `any`
- `new Date(s.lastSyncAt)` called on potentially null value without null check

**Impact:** Runtime errors on unexpected server responses, potential Invalid Date errors.

### 2.4 [HIGH] Inconsistent Error Handling in API Mutations

**Locations:**
- `AlertQueue.tsx` (lines 115-119) — No differentiation between `PRECONDITION_FAILED`, `FORBIDDEN`, or other errors
- `AdminUsers.tsx` (lines 120, 129, 138) — Simple `toast.error(err.message)` without error code checking
- `Investigations.tsx` — generic `onError` callbacks throughout

**Fix:** Add error code discrimination (e.g., check `TRPCClientError.data.code`) for user-friendly messages.

### 2.5 [HIGH] Race Condition in Batch Ticket Processing

**Location:** `client/src/pages/AlertQueue.tsx` (lines 45-87)
- `batchProgress` polling at 500ms with no operation deduplication
- Multiple rapid clicks could trigger multiple batch operations before `isBatchRunning` state updates

**Fix:** Add debouncing and server-side batch operation deduplication.

### 2.6 [HIGH] `canRunTicketing` Defaults to `true` (Fail-Open)

**Location:** `QueueItemCard.tsx`
**Details:** The `canRunTicketing` prop defaults to `true`. If a parent fails to pass this prop, the ticketing button appears enabled even when Splunk is unavailable.
**Fix:** Default to `false` (fail-closed) for security-critical capabilities.

### 2.7 [MEDIUM] Missing Input Validation Before Mutations

- `Investigations.tsx` (lines 108-110) — `statusFilter` passed to server without type guards against server's enum
- `Register.tsx` (lines 42-45) — Duplicated password validation logic (client: `password.length < 8`, server: `z.string().min(8)`)

### 2.8 [MEDIUM] Array Type Confusion in Search Filtering

- `Investigations.tsx` (lines 355-359) — `tags.some((t: string) => ...)` casts without validation
- `QueueItemCard.tsx` (line 73) — `const triage = item.triageResult as TriageData | null` with no runtime validation

### 2.9 [MEDIUM] Missing Null/Undefined Checks in Critical Paths

- `TriagePipeline.tsx` (lines 364-373) — `const Icon = c.icon || config.active` falls back silently for unknown status values
- Inconsistent null handling across pages (some use optional chaining, some don't)

### 2.10 [LOW] `WorkingTheoryCard` Typed as `any`

- `LivingCaseView.tsx` (line 115) — `function WorkingTheoryCard({ theory }: { theory: any })` should use shared type

### 2.11 [LOW] Debug Collector Hardcoded Content-Type

- `client/public/__manus__/debug-collector.js` (lines 740-743) — Hardcoded `Content-Type: application/json` with no server validation

---

## 3. Validation & Schema Contract Violations

### 3.1 [CRITICAL] Server-Side `as any` in Production Code

**Locations:**
- `server/hybridrag/hybridragRouter.ts:227` — `await (db.delete(ragSessions) as any).where(...)` — bypasses Drizzle type checking
- `server/hunt/huntRouter.ts:295` — `results: input.results as any` — unvalidated input passed through
- `server/storage.ts:60` — `new Blob([data as any], { type: contentType })` — data type not validated

**Impact:** Type safety bypassed in production code paths, not just tests.

### 3.2 [HIGH] Test Files Rely Heavily on `as any` (36+ instances)

**Locations:**
- `server/directions1-6.test.ts` — 16 instances of `as any` for test data
- `server/pipelineHandoff.test.ts` — 14 instances of `as any` for assertions
- `server/agentDetail.test.ts` — 4 instances
- `server/counterDrift.test.ts` — 2 instances
- `server/kg-enhancements.test.ts` — 3 instances

**Impact:** Tests don't validate type contracts. Schema changes won't cause test failures, reducing test effectiveness.

### 3.3 [HIGH] No Contract Tests for Full Request Chain

**Details:** No test validates the complete chain: client request → tRPC input schema → server handler → external API call → response transformation → tRPC output schema → client consumption. Each layer is tested (if at all) in isolation.

### 3.4 [MEDIUM] Shared Schemas Not Imported in Server Routers

**Details:** `shared/agenticSchemas.ts` defines canonical schemas for triage, correlation, and living case objects, but server routers define their own inline schemas or use `z.any()` for complex objects.

### 3.5 [MEDIUM] Missing `VITE_APP_ID` in Environment Validation

**Location:** `server/_core/envValidation.ts`
**Details:** `VITE_APP_ID` is used in `localAuthService.ts` (line 159) for JWT session signing but not listed in `ENV_CHECKS`. Silently defaults to `"dang-local"`.

### 3.6 [LOW] `process.env.JWT_SECRET` Defaults to Empty String

**Location:** `server/_core/env.ts:3` — `cookieSecret: process.env.JWT_SECRET ?? ""` provides empty-string fallback for a security-critical value. While `envValidation.ts` checks for it, the fallback means code can run with an empty secret if validation is bypassed.

---

## 4. Runtime & Deployment Contract Violations

### 4.1 [HIGH] `VITE_APP_ID` Used in Server Code (Cross-Boundary Violation)

**Location:** `server/localAuth/localAuthService.ts:159`
**Details:** `process.env.VITE_APP_ID || "dang-local"` — reads a `VITE_`-prefixed (client-only) variable server-side for JWT signing. Violates the Vite convention that `VITE_` vars are client-only.

### 4.2 [MEDIUM] `RUN_MIGRATIONS=true` Default with No Concurrent Migration Guard

**Location:** `docker-compose.yml:56`
**Details:** Migrations run on every container startup by default. No lock mechanism prevents concurrent migrations in multi-instance deployments, risking data corruption.

### 4.3 [MEDIUM] Inconsistent Secret Configuration

**Location:** `docker-compose.yml`
**Details:** `JWT_SECRET` uses `:?` (fail-if-missing), but `MYSQL_ROOT_PASSWORD` has a weak default (`dang_root_secret`). Inconsistent security posture for production secrets.

### 4.4 [MEDIUM] No Health Check for DB Readiness Before Migrations

**Location:** `docker-compose.yml:44-45`
**Details:** App service depends on `db` with `condition: service_healthy`, but Docker's health check is TCP-only. DB may not be ready for schema modifications, causing migration failures.

### 4.5 [MEDIUM] No Service Connectivity Validation at Deploy Time

**Details:** If `WAZUH_HOST` is misconfigured, the app only fails at runtime with connection errors. No deployment-time validation of service reachability.

### 4.6 [MEDIUM] Node.js Version Not Pinned

**Location:** `Dockerfile:7,37`
**Details:** Uses `node:22-slim` without minor version constraint. Could pull incompatible versions in the future.

### 4.7 [LOW] `ComponentShowcase.tsx` Not Routed

**Details:** 1,437-line development reference page exists but isn't registered in `App.tsx` routes. Should be routed under `/dev/showcase` or removed.

### 4.8 [LOW] `VITE_APP_LOGO` Defined but Never Referenced in Code

**Location:** `docker-compose.yml:96`
**Details:** Dead configuration — defined but not used anywhere in components or env exports.

---

## 5. Environment Configuration Violations

### 5.1 [HIGH] Undocumented Environment Variables in Production Code

**Location:** `server/_core/env.ts:5,7-8`
**Details:** `OWNER_OPEN_ID`, `BUILT_IN_FORGE_API_URL`, and `BUILT_IN_FORGE_API_KEY` are referenced in code but not in `docker-compose.yml` or `envValidation.ts`. Silent empty-string defaults.

### 5.2 [MEDIUM] `VITE_APP_TITLE` and `VITE_APP_LOGO` in docker-compose.yml

**Location:** `docker-compose.yml:95-96`
**Details:** `VITE_`-prefixed variables passed to server container. Semantic violation of client/server boundary.

### 5.3 [MEDIUM] `RUN_MIGRATIONS` Not Overridable Without File Edits

**Location:** `docker-compose.yml:56`
**Details:** Cannot set `RUN_MIGRATIONS=false` via `--env-file` override. Operators must edit docker-compose.yml directly.

### 5.4 [MEDIUM] No Validation That Linked Services Match Configuration

**Details:** `WAZUH_HOST`, Splunk host, LLM host — all configurable but no validation that configured hosts are reachable or correct.

### 5.5 [LOW] `OWNER_OPEN_ID` Defined but Never Set in Deployment

**Location:** `server/_core/env.ts:5`
**Details:** Suggests incomplete feature implementation or orphaned code. Should be documented, validated, or removed.

---

## Priority Remediation Plan

### Immediate (P0) — Critical Violations
1. **Remove or version-gate** `wazuh.agentVulnerabilities` REST call (§1.1)
2. **Import shared types** from `agenticSchemas.ts` in client pages, replacing `as any` (§2.1, §2.2)
3. **Fix `as any` in production server code** — `hybridragRouter.ts`, `huntRouter.ts`, `storage.ts` (§3.1)

### Short-Term (P1) — High Violations
4. **Add `readiness` rate limit group** to rate limit config (§1.3)
5. **Change `canRunTicketing` default to `false`** (§2.6)
6. **Add error code discrimination** to mutation error handlers (§2.4)
7. **Add batch operation deduplication** to prevent race conditions (§2.5)
8. **Document or remove undocumented env vars** (§5.1)
9. **Add `VITE_APP_ID` to env validation** (§3.5)

### Medium-Term (P2) — Medium Violations
10. Add deprecation-aware logic for Wazuh endpoints (§1.2)
11. Add contract integration tests for full request chains (§3.3)
12. Strengthen Docker deployment guards — concurrent migration lock, DB readiness (§4.2, §4.4)
13. Pin Node.js minor version in Dockerfile (§4.6)
14. Make all secrets require explicit configuration (§4.3)

---

## Appendix: Files with Most Contract Violations

| File | Violation Count | Severity Range |
|------|----------------|----------------|
| `client/src/pages/AgentDetail.tsx` | 12 | CRITICAL-MEDIUM |
| `server/pipelineHandoff.test.ts` | 14 | HIGH |
| `server/directions1-6.test.ts` | 16 | HIGH |
| `client/src/pages/AlertQueue.tsx` | 5 | CRITICAL-HIGH |
| `client/src/pages/TriagePipeline.tsx` | 4 | CRITICAL-MEDIUM |
| `client/src/pages/LivingCaseView.tsx` | 3 | CRITICAL-MEDIUM |
| `docker-compose.yml` | 5 | MEDIUM |
| `server/_core/env.ts` | 3 | HIGH-LOW |
