# Wazuh API Compliance Audit Report

**Date**: 2026-02-27
**Scope**: All tRPC routes in `server/wazuh/wazuhRouter.ts` and `server/indexer/indexerRouter.ts` compared against the official **Wazuh REST API v4.9.0 OpenAPI specification** (~157 endpoints).

**Methodology**: Multi-agent analysis cross-referencing the app's tRPC router, Wazuh client, indexer client, client-side page usage, and the official Wazuh OpenAPI spec.

---

## CRITICAL Issues (API calls will fail)

### C1. `activeResponseList` calls non-existent `GET /active-response`

**File**: `server/wazuh/wazuhRouter.ts:608-610`

The Wazuh API has **no** `GET /active-response` endpoint. Only `PUT /active-response` exists (to execute commands on agents). This route will return 405 Method Not Allowed.

**Fix**: Remove or replace with a read of the manager configuration's `<command>` blocks:
```typescript
// Replace:  proxyGet("/active-response")
// With:     proxyGet("/manager/configuration", { section: "command" })
```

### C2. `agentVulnerabilities` calls removed `GET /vulnerability/{agent_id}`

**File**: `server/wazuh/wazuhRouter.ts:449-471`

`GET /vulnerability/{agent_id}` was **deprecated in Wazuh 4.7.0** and **removed in 4.8.0**. This endpoint will return 404 on any Wazuh >= 4.8. The app's Indexer router (`vulnSearch` querying `wazuh-states-vulnerabilities-*`) is the correct replacement, but the direct API route is broken.

**Fix**: Either remove the endpoint or gate it behind a version check, pointing users to the indexer-based `vulnSearch` instead.

### C3. `taskStatus` uses wrong parameter name

**File**: `server/wazuh/wazuhRouter.ts:597-603`

```typescript
proxyGet("/tasks/status", { task_list: input.taskIds?.join(",") })
//                          ^^^^^^^^^ WRONG — should be tasks_list
```

The Wazuh API expects `tasks_list` (plural), not `task_list`. All task queries will silently ignore the filter and return unfiltered results.

**Fix**:
```typescript
proxyGet("/tasks/status", { tasks_list: input.taskIds?.join(",") })
```

---

## HIGH Severity (Silent data loss / incorrect behavior)

### H1. `os_platform` parameter silently dropped from `agents` query

**File**: `server/wazuh/wazuhRouter.ts:128-148`

The input schema accepts `os_platform` but the `proxyGet` call never forwards it. The Wazuh API supports `os.platform` as a filter parameter on `GET /agents`.

```typescript
// Input declares: os_platform: z.string().optional(),
// proxyGet omits it entirely — the filter is silently ignored
```

**Fix**: Forward the parameter with the correct Wazuh API name:
```typescript
proxyGet("/agents", {
  ...existing params,
  "os.platform": input.os_platform,
})
```

### H2. Non-existent syscollector endpoints always 404

**File**: `server/wazuh/wazuhRouter.ts:309-356`

Four syscollector endpoints do not exist in the Wazuh API v4.9.0 spec:
- `agentBrowserExtensions` -> `/syscollector/{id}/browser_extensions`
- `agentServices` -> `/syscollector/{id}/services`
- `agentUsers` -> `/syscollector/{id}/users`
- `agentGroups2` -> `/syscollector/{id}/groups`

These always fail and return fallback empty data via `.catch()`. While gracefully handled, every call wastes a rate-limit token and generates unnecessary network traffic/error logs.

**Fix**: Either remove these endpoints or add clear documentation that they are aspirational. Consider checking the Wazuh version before calling them, or using the experimental cross-agent syscollector endpoints instead.

---

## MEDIUM Severity (Inconsistencies / missing features)

### M1. `mitreTactics` lacks pagination (inconsistent with other MITRE endpoints)

**File**: `server/wazuh/wazuhRouter.ts:406-408`

All other MITRE endpoints (`mitreTechniques`, `mitreMitigations`, `mitreSoftware`, `mitreGroups`, `mitreReferences`) accept pagination input, but `mitreTactics` doesn't. The test at `wazuhRouter.test.ts:186` even tries to pass `{ limit: 10, offset: 0 }` to it.

**Fix**: Add pagination input:
```typescript
mitreTactics: publicProcedure
  .input(paginationSchema.extend({ search: z.string().optional() }))
  .query(({ input }) =>
    proxyGet("/mitre/tactics", { limit: input.limit, offset: input.offset, search: input.search })
  ),
```

### M2. Manager logs rate-limited under wrong group

**File**: `server/wazuh/wazuhRouter.ts:97-101`

`managerLogs` and `managerLogsSummary` use `"alerts"` as the rate-limit group (30 req/min), sharing quota with actual alert queries. These should use `"default"` (60 req/min) or a dedicated `"logs"` group.

### M3. Missing `security/rules` RBAC endpoint

The app exposes `securityRoles`, `securityPolicies`, and `securityUsers` but is missing `GET /security/rules` (RBAC rules, distinct from detection rules). Also missing `GET /security/config`.

### M4. Missing cluster per-node endpoints

The following per-node cluster endpoints exist in the API but aren't exposed:
- `GET /cluster/{node_id}/stats/weekly`
- `GET /cluster/{node_id}/stats/analysisd`
- `GET /cluster/{node_id}/stats/remoted`
- `GET /cluster/{node_id}/logs`
- `GET /cluster/{node_id}/logs/summary`
- `GET /cluster/{node_id}/configuration`
- `GET /cluster/{node_id}/daemons/stats`

### M5. Missing `logtest` endpoint

`PUT /logtest` enables testing log parsing against rules/decoders. Highly useful for SOC analysts. Would require a mutation endpoint.

### M6. Missing API introspection endpoints

Not implemented: `GET /manager/api/config`, `GET /cluster/api/config`, `GET /cluster/configuration/validation`, `GET /cluster/ruleset/synchronization`.

### M7. Missing experimental cross-agent syscollector endpoints

`GET /experimental/syscollector/{resource}` endpoints allow querying hardware/packages/processes across ALL agents in a single call. Useful for fleet-wide IT hygiene views.

### M8. Missing `groups/{group_id}/files/{file_name}` endpoint

The app has `groupFiles` (list files) but not the endpoint to read individual file content.

### M9. Missing `security/users/me` and `security/users/me/policies`

These endpoints let authenticated users check their own identity and effective RBAC policies on the Wazuh side.

---

## LOW Severity (Minor improvements)

### L1. `rules` endpoint missing several Wazuh filter parameters

The Wazuh API `GET /rules` supports `status` (enabled/disabled), `filename`, `relative_dirname`, `pci_dss`, `gdpr`, `hipaa`, `nist-800-53`, `gpg13`, `tsc`, `mitre`, and `rule_ids` filters. The app only exposes `level`, `search`, `group`, `requirement`, and `sort`.

### L2. No `select` parameter support on most endpoints

Most Wazuh API endpoints support a `select` parameter for field projection. Adding this would reduce response payload sizes.

### L3. No `wait_for_complete` parameter support

For potentially slow operations (large agent lists, cluster queries), the Wazuh API supports `wait_for_complete=true` to disable timeout.

### L4. `syscheck` missing hash-based search parameters

The Wazuh API `GET /syscheck/{agent_id}` supports `md5`, `sha1`, `sha256` filters for IOC hunting. The app's `syscheckFiles` endpoint accepts `hash` as a generic field but doesn't map to the specific hash algorithm parameters.

### L5. SCA checks missing several filter parameters

The Wazuh API `GET /sca/{agent_id}/checks/{policy_id}` supports `title`, `description`, `rationale`, `remediation`, `command`, `status`, `reason`, `condition` filters. The app only supports `result` and `search`.

---

## What's Working Well

- **Authentication**: JWT flow is correct: `POST /security/user/authenticate` with Basic Auth, no body, Bearer token for subsequent requests.
- **Token lifecycle**: 60s expiry buffer and 401 retry-once pattern are solid.
- **Sensitive field stripping**: Comprehensive (password, token, secret, api_key, key, auth, credential).
- **Rate limiting**: Per-endpoint token bucket is well-implemented.
- **Indexer integration**: All 5 index patterns (`wazuh-alerts-*`, `wazuh-states-vulnerabilities-*`, `wazuh-monitoring-*`, `wazuh-statistics-*`, `wazuh-archives-*`) are correctly queried.
- **Client-side usage**: All pages use proper `enabled` guards, fallback data, `SourceBadge` indicators, and safe data extraction.
- **Read-only enforcement**: No write mutations in the Wazuh router.
- **65+ read-only endpoints**: Comprehensive coverage of the Wazuh API's GET surface area.
- **Dual data source pattern**: Indexer for time-series/aggregation queries, Server API for inventory/configuration.

---

## Coverage Summary

| Category | Wazuh API (v4.9.0 GET endpoints) | App Coverage | Notes |
|---|---|---|---|
| Agents | 8 | 8/8 | Full coverage |
| Groups | 4 GET | 4/4 | Full coverage |
| Syscollector | 9 | 9/9 + 4 non-standard | Core: complete |
| Manager | 12 GET | 9/12 | Missing api/config, component config |
| Cluster | 15 GET | 8/15 | Missing per-node logs, config, daemon stats |
| Rules | 4 GET | 4/4 | Full coverage |
| Decoders | 4 GET | 4/4 | Full coverage |
| MITRE | 7 | 7/7 | Full (pagination gap on tactics) |
| Security | 8 GET | 3/8 | Missing rules, config, me, catalog |
| Syscheck | 2 GET | 2/2 | Full coverage |
| Rootcheck | 2 GET | 2/2 | Full coverage |
| SCA | 2 | 2/2 | Full coverage |
| CIS-CAT | 1 | 1/1 | Full coverage |
| Vulnerability | 0 (removed in 4.8) | 1 (stale) | Needs removal |
| CDB Lists | 2 GET | 2/2 | Full coverage |
| Tasks | 1 | 1/1 (param bug) | Has parameter name bug |
| Overview | 1 | 1/1 | Full coverage |
| Active Response | 0 GET | 1 (invalid) | Needs removal |
| Experimental | 12 | 0/12 | None implemented |
| Logtest | 0 GET | 0 | Write-only endpoint |

**Overall Read-Only Coverage**: ~53 of 64 valid GET endpoints covered (83%), with 3 calling invalid paths.

---

## Sources

- [Wazuh Server API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Wazuh API Getting Started](https://documentation.wazuh.com/current/user-manual/api/getting-started.html)
- [Wazuh Active Response Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
- [Wazuh 4.8.0 Release Notes (vulnerability endpoint removal)](https://documentation.wazuh.com/current/release-notes/release-4-8-0.html)
- [Wazuh OpenAPI Spec v4.9.0](https://raw.githubusercontent.com/wazuh/wazuh/v4.9.0/api/api/spec/spec.yaml)
