# Wazuh API Compliance Audit Report

**Date**: 2026-02-27
**Scope**: Every tRPC route in `server/wazuh/wazuhRouter.ts` (65 procedures) and `server/indexer/indexerRouter.ts` (16 procedures) audited line-by-line against the official **Wazuh REST API v4.9.0 OpenAPI specification**.

**Methodology**: Multi-agent analysis cross-referencing the app's tRPC router, Wazuh client, indexer client, client-side page usage, and the official Wazuh OpenAPI spec. Second pass: exhaustive line-by-line review of every procedure.

---

## CRITICAL Issues (API calls will fail or return wrong data)

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

## HIGH Severity (Silent data loss / security issues)

### H1. `rules` endpoint: `requirement` parameter silently dropped

**File**: `server/wazuh/wazuhRouter.ts:361-380`

The input schema at line 367 declares `requirement: z.string().optional()` but the `proxyGet` call at lines 372-379 **never forwards it**. Users filtering rules by compliance requirement (PCI DSS, HIPAA, NIST, etc.) get zero filtering — they silently receive unfiltered results.

```typescript
// Line 367: requirement: z.string().optional(),  ← DECLARED
// Lines 372-379: proxyGet("/rules", {
//   limit, offset, level, search, group, sort   ← requirement MISSING
// })
```

**Fix**: Add `requirement: input.requirement` to the proxyGet params object.

### H2. `agents` endpoint: `os_platform` parameter silently dropped

**File**: `server/wazuh/wazuhRouter.ts:128-148`

The input schema accepts `os_platform` (line 132) but the `proxyGet` call (lines 140-147) never forwards it. The Wazuh API supports `os.platform` as a filter parameter on `GET /agents`.

**Fix**: Add `"os.platform": input.os_platform` to the proxyGet params.

### H3. Path injection in 12 endpoints — unvalidated strings in URL paths

**File**: `server/wazuh/wazuhRouter.ts` (multiple locations)

The router uses `agentIdSchema = z.string().regex(/^\d{3,}$/)` for agent IDs (safe — digits only). But **12 other endpoints** interpolate `z.string()` parameters directly into URL paths with **no path traversal validation**:

| Line | Procedure | Vulnerable Param | Path Template |
|------|-----------|-----------------|---------------|
| 114 | `clusterNodeInfo` | `nodeId` | `/cluster/${nodeId}/info` |
| 118 | `clusterNodeStats` | `nodeId` | `/cluster/${nodeId}/stats` |
| 122 | `clusterNodeStatsHourly` | `nodeId` | `/cluster/${nodeId}/stats/hourly` |
| 183 | `agentStats` | `component` | `/agents/{id}/stats/${component}` |
| 193 | `agentConfig` | `component`, `configuration` | `/agents/{id}/config/${component}/${configuration}` |
| 222 | `agentGroupMembers` | `groupId` | `/groups/${groupId}/agents` |
| 387 | `rulesByRequirement` | `requirement` | `/rules/requirement/${requirement}` |
| 400 | `ruleFileContent` | `filename` | `/rules/files/${filename}` |
| 591 | `decoderFileContent` | `filename` | `/decoders/files/${filename}` |
| 493 | `scaChecks` | `policyId` | `/sca/{id}/checks/${policyId}` |
| 641 | `groupConfiguration` | `groupId` | `/groups/${groupId}/configuration` |
| 648 | `groupFiles` | `groupId` | `/groups/${groupId}/files` |

A malicious client could craft a `nodeId` like `../security/users` which would resolve to `GET /cluster/../security/users/info` — potentially accessing unintended API endpoints. While the app is read-only (GET only), this could expose data from endpoints not intended to be proxied.

**Fix**: Add a safe path segment validator and apply it to all interpolated parameters:
```typescript
const safePathSegment = z.string().regex(
  /^[a-zA-Z0-9._-]+$/,
  "Invalid characters in path parameter"
);
```

### H4. Non-existent syscollector endpoints always 404

**File**: `server/wazuh/wazuhRouter.ts:309-346`

Four syscollector endpoints do not exist in the Wazuh API v4.9.0 spec:
- `agentBrowserExtensions` (line 309) → `/syscollector/{id}/browser_extensions`
- `agentServices` (line 319) → `/syscollector/{id}/services`
- `agentUsers` (line 329) → `/syscollector/{id}/users`
- `agentGroups2` (line 339) → `/syscollector/{id}/groups`

These always fail and return fallback empty data via `.catch()`. While gracefully handled, every call wastes a rate-limit token, generates error logs, and is misleading.

**Fix**: Remove these or document them as aspirational. If the intent is to support future Wazuh versions, gate behind a version check.

### H5. `agentKey` endpoint is effectively dead code

**File**: `server/wazuh/wazuhRouter.ts:168-172` + `wazuhClient.ts:74-96`

The `agentKey` endpoint calls `GET /agents/{id}/key` to retrieve the agent's authentication key. But `wazuhClient.ts` strips all fields named `"key"` (line 79 of `STRIP_FIELDS`). The Wazuh API returns `{ data: { affected_items: [{ id: "001", key: "MDAxI..." }] } }` — the `key` field gets stripped before reaching the client.

This means the endpoint returns the agent record **without the key**, making it useless for its stated purpose.

**Fix**: Either remove the endpoint (keys shouldn't be browser-accessible per project's read-only security policy), or add a targeted exception in `stripSensitiveFields` for this specific response path if key exposure is intentional.

---

## MEDIUM Severity (Inconsistencies / missing features)

### M1. `mitreTactics` lacks pagination (inconsistent with other MITRE endpoints)

**File**: `server/wazuh/wazuhRouter.ts:406-408`

All other MITRE endpoints (`mitreTechniques`, `mitreMitigations`, `mitreSoftware`, `mitreGroups`, `mitreReferences`) accept pagination input, but `mitreTactics` doesn't. The test at `wazuhSpecCoverage.test.ts` doesn't test pagination for this endpoint either.

**Fix**: Add pagination input to match other MITRE endpoints.

### M2. Manager logs rate-limited under wrong group

**File**: `server/wazuh/wazuhRouter.ts:97,101`

`managerLogs` and `managerLogsSummary` use `"alerts"` as the rate-limit group (30 req/min), sharing quota with actual alert queries. These should use `"default"` (60 req/min) or a dedicated `"logs"` group.

### M3. `agentNetproto` has unnecessary `.catch()` fallback

**File**: `server/wazuh/wazuhRouter.ts:349-356`

Unlike the four non-existent endpoints above it, `/syscollector/{id}/netproto` IS a valid Wazuh API endpoint. It's wrapped in `.catch()` like the invalid ones, which silently swallows real errors (auth failures, network issues, etc.) and returns empty data instead.

**Fix**: Remove the `.catch()` wrapper to allow errors to propagate properly.

### M4. Missing `security/rules` RBAC endpoint

The app exposes `securityRoles`, `securityPolicies`, and `securityUsers` but is missing `GET /security/rules` (RBAC rules, distinct from detection rules). Also missing `GET /security/config`.

### M5. Missing cluster per-node endpoints

The following per-node cluster endpoints exist in the API but aren't exposed:
- `GET /cluster/{node_id}/stats/weekly`
- `GET /cluster/{node_id}/stats/analysisd`
- `GET /cluster/{node_id}/stats/remoted`
- `GET /cluster/{node_id}/logs`
- `GET /cluster/{node_id}/logs/summary`
- `GET /cluster/{node_id}/configuration`
- `GET /cluster/{node_id}/daemons/stats`

### M6. Missing `logtest` endpoint

`PUT /logtest` enables testing log parsing against rules/decoders. Highly useful for SOC analysts. Would require a mutation endpoint.

### M7. Missing API introspection endpoints

Not implemented: `GET /manager/api/config`, `GET /cluster/api/config`, `GET /cluster/configuration/validation`, `GET /cluster/ruleset/synchronization`.

### M8. Missing experimental cross-agent syscollector endpoints

`GET /experimental/syscollector/{resource}` endpoints allow querying hardware/packages/processes across ALL agents in a single call. Useful for fleet-wide IT hygiene views.

### M9. Missing `groups/{group_id}/files/{file_name}` endpoint

The app has `groupFiles` (list files) but not the endpoint to read individual file content.

### M10. Missing `security/users/me` and `security/users/me/policies`

These endpoints let authenticated users check their own identity and effective RBAC policies on the Wazuh side.

---

## LOW Severity (Minor improvements)

### L1. `rules` endpoint missing several Wazuh filter parameters

The Wazuh API `GET /rules` supports `status` (enabled/disabled), `filename`, `relative_dirname`, `pci_dss`, `gdpr`, `hipaa`, `nist-800-53`, `gpg13`, `tsc`, `mitre`, and `rule_ids` filters. The app only exposes `level`, `search`, `group`, `requirement` (dropped!), and `sort`.

### L2. No `select` parameter support on most endpoints

Most Wazuh API endpoints support a `select` parameter for field projection. Adding this would reduce response payload sizes.

### L3. No `wait_for_complete` parameter support

For potentially slow operations (large agent lists, cluster queries), the Wazuh API supports `wait_for_complete=true` to disable timeout.

### L4. `syscheck` missing hash-based search parameters

The Wazuh API `GET /syscheck/{agent_id}` supports `md5`, `sha1`, `sha256` filters for IOC hunting. The app's `syscheckFiles` endpoint accepts `hash` as a generic field but doesn't map to the specific hash algorithm parameters.

### L5. SCA checks missing several filter parameters

The Wazuh API `GET /sca/{agent_id}/checks/{policy_id}` supports `title`, `description`, `rationale`, `remediation`, `command`, `status`, `reason`, `condition` filters. The app only supports `result` and `search`.

---

## Full Route-by-Route Audit (65 procedures)

### System Status (2 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 1 | `status` | `GET /manager/info` | OK |
| 2 | `isConfigured` | _(local check)_ | OK — exposes WAZUH_HOST/PORT to client (low info leak) |

### Manager (11 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 3 | `managerInfo` | `GET /manager/info` | OK |
| 4 | `managerStatus` | `GET /manager/status` | OK |
| 5 | `managerConfiguration` | `GET /manager/configuration` | OK |
| 6 | `managerConfigValidation` | `GET /manager/configuration/validation` | OK |
| 7 | `managerStats` | `GET /manager/stats` | OK |
| 8 | `statsHourly` | `GET /manager/stats/hourly` | OK |
| 9 | `statsWeekly` | `GET /manager/stats/weekly` | OK |
| 10 | `analysisd` | `GET /manager/stats/analysisd` | OK |
| 11 | `remoted` | `GET /manager/stats/remoted` | OK |
| 12 | `daemonStats` | `GET /manager/daemons/stats` | OK |
| 13 | `managerLogs` | `GET /manager/logs` | BUG: rate limit group `"alerts"` is wrong (M2) |
| 14 | `managerLogsSummary` | `GET /manager/logs/summary` | BUG: rate limit group `"alerts"` is wrong (M2) |

### Cluster (7 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 15 | `clusterStatus` | `GET /cluster/status` | OK |
| 16 | `clusterNodes` | `GET /cluster/nodes` | OK |
| 17 | `clusterHealthcheck` | `GET /cluster/healthcheck` | OK |
| 18 | `clusterLocalInfo` | `GET /cluster/local/info` | OK |
| 19 | `clusterLocalConfig` | `GET /cluster/local/config` | OK |
| 20 | `clusterNodeInfo` | `GET /cluster/{nodeId}/info` | BUG: `nodeId` path injection (H3) |
| 21 | `clusterNodeStats` | `GET /cluster/{nodeId}/stats` | BUG: `nodeId` path injection (H3) |
| 22 | `clusterNodeStatsHourly` | `GET /cluster/{nodeId}/stats/hourly` | BUG: `nodeId` path injection (H3) |

### Agents (12 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 23 | `agents` | `GET /agents` | BUG: `os_platform` dropped (H2) |
| 24 | `agentSummaryStatus` | `GET /agents/summary/status` | OK |
| 25 | `agentSummaryOs` | `GET /agents/summary/os` | OK |
| 26 | `agentOverview` | `GET /overview/agents` | OK |
| 27 | `agentById` | `GET /agents?agents_list=X` | OK |
| 28 | `agentKey` | `GET /agents/{id}/key` | BUG: `key` field stripped (H5) |
| 29 | `agentDaemonStats` | `GET /agents/{id}/daemons/stats` | OK (agentId validated) |
| 30 | `agentStats` | `GET /agents/{id}/stats/{component}` | BUG: `component` path injection (H3) |
| 31 | `agentConfig` | `GET /agents/{id}/config/{comp}/{conf}` | BUG: `component` + `configuration` path injection (H3) |
| 32 | `agentGroups` | `GET /groups` | OK |
| 33 | `agentsOutdated` | `GET /agents/outdated` | OK |
| 34 | `agentsNoGroup` | `GET /agents/no_group` | OK |
| 35 | `agentsStatsDistinct` | `GET /agents/stats/distinct` | OK |
| 36 | `agentGroupMembers` | `GET /groups/{groupId}/agents` | BUG: `groupId` path injection (H3) |

### Syscollector (14 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 37 | `agentOs` | `GET /syscollector/{id}/os` | OK |
| 38 | `agentHardware` | `GET /syscollector/{id}/hardware` | OK |
| 39 | `agentPackages` | `GET /syscollector/{id}/packages` | OK |
| 40 | `agentPorts` | `GET /syscollector/{id}/ports` | OK |
| 41 | `agentProcesses` | `GET /syscollector/{id}/processes` | OK |
| 42 | `agentNetaddr` | `GET /syscollector/{id}/netaddr` | OK |
| 43 | `agentNetiface` | `GET /syscollector/{id}/netiface` | OK |
| 44 | `agentHotfixes` | `GET /syscollector/{id}/hotfixes` | OK |
| 45 | `agentBrowserExtensions` | `/syscollector/{id}/browser_extensions` | BUG: endpoint doesn't exist (H4) |
| 46 | `agentServices` | `/syscollector/{id}/services` | BUG: endpoint doesn't exist (H4) |
| 47 | `agentUsers` | `/syscollector/{id}/users` | BUG: endpoint doesn't exist (H4) |
| 48 | `agentGroups2` | `/syscollector/{id}/groups` | BUG: endpoint doesn't exist (H4) |
| 49 | `agentNetproto` | `GET /syscollector/{id}/netproto` | WARN: unnecessary .catch() (M3) |

### Rules (5 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 50 | `rules` | `GET /rules` | BUG: `requirement` param dropped (H1) |
| 51 | `ruleGroups` | `GET /rules/groups` | OK |
| 52 | `rulesByRequirement` | `GET /rules/requirement/{req}` | BUG: `requirement` path injection (H3) |
| 53 | `rulesFiles` | `GET /rules/files` | OK |
| 54 | `ruleFileContent` | `GET /rules/files/{filename}` | BUG: `filename` path injection (H3) |

### MITRE ATT&CK (7 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 55 | `mitreTactics` | `GET /mitre/tactics` | WARN: no pagination (M1) |
| 56 | `mitreTechniques` | `GET /mitre/techniques` | OK |
| 57 | `mitreMitigations` | `GET /mitre/mitigations` | OK |
| 58 | `mitreSoftware` | `GET /mitre/software` | OK |
| 59 | `mitreGroups` | `GET /mitre/groups` | OK |
| 60 | `mitreMetadata` | `GET /mitre/metadata` | OK |
| 61 | `mitreReferences` | `GET /mitre/references` | OK |

### Vulnerabilities (1 route)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 62 | `agentVulnerabilities` | `GET /vulnerability/{id}` | CRITICAL: removed in v4.8 (C2) |

### SCA / Compliance (3 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 63 | `scaPolicies` | `GET /sca/{id}` | OK |
| 64 | `scaChecks` | `GET /sca/{id}/checks/{policyId}` | BUG: `policyId` path injection (H3) |
| 65 | `ciscatResults` | `GET /ciscat/{id}/results` | OK |

### FIM / Syscheck (2 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 66 | `syscheckFiles` | `GET /syscheck/{id}` | OK |
| 67 | `syscheckLastScan` | `GET /syscheck/{id}/last_scan` | OK |

### Rootcheck (2 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 68 | `rootcheckResults` | `GET /rootcheck/{id}` | OK |
| 69 | `rootcheckLastScan` | `GET /rootcheck/{id}/last_scan` | OK |

### Decoders (4 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 70 | `decoders` | `GET /decoders` | OK |
| 71 | `decoderFiles` | `GET /decoders/files` | OK |
| 72 | `decoderParents` | `GET /decoders/parents` | OK |
| 73 | `decoderFileContent` | `GET /decoders/files/{filename}` | BUG: `filename` path injection (H3) |

### Tasks (1 route)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 74 | `taskStatus` | `GET /tasks/status` | CRITICAL: wrong param `task_list` → `tasks_list` (C3) |

### Active Response (1 route)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 75 | `activeResponseList` | `GET /active-response` | CRITICAL: endpoint doesn't exist (C1) |

### Security (3 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 76 | `securityRoles` | `GET /security/roles` | OK |
| 77 | `securityPolicies` | `GET /security/policies` | OK |
| 78 | `securityUsers` | `GET /security/users` | OK |

### CDB Lists (2 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 79 | `lists` | `GET /lists` | OK |
| 80 | `listsFiles` | `GET /lists/files` | OK |

### Groups (2 routes)
| # | Procedure | API Path | Verdict |
|---|-----------|----------|---------|
| 81 | `groupConfiguration` | `GET /groups/{groupId}/configuration` | BUG: `groupId` path injection (H3) |
| 82 | `groupFiles` | `GET /groups/{groupId}/files` | BUG: `groupId` path injection (H3) |

---

## Issue Count Summary

| Severity | Count | Issues |
|----------|-------|--------|
| **CRITICAL** | 3 | C1 (dead endpoint), C2 (removed endpoint), C3 (wrong param name) |
| **HIGH** | 5 | H1 (requirement dropped), H2 (os_platform dropped), H3 (12 path-injectable endpoints), H4 (4 non-existent syscollector), H5 (agentKey dead code) |
| **MEDIUM** | 10 | M1-M10 (inconsistencies, missing features) |
| **LOW** | 5 | L1-L5 (missing optional params) |

**Routes with bugs**: 25 of 82 (30%)
**Routes that are clean**: 57 of 82 (70%)

---

## What's Working Well

- **Authentication**: JWT flow is correct: `POST /security/user/authenticate` with Basic Auth, no body, Bearer token for subsequent requests.
- **Token lifecycle**: 60s expiry buffer and 401 retry-once pattern are solid.
- **Sensitive field stripping**: Comprehensive (password, token, secret, api_key, key, auth, credential).
- **Rate limiting**: Per-endpoint token bucket is well-implemented.
- **Indexer integration**: All 5 index patterns (`wazuh-alerts-*`, `wazuh-states-vulnerabilities-*`, `wazuh-monitoring-*`, `wazuh-statistics-*`, `wazuh-archives-*`) are correctly queried with proper aggregations.
- **Client-side usage**: All 15+ pages use proper `enabled` guards, fallback data, `SourceBadge` indicators, and safe data extraction.
- **Read-only enforcement**: No write mutations in the Wazuh router.
- **Dual data source pattern**: Indexer for time-series/aggregation queries, Server API for inventory/configuration.
- **Core syscollector**: All 9 valid endpoints (os, hardware, packages, processes, ports, netaddr, netiface, netproto, hotfixes) are correctly wired.

---

## Sources

- [Wazuh Server API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Wazuh API Getting Started](https://documentation.wazuh.com/current/user-manual/api/getting-started.html)
- [Wazuh 4.8.0 Release Notes (vulnerability endpoint removal)](https://documentation.wazuh.com/current/release-notes/release-4-8-0.html)
- [Wazuh OpenAPI Spec v4.9.0](https://raw.githubusercontent.com/wazuh/wazuh/v4.9.0/api/api/spec/spec.yaml)
