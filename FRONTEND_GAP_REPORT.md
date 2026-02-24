# Frontend Mock Data Gap Report

**Date:** 2026-02-24
**Scope:** All frontend pages/components using mock/fallback data instead of live Wazuh API + Indexer data
**Backend:** Wazuh Server API v4.x via tRPC proxy (`server/wazuh/wazuhRouter.ts`) + Wazuh Indexer/OpenSearch (`server/indexer/indexerRouter.ts`)
**Reference:** [Wazuh REST API v4 Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Mock Data Inventory](#2-mock-data-inventory)
3. [Page-by-Page Gap Analysis](#3-page-by-page-gap-analysis)
4. [Gap Summary Matrix](#4-gap-summary-matrix)
5. [Priority Ranking](#5-priority-ranking)
6. [Proposed Migration Plan](#6-proposed-migration-plan)
7. [Appendix: Wazuh API Endpoint Mapping](#7-appendix-wazuh-api-endpoint-mapping)

---

## 1. Architecture Overview

### Current Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  Frontend (React + tRPC client)                                     │
│                                                                     │
│  Page Component                                                     │
│    ├── trpc.wazuh.<endpoint>.useQuery()  ──► tRPC server ──► Wazuh API
│    ├── trpc.indexer.<endpoint>.useQuery() ──► tRPC server ──► OpenSearch
│    │                                                                │
│    └── if (!isConnected) → MOCK_* from mockData.ts  ◄── FALLBACK   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Files

| File | Role |
|---|---|
| `client/src/lib/mockData.ts` | Central mock data store (~1,076 lines, 30+ exports) |
| `server/wazuh/wazuhRouter.ts` | tRPC proxy to Wazuh REST API (581 lines, 60+ procedures) |
| `server/wazuh/wazuhClient.ts` | JWT auth, rate limiting, HTTP client for Wazuh API |
| `server/indexer/indexerRouter.ts` | tRPC proxy to Wazuh Indexer/OpenSearch (732 lines) |
| `client/src/components/shared/WazuhGuard.tsx` | Connection status banner + `useWazuhStatus()` hook |

### Fallback Pattern (current)

Most pages use a pattern like:
```typescript
const { isConnected } = useWazuhStatus();
const agentsQ = trpc.wazuh.agents.useQuery({ limit: 100, offset: 0 });
// Falls back to mock if not connected:
const agents = isConnected ? agentsQ.data : MOCK_AGENTS;
```

Or via the helper:
```typescript
import { useFallback } from "@/lib/mockData";
const rules = useFallback(rulesQ.data, MOCK_RULES, isConfigured);
```

---

## 2. Mock Data Inventory

### Central Mock Store: `client/src/lib/mockData.ts`

| Export Constant | Data Domain | Records | Wazuh API Endpoint |
|---|---|---|---|
| `MOCK_AGENTS` | Agent list with OS, groups, status | 12 agents | `GET /agents` |
| `MOCK_AGENT_SUMMARY` | Agent status counts | 1 summary | `GET /agents/summary/status` |
| `MOCK_RULES` | Detection rules with MITRE mappings | 15 rules | `GET /rules` |
| `MOCK_MANAGER_STATUS` | Daemon running states | 16 daemons | `GET /manager/status` |
| `MOCK_MANAGER_INFO` | Manager version/config | 1 record | `GET /manager/info` |
| `MOCK_MANAGER_STATS` / `MOCK_STATS_HOURLY` | Hourly event throughput | 24 hours | `GET /manager/stats/hourly` |
| `MOCK_MANAGER_LOGS` | Manager log entries (alerts) | 15 entries | `GET /manager/logs` |
| `MOCK_VULNERABILITIES` | CVE records per agent | 10 CVEs | `GET /vulnerability/{agent_id}` |
| `MOCK_MITRE_TACTICS` | MITRE ATT&CK tactics | 14 tactics | `GET /mitre/tactics` |
| `MOCK_MITRE_TECHNIQUES` | MITRE ATT&CK techniques | 16 techniques | `GET /mitre/techniques` |
| `MOCK_MITRE_GROUPS` | MITRE threat groups | 6 groups | `GET /mitre/groups` |
| `MOCK_SCA_POLICIES` | SCA/compliance policies | 5 policies | `GET /sca/{agent_id}` |
| `MOCK_SCA_CHECKS` | SCA check results | 8 checks | `GET /sca/{agent_id}/checks/{policy_id}` |
| `MOCK_SYSCHECK_FILES` | FIM file events | 10 files | `GET /syscheck/{agent_id}` |
| `MOCK_SYSCHECK_LAST_SCAN` | Last FIM scan timestamp | 1 record | `GET /syscheck/{agent_id}/last_scan` |
| `MOCK_PACKAGES` | Installed packages | 12 packages | `GET /syscollector/{agent_id}/packages` |
| `MOCK_PORTS` | Open network ports | 8 ports | `GET /syscollector/{agent_id}/ports` |
| `MOCK_PROCESSES` | Running processes | 10 processes | `GET /syscollector/{agent_id}/processes` |
| `MOCK_NETIFACE` | Network interfaces | 3 interfaces | `GET /syscollector/{agent_id}/netiface` |
| `MOCK_NETADDR` | Network addresses | 4 addresses | `GET /syscollector/{agent_id}/netaddr` |
| `MOCK_HOTFIXES` | Windows hotfixes | 3 hotfixes | `GET /syscollector/{agent_id}/hotfixes` |
| `MOCK_CLUSTER_STATUS` | Cluster enabled/running | 1 record | `GET /cluster/status` |
| `MOCK_CLUSTER_NODES` | Cluster node list | 3 nodes | `GET /cluster/nodes` |
| `MOCK_DAEMON_STATS` | Per-daemon performance metrics | 3 daemons | `GET /manager/daemons/stats` |
| `MOCK_CONFIG_VALIDATION` | Config validation result | 1 record | `GET /manager/configuration/validation` |
| `MOCK_SIEM_EVENTS` | Full structured alert events | 20 events | **Indexer:** `wazuh-alerts-*` |
| `MOCK_LOG_SOURCES` | Log source categories | 8 sources | **Derived from alert aggregation** |
| `MOCK_DECODERS` | Decoder definitions | 15 decoders | `GET /decoders` |
| `MOCK_RULES_EXTENDED` | Rules with file/status metadata | 20 rules | `GET /rules` (with extra fields) |
| `MOCK_RULE_GROUPS` | Rule group names | 23 groups | `GET /rules/groups` |
| `MOCK_RULE_FILES` | Rule file list | 10 files | `GET /rules/files` |
| `MOCK_BROWSER_EXTENSIONS` | Browser extensions (syscollector) | 8 extensions | `GET /syscollector/{agent_id}/browser_extensions` |
| `MOCK_SERVICES` | System services | 14 services | `GET /syscollector/{agent_id}/services` |
| `MOCK_USERS` | Local OS users | 10 users | `GET /syscollector/{agent_id}/users` |
| `MOCK_GROUPS` | Local OS groups | 10 groups | `GET /syscollector/{agent_id}/groups` |
| `MOCK_AGENT_PACKAGES` | Per-agent package variants | 4 agents | `GET /syscollector/{agent_id}/packages` |
| `MOCK_AGENT_SERVICES` | Per-agent service variants | 4 agents | `GET /syscollector/{agent_id}/services` |
| `MOCK_AGENT_USERS` | Per-agent user variants | 4 agents | `GET /syscollector/{agent_id}/users` |

### Page-Local Mock Data (defined inline, NOT in mockData.ts)

| Page | Inline Mock Constant | Data Domain | Needed API Source |
|---|---|---|---|
| `Home.tsx:152` | `MOCK_THREAT_TRENDS` | 24hr threat level timeline | **Indexer:** `alertsAggByLevel` |
| `Home.tsx:161` | `MOCK_TOP_TALKERS` | Top agents by alert volume | **Indexer:** `alertsAggByAgent` |
| `Home.tsx:172` | `MOCK_GEO_DATA` | Geographic threat distribution | **Indexer:** `alertsGeoEnriched` |
| `Home.tsx:185` | `MOCK_TOP_RULES` | Most triggered rules | **Indexer:** `alertsAggByRule` |
| `Home.tsx:198` | `MOCK_MITRE_TRENDS` | MITRE tactic trends over time | **Indexer:** `alertsAggByMitre` |
| `AlertsTimeline.tsx:121` | `MOCK_ALERTS` (generated) | Alert records with filters | **Indexer:** `alertsSearch` |
| `AlertsTimeline.tsx:154` | `MOCK_TIMELINE` (generated) | Alert timeline histogram | **Indexer:** `alertsTimeline` |
| `AlertsTimeline.tsx:155` | `MOCK_RULE_DIST` (generated) | Rule severity distribution | **Indexer:** `alertsAggByLevel` |
| `MitreAttack.tsx:66` | `MOCK_MITRE_ALERT_DATA` | MITRE tactic alert counts | **Indexer:** `alertsAggByMitre` |
| `Compliance.tsx:92` | `MOCK_COMPLIANCE_ALERTS` | Per-framework alert counts | **Indexer:** `alertsComplianceAgg` |

---

## 3. Page-by-Page Gap Analysis

### 3.1 Home Dashboard (`Home.tsx`)

**Mock Dependency Level: HIGH** — 11 mock data sources

| Data Point | Current Source | Target API Source | Backend Ready? | Gap |
|---|---|---|---|---|
| Agent summary (active/disconnected counts) | `MOCK_AGENT_SUMMARY` fallback | `trpc.wazuh.agentSummaryStatus` | **Yes** | Fallback logic needs removal when connected |
| Hourly event stats | `MOCK_MANAGER_STATS` fallback | `trpc.wazuh.statsHourly` | **Yes** | Same — fallback removal |
| Daemon status | `MOCK_MANAGER_STATUS` fallback | `trpc.wazuh.managerStatus` | **Yes** | Same |
| Rules list | `MOCK_RULES` fallback | `trpc.wazuh.rules` | **Yes** | Same |
| Agents list | `MOCK_AGENTS` fallback | `trpc.wazuh.agents` | **Yes** | Same |
| MITRE tactics | `MOCK_MITRE_TACTICS` fallback | `trpc.wazuh.mitreTactics` | **Yes** | Same |
| Daemon metrics (EPS gauge) | `MOCK_DAEMON_STATS` **always used** | `trpc.wazuh.daemonStats` | **Yes** | **GAP: Never queries real API for daemon stats** |
| Threat level trends (24hr chart) | `MOCK_THREAT_TRENDS` **always used** | `trpc.indexer.alertsAggByLevel` | **Yes** | **GAP: Hardcoded, no indexer query attempted** |
| Top talkers | `MOCK_TOP_TALKERS` **always used** | `trpc.indexer.alertsAggByAgent` | **Yes** | **GAP: Hardcoded, no indexer query attempted** |
| Geographic distribution | `MOCK_GEO_DATA` fallback | `trpc.indexer.alertsGeoEnriched` | **Yes** | Partially wired — falls to mock on any failure |
| Top triggered rules | `MOCK_TOP_RULES` **always used** | `trpc.indexer.alertsAggByRule` | **Yes** | **GAP: Hardcoded, no indexer query attempted** |
| MITRE tactic trends | `MOCK_MITRE_TRENDS` **always used** | `trpc.indexer.alertsAggByMitre` | **Yes** | **GAP: Hardcoded, no indexer query attempted** |

**Key Gaps:**
- 5 data points (daemon stats, threat trends, top talkers, top rules, MITRE trends) are **unconditionally hardcoded** — they never attempt a real API call
- The remaining 6 use fallback correctly but remain on mock when Wazuh is disconnected

---

### 3.2 Agent Health (`AgentHealth.tsx`)

**Mock Dependency Level: HIGH** — All data falls back to `MOCK_AGENTS`/`MOCK_AGENT_SUMMARY`

| Data Point | Current Source | Target API Source | Backend Ready? | Gap |
|---|---|---|---|---|
| Agent summary | `MOCK_AGENT_SUMMARY` fallback | `trpc.wazuh.agentSummaryStatus` | **Yes** | Fallback pattern — works when connected |
| OS distribution | `MOCK_AGENTS` computed fallback | `trpc.wazuh.agentSummaryOs` | **Yes** | **GAP: `agentSummaryOs` endpoint exists but not used; distribution computed from mock agents list instead** |
| Group distribution | `MOCK_AGENTS` computed fallback | `trpc.wazuh.agentGroups` | **Yes** | **GAP: Groups computed from mock agent list instead of `GET /groups`** |
| Agent list (table) | `MOCK_AGENTS` fallback | `trpc.wazuh.agents` | **Yes** | Fallback pattern — works when connected |
| Agent detail panel | `MOCK_AGENTS.find()` fallback | `trpc.wazuh.agentById` | **Yes** | Fallback pattern — works when connected |
| Agent OS detail | `MOCK_AGENTS` derived | `trpc.wazuh.agentOs` (syscollector) | **Yes** | **GAP: Detailed OS info available via syscollector but not fetched** |

**Key Gaps:**
- OS distribution always derived from agent list instead of using dedicated `GET /agents/summary/os` endpoint
- Group distribution not using `GET /groups` endpoint
- Agent detail view doesn't pull syscollector OS info for richer data

---

### 3.3 Cluster Health (`ClusterHealth.tsx`)

**Mock Dependency Level: MEDIUM** — 7 mock fallbacks, all have corresponding tRPC queries

| Data Point | Current Source | Target API Source | Backend Ready? | Gap |
|---|---|---|---|---|
| Daemon status | `MOCK_MANAGER_STATUS` fallback | `trpc.wazuh.managerStatus` | **Yes** | Fallback pattern |
| Manager info | `MOCK_MANAGER_INFO` fallback | `trpc.wazuh.managerInfo` | **Yes** | Fallback pattern |
| Hourly stats | `MOCK_MANAGER_STATS` fallback | `trpc.wazuh.statsHourly` | **Yes** | Fallback pattern |
| Daemon metrics | `MOCK_DAEMON_STATS` fallback | `trpc.wazuh.daemonStats` | **Yes** | Fallback pattern |
| Config validation | `MOCK_CONFIG_VALIDATION` fallback | `trpc.wazuh.managerConfigValidation` | **Yes** | Fallback pattern |
| Cluster status | `MOCK_CLUSTER_STATUS` fallback | `trpc.wazuh.clusterStatus` | **Yes** | Fallback pattern |
| Cluster nodes | `MOCK_CLUSTER_NODES` fallback | `trpc.wazuh.clusterNodes` | **Yes** | Fallback pattern |

**Key Gaps:**
- All queries exist and are wired — **this page is the closest to working with live data**
- Missing: cluster healthcheck (`trpc.wazuh.clusterHealthcheck` exists but not called)
- Missing: per-node stats (`trpc.wazuh.clusterNodeStats` exists but not called)

---

### 3.4 Vulnerabilities (`Vulnerabilities.tsx`)

**Mock Dependency Level: CRITICAL** — Almost entirely mock-driven

| Data Point | Current Source | Target API Source | Backend Ready? | Gap |
|---|---|---|---|---|
| Agent list for selector | `MOCK_AGENTS` filtered | `trpc.wazuh.agents` | **Yes** | **GAP: Agent query exists but mock always wins in the current fallback logic** |
| Vulnerability list | `MOCK_VULNERABILITIES` **always used** | `trpc.wazuh.agentVulnerabilities` | **Yes** | **GAP: tRPC endpoint wired but page uses mock fallback unconditionally** |
| Fleet-wide vuln totals | `MOCK_VULNERABILITIES.total` | `trpc.indexer.vulnAggBySeverity` | **Yes** | **GAP: Indexer aggregation exists but not called** |
| Severity distribution | `MOCK_VULNERABILITIES` computed | `trpc.indexer.vulnAggBySeverity` | **Yes** | **GAP: Not wired to indexer** |
| Per-agent breakdown | `MOCK_VULNERABILITIES` computed | `trpc.indexer.vulnAggByAgent` | **Yes** | **GAP: Not wired to indexer** |
| Top packages by vuln | `MOCK_VULNERABILITIES` computed | `trpc.indexer.vulnAggByPackage` | **Yes** | **GAP: Not wired to indexer** |
| Top CVEs fleet-wide | `MOCK_VULNERABILITIES` computed | `trpc.indexer.vulnAggByCVE` | **Yes** | **GAP: Not wired to indexer** |
| Trend over time | `MOCK_VULNERABILITIES` computed | Indexer date_histogram | **Partial** | **GAP: No timeline aggregation endpoint exists for vulns** |

**Key Gaps:**
- The Wazuh API's vulnerability endpoint (`GET /vulnerability/{agent_id}`) is per-agent and **deprecated since v4.7** — fleet-wide data must come from the Indexer (`wazuh-states-vulnerabilities-*`)
- Page has NO indexer queries wired despite `indexerRouter.ts` having full vuln aggregation endpoints
- This is the **highest-impact gap** because vulnerabilities are a primary security dashboard

---

### 3.5 SIEM Events (`SiemEvents.tsx`)

**Mock Dependency Level: CRITICAL** — Core event data is 100% mock

| Data Point | Current Source | Target API Source | Backend Ready? | Gap |
|---|---|---|---|---|
| Event list (table) | `MOCK_SIEM_EVENTS` **always used** | `trpc.indexer.alertsSearch` | **Yes** | **GAP: No indexer query — events are hardcoded** |
| Log source list | `MOCK_LOG_SOURCES` **always used** | Derived from `alertsSearch` aggregation | **No** | **GAP: No aggregation endpoint for log source breakdown** |
| Rules | `MOCK_RULES` fallback via `useFallback` | `trpc.wazuh.rules` | **Yes** | Fallback pattern |
| Agents | `MOCK_AGENTS` fallback via `useFallback` | `trpc.wazuh.agents` | **Yes** | Fallback pattern |
| Event filtering/search | Client-side on mock array | `trpc.indexer.alertsSearch` (server-side) | **Yes** | **GAP: All filtering is client-side on 20 static events** |
| Event detail/raw log | From mock event objects | From indexer `_source` | **Yes** | **GAP: Full event detail only available from indexer** |

**Key Gaps:**
- **SIEM Events is the single most important page** for an SOC analyst and is 100% hardcoded
- The indexer `alertsSearch` endpoint supports full-text search, agent/rule/MITRE/severity filters, pagination, and sorting — none of this is wired
- Log source breakdown needs a new aggregation (terms on `decoder.name` or `rule.groups`)

---

### 3.6 Alerts Timeline (`AlertsTimeline.tsx`)

**Mock Dependency Level: CRITICAL** — All chart/timeline data generated from mock

| Data Point | Current Source | Target API Source | Backend Ready? | Gap |
|---|---|---|---|---|
| Alert records | `MOCK_ALERTS` (generated function) | `trpc.indexer.alertsSearch` | **Yes** | **GAP: Generated locally, not from indexer** |
| Timeline histogram | `MOCK_TIMELINE` (generated function) | `trpc.indexer.alertsTimeline` | **Yes** | **GAP: Generated locally, not from indexer** |
| Rule distribution | `MOCK_RULE_DIST` (generated function) | `trpc.indexer.alertsAggByLevel` | **Yes** | **GAP: Generated locally, not from indexer** |
| Hourly stats (throughput) | `MOCK_STATS_HOURLY` fallback | `trpc.wazuh.statsHourly` | **Yes** | Partial — uses Wazuh API stats when connected |

**Key Gaps:**
- Alert records, timeline, and distribution are all generated by local functions from `MOCK_RULES` + random data
- All three have exact indexer endpoint matches that are not wired

---

### 3.7 MITRE ATT&CK (`MitreAttack.tsx`)

**Mock Dependency Level: HIGH**

| Data Point | Current Source | Target API Source | Backend Ready? | Gap |
|---|---|---|---|---|
| Tactics list | `MOCK_MITRE_TACTICS` fallback | `trpc.wazuh.mitreTactics` | **Yes** | Fallback pattern |
| Techniques list | `MOCK_MITRE_TECHNIQUES` fallback | `trpc.wazuh.mitreTechniques` | **Yes** | Fallback pattern |
| Threat groups | `MOCK_MITRE_GROUPS` fallback | `trpc.wazuh.mitreGroups` | **Yes** | Fallback pattern |
| Technique → rule mapping | `MOCK_RULES` fallback | `trpc.wazuh.rules` | **Yes** | Fallback pattern |
| Tactic alert counts | `MOCK_MITRE_ALERT_DATA.tacticAlerts` **always used** | `trpc.indexer.alertsAggByMitre` | **Yes** | **GAP: Hardcoded, indexer agg not wired** |
| MITRE timeline | `MOCK_MITRE_ALERT_DATA.timeline` **always used** | `trpc.indexer.alertsAggByMitre` | **Yes** | **GAP: Hardcoded, indexer agg not wired** |
| Top techniques | `MOCK_MITRE_ALERT_DATA.topTechniques` **always used** | `trpc.indexer.alertsAggByMitre` | **Yes** | **GAP: Hardcoded, indexer agg not wired** |

**Key Gaps:**
- Wazuh API reference data (tactics, techniques, groups) works via fallback — should work when connected
- All **alert-based analytics** (counts per tactic, timeline, top techniques) are hardcoded and need indexer wiring

---

### 3.8 Compliance (`Compliance.tsx`)

**Mock Dependency Level: HIGH**

| Data Point | Current Source | Target API Source | Backend Ready? | Gap |
|---|---|---|---|---|
| Agent list | `MOCK_AGENTS` filtered | `trpc.wazuh.agents` | **Yes** | Fallback pattern |
| SCA policies | `MOCK_SCA_POLICIES` fallback | `trpc.wazuh.scaPolicies` | **Yes** | Fallback pattern |
| SCA checks | `MOCK_SCA_CHECKS` fallback | `trpc.wazuh.scaChecks` | **Yes** | Fallback pattern |
| Framework alert counts | `MOCK_COMPLIANCE_ALERTS` **always used** | `trpc.indexer.alertsComplianceAgg` | **Yes** | **GAP: Hardcoded, indexer agg not wired** |
| Per-framework drill-down | `MOCK_COMPLIANCE_ALERTS[fw]` | `trpc.indexer.alertsComplianceAgg` | **Yes** | **GAP: Hardcoded** |

**Key Gaps:**
- SCA data (policies + checks) correctly falls back and should work when connected
- Compliance alert analytics (PCI DSS, HIPAA, GDPR, NIST counts) are hardcoded — the indexer has an exact `alertsComplianceAgg` endpoint that is not wired

---

### 3.9 File Integrity Monitoring (`FileIntegrity.tsx`)

**Mock Dependency Level: HIGH**

| Data Point | Current Source | Target API Source | Backend Ready? | Gap |
|---|---|---|---|---|
| Agent selector | `MOCK_AGENTS` filtered | `trpc.wazuh.agents` | **Yes** | Fallback pattern |
| FIM file list | `MOCK_SYSCHECK_FILES` fallback | `trpc.wazuh.syscheckFiles` | **Yes** | **GAP: Query exists but page always falls to mock when data shape check fails** |
| Last scan time | `MOCK_SYSCHECK_LAST_SCAN` fallback | `trpc.wazuh.syscheckLastScan` | **Yes** | Similar fallback issue |
| Event type distribution | Computed from mock | Computed from API response | **Yes** | Derived — depends on fixing file list |

**Key Gaps:**
- tRPC endpoints exist and are wired with fallback
- The page likely works when connected but needs verification of the response shape parsing
- Missing: FIM alerting via indexer (`wazuh-alerts-*` with `rule.groups: syscheck`)

---

### 3.10 IT Hygiene (`ITHygiene.tsx`)

**Mock Dependency Level: CRITICAL** — 11 mock imports, all unconditionally used

| Data Point | Current Source | Target API Source | Backend Ready? | Gap |
|---|---|---|---|---|
| Agent selector | `MOCK_AGENTS` filtered | `trpc.wazuh.agents` | **Yes** | **GAP: No tRPC query attempted** |
| Packages | `MOCK_PACKAGES` **always used** | `trpc.wazuh.agentPackages` | **Yes** | **GAP: No tRPC query attempted** |
| Ports | `MOCK_PORTS` **always used** | `trpc.wazuh.agentPorts` | **Yes** | **GAP: No tRPC query attempted** |
| Processes | `MOCK_PROCESSES` **always used** | `trpc.wazuh.agentProcesses` | **Yes** | **GAP: No tRPC query attempted** |
| Network interfaces | `MOCK_NETIFACE` **always used** | `trpc.wazuh.agentNetiface` | **Yes** | **GAP: No tRPC query attempted** |
| Network addresses | `MOCK_NETADDR` **always used** | `trpc.wazuh.agentNetaddr` | **Yes** | **GAP: No tRPC query attempted** |
| Hotfixes | `MOCK_HOTFIXES` **always used** | `trpc.wazuh.agentHotfixes` | **Yes** | **GAP: No tRPC query attempted** |
| Browser extensions | `MOCK_BROWSER_EXTENSIONS` **always** | `trpc.wazuh.agentBrowserExtensions` | **Yes** | **GAP: No tRPC query attempted** |
| Services | `MOCK_SERVICES` **always used** | `trpc.wazuh.agentServices` | **Yes** | **GAP: No tRPC query attempted** |
| Users | `MOCK_USERS` **always used** | `trpc.wazuh.agentUsers` | **Yes** | **GAP: No tRPC query attempted** |
| Groups | `MOCK_GROUPS` **always used** | `trpc.wazuh.agentGroups2` | **Yes** | **GAP: No tRPC query attempted** |

**Key Gaps:**
- **All 11 syscollector data sources are unconditionally hardcoded** — zero tRPC queries
- Every single backend endpoint already exists in `wazuhRouter.ts`
- This is the easiest page to fix because the backend is fully ready

---

### 3.11 Ruleset Explorer (`RulesetExplorer.tsx`)

**Mock Dependency Level: MEDIUM**

| Data Point | Current Source | Target API Source | Backend Ready? | Gap |
|---|---|---|---|---|
| Rules (extended) | `MOCK_RULES_EXTENDED` fallback via `useFallback` | `trpc.wazuh.rules` | **Yes** | Fallback pattern — works when connected |
| Decoders | `MOCK_DECODERS` fallback via `useFallback` | `trpc.wazuh.decoders` | **Yes** | Fallback pattern — works when connected |
| Rule groups | `MOCK_RULE_GROUPS` fallback via `useFallback` | `trpc.wazuh.ruleGroups` | **Yes** | Fallback pattern — works when connected |

**Key Gaps:**
- Lowest gap page — uses `useFallback()` correctly for all three data sources
- Will work with live data when Wazuh is connected
- Minor: Rule files listing (`trpc.wazuh.rulesFiles`) not used on this page

---

### 3.12 Threat Hunting (`ThreatHunting.tsx`)

**Mock Dependency Level: HIGH**

| Data Point | Current Source | Target API Source | Backend Ready? | Gap |
|---|---|---|---|---|
| Agents | `MOCK_AGENTS` via `useFallback` | `trpc.wazuh.agents` | **Yes** | Fallback pattern |
| Rules | `MOCK_RULES` via `useFallback` | `trpc.wazuh.rules` | **Yes** | Fallback pattern |
| Manager logs | `MOCK_MANAGER_LOGS` via `useFallback` | `trpc.wazuh.managerLogs` | **Yes** | Fallback pattern |
| MITRE techniques | `MOCK_MITRE_TECHNIQUES` via `useFallback` | `trpc.wazuh.mitreTechniques` | **Yes** | Fallback pattern |
| Vulnerabilities | `MOCK_VULNERABILITIES` **always used** | `trpc.wazuh.agentVulnerabilities` | **Partial** | **GAP: Always mock — vuln queries need an agentId, no cross-agent support** |
| Syscheck files | `MOCK_SYSCHECK_FILES` **always used** | `trpc.wazuh.syscheckFiles` | **Partial** | **GAP: Always mock — syscheck queries need an agentId** |
| Cross-data correlation | All mock combined | **Indexer full-text search** | **Yes** | **GAP: Cross-data search needs indexer, not per-endpoint queries** |

**Key Gaps:**
- Cross-agent vulnerability and syscheck search is not possible with per-agent Wazuh API endpoints
- True threat hunting needs indexer-based full-text search across `wazuh-alerts-*` and `wazuh-archives-*`
- The indexer `alertsSearch` and `archivesSearch` endpoints exist but are not wired

---

### 3.13 Drift Comparison (`DriftComparison.tsx`)

**Mock Dependency Level: CRITICAL** — 100% mock, used by IT Hygiene page

| Data Point | Current Source | Target API Source | Backend Ready? | Gap |
|---|---|---|---|---|
| Agent list | `MOCK_AGENTS` **always used** | `trpc.wazuh.agents` | **Yes** | **GAP: No tRPC query** |
| Per-agent packages | `MOCK_AGENT_PACKAGES[id]` **always** | `trpc.wazuh.agentPackages` | **Yes** | **GAP: No tRPC query** |
| Per-agent services | `MOCK_AGENT_SERVICES[id]` **always** | `trpc.wazuh.agentServices` | **Yes** | **GAP: No tRPC query** |
| Per-agent users | `MOCK_AGENT_USERS[id]` **always** | `trpc.wazuh.agentUsers` | **Yes** | **GAP: No tRPC query** |
| Baseline comparison | Client-side diff on mock | `trpc.baselines.*` | **Yes** | Baselines router exists for drift detection |

**Key Gaps:**
- Completely hardcoded — no real API queries
- All backend endpoints exist

---

### 3.14 Pages With NO Mock Data (already live or API-only)

| Page | Data Source | Status |
|---|---|---|
| `DataPipeline.tsx` | `trpc.graph.etlStatus` / `trpc.graph.graphStats` | **Live** — uses graph/ETL pipeline |
| `ThreatIntel.tsx` | `trpc.otx.*` (AlienVault OTX) | **Live** — uses OTX API |
| `Investigations.tsx` | `trpc.graph.createInvestigation` / `listInvestigations` | **Live** — uses graph DB |
| `KnowledgeGraph.tsx` | `trpc.graph.*` | **Live** — uses graph DB |
| `AnalystNotes.tsx` | `trpc.notes.*` | **Live** — uses local notes DB |
| `AnalystChat.tsx` | `trpc.hybridrag.*` | **Live** — uses HybridRAG |
| `Assistant.tsx` | `trpc.hybridrag.*` | **Live** — uses HybridRAG |
| `AdminSettings.tsx` | `trpc.connectionSettings.*` | **Live** — uses admin DB |
| `AdminUsers.tsx` | `trpc.adminUsers.*` | **Live** — uses admin DB |
| `Status.tsx` | `trpc.wazuh.status` / `trpc.indexer.status` | **Live** — direct API checks |
| `Login.tsx` / `Register.tsx` | `trpc.localAuth.*` | **Live** — auth system |

---

## 4. Gap Summary Matrix

| Page | Mock Imports | Hardcoded (no API attempt) | Fallback (works when connected) | Backend Ready? | Effort |
|---|---|---|---|---|---|
| **SIEM Events** | 4 | **2 critical** (events, log sources) | 2 | Yes (indexer) | High |
| **Vulnerabilities** | 2 | **5+ computed** | 0 (all mock) | Yes (indexer) | High |
| **IT Hygiene** | 11 | **11 (all)** | 0 | Yes (all) | Medium |
| **Home** | 7 | **5** (trends, talkers, geo, rules, MITRE) | 6 | Yes (all) | Medium |
| **Alerts Timeline** | 3 | **3** (alerts, timeline, dist) | 1 | Yes (indexer) | Medium |
| **MITRE ATT&CK** | 4 | **3** (alert data) | 4 | Yes (indexer) | Medium |
| **Drift Comparison** | 7 | **7 (all)** | 0 | Yes (all) | Medium |
| **Compliance** | 3 | **2** (alert counts) | 3 | Yes (indexer) | Low-Med |
| **Threat Hunting** | 6 | **2** (vulns, syscheck) | 4 | Partial | High |
| **Agent Health** | 2 | **2** (OS dist, groups) | 3 | Yes | Low |
| **File Integrity** | 3 | 0 | 3 | Yes | Low |
| **Cluster Health** | 7 | 0 | 7 | Yes | Low |
| **Ruleset Explorer** | 3 | 0 | 3 | Yes | Low |

---

## 5. Priority Ranking

### P0 — Critical (SOC Analyst Workflow Blocked)

1. **SIEM Events** — Core alert investigation view is 100% static. Wire `trpc.indexer.alertsSearch` with full filter/pagination support.
2. **Vulnerabilities** — Primary vulnerability posture view is 100% mock. Wire indexer aggregation endpoints (`vulnAggBySeverity`, `vulnAggByAgent`, `vulnAggByCVE`, `vulnAggByPackage`).

### P1 — High (Dashboard Accuracy)

3. **Home Dashboard** — 5 hardcoded analytics sections need indexer wiring. Daemon stats needs its existing tRPC endpoint wired.
4. **Alerts Timeline** — Alert timeline charts are generated from random data. Wire `trpc.indexer.alertsTimeline` and `alertsAggByLevel`.
5. **IT Hygiene** — 11 syscollector data points completely hardcoded despite backend being fully ready. Straightforward wiring task.

### P2 — Medium (Analytics Accuracy)

6. **MITRE ATT&CK** — Alert-based analytics hardcoded. Wire `trpc.indexer.alertsAggByMitre`.
7. **Compliance** — Framework alert counts hardcoded. Wire `trpc.indexer.alertsComplianceAgg`.
8. **Drift Comparison** — All comparison data hardcoded. Wire syscollector per-agent queries.
9. **Threat Hunting** — Cross-agent search needs indexer. Wire `trpc.indexer.alertsSearch` + `archivesSearch`.

### P3 — Low (Already Mostly Working)

10. **Agent Health** — Minor: use `agentSummaryOs` instead of computing from agent list.
11. **File Integrity** — Fallback pattern works; verify response shape parsing.
12. **Cluster Health** — Fallback pattern works; add healthcheck + per-node stats.
13. **Ruleset Explorer** — Fallback pattern works; no changes needed.

---

## 6. Proposed Migration Plan

### Phase 1: Indexer Integration (P0 + P1 — SIEM, Vulns, Home, Alerts)

These pages require the **Wazuh Indexer** (OpenSearch) connection, not just the Wazuh Server API.

**Prerequisites:**
- Indexer connection configured (`INDEXER_HOST`, `INDEXER_USER`, `INDEXER_PASS`)
- Index patterns exist: `wazuh-alerts-*`, `wazuh-states-vulnerabilities-*`

**Step 1: Create a shared indexer status hook**
```typescript
// client/src/hooks/useIndexerStatus.ts
export function useIndexerStatus() {
  const { data } = trpc.indexer.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  return {
    isConfigured: data?.configured === true,
    isHealthy: data?.healthy === true,
  };
}
```

**Step 2: Wire SIEM Events page**
- Replace `MOCK_SIEM_EVENTS` with `trpc.indexer.alertsSearch.useQuery()`
- Implement server-side filtering (agent, rule level, MITRE tactic, time range)
- Add server-side pagination (the indexer supports `size`/`from`)
- Add a new `alertsAggByDecoder` endpoint for log source breakdown
- Keep mock as offline fallback via `useFallback()`

**Step 3: Wire Vulnerabilities page**
- Replace mock with `trpc.indexer.vulnSearch.useQuery()` for the table
- Wire `vulnAggBySeverity`, `vulnAggByAgent`, `vulnAggByPackage`, `vulnAggByCVE` for charts
- Remove per-agent vulnerability approach — use fleet-wide indexer queries
- Keep `trpc.wazuh.agentVulnerabilities` as agent-detail drilldown only

**Step 4: Wire Home Dashboard analytics**
- Replace `MOCK_THREAT_TRENDS` → `trpc.indexer.alertsAggByLevel`
- Replace `MOCK_TOP_TALKERS` → `trpc.indexer.alertsAggByAgent`
- Replace `MOCK_TOP_RULES` → `trpc.indexer.alertsAggByRule`
- Replace `MOCK_MITRE_TRENDS` → `trpc.indexer.alertsAggByMitre`
- Wire `MOCK_DAEMON_STATS` → `trpc.wazuh.daemonStats`

**Step 5: Wire Alerts Timeline**
- Replace `generateMockAlerts()` → `trpc.indexer.alertsSearch`
- Replace `generateMockTimeline()` → `trpc.indexer.alertsTimeline`
- Replace `generateMockRuleDistribution()` → `trpc.indexer.alertsAggByLevel`

### Phase 2: Syscollector Wiring (P1-P2 — IT Hygiene, Drift)

These pages need only the **Wazuh Server API** (no indexer required).

**Step 6: Wire IT Hygiene page**

For each of the 11 data tabs, add a tRPC query conditioned on selected agent:
```typescript
const selectedAgent = "001"; // from agent selector
const packagesQ = trpc.wazuh.agentPackages.useQuery(
  { agentId: selectedAgent, limit: 100, offset: 0 },
  { enabled: !!selectedAgent }
);
const packages = isConnected && packagesQ.data
  ? packagesQ.data
  : MOCK_PACKAGES;
```

Repeat for: `agentPorts`, `agentProcesses`, `agentNetiface`, `agentNetaddr`, `agentHotfixes`, `agentBrowserExtensions`, `agentServices`, `agentUsers`, `agentGroups2`.

**Step 7: Wire Drift Comparison component**
- Replace `MOCK_AGENTS` → `trpc.wazuh.agents`
- Replace `MOCK_AGENT_PACKAGES[id]` → `trpc.wazuh.agentPackages({ agentId: id })`
- Replace `MOCK_AGENT_SERVICES[id]` → `trpc.wazuh.agentServices({ agentId: id })`
- Replace `MOCK_AGENT_USERS[id]` → `trpc.wazuh.agentUsers({ agentId: id })`

### Phase 3: Analytics Wiring (P2 — MITRE, Compliance, Threat Hunting)

**Step 8: Wire MITRE ATT&CK analytics**
- Replace `MOCK_MITRE_ALERT_DATA` → `trpc.indexer.alertsAggByMitre`
- Parse indexer response to build tactic alert counts, timeline, and top techniques

**Step 9: Wire Compliance analytics**
- Replace `MOCK_COMPLIANCE_ALERTS` → `trpc.indexer.alertsComplianceAgg`
- One query per framework (PCI DSS, HIPAA, GDPR, NIST)

**Step 10: Wire Threat Hunting**
- Add `trpc.indexer.alertsSearch` for cross-agent alert search
- Add `trpc.indexer.archivesSearch` for raw log search
- Keep Wazuh API fallback for rules/agents/MITRE data

### Phase 4: Cleanup (P3)

**Step 11: Minor improvements**
- Agent Health: use `agentSummaryOs` endpoint for OS distribution
- Cluster Health: add `clusterHealthcheck` and per-node stats
- File Integrity: verify response shape handling

**Step 12: Mock data deprecation**
- Add `// @deprecated — remove after live API verification` comments
- Consider making mock data lazy-loaded (dynamic import) to reduce bundle size
- Keep as test fixtures but remove from production hot path

---

## 7. Appendix: Wazuh API Endpoint Mapping

### Wazuh Server API Endpoints (via tRPC proxy)

| tRPC Procedure | Wazuh API Path | Used By Pages |
|---|---|---|
| `wazuh.status` | `GET /manager/info` | WazuhGuard, Status |
| `wazuh.managerInfo` | `GET /manager/info` | ClusterHealth |
| `wazuh.managerStatus` | `GET /manager/status` | Home, ClusterHealth |
| `wazuh.statsHourly` | `GET /manager/stats/hourly` | Home, ClusterHealth, AlertsTimeline |
| `wazuh.daemonStats` | `GET /manager/daemons/stats` | Home (not wired), ClusterHealth |
| `wazuh.managerConfigValidation` | `GET /manager/configuration/validation` | ClusterHealth |
| `wazuh.managerLogs` | `GET /manager/logs` | ThreatHunting |
| `wazuh.clusterStatus` | `GET /cluster/status` | ClusterHealth |
| `wazuh.clusterNodes` | `GET /cluster/nodes` | ClusterHealth |
| `wazuh.clusterHealthcheck` | `GET /cluster/healthcheck` | **Not used by any page** |
| `wazuh.agents` | `GET /agents` | Home, AgentHealth, many others |
| `wazuh.agentSummaryStatus` | `GET /agents/summary/status` | Home, AgentHealth |
| `wazuh.agentSummaryOs` | `GET /agents/summary/os` | **Not used by any page** |
| `wazuh.agentById` | `GET /agents?agents_list={id}` | AgentHealth |
| `wazuh.agentGroups` | `GET /groups` | **Not used by any page** |
| `wazuh.rules` | `GET /rules` | Home, SiemEvents, RulesetExplorer, etc. |
| `wazuh.ruleGroups` | `GET /rules/groups` | RulesetExplorer |
| `wazuh.decoders` | `GET /decoders` | RulesetExplorer |
| `wazuh.mitreTactics` | `GET /mitre/tactics` | Home, MitreAttack |
| `wazuh.mitreTechniques` | `GET /mitre/techniques` | MitreAttack, ThreatHunting |
| `wazuh.mitreGroups` | `GET /mitre/groups` | MitreAttack |
| `wazuh.agentVulnerabilities` | `GET /vulnerability/{agent_id}` | Vulnerabilities (not wired) |
| `wazuh.scaPolicies` | `GET /sca/{agent_id}` | Compliance |
| `wazuh.scaChecks` | `GET /sca/{agent_id}/checks/{policy_id}` | Compliance |
| `wazuh.syscheckFiles` | `GET /syscheck/{agent_id}` | FileIntegrity |
| `wazuh.syscheckLastScan` | `GET /syscheck/{agent_id}/last_scan` | FileIntegrity |
| `wazuh.agentPackages` | `GET /syscollector/{agent_id}/packages` | **IT Hygiene (not wired)** |
| `wazuh.agentPorts` | `GET /syscollector/{agent_id}/ports` | **IT Hygiene (not wired)** |
| `wazuh.agentProcesses` | `GET /syscollector/{agent_id}/processes` | **IT Hygiene (not wired)** |
| `wazuh.agentNetiface` | `GET /syscollector/{agent_id}/netiface` | **IT Hygiene (not wired)** |
| `wazuh.agentNetaddr` | `GET /syscollector/{agent_id}/netaddr` | **IT Hygiene (not wired)** |
| `wazuh.agentHotfixes` | `GET /syscollector/{agent_id}/hotfixes` | **IT Hygiene (not wired)** |
| `wazuh.agentBrowserExtensions` | `GET /syscollector/{agent_id}/browser_extensions` | **IT Hygiene (not wired)** |
| `wazuh.agentServices` | `GET /syscollector/{agent_id}/services` | **IT Hygiene (not wired)** |
| `wazuh.agentUsers` | `GET /syscollector/{agent_id}/users` | **IT Hygiene (not wired)** |
| `wazuh.agentGroups2` | `GET /syscollector/{agent_id}/groups` | **IT Hygiene (not wired)** |
| `wazuh.agentOs` | `GET /syscollector/{agent_id}/os` | **Not used by any page** |
| `wazuh.agentHardware` | `GET /syscollector/{agent_id}/hardware` | **Not used by any page** |

### Wazuh Indexer Endpoints (via tRPC proxy)

| tRPC Procedure | Index Pattern | Used By Pages |
|---|---|---|
| `indexer.alertsSearch` | `wazuh-alerts-*` | **Not wired** (needed by SIEM, AlertsTimeline, ThreatHunting) |
| `indexer.alertsAggByLevel` | `wazuh-alerts-*` | **Not wired** (needed by Home, AlertsTimeline) |
| `indexer.alertsAggByAgent` | `wazuh-alerts-*` | **Not wired** (needed by Home) |
| `indexer.alertsAggByMitre` | `wazuh-alerts-*` | **Not wired** (needed by Home, MitreAttack) |
| `indexer.alertsAggByRule` | `wazuh-alerts-*` | **Not wired** (needed by Home) |
| `indexer.alertsTimeline` | `wazuh-alerts-*` | **Not wired** (needed by AlertsTimeline) |
| `indexer.alertsGeoAgg` | `wazuh-alerts-*` | Home (partially wired) |
| `indexer.alertsGeoEnriched` | `wazuh-alerts-*` | Home (partially wired) |
| `indexer.alertsComplianceAgg` | `wazuh-alerts-*` | **Not wired** (needed by Compliance) |
| `indexer.vulnSearch` | `wazuh-states-vulnerabilities-*` | **Not wired** (needed by Vulnerabilities) |
| `indexer.vulnAggBySeverity` | `wazuh-states-vulnerabilities-*` | **Not wired** (needed by Vulnerabilities) |
| `indexer.vulnAggByAgent` | `wazuh-states-vulnerabilities-*` | **Not wired** (needed by Vulnerabilities) |
| `indexer.vulnAggByPackage` | `wazuh-states-vulnerabilities-*` | **Not wired** (needed by Vulnerabilities) |
| `indexer.vulnAggByCVE` | `wazuh-states-vulnerabilities-*` | **Not wired** (needed by Vulnerabilities) |
| `indexer.monitoringAgentHistory` | `wazuh-monitoring-*` | **Not wired** (useful for AgentHealth) |
| `indexer.statisticsPerformance` | `wazuh-statistics-*` | **Not wired** (useful for ClusterHealth) |
| `indexer.archivesSearch` | `wazuh-archives-*` | **Not wired** (needed by ThreatHunting) |

---

## Summary Statistics

| Metric | Count |
|---|---|
| Total mock data exports in `mockData.ts` | **38** |
| Total page-local mock constants | **10** |
| Pages with hardcoded mock data (no API attempt) | **8** |
| Pages with fallback pattern (work when connected) | **5** |
| Pages with zero mock dependency | **11** |
| tRPC Wazuh endpoints implemented but unused | **6** (`agentSummaryOs`, `agentOs`, `agentHardware`, `agentGroups`, `clusterHealthcheck`, plus 10 syscollector endpoints) |
| tRPC Indexer endpoints implemented but unused | **15** (all alert/vuln aggregation endpoints) |
| **Total frontend-to-backend wiring gaps** | **~48 data points across 13 pages** |

The backend tRPC layer is substantially complete — the primary work is on the frontend to wire existing endpoints and replace hardcoded mock data with real API queries.
