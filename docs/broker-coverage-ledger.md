# Wazuh Parameter Broker — Coverage Ledger

**Spec baseline:** Wazuh REST API OpenAPI v4.14.3-rc3
**Last updated:** Phase 2 completion

## Broker-Wired Endpoints

The following endpoints are fully wired through `paramBroker.ts`. All accepted parameters are forwarded with correct Wazuh outbound names. Unsupported parameters are explicitly rejected.

| Endpoint | Config Name | Universal Params | Endpoint-Specific Params | Phase |
|---|---|---|---|---|
| `GET /agents` | `AGENTS_CONFIG` | offset, limit, sort, search, select, q, distinct | status, os.platform (aliases: os_platform, osPlatform, platform), os.version, os.name, older_than, manager_host, version, group, node_name, name, ip, registerIP, group_config_status | 1 |
| `GET /rules` | `RULES_CONFIG` | offset, limit, sort, search, select, q, distinct | status, group, level, filename, relative_dirname, pci_dss, gdpr, gpg13, hipaa, nist-800-53 (alias: nist_800_53), tsc, mitre | 1 |
| `GET /groups` | `GROUPS_CONFIG` | offset, limit, sort, search, select, q, distinct | hash | 1 |
| `GET /cluster/nodes` | `CLUSTER_NODES_CONFIG` | offset, limit, sort, search, select, q, distinct | type (aliases: node_type, nodeType) | 1 |
| `GET /sca/{agent_id}` | `SCA_POLICIES_CONFIG` | offset, limit, sort, search, select, q, distinct | name (alias: policyName), description, references | 1 |
| `GET /sca/{agent_id}/checks/{policy_id}` | `SCA_CHECKS_CONFIG` | offset, limit, sort, search, select, q, distinct | title, description, rationale, remediation, command, reason, file (alias: full_path), process, directory, registry, references, result, condition | 1 |
| `GET /manager/configuration` | `MANAGER_CONFIG` | distinct only (offset/limit/sort/search/select/q NOT in spec) | section, field, raw | 2 |

## Universal Query Family

These parameters are shared across most endpoints (except `/manager/configuration` which only supports `distinct`):

| Parameter | Wazuh Name | Type | Description |
|---|---|---|---|
| offset | offset | number | First element to return in the collection |
| limit | limit | number | Maximum number of elements to return |
| sort | sort | string | Sort by field(s) with +/- prefix for asc/desc |
| search | search | string | Native full-text search. Prefix with `-` for complementary search |
| select | select | csv | Comma-separated field selection |
| q | q | string | Query filter (e.g. `q="status=active"`) |
| distinct | distinct | boolean | Return distinct values |

**Critical distinction:** `search` and `q` are independent parameters with different semantics. `search` is Wazuh's native full-text search. `q` is a structured query filter. They are never conflated or rewritten into each other.

## Compliance Filter Family (Rules Only)

Available exclusively on `GET /rules`:

| Parameter | Wazuh Name | Description |
|---|---|---|
| pci_dss | pci_dss | PCI DSS requirement filter |
| gdpr | gdpr | GDPR requirement filter |
| hipaa | hipaa | HIPAA requirement filter |
| nist-800-53 | nist-800-53 | NIST 800-53 requirement filter (alias: nist_800_53) |
| tsc | tsc | TSC requirement filter |
| gpg13 | gpg13 | GPG13 requirement filter |
| mitre | mitre | MITRE ATT&CK technique ID filter |

## Manager Configuration Precision Params

Available exclusively on `GET /manager/configuration`:

| Parameter | Wazuh Name | Type | Description |
|---|---|---|---|
| section | section | string | Configuration section (e.g. global, alerts, syscheck, ruleset) |
| field | field | string | Section child field (e.g. decoder_dir, rule_dir) |
| raw | raw | boolean | Return raw config text. When true, section and field are ignored by Wazuh |

## Correctness Fixes Applied

| Fix | Description | Phase |
|---|---|---|
| A1 | `os_platform` now maps to spec-correct `os.platform` via alias resolution | 1 |
| A2 | `search` is forwarded natively as `search`, never rewritten into `q=name~...` | 1 |

## Test Coverage

| Test Suite | Tests | Phase |
|---|---|---|
| Broker core (coercion, alias, unsupported detection) | 16 | 1 |
| Fix A1: os_platform → os.platform mapping | 4 | 1 |
| Fix A2: search vs q distinction | 4 | 1 |
| Endpoint-specific configs (agents, rules, groups, cluster, SCA) | 62 | 1 |
| Universal params present in all configs | 42 | 1 |
| Rules compliance filter family (forwarding + isolation) | 14 | 2 |
| Rules severity/group/classification filters | 8 | 2 |
| Manager configuration precision params | 12 | 2 |
| SCA expanded filter verification | 21 | 2 |
| Manager config universal param scoping | 1 | 2 |
| Phase 2 cross-endpoint isolation | 5 | 2 |
| **Total paramBroker tests** | **189** | |

## Out of Scope (Not Yet Broker-Wired)

The following endpoint families are intentionally NOT wired in Phase 1 or Phase 2. They remain candidates for future phases.

### Phase 3 Candidate: Syscollector Family

| Endpoint | Current State |
|---|---|
| `GET /syscollector/{agent_id}/hardware` | Manual param forwarding (limit, offset only) |
| `GET /syscollector/{agent_id}/os` | Manual param forwarding (limit, offset only) |
| `GET /syscollector/{agent_id}/packages` | Manual param forwarding (limit, offset, search) |
| `GET /syscollector/{agent_id}/processes` | Manual param forwarding (limit, offset only) |
| `GET /syscollector/{agent_id}/ports` | Manual param forwarding (limit, offset only) |
| `GET /syscollector/{agent_id}/netiface` | Manual param forwarding (limit, offset only) |
| `GET /syscollector/{agent_id}/netaddr` | Manual param forwarding (limit, offset only) |
| `GET /syscollector/{agent_id}/netproto` | Manual param forwarding (limit, offset only) |

### Other Endpoints Not Yet Broker-Wired

| Endpoint | Current State |
|---|---|
| `GET /manager/info` | Zero-param passthrough |
| `GET /manager/status` | Zero-param passthrough |
| `GET /manager/configuration/validation` | Zero-param passthrough |
| `GET /manager/stats` | Zero-param passthrough |
| `GET /manager/stats/hourly` | Zero-param passthrough |
| `GET /manager/stats/weekly` | Zero-param passthrough |
| `GET /manager/stats/remoted` | Zero-param passthrough |
| `GET /manager/stats/analysisd` | Zero-param passthrough |
| `GET /manager/logs` | Manual param forwarding (limit, offset, level, tag, q) |
| `GET /manager/logs/summary` | Zero-param passthrough |
| `GET /rules/groups` | Zero-param passthrough |
| `GET /rules/requirement/{requirement}` | Path param only |
| `GET /rules/files` | Manual param forwarding (limit, offset only) |
| `GET /rules/files/{filename}` | Path param only |
| `GET /mitre/tactics` | Zero-param passthrough |
| `GET /mitre/techniques` | Manual param forwarding (limit, offset, search) |
| `GET /mitre/mitigations` | Manual param forwarding (limit, offset, search) |
| `GET /syscheck/{agent_id}` | Manual param forwarding (limit, offset, search, type, sort, q) |
| `GET /cluster/status` | Zero-param passthrough |
| `GET /cluster/healthcheck` | Zero-param passthrough |
| `GET /cluster/local/info` | Zero-param passthrough |
| `GET /ciscat/{agent_id}/results` | Manual param forwarding (limit, offset only) |
| `GET /vulnerability/{agent_id}` | Manual param forwarding (limit, offset, search, sort, q) |
