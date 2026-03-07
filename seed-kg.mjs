#!/usr/bin/env node
/**
 * seed-kg.mjs — Knowledge Graph Seeder (CLI)
 *
 * Thin CLI wrapper that mirrors the shared ETL library logic:
 *   - Extraction: same algorithm as server/graph/kgExtractor.ts
 *   - Loading: same layer-by-layer pattern as server/graph/kgLoader.ts
 *   - Sync status: same column names as drizzle/schema.ts kg_sync_status
 *
 * This file is plain JS (.mjs) so it can run without tsx in CI and Docker.
 * The extraction/loading logic is kept in sync with the TypeScript library
 * by sharing the same static data (use cases, indices, fields, error patterns)
 * and the same classification/resolution functions.
 *
 * Usage:
 *   DATABASE_URL=mysql://user:pass@host:port/db node seed-kg.mjs [--spec path] [--drop] [--dry-run]
 *
 * Options:
 *   --spec <path>   Path to the Wazuh OpenAPI YAML spec (default: ./spec-v4.14.3.yaml)
 *   --drop          TRUNCATE all kg_* tables before seeding (default: false)
 *   --dry-run       Print extraction counts without writing to DB
 */

import mysql from "mysql2/promise";
import yaml from "js-yaml";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── CLI args ────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const specIdx = args.indexOf("--spec");
const specPath = specIdx !== -1 ? resolve(args[specIdx + 1]) : resolve(__dirname, "spec-v4.14.3.yaml");
const DROP = args.includes("--drop");
const DRY_RUN = args.includes("--dry-run");

const DB_URL = process.env.DATABASE_URL;
if (!DB_URL && !DRY_RUN) {
  console.error("ERROR: DATABASE_URL environment variable is required.");
  console.error("Example: DATABASE_URL=mysql://dang:password@localhost:3307/dang node seed-kg.mjs");
  process.exit(1);
}

// ── Helpers (mirrors kgExtractor.ts) ───────────────────────────────────────

function resolveRef(spec, ref) {
  if (!ref || !ref.startsWith("#/")) return null;
  const parts = ref.replace("#/", "").split("/");
  let obj = spec;
  for (const p of parts) { obj = obj?.[p]; if (!obj) return null; }
  return obj;
}

function flattenBodySchema(spec, schema, prefix = "") {
  const results = [];
  if (!schema) return results;
  const resolved = schema["$ref"] ? resolveRef(spec, schema["$ref"]) : schema;
  if (!resolved) return results;
  const props = resolved.properties || {};
  const required = resolved.required || [];
  for (const [name, propSchema] of Object.entries(props)) {
    const fullName = prefix ? `${prefix}.${name}` : name;
    const prop = propSchema["$ref"] ? resolveRef(spec, propSchema["$ref"]) : propSchema;
    if (!prop) continue;
    if (prop.type === "object" && prop.properties) {
      results.push(...flattenBodySchema(spec, prop, fullName));
    } else {
      results.push({ name: fullName, type: prop.type || "string", required: required.includes(name), description: (prop.description || "").slice(0, 500) });
    }
  }
  return results;
}

function classifyRisk(method, path, operationId) {
  const m = method.toUpperCase();
  if (m === "DELETE") return "DESTRUCTIVE";
  if (m === "PUT" || m === "POST") {
    if (path.includes("/authenticate") || path.includes("/logtest")) return "SAFE";
    if (operationId?.includes("run_command")) return "DESTRUCTIVE";
    return "MUTATING";
  }
  return "SAFE";
}

function classifyOperationType(method) {
  const m = method.toUpperCase();
  return m === "GET" ? "READ" : m === "POST" ? "CREATE" : m === "PUT" ? "UPDATE" : m === "DELETE" ? "DELETE" : "READ";
}

const TAG_MAP = {
  "API Info": "root", "Active-response": "active-response", Agents: "agents", Ciscat: "ciscat",
  Cluster: "cluster", Decoders: "decoders", Events: "events", Experimental: "experimental",
  Groups: "groups", Lists: "lists", Logtest: "logtest", MITRE: "mitre", Manager: "manager",
  Overview: "overview", Rootcheck: "rootcheck", Rules: "rules", SCA: "sca", Security: "security",
  Syscheck: "syscheck", Syscollector: "syscollector", Task: "tasks", Vulnerability: "vulnerability",
};

function getResource(tags) {
  if (!tags || tags.length === 0) return "unknown";
  return TAG_MAP[tags[0]] || tags[0].toLowerCase().replace(/[^a-z0-9-]/g, "-");
}

// ── Static data (canonical — shared with kgExtractor.ts) ───────────────────

const AUTH_METHODS = [
  { auth_id: "JWT", auth_type: "bearer_token", description: "JSON Web Token obtained via POST /security/user/authenticate", ttl_seconds: 900 },
  { auth_id: "BasicAuth", auth_type: "basic_http", description: "HTTP Basic Authentication for initial token acquisition", ttl_seconds: null },
];

const USE_CASES = [
  { intent: "LIST_AGENTS", semantic_type: "READ", domain: "endpoint_security", description: "List all registered Wazuh agents with status and metadata", endpoint_ids: ["GET:/agents"] },
  { intent: "GET_AGENT_DETAIL", semantic_type: "READ", domain: "endpoint_security", description: "Get detailed information about a specific agent", endpoint_ids: ["GET:/agents/{agent_id}/config/{component}/{configuration}","GET:/agents/{agent_id}/group/is_sync","GET:/agents/{agent_id}/key","GET:/agents/{agent_id}/daemons/stats","GET:/agents/{agent_id}/stats/{component}"] },
  { intent: "LIST_AGENT_GROUPS", semantic_type: "READ", domain: "endpoint_security", description: "List all agent groups", endpoint_ids: ["DELETE:/groups","GET:/groups","POST:/groups","GET:/groups/{group_id}/agents","GET:/groups/{group_id}/configuration","PUT:/groups/{group_id}/configuration","GET:/groups/{group_id}/files","GET:/groups/{group_id}/files/{file_name}","GET:/mitre/groups","GET:/rules/groups"] },
  { intent: "CHECK_AGENT_SCA", semantic_type: "READ", domain: "compliance", description: "Check SCA policy compliance for an agent", endpoint_ids: ["GET:/sca/{agent_id}","GET:/sca/{agent_id}/checks/{policy_id}"] },
  { intent: "CHECK_AGENT_SYSCHECK", semantic_type: "READ", domain: "file_integrity", description: "Check file integrity monitoring results for an agent", endpoint_ids: ["PUT:/syscheck","GET:/syscheck/{agent_id}","DELETE:/syscheck/{agent_id}","GET:/syscheck/{agent_id}/last_scan","DELETE:/experimental/syscheck"] },
  { intent: "GET_AGENT_SYSCOLLECTOR", semantic_type: "READ", domain: "asset_inventory", description: "Get system inventory (packages, ports, processes, hardware, OS)", endpoint_ids: ["GET:/experimental/syscollector/hardware","GET:/experimental/syscollector/netaddr","GET:/experimental/syscollector/netiface","GET:/experimental/syscollector/netproto","GET:/experimental/syscollector/os","GET:/experimental/syscollector/packages","GET:/experimental/syscollector/ports","GET:/experimental/syscollector/processes","GET:/experimental/syscollector/hotfixes","GET:/syscollector/{agent_id}/hardware","GET:/syscollector/{agent_id}/hotfixes","GET:/syscollector/{agent_id}/netaddr","GET:/syscollector/{agent_id}/netiface","GET:/syscollector/{agent_id}/netproto","GET:/syscollector/{agent_id}/os","GET:/syscollector/{agent_id}/packages","GET:/syscollector/{agent_id}/ports","GET:/syscollector/{agent_id}/processes"] },
  { intent: "CHECK_VULNERABILITIES", semantic_type: "READ", domain: "vulnerability_management", description: "Check vulnerability assessment results for agents", endpoint_ids: ["GET:/vulnerability/{agent_id}","GET:/vulnerability/{agent_id}/last_scan","GET:/vulnerability/{agent_id}/field/summary"] },
  { intent: "LIST_RULES", semantic_type: "READ", domain: "detection", description: "List all detection rules", endpoint_ids: ["GET:/cluster/ruleset/synchronization","GET:/rules","GET:/rules/requirement/{requirement}","GET:/rules/files","GET:/rules/files/{filename}","PUT:/rules/files/{filename}","DELETE:/rules/files/{filename}"] },
  { intent: "LIST_DECODERS", semantic_type: "READ", domain: "detection", description: "List all log decoders", endpoint_ids: ["GET:/decoders","GET:/decoders/parents","GET:/decoders/files","GET:/decoders/files/{filename}","PUT:/decoders/files/{filename}","DELETE:/decoders/files/{filename}"] },
  { intent: "MITRE_LOOKUP", semantic_type: "READ", domain: "threat_intelligence", description: "Look up MITRE ATT&CK techniques, tactics, groups, software", endpoint_ids: ["GET:/mitre/metadata","GET:/mitre/techniques","GET:/mitre/tactics","GET:/mitre/groups","GET:/mitre/mitigations","GET:/mitre/software","GET:/mitre/references"] },
  { intent: "CLUSTER_STATUS", semantic_type: "READ", domain: "infrastructure", description: "Check Wazuh cluster health and node status", endpoint_ids: ["GET:/cluster/healthcheck","GET:/cluster/local/info","GET:/cluster/nodes","GET:/cluster/status","GET:/cluster/api/config","GET:/cluster/configuration/validation"] },
  { intent: "MANAGE_SECURITY", semantic_type: "ADMIN", domain: "access_control", description: "Manage RBAC users, roles, policies, and rules", endpoint_ids: ["GET:/security/users","GET:/security/roles","GET:/security/policies","GET:/security/rules","GET:/security/config","GET:/security/resources","POST:/security/user/authenticate","POST:/security/user/authenticate/run_as"] },
  { intent: "RUN_LOGTEST", semantic_type: "READ", domain: "detection", description: "Test log decoding and rule matching without affecting production", endpoint_ids: ["PUT:/logtest","DELETE:/logtest/sessions/{token}"] },
  { intent: "CHECK_ROOTCHECK", semantic_type: "READ", domain: "compliance", description: "Check rootcheck scan results for an agent", endpoint_ids: ["GET:/rootcheck/{agent_id}","GET:/rootcheck/{agent_id}/last_scan","DELETE:/rootcheck/{agent_id}"] },
  { intent: "CHECK_CISCAT", semantic_type: "READ", domain: "compliance", description: "Check CIS-CAT benchmark results for an agent", endpoint_ids: ["GET:/ciscat/{agent_id}/results","GET:/experimental/ciscat/results"] },
  { intent: "LIST_CDB_LISTS", semantic_type: "READ", domain: "detection", description: "List CDB lists used for rule enrichment", endpoint_ids: ["GET:/lists","GET:/lists/files","GET:/lists/files/{filename}","PUT:/lists/files/{filename}","DELETE:/lists/files/{filename}"] },
  { intent: "MANAGER_STATUS", semantic_type: "READ", domain: "infrastructure", description: "Check Wazuh manager status and configuration", endpoint_ids: ["GET:/manager/status","GET:/manager/info","GET:/manager/configuration","GET:/manager/stats","GET:/manager/stats/hourly","GET:/manager/stats/weekly","GET:/manager/stats/analysisd","GET:/manager/stats/remoted","GET:/manager/logs","GET:/manager/logs/summary","GET:/manager/api/config","GET:/manager/configuration/validation","GET:/manager/daemons/stats"] },
  { intent: "TASK_STATUS", semantic_type: "READ", domain: "infrastructure", description: "Check status of async tasks (upgrades, etc.)", endpoint_ids: ["GET:/tasks/status"] },
];

const INDICES = [
  { pattern: "wazuh-alerts-*", description: "Security alerts generated by Wazuh rules engine" },
  { pattern: "wazuh-states-vulnerabilities-*", description: "Vulnerability assessment results per agent" },
  { pattern: "wazuh-monitoring-*", description: "Agent connection status monitoring data" },
  { pattern: "wazuh-statistics-*", description: "Wazuh manager performance statistics" },
  { pattern: "wazuh-archives-*", description: "Raw archived events (all logs, not just alerts)" },
];

const FIELDS = [
  { index_id: 1, field_name: "timestamp", field_type: "date", description: "Event timestamp" },
  { index_id: 1, field_name: "rule.id", field_type: "keyword", description: "Rule ID that triggered the alert" },
  { index_id: 1, field_name: "rule.level", field_type: "integer", description: "Rule severity level (0-15)" },
  { index_id: 1, field_name: "rule.description", field_type: "text", description: "Rule description" },
  { index_id: 1, field_name: "rule.groups", field_type: "keyword", description: "Rule groups" },
  { index_id: 1, field_name: "rule.mitre.id", field_type: "keyword", description: "MITRE ATT&CK technique ID" },
  { index_id: 1, field_name: "rule.mitre.tactic", field_type: "keyword", description: "MITRE ATT&CK tactic" },
  { index_id: 1, field_name: "rule.mitre.technique", field_type: "keyword", description: "MITRE ATT&CK technique name" },
  { index_id: 1, field_name: "rule.pci_dss", field_type: "keyword", description: "PCI DSS compliance mapping" },
  { index_id: 1, field_name: "rule.hipaa", field_type: "keyword", description: "HIPAA compliance mapping" },
  { index_id: 1, field_name: "rule.nist_800_53", field_type: "keyword", description: "NIST 800-53 compliance mapping" },
  { index_id: 1, field_name: "rule.gdpr", field_type: "keyword", description: "GDPR compliance mapping" },
  { index_id: 1, field_name: "rule.tsc", field_type: "keyword", description: "TSC compliance mapping" },
  { index_id: 1, field_name: "agent.id", field_type: "keyword", description: "Agent ID" },
  { index_id: 1, field_name: "agent.name", field_type: "keyword", description: "Agent hostname" },
  { index_id: 1, field_name: "agent.ip", field_type: "ip", description: "Agent IP address" },
  { index_id: 1, field_name: "data.srcip", field_type: "ip", description: "Source IP from event data" },
  { index_id: 1, field_name: "data.dstip", field_type: "ip", description: "Destination IP from event data" },
  { index_id: 1, field_name: "data.srcport", field_type: "integer", description: "Source port" },
  { index_id: 1, field_name: "data.dstport", field_type: "integer", description: "Destination port" },
  { index_id: 1, field_name: "data.srcuser", field_type: "keyword", description: "Source username" },
  { index_id: 1, field_name: "data.dstuser", field_type: "keyword", description: "Destination username" },
  { index_id: 1, field_name: "decoder.name", field_type: "keyword", description: "Decoder that parsed the log" },
  { index_id: 1, field_name: "full_log", field_type: "text", description: "Original log message" },
  { index_id: 1, field_name: "location", field_type: "keyword", description: "Log source location" },
  { index_id: 1, field_name: "GeoLocation.country_name", field_type: "keyword", description: "GeoIP country" },
  { index_id: 1, field_name: "GeoLocation.city_name", field_type: "keyword", description: "GeoIP city" },
  { index_id: 2, field_name: "agent.id", field_type: "keyword", description: "Agent ID" },
  { index_id: 2, field_name: "agent.name", field_type: "keyword", description: "Agent hostname" },
  { index_id: 2, field_name: "vulnerability.id", field_type: "keyword", description: "CVE identifier" },
  { index_id: 2, field_name: "vulnerability.severity", field_type: "keyword", description: "Severity (Critical/High/Medium/Low)" },
  { index_id: 2, field_name: "vulnerability.score.base", field_type: "float", description: "CVSS base score" },
  { index_id: 2, field_name: "vulnerability.score.version", field_type: "keyword", description: "CVSS version" },
  { index_id: 2, field_name: "vulnerability.status", field_type: "keyword", description: "Vulnerability status" },
  { index_id: 2, field_name: "vulnerability.description", field_type: "text", description: "CVE description" },
  { index_id: 2, field_name: "vulnerability.reference", field_type: "keyword", description: "Reference URLs" },
  { index_id: 2, field_name: "vulnerability.detected_at", field_type: "date", description: "Detection timestamp" },
  { index_id: 2, field_name: "package.name", field_type: "keyword", description: "Affected package name" },
  { index_id: 2, field_name: "package.version", field_type: "keyword", description: "Affected package version" },
  { index_id: 2, field_name: "package.architecture", field_type: "keyword", description: "Package architecture" },
  { index_id: 2, field_name: "package.type", field_type: "keyword", description: "Package type (deb/rpm)" },
  { index_id: 3, field_name: "timestamp", field_type: "date", description: "Monitoring timestamp" },
  { index_id: 3, field_name: "id", field_type: "keyword", description: "Agent ID" },
  { index_id: 3, field_name: "name", field_type: "keyword", description: "Agent name" },
  { index_id: 3, field_name: "status", field_type: "keyword", description: "Agent connection status" },
  { index_id: 3, field_name: "ip", field_type: "ip", description: "Agent IP address" },
  { index_id: 3, field_name: "host", field_type: "keyword", description: "Agent hostname" },
  { index_id: 4, field_name: "timestamp", field_type: "date", description: "Statistics timestamp" },
  { index_id: 4, field_name: "analysisd.events_processed", field_type: "long", description: "Events processed by analysisd" },
  { index_id: 4, field_name: "analysisd.events_received", field_type: "long", description: "Events received by analysisd" },
  { index_id: 4, field_name: "analysisd.events_dropped", field_type: "long", description: "Events dropped by analysisd" },
  { index_id: 4, field_name: "remoted.recv_bytes", field_type: "long", description: "Bytes received by remoted" },
  { index_id: 4, field_name: "remoted.tcp_sessions", field_type: "integer", description: "Active TCP sessions" },
  { index_id: 5, field_name: "timestamp", field_type: "date", description: "Event timestamp" },
  { index_id: 5, field_name: "agent.id", field_type: "keyword", description: "Agent ID" },
  { index_id: 5, field_name: "agent.name", field_type: "keyword", description: "Agent name" },
  { index_id: 5, field_name: "rule.id", field_type: "keyword", description: "Rule ID" },
  { index_id: 5, field_name: "rule.level", field_type: "integer", description: "Rule level" },
  { index_id: 5, field_name: "full_log", field_type: "text", description: "Full log message" },
  { index_id: 5, field_name: "decoder.name", field_type: "keyword", description: "Decoder name" },
];

const ERROR_PATTERNS = [
  { http_status: 400, description: "", cause: "Malformed request parameters or body", mitigation: "Validate request parameters against the API schema" },
  { http_status: 401, description: "", cause: "Missing or expired JWT token", mitigation: "Re-authenticate via POST /security/user/authenticate" },
  { http_status: 403, description: "", cause: "Insufficient RBAC permissions for this resource", mitigation: "Check RBAC policies; ensure role has required permissions" },
  { http_status: 404, description: "", cause: "Resource not found (agent, rule, group, etc.)", mitigation: "Verify resource ID exists; check agent/group/rule status" },
  { http_status: 405, description: "", cause: "HTTP method not allowed for this endpoint", mitigation: "Use the correct HTTP method for this endpoint" },
  { http_status: 406, description: "", cause: "Requested content type not supported", mitigation: "Set Accept header to application/json" },
  { http_status: 413, description: "", cause: "Request body exceeds maximum allowed size", mitigation: "Reduce request body size or use pagination" },
  { http_status: 415, description: "", cause: "HTTP 415 error", mitigation: "Consult Wazuh API documentation for this error code" },
  { http_status: 429, description: "", cause: "Rate limit exceeded", mitigation: "Implement exponential backoff; reduce request frequency" },
];

// ── Extract from spec ──────────────────────────────────────────────────────

function extractFromSpec(spec) {
  const paths = spec.paths || {};
  const endpoints = [];
  const allParams = [];
  const allResponses = [];
  const resourceCounts = {};

  for (const [path, ops] of Object.entries(paths)) {
    for (const method of ["get", "post", "put", "delete", "patch"]) {
      if (!ops[method]) continue;
      const details = ops[method];
      if (typeof details !== "object") continue;

      const tags = details.tags || [];
      const resource = getResource(tags);
      const operationId = details.operationId || "";
      const riskLevel = classifyRisk(method, path, operationId);
      const operationType = classifyOperationType(method);
      const endpointId = `${method.toUpperCase()}:${path}`;

      endpoints.push({
        endpoint_id: endpointId, path, method: method.toUpperCase(),
        summary: details.summary || null, description: details.description || null,
        tags: JSON.stringify(tags), operation_id: operationId || null,
        resource, operation_type: operationType, risk_level: riskLevel,
        allowed_for_llm: riskLevel === "SAFE" ? 1 : 0, auth_method: "none",
        trust_score: "0.500", deprecated: details.deprecated ? 1 : 0,
      });
      resourceCounts[resource] = (resourceCounts[resource] || 0) + 1;

      for (const p of (details.parameters || [])) {
        if (!p || typeof p !== "object") continue;
        const param = p.$ref ? resolveRef(spec, p.$ref) : p;
        if (!param) continue;
        allParams.push({ endpoint_id: endpointId, name: param.name || "unknown", location: param.in || "query", required: param.required ? 1 : 0, param_type: param.schema?.type || "string", description: param.description || null });
      }

      if (details.requestBody) {
        const rb = details.requestBody["$ref"] ? resolveRef(spec, details.requestBody["$ref"]) : details.requestBody;
        if (rb?.content?.["application/json"]?.schema) {
          for (const bp of flattenBodySchema(spec, rb.content["application/json"].schema)) {
            allParams.push({ endpoint_id: endpointId, name: bp.name, location: "body", required: bp.required ? 1 : 0, param_type: bp.type, description: bp.description });
          }
        }
      }

      for (const [sc, rd] of Object.entries(details.responses || {})) {
        const hs = parseInt(sc, 10);
        if (isNaN(hs)) continue;
        const resp = rd.$ref ? resolveRef(spec, rd.$ref) : rd;
        allResponses.push({ endpoint_id: endpointId, http_status: hs, description: resp?.description || "" });
      }
    }
  }

  return {
    specTitle: spec.info?.title || "Wazuh API",
    specVersion: spec.info?.version || "unknown",
    endpoints, parameters: allParams, responses: allResponses,
    authMethods: AUTH_METHODS,
    resources: Object.entries(resourceCounts).map(([name, count]) => ({ name, endpoint_count: count })),
    useCases: USE_CASES, indices: INDICES, fields: FIELDS, errorPatterns: ERROR_PATTERNS,
  };
}

// ── Sync status helper ─────────────────────────────────────────────────────

async function upsertSyncStatus(conn, layer, status, entityCount, errorMessage, durationMs, specVersion) {
  const [upd] = await conn.execute(
    `UPDATE kg_sync_status SET status=?, entity_count=?, error_message=?, duration_ms=?, spec_version=COALESCE(?,spec_version), last_sync_at=UTC_TIMESTAMP() WHERE layer=?`,
    [status, entityCount, errorMessage, durationMs, specVersion ?? null, layer],
  );
  if (upd.affectedRows === 0) {
    await conn.execute(
      `INSERT INTO kg_sync_status (layer,status,entity_count,error_message,duration_ms,spec_version,last_sync_at) VALUES (?,?,?,?,?,?,UTC_TIMESTAMP())`,
      [layer, status, entityCount, errorMessage, durationMs, specVersion ?? null],
    );
  }
}

// ── Load all layers ────────────────────────────────────────────────────────

async function loadAllLayers(conn, data) {
  const start = Date.now();
  let totalRecords = 0;
  let allSuccess = true;

  // Layer 1: API Ontology
  const l1Start = Date.now();
  try {
    await upsertSyncStatus(conn, "api_ontology", "syncing", 0, null, null, data.specVersion);
    for (const t of ["kg_resources","kg_auth_methods","kg_responses","kg_parameters","kg_endpoints"]) await conn.execute(`DELETE FROM \`${t}\``);

    const endpointIdMap = {};
    for (const ep of data.endpoints) {
      const [r] = await conn.execute(`INSERT INTO kg_endpoints (endpoint_id,path,method,summary,description,tags,operation_id,resource,operation_type,risk_level,allowed_for_llm,auth_method,trust_score,deprecated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [ep.endpoint_id, ep.path, ep.method, ep.summary, ep.description, ep.tags, ep.operation_id, ep.resource, ep.operation_type, ep.risk_level, ep.allowed_for_llm, ep.auth_method, ep.trust_score, ep.deprecated]);
      endpointIdMap[ep.endpoint_id] = r.insertId;
    }

    let paramCount = 0;
    for (const p of data.parameters) {
      const fk = endpointIdMap[p.endpoint_id];
      if (!fk) continue;
      await conn.execute(`INSERT INTO kg_parameters (endpoint_id,name,location,required,param_type,description) VALUES (?,?,?,?,?,?)`, [fk, p.name, p.location, p.required, p.param_type, p.description]);
      paramCount++;
    }

    let respCount = 0;
    for (const r of data.responses) {
      const fk = endpointIdMap[r.endpoint_id];
      if (!fk) continue;
      await conn.execute(`INSERT INTO kg_responses (endpoint_id,http_status,description) VALUES (?,?,?)`, [fk, r.http_status, r.description]);
      respCount++;
    }

    for (const a of data.authMethods) await conn.execute(`INSERT INTO kg_auth_methods (auth_id,auth_type,description,ttl_seconds) VALUES (?,?,?,?)`, [a.auth_id, a.auth_type, a.description, a.ttl_seconds]);
    for (const r of data.resources) await conn.execute(`INSERT INTO kg_resources (name,endpoint_count) VALUES (?,?)`, [r.name, r.endpoint_count]);

    const l1Count = data.endpoints.length + paramCount + respCount + data.authMethods.length + data.resources.length;
    await upsertSyncStatus(conn, "api_ontology", "completed", l1Count, null, Date.now() - l1Start, data.specVersion);
    totalRecords += l1Count;
    console.log(`[seed-kg]   api_ontology: ${l1Count} entities (${Date.now()-l1Start}ms)`);
  } catch (err) {
    await upsertSyncStatus(conn, "api_ontology", "error", 0, err.message, Date.now() - l1Start, data.specVersion);
    allSuccess = false;
    console.error(`[seed-kg]   api_ontology: ERROR — ${err.message}`);
  }

  // Layer 2: Operational Semantics
  const l2Start = Date.now();
  try {
    await upsertSyncStatus(conn, "operational_semantics", "syncing", 0, null, null, data.specVersion);
    await conn.execute("DELETE FROM `kg_use_cases`");
    for (const uc of data.useCases) {
      await conn.execute(`INSERT INTO kg_use_cases (intent,semantic_type,domain,description,endpoint_ids) VALUES (?,?,?,?,?)`,
        [uc.intent, uc.semantic_type, uc.domain, uc.description, JSON.stringify(uc.endpoint_ids)]);
    }
    await upsertSyncStatus(conn, "operational_semantics", "completed", data.useCases.length, null, Date.now() - l2Start, data.specVersion);
    totalRecords += data.useCases.length;
    console.log(`[seed-kg]   operational_semantics: ${data.useCases.length} entities (${Date.now()-l2Start}ms)`);
  } catch (err) {
    await upsertSyncStatus(conn, "operational_semantics", "error", 0, err.message, Date.now() - l2Start, data.specVersion);
    allSuccess = false;
    console.error(`[seed-kg]   operational_semantics: ERROR — ${err.message}`);
  }

  // Layer 3: Schema Lineage
  const l3Start = Date.now();
  try {
    await upsertSyncStatus(conn, "schema_lineage", "syncing", 0, null, null, data.specVersion);
    await conn.execute("DELETE FROM `kg_fields`");
    await conn.execute("DELETE FROM `kg_indices`");
    const indexIdMap = {};
    for (let i = 0; i < data.indices.length; i++) {
      const [r] = await conn.execute(`INSERT INTO kg_indices (pattern,description) VALUES (?,?)`, [data.indices[i].pattern, data.indices[i].description]);
      indexIdMap[i + 1] = r.insertId;
    }
    for (const f of data.fields) {
      const fk = indexIdMap[f.index_id];
      if (!fk) continue;
      await conn.execute(`INSERT INTO kg_fields (index_id,field_name,field_type,description) VALUES (?,?,?,?)`, [fk, f.field_name, f.field_type, f.description]);
    }
    const l3Count = data.indices.length + data.fields.length;
    await upsertSyncStatus(conn, "schema_lineage", "completed", l3Count, null, Date.now() - l3Start, data.specVersion);
    totalRecords += l3Count;
    console.log(`[seed-kg]   schema_lineage: ${l3Count} entities (${Date.now()-l3Start}ms)`);
  } catch (err) {
    await upsertSyncStatus(conn, "schema_lineage", "error", 0, err.message, Date.now() - l3Start, data.specVersion);
    allSuccess = false;
    console.error(`[seed-kg]   schema_lineage: ERROR — ${err.message}`);
  }

  // Layer 4: Error Graph
  const l4Start = Date.now();
  try {
    await upsertSyncStatus(conn, "error_graph", "syncing", 0, null, null, data.specVersion);
    await conn.execute("DELETE FROM `kg_error_patterns`");
    for (const ep of data.errorPatterns) {
      await conn.execute(`INSERT INTO kg_error_patterns (http_status,description,cause,mitigation) VALUES (?,?,?,?)`, [ep.http_status, ep.description, ep.cause, ep.mitigation]);
    }
    await upsertSyncStatus(conn, "error_graph", "completed", data.errorPatterns.length, null, Date.now() - l4Start, data.specVersion);
    totalRecords += data.errorPatterns.length;
    console.log(`[seed-kg]   error_graph: ${data.errorPatterns.length} entities (${Date.now()-l4Start}ms)`);
  } catch (err) {
    await upsertSyncStatus(conn, "error_graph", "error", 0, err.message, Date.now() - l4Start, data.specVersion);
    allSuccess = false;
    console.error(`[seed-kg]   error_graph: ERROR — ${err.message}`);
  }

  return { success: allSuccess, totalRecords, durationMs: Date.now() - start };
}

// ── Main ───────────────────────────────────────────────────────────────────

console.log(`[seed-kg] Loading spec from ${specPath}`);
const specRaw = readFileSync(specPath, "utf8");
const spec = yaml.load(specRaw);
const data = extractFromSpec(spec);

console.log(`[seed-kg] Parsed spec: ${data.specTitle} v${data.specVersion}`);
console.log(`[seed-kg] Endpoints:      ${data.endpoints.length}`);
console.log(`[seed-kg] Parameters:     ${data.parameters.length}`);
console.log(`[seed-kg] Responses:      ${data.responses.length}`);
console.log(`[seed-kg] Auth methods:   ${data.authMethods.length}`);
console.log(`[seed-kg] Resources:      ${data.resources.length}`);
console.log(`[seed-kg] Use cases:      ${data.useCases.length}`);
console.log(`[seed-kg] Indices:        ${data.indices.length}`);
console.log(`[seed-kg] Fields:         ${data.fields.length}`);
console.log(`[seed-kg] Error patterns: ${data.errorPatterns.length}`);
console.log(`[seed-kg] Sync status:    4`);
const total = data.endpoints.length + data.parameters.length + data.responses.length +
  data.authMethods.length + data.resources.length + data.useCases.length +
  data.indices.length + data.fields.length + data.errorPatterns.length + 4;
console.log(`[seed-kg] TOTAL:          ${total}`);

if (DRY_RUN) {
  console.log("[seed-kg] Dry run complete. No database changes made.");
  process.exit(0);
}

const conn = await mysql.createConnection(DB_URL);
console.log("[seed-kg] Connected to database");

try {
  if (DROP) {
    console.log("[seed-kg] Truncating all kg_* tables...");
    await conn.execute("SET FOREIGN_KEY_CHECKS = 0");
    for (const t of ["kg_answer_provenance","kg_trust_history","kg_sync_status","kg_error_patterns","kg_fields","kg_indices","kg_use_cases","kg_resources","kg_responses","kg_parameters","kg_auth_methods","kg_endpoints"]) {
      await conn.execute(`TRUNCATE TABLE ${t}`);
    }
    await conn.execute("SET FOREIGN_KEY_CHECKS = 1");
    console.log("[seed-kg] All kg_* tables truncated");
  } else {
    const [rows] = await conn.execute("SELECT COUNT(*) as c FROM kg_endpoints");
    if (rows[0].c > 0) {
      console.log(`[seed-kg] WARNING: kg_endpoints already has ${rows[0].c} rows. Use --drop to truncate first.`);
      await conn.end();
      process.exit(1);
    }
  }

  console.log("[seed-kg] Loading all 4 layers...");
  const result = await loadAllLayers(conn, data);

  console.log("\n[seed-kg] ═══ Verification ═══");
  let grandTotal = 0;
  for (const t of ["kg_endpoints","kg_parameters","kg_responses","kg_auth_methods","kg_resources","kg_use_cases","kg_indices","kg_fields","kg_error_patterns","kg_sync_status"]) {
    const [rows] = await conn.execute(`SELECT COUNT(*) as c FROM ${t}`);
    grandTotal += rows[0].c;
    console.log(`[seed-kg]   ${t}: ${rows[0].c}`);
  }
  console.log(`[seed-kg]   ─────────────────`);
  console.log(`[seed-kg]   TOTAL: ${grandTotal}`);

  if (result.success) {
    console.log(`\n[seed-kg] ✓ Knowledge Graph seeded successfully in ${result.durationMs}ms!`);
  } else {
    console.error(`\n[seed-kg] ✗ Some layers failed. Check errors above.`);
    process.exit(1);
  }
} catch (err) {
  console.error(`[seed-kg] ERROR: ${err.message}`);
  if (err.code === "ER_DUP_ENTRY") console.error("[seed-kg] Duplicate entry detected. Use --drop to truncate tables first.");
  process.exit(1);
} finally {
  await conn.end();
}
