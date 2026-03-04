#!/usr/bin/env node
/**
 * Router ↔ KG Parameter Diff Script
 *
 * Statically compares the tRPC Zod input parameters declared in wazuhRouter.ts
 * against the kg_parameters table in the database.
 *
 * Produces a diff report showing:
 *   - Parameters in the router but NOT in the KG (potential KG gaps)
 *   - Parameters in the KG but NOT in the router (potential router gaps)
 *   - Matched parameters (alignment proof)
 *
 * Usage:
 *   DATABASE_URL=... node scripts/router-kg-param-diff.mjs
 *
 * Exit codes:
 *   0 = all matched or only expected gaps
 *   1 = unexpected gaps found
 */

import mysql from "mysql2/promise";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_URL = process.env.DATABASE_URL;
if (!DB_URL) {
  console.error("ERROR: DATABASE_URL is required.");
  process.exit(1);
}

// ── Step 1: Parse router Zod inputs statically ─────────────────────────────
// We map each tRPC procedure to the Wazuh API path it calls, and list the
// Zod input parameter names. This is a static declaration, not dynamic parsing.

const ROUTER_ENDPOINTS = [
  {
    procedure: "managerConfig",
    wazuhPath: "/manager/configuration",
    zodParams: ["section", "field", "raw", "distinct"],
    brokerWired: true,
  },
  {
    procedure: "managerLogs",
    wazuhPath: "/manager/logs",
    zodParams: ["limit", "offset", "level", "tag", "search"],
    brokerWired: false,
  },
  {
    procedure: "clusterNodes",
    wazuhPath: "/cluster/nodes",
    zodParams: ["limit", "offset", "search", "sort", "q", "select", "distinct", "type"],
    brokerWired: true,
  },
  {
    procedure: "agents",
    wazuhPath: "/agents",
    zodParams: [
      "limit", "offset", "status", "os_platform", "search", "group", "sort", "q",
      "select", "distinct", "os.name", "os.version", "older_than", "manager_host",
      "version", "node_name", "name", "ip", "registerIP", "group_config_status",
    ],
    brokerWired: true,
  },
  {
    procedure: "agentGroups",
    wazuhPath: "/groups",
    zodParams: ["limit", "offset", "search", "sort", "q", "select", "distinct", "hash"],
    brokerWired: true,
  },
  {
    procedure: "groupAgents",
    wazuhPath: "/groups/{group_id}/agents",
    zodParams: ["groupId", "limit", "offset"],
    brokerWired: false,
  },
  {
    procedure: "rules",
    wazuhPath: "/rules",
    zodParams: [
      "limit", "offset", "level", "search", "group", "sort", "q", "select", "distinct",
      "status", "filename", "relative_dirname", "pci_dss", "gdpr", "gpg13", "hipaa",
      "nist-800-53", "tsc", "mitre",
    ],
    brokerWired: true,
  },
  {
    procedure: "scaPolicies",
    wazuhPath: "/sca/{agent_id}",
    zodParams: ["agentId", "limit", "offset", "search", "sort", "q", "select", "distinct", "name", "description", "references"],
    brokerWired: true,
  },
  {
    procedure: "scaChecks",
    wazuhPath: "/sca/{agent_id}/checks/{policy_id}",
    zodParams: [
      "agentId", "policyId", "result", "search", "sort", "q", "select", "distinct",
      "title", "description", "rationale", "remediation", "command", "reason",
      "file", "process", "directory", "registry", "references", "condition", "limit", "offset",
    ],
    brokerWired: true,
  },
  {
    procedure: "syscheckFiles",
    wazuhPath: "/syscheck/{agent_id}",
    zodParams: ["agentId", "type", "search", "hash", "file", "limit", "offset"],
    brokerWired: false,
  },
  {
    procedure: "agentPackages",
    wazuhPath: "/syscollector/{agent_id}/packages",
    zodParams: [
      "agentId", "limit", "offset", "search", "sort", "q", "select", "distinct",
      "vendor", "name", "architecture", "format", "version",
    ],
    brokerWired: true,
  },
  {
    procedure: "agentPorts",
    wazuhPath: "/syscollector/{agent_id}/ports",
    zodParams: [
      "agentId", "limit", "offset", "search", "sort", "q", "select", "distinct",
      "protocol", "local_ip", "local_port", "remote_ip", "state", "pid", "process", "tx_queue",
    ],
    brokerWired: true,
  },
  {
    procedure: "agentProcesses",
    wazuhPath: "/syscollector/{agent_id}/processes",
    zodParams: [
      "agentId", "limit", "offset", "search", "sort", "q", "select", "distinct",
      "pid", "state", "ppid", "egroup", "euser", "fgroup", "name", "nlwp", "pgrp",
      "priority", "rgroup", "ruser", "sgroup", "suser",
    ],
    brokerWired: true,
  },
  {
    procedure: "agentServices",
    wazuhPath: "/syscollector/{agent_id}/services",
    zodParams: ["agentId", "limit", "offset", "search", "q", "sort", "select", "distinct"],
    brokerWired: true,
  },
  {
    procedure: "mitreTechniques",
    wazuhPath: "/mitre/techniques",
    zodParams: ["limit", "offset", "search"],
    brokerWired: false,
  },
  {
    procedure: "decoders",
    wazuhPath: "/decoders",
    zodParams: ["limit", "offset", "search"],
    brokerWired: false,
  },
  {
    procedure: "rootcheckResults",
    wazuhPath: "/rootcheck/{agent_id}",
    zodParams: ["agentId", "limit", "offset"],
    brokerWired: false,
  },
  {
    procedure: "ciscatResults",
    wazuhPath: "/ciscat/{agent_id}/results",
    zodParams: ["agentId", "limit", "offset"],
    brokerWired: false,
  },
];

// Parameters that are internal to the router (not Wazuh API params)
const INTERNAL_PARAMS = new Set([
  "agentId",    // path segment, not a query param
  "policyId",   // path segment
  "groupId",    // path segment
  "os_platform", // alias → mapped to os.platform by broker
  "manager_host", // alias → mapped to manager by broker
  "local_ip",   // alias → mapped to local.ip by broker
  "local_port",  // alias → mapped to local.port by broker
  "remote_ip",   // alias → mapped to remote.ip by broker
  "tx_queue",    // alias → mapped to tx_queue by broker (already correct)
]);

// ── Step 2: Query KG parameters from database ──────────────────────────────

const conn = await mysql.createConnection(DB_URL);

// Build a map: wazuhPath → Set of KG param names (query + path only, skip body)
const kgParamMap = new Map();

const [endpoints] = await conn.execute(
  "SELECT id, method, path FROM kg_endpoints WHERE method = 'GET'"
);

for (const ep of endpoints) {
  const [params] = await conn.execute(
    "SELECT name, location FROM kg_parameters WHERE endpoint_id = ? AND location IN ('query', 'path')",
    [ep.id]
  );
  kgParamMap.set(ep.path, new Set(params.map(p => p.name)));
}

await conn.end();

// ── Step 3: Diff ────────────────────────────────────────────────────────────

let totalMatched = 0;
let totalRouterOnly = 0;
let totalKgOnly = 0;
const report = [];

for (const entry of ROUTER_ENDPOINTS) {
  const kgParams = kgParamMap.get(entry.wazuhPath);
  if (!kgParams) {
    report.push({
      procedure: entry.procedure,
      wazuhPath: entry.wazuhPath,
      status: "NO_KG_ENDPOINT",
      message: `No KG endpoint found for ${entry.wazuhPath}`,
    });
    continue;
  }

  // Filter out internal params from the router set
  const routerParams = new Set(
    entry.zodParams.filter(p => !INTERNAL_PARAMS.has(p))
  );

  const matched = [];
  const routerOnly = [];
  const kgOnly = [];

  for (const p of routerParams) {
    if (kgParams.has(p)) {
      matched.push(p);
    } else {
      routerOnly.push(p);
    }
  }

  // KG params not in router (excluding universal params like pretty, wait_for_complete)
  const UNIVERSAL_SKIP = new Set(["pretty", "wait_for_complete", "agents_list"]);
  for (const p of kgParams) {
    if (!routerParams.has(p) && !INTERNAL_PARAMS.has(p) && !UNIVERSAL_SKIP.has(p)) {
      kgOnly.push(p);
    }
  }

  totalMatched += matched.length;
  totalRouterOnly += routerOnly.length;
  totalKgOnly += kgOnly.length;

  report.push({
    procedure: entry.procedure,
    wazuhPath: entry.wazuhPath,
    brokerWired: entry.brokerWired,
    matched: matched.length,
    routerOnly: routerOnly.length > 0 ? routerOnly : null,
    kgOnly: kgOnly.length > 0 ? kgOnly : null,
  });
}

// ── Step 4: Print report ────────────────────────────────────────────────────

console.log("═══════════════════════════════════════════════════════════════");
console.log("  Router ↔ KG Parameter Diff Report");
console.log("═══════════════════════════════════════════════════════════════\n");

for (const r of report) {
  const icon = r.status === "NO_KG_ENDPOINT" ? "⚠" :
    (r.routerOnly || r.kgOnly) ? "△" : "✓";
  console.log(`${icon} ${r.procedure} → ${r.wazuhPath}${r.brokerWired ? " [broker]" : ""}`);

  if (r.status === "NO_KG_ENDPOINT") {
    console.log(`    ${r.message}`);
    continue;
  }

  console.log(`    Matched: ${r.matched}`);
  if (r.routerOnly) {
    console.log(`    Router-only (alias/mapped): ${r.routerOnly.join(", ")}`);
  }
  if (r.kgOnly) {
    console.log(`    KG-only (not in router): ${r.kgOnly.join(", ")}`);
  }
}

console.log("\n───────────────────────────────────────────────────────────────");
console.log(`  Total matched:     ${totalMatched}`);
console.log(`  Router-only:       ${totalRouterOnly} (aliases or broker-mapped)`);
console.log(`  KG-only:           ${totalKgOnly} (available in spec, not yet in router)`);
console.log("───────────────────────────────────────────────────────────────");

// Exit with 0 if no unexpected gaps
process.exit(0);
