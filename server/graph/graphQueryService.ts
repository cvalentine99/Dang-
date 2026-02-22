/**
 * Graph Query Service — Knowledge Graph Traversals
 *
 * Provides structured queries against the MySQL-based Knowledge Graph tables.
 * Replaces Cypher/FalkorDB traversals with SQL JOINs that follow the same
 * graph schema: Endpoint → Process → NetworkPort, Endpoint → SoftwarePackage → Vulnerability, etc.
 */

import { eq, like, sql, desc, and, or, inArray } from "drizzle-orm";
import { getDb } from "../db";
import {
  graphEndpoints,
  graphProcesses,
  graphNetworkPorts,
  graphSoftwarePackages,
  graphIdentities,
  graphVulnerabilities,
  graphSecurityEvents,
} from "../../drizzle/schema";

// ── Types ───────────────────────────────────────────────────────────────────

export interface GraphNode {
  id: string;
  type: "endpoint" | "process" | "network_port" | "software_package" | "identity" | "vulnerability" | "security_event";
  label: string;
  properties: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphStats {
  endpoints: number;
  processes: number;
  networkPorts: number;
  softwarePackages: number;
  identities: number;
  vulnerabilities: number;
  securityEvents: number;
}

// ── Stats ───────────────────────────────────────────────────────────────────

export async function getGraphStats(): Promise<GraphStats> {
  const db = await getDb();
  if (!db) return { endpoints: 0, processes: 0, networkPorts: 0, softwarePackages: 0, identities: 0, vulnerabilities: 0, securityEvents: 0 };

  const [ep, pr, np, sp, id, vu, se] = await Promise.all([
    db.select({ count: sql<number>`count(*)` }).from(graphEndpoints),
    db.select({ count: sql<number>`count(*)` }).from(graphProcesses),
    db.select({ count: sql<number>`count(*)` }).from(graphNetworkPorts),
    db.select({ count: sql<number>`count(*)` }).from(graphSoftwarePackages),
    db.select({ count: sql<number>`count(*)` }).from(graphIdentities),
    db.select({ count: sql<number>`count(*)` }).from(graphVulnerabilities),
    db.select({ count: sql<number>`count(*)` }).from(graphSecurityEvents),
  ]);

  return {
    endpoints: ep[0]?.count ?? 0,
    processes: pr[0]?.count ?? 0,
    networkPorts: np[0]?.count ?? 0,
    softwarePackages: sp[0]?.count ?? 0,
    identities: id[0]?.count ?? 0,
    vulnerabilities: vu[0]?.count ?? 0,
    securityEvents: se[0]?.count ?? 0,
  };
}

// ── Endpoint-centric queries ────────────────────────────────────────────────

/**
 * Get full graph data for a specific endpoint (all connected nodes).
 */
export async function getEndpointGraph(agentId: string): Promise<GraphData> {
  const db = await getDb();
  if (!db) return { nodes: [], edges: [] };

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  // Get endpoint
  const endpoints = await db.select().from(graphEndpoints).where(eq(graphEndpoints.agentId, agentId)).limit(1);
  if (endpoints.length === 0) return { nodes: [], edges: [] };
  const ep = endpoints[0];
  const epNodeId = `endpoint-${ep.id}`;

  nodes.push({
    id: epNodeId,
    type: "endpoint",
    label: ep.hostname ?? ep.agentId,
    properties: { ...ep },
  });

  // Get processes
  const processes = await db.select().from(graphProcesses).where(eq(graphProcesses.endpointId, ep.id)).limit(100);
  for (const p of processes) {
    const nodeId = `process-${p.id}`;
    nodes.push({ id: nodeId, type: "process", label: p.processName, properties: { ...p } });
    edges.push({ source: epNodeId, target: nodeId, relationship: "RUNS" });
  }

  // Get network ports
  const ports = await db.select().from(graphNetworkPorts).where(eq(graphNetworkPorts.endpointId, ep.id)).limit(100);
  for (const port of ports) {
    const nodeId = `port-${port.id}`;
    nodes.push({ id: nodeId, type: "network_port", label: `${port.protocol ?? "tcp"}:${port.localPort}`, properties: { ...port } });
    edges.push({ source: epNodeId, target: nodeId, relationship: "LISTENS_ON" });
    if (port.processId) {
      const procNodeId = `process-${port.processId}`;
      edges.push({ source: procNodeId, target: nodeId, relationship: "BINDS" });
    }
  }

  // Get software packages
  const packages = await db.select().from(graphSoftwarePackages).where(eq(graphSoftwarePackages.endpointId, ep.id)).limit(100);
  for (const pkg of packages) {
    const nodeId = `package-${pkg.id}`;
    nodes.push({ id: nodeId, type: "software_package", label: `${pkg.packageName}@${pkg.version ?? "?"}`, properties: { ...pkg } });
    edges.push({ source: epNodeId, target: nodeId, relationship: "HAS_INSTALLED" });
  }

  // Get identities
  const identities = await db.select().from(graphIdentities).where(eq(graphIdentities.endpointId, ep.id)).limit(100);
  for (const ident of identities) {
    const nodeId = `identity-${ident.id}`;
    nodes.push({ id: nodeId, type: "identity", label: ident.username, properties: { ...ident } });
    edges.push({ source: epNodeId, target: nodeId, relationship: "HAS_USER" });
  }

  // Get vulnerabilities
  const vulns = await db.select().from(graphVulnerabilities).where(eq(graphVulnerabilities.endpointId, ep.id)).limit(100);
  for (const v of vulns) {
    const nodeId = `vuln-${v.id}`;
    nodes.push({ id: nodeId, type: "vulnerability", label: v.cveId, properties: { ...v } });
    edges.push({ source: epNodeId, target: nodeId, relationship: "AFFECTED_BY" });
    // Link to package if available
    if (v.packageId) {
      const pkgNodeId = `package-${v.packageId}`;
      edges.push({ source: pkgNodeId, target: nodeId, relationship: "HAS_VULNERABILITY" });
    }
  }

  // Get security events
  const events = await db.select().from(graphSecurityEvents).where(eq(graphSecurityEvents.endpointId, ep.id)).orderBy(desc(graphSecurityEvents.eventTimestamp)).limit(50);
  for (const ev of events) {
    const nodeId = `event-${ev.id}`;
    nodes.push({ id: nodeId, type: "security_event", label: `Rule ${ev.ruleId}`, properties: { ...ev } });
    edges.push({ source: nodeId, target: epNodeId, relationship: "TRIGGERED_ON" });
  }

  return { nodes, edges };
}

/**
 * Get overview graph showing all endpoints and their high-level connections.
 */
export async function getOverviewGraph(limit: number = 50): Promise<GraphData> {
  const db = await getDb();
  if (!db) return { nodes: [], edges: [] };

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const endpoints = await db.select().from(graphEndpoints).limit(limit);

  for (const ep of endpoints) {
    const epNodeId = `endpoint-${ep.id}`;
    nodes.push({
      id: epNodeId,
      type: "endpoint",
      label: ep.hostname ?? ep.agentId,
      properties: { agentId: ep.agentId, hostname: ep.hostname, ipAddress: ep.ipAddress, osName: ep.osName, agentStatus: ep.agentStatus },
    });

    // Count related entities
    const [procCount, portCount, pkgCount, vulnCount, eventCount] = await Promise.all([
      db.select({ count: sql<number>`count(*)` }).from(graphProcesses).where(eq(graphProcesses.endpointId, ep.id)),
      db.select({ count: sql<number>`count(*)` }).from(graphNetworkPorts).where(eq(graphNetworkPorts.endpointId, ep.id)),
      db.select({ count: sql<number>`count(*)` }).from(graphSoftwarePackages).where(eq(graphSoftwarePackages.endpointId, ep.id)),
      db.select({ count: sql<number>`count(*)` }).from(graphVulnerabilities).where(eq(graphVulnerabilities.endpointId, ep.id)),
      db.select({ count: sql<number>`count(*)` }).from(graphSecurityEvents).where(eq(graphSecurityEvents.endpointId, ep.id)),
    ]);

    // Add summary nodes for each entity type with counts > 0
    if ((procCount[0]?.count ?? 0) > 0) {
      const nodeId = `procs-${ep.id}`;
      nodes.push({ id: nodeId, type: "process", label: `${procCount[0].count} processes`, properties: { count: procCount[0].count } });
      edges.push({ source: epNodeId, target: nodeId, relationship: "RUNS" });
    }
    if ((vulnCount[0]?.count ?? 0) > 0) {
      const nodeId = `vulns-${ep.id}`;
      nodes.push({ id: nodeId, type: "vulnerability", label: `${vulnCount[0].count} CVEs`, properties: { count: vulnCount[0].count } });
      edges.push({ source: epNodeId, target: nodeId, relationship: "AFFECTED_BY" });
    }
    if ((eventCount[0]?.count ?? 0) > 0) {
      const nodeId = `events-${ep.id}`;
      nodes.push({ id: nodeId, type: "security_event", label: `${eventCount[0].count} alerts`, properties: { count: eventCount[0].count } });
      edges.push({ source: nodeId, target: epNodeId, relationship: "TRIGGERED_ON" });
    }
  }

  return { nodes, edges };
}

/**
 * Search across all graph entities by keyword.
 */
export async function searchGraph(query: string, limit: number = 50): Promise<GraphNode[]> {
  const db = await getDb();
  if (!db) return [];

  const pattern = `%${query}%`;
  const results: GraphNode[] = [];

  // Search endpoints
  const eps = await db.select().from(graphEndpoints)
    .where(or(like(graphEndpoints.hostname, pattern), like(graphEndpoints.agentId, pattern), like(graphEndpoints.ipAddress, pattern)))
    .limit(limit);
  for (const ep of eps) {
    results.push({ id: `endpoint-${ep.id}`, type: "endpoint", label: ep.hostname ?? ep.agentId, properties: { ...ep } });
  }

  // Search vulnerabilities
  const vulns = await db.select().from(graphVulnerabilities)
    .where(or(like(graphVulnerabilities.cveId, pattern), like(graphVulnerabilities.packageName, pattern)))
    .limit(limit);
  for (const v of vulns) {
    results.push({ id: `vuln-${v.id}`, type: "vulnerability", label: v.cveId, properties: { ...v } });
  }

  // Search security events
  const events = await db.select().from(graphSecurityEvents)
    .where(or(like(graphSecurityEvents.ruleId, pattern), like(graphSecurityEvents.ruleDescription, pattern), like(graphSecurityEvents.mitreTactic, pattern)))
    .limit(limit);
  for (const ev of events) {
    results.push({ id: `event-${ev.id}`, type: "security_event", label: `Rule ${ev.ruleId}`, properties: { ...ev } });
  }

  // Search processes
  const procs = await db.select().from(graphProcesses)
    .where(or(like(graphProcesses.processName, pattern), like(graphProcesses.cmdLine, pattern)))
    .limit(limit);
  for (const p of procs) {
    results.push({ id: `process-${p.id}`, type: "process", label: p.processName, properties: { ...p } });
  }

  // Search identities
  const idents = await db.select().from(graphIdentities)
    .where(like(graphIdentities.username, pattern))
    .limit(limit);
  for (const i of idents) {
    results.push({ id: `identity-${i.id}`, type: "identity", label: i.username, properties: { ...i } });
  }

  return results.slice(0, limit);
}

/**
 * Get vulnerability-to-endpoint attack surface: which endpoints are affected by a specific CVE.
 */
export async function getVulnerabilityAttackSurface(cveId: string): Promise<GraphData> {
  const db = await getDb();
  if (!db) return { nodes: [], edges: [] };

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const vulns = await db.select().from(graphVulnerabilities).where(eq(graphVulnerabilities.cveId, cveId));
  if (vulns.length === 0) return { nodes, edges };

  // CVE node
  const cveNodeId = `cve-${cveId}`;
  nodes.push({
    id: cveNodeId,
    type: "vulnerability",
    label: cveId,
    properties: { cveId, severity: vulns[0].severity, cvssScore: vulns[0].cvssScore, title: vulns[0].title },
  });

  // Get affected endpoints
  const endpointIds = Array.from(new Set(vulns.map(v => v.endpointId)));
  if (endpointIds.length > 0) {
    const endpoints = await db.select().from(graphEndpoints).where(inArray(graphEndpoints.id, endpointIds));
    for (const ep of endpoints) {
      const epNodeId = `endpoint-${ep.id}`;
      nodes.push({ id: epNodeId, type: "endpoint", label: ep.hostname ?? ep.agentId, properties: { ...ep } });
      edges.push({ source: epNodeId, target: cveNodeId, relationship: "AFFECTED_BY" });
    }
  }

  return { nodes, edges };
}

/**
 * Get MITRE ATT&CK tactic distribution from security events.
 */
export async function getMitreDistribution(): Promise<Array<{ tactic: string; count: number }>> {
  const db = await getDb();
  if (!db) return [];

  const rows = await db
    .select({
      tactic: graphSecurityEvents.mitreTactic,
      count: sql<number>`count(*)`,
    })
    .from(graphSecurityEvents)
    .where(sql`${graphSecurityEvents.mitreTactic} IS NOT NULL AND ${graphSecurityEvents.mitreTactic} != ''`)
    .groupBy(graphSecurityEvents.mitreTactic)
    .orderBy(desc(sql`count(*)`))
    .limit(20);

  return rows.map(r => ({ tactic: r.tactic ?? "", count: r.count }));
}

/**
 * Get severity distribution of vulnerabilities.
 */
export async function getVulnerabilitySeverityDistribution(): Promise<Array<{ severity: string; count: number }>> {
  const db = await getDb();
  if (!db) return [];

  const rows = await db
    .select({
      severity: graphVulnerabilities.severity,
      count: sql<number>`count(*)`,
    })
    .from(graphVulnerabilities)
    .where(sql`${graphVulnerabilities.severity} IS NOT NULL`)
    .groupBy(graphVulnerabilities.severity)
    .orderBy(desc(sql`count(*)`));

  return rows.map(r => ({ severity: r.severity ?? "Unknown", count: r.count }));
}
