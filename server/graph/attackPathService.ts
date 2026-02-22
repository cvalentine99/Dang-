/**
 * Attack Path Detection Service
 *
 * Detects multi-hop attack paths through the Knowledge Graph by traversing
 * relationships between vulnerabilities, software packages, endpoints,
 * identities, and security events.
 *
 * Kill chain stages modeled:
 *   Vulnerability → Software Package → Endpoint → Identity → Security Event
 *   (Initial Access)  (Exploitation)   (Foothold)  (Lateral)  (Impact)
 */

import { eq, desc, sql, and, gte } from "drizzle-orm";
import { getDb } from "../db";
import {
  graphEndpoints,
  graphSoftwarePackages,
  graphVulnerabilities,
  graphIdentities,
  graphSecurityEvents,
} from "../../drizzle/schema";

// ── Types ───────────────────────────────────────────────────────────────────

export interface AttackPathHop {
  nodeId: string;
  nodeType: "vulnerability" | "software_package" | "endpoint" | "identity" | "security_event";
  label: string;
  stage: string;
  severity?: string;
  properties: Record<string, unknown>;
}

export interface AttackPath {
  id: string;
  hops: AttackPathHop[];
  score: number;           // 0-100 severity score
  maxCvss: number;
  killChainStages: string[];
  summary: string;
}

export interface AttackPathResult {
  paths: AttackPath[];
  totalPaths: number;
  maxScore: number;
  criticalPaths: number;
}

// ── Scoring ─────────────────────────────────────────────────────────────────

function severityToScore(severity: string | null): number {
  switch (severity?.toLowerCase()) {
    case "critical": return 95;
    case "high": return 75;
    case "medium": return 50;
    case "low": return 25;
    case "info": return 10;
    default: return 0;
  }
}

function cvssToScore(cvss: number | null): number {
  if (!cvss) return 0;
  return Math.round((cvss / 10) * 100);
}

function computePathScore(hops: AttackPathHop[], maxCvss: number): number {
  // Score based on: CVSS severity, number of hops (more hops = more complex = higher risk),
  // and presence of high-severity security events
  let score = cvssToScore(maxCvss);

  // Bonus for longer chains (more attack surface)
  score += Math.min(20, hops.length * 4);

  // Bonus for having security events (active exploitation evidence)
  const hasEvents = hops.some(h => h.nodeType === "security_event");
  if (hasEvents) score += 15;

  // Bonus for admin identities in the path
  const hasAdmin = hops.some(h =>
    h.nodeType === "identity" && h.properties.isAdmin
  );
  if (hasAdmin) score += 10;

  return Math.min(100, score);
}

// ── Path Detection ──────────────────────────────────────────────────────────

/**
 * Detect attack paths starting from high-severity vulnerabilities.
 * Traversal: Vulnerability → Package → Endpoint → Identity → Security Events
 */
export async function detectAttackPaths(
  options: {
    minCvss?: number;
    limit?: number;
    endpointId?: number;
  } = {}
): Promise<AttackPathResult> {
  const db = await getDb();
  if (!db) return { paths: [], totalPaths: 0, maxScore: 0, criticalPaths: 0 };

  const minCvss = options.minCvss ?? 5.0;
  const limit = options.limit ?? 20;

  // Step 1: Find high-severity vulnerabilities as entry points
  const vulnConditions = [gte(graphVulnerabilities.cvssScore, String(minCvss))];
  if (options.endpointId) {
    vulnConditions.push(eq(graphVulnerabilities.endpointId, options.endpointId));
  }

  const vulns = await db
    .select()
    .from(graphVulnerabilities)
    .where(vulnConditions.length === 1 ? vulnConditions[0] : and(...vulnConditions))
    .orderBy(desc(graphVulnerabilities.cvssScore))
    .limit(limit * 2); // Fetch more to allow filtering

  const paths: AttackPath[] = [];
  const seenEndpoints = new Set<number>();

  for (const vuln of vulns) {
    if (paths.length >= limit) break;

    const hops: AttackPathHop[] = [];
    let maxCvss = parseFloat(vuln.cvssScore ?? "0");

    // Hop 1: Vulnerability (Initial Access)
    hops.push({
      nodeId: `vuln-${vuln.id}`,
      nodeType: "vulnerability",
      label: vuln.cveId,
      stage: "Initial Access",
      severity: vuln.severity ?? undefined,
      properties: {
        cveId: vuln.cveId,
        cvssScore: vuln.cvssScore,
        severity: vuln.severity,
        title: vuln.title,
        packageName: vuln.packageName,
      },
    });

    // Hop 2: Software Package (Exploitation Vector)
    if (vuln.packageId) {
      const pkgs = await db
        .select()
        .from(graphSoftwarePackages)
        .where(eq(graphSoftwarePackages.id, vuln.packageId))
        .limit(1);

      if (pkgs.length > 0) {
        const pkg = pkgs[0];
        hops.push({
          nodeId: `package-${pkg.id}`,
          nodeType: "software_package",
          label: `${pkg.packageName}@${pkg.version ?? "?"}`,
          stage: "Exploitation",
          properties: {
            packageName: pkg.packageName,
            version: pkg.version,
            architecture: pkg.architecture,
            vendor: pkg.vendor,
          },
        });
      }
    }

    // Hop 3: Endpoint (Foothold)
    if (vuln.endpointId && !seenEndpoints.has(vuln.endpointId)) {
      seenEndpoints.add(vuln.endpointId);

      const endpoints = await db
        .select()
        .from(graphEndpoints)
        .where(eq(graphEndpoints.id, vuln.endpointId))
        .limit(1);

      if (endpoints.length > 0) {
        const ep = endpoints[0];
        hops.push({
          nodeId: `endpoint-${ep.id}`,
          nodeType: "endpoint",
          label: ep.hostname ?? ep.agentId,
          stage: "Foothold",
          properties: {
            agentId: ep.agentId,
            hostname: ep.hostname,
            ipAddress: ep.ipAddress,
            osName: ep.osName,
            agentStatus: ep.agentStatus,
          },
        });

        // Hop 4: Identities on this endpoint (Lateral Movement potential)
        const identities = await db
          .select()
          .from(graphIdentities)
          .where(eq(graphIdentities.endpointId, ep.id))
          .limit(5);

        for (const ident of identities) {
          hops.push({
            nodeId: `identity-${ident.id}`,
            nodeType: "identity",
            label: ident.username,
            stage: ident.isAdmin ? "Privilege Escalation" : "Lateral Movement",
            properties: {
              username: ident.username,
              uid: ident.uid,
              isAdmin: ident.isAdmin,
              shell: ident.shell,
            },
          });
        }

        // Hop 5: Security events on this endpoint (Impact evidence)
        const events = await db
          .select()
          .from(graphSecurityEvents)
          .where(eq(graphSecurityEvents.endpointId, ep.id))
          .orderBy(desc(graphSecurityEvents.ruleLevel))
          .limit(3);

        for (const ev of events) {
          hops.push({
            nodeId: `event-${ev.id}`,
            nodeType: "security_event",
            label: `Rule ${ev.ruleId}: ${ev.ruleDescription ?? ""}`.slice(0, 80),
            stage: ev.mitreTactic ?? "Impact",
            severity: (ev.ruleLevel ?? 0) >= 12 ? "critical" : (ev.ruleLevel ?? 0) >= 8 ? "high" : (ev.ruleLevel ?? 0) >= 4 ? "medium" : "low",
            properties: {
              ruleId: ev.ruleId,
              ruleDescription: ev.ruleDescription,
              mitreTactic: ev.mitreTactic,
              mitreTechnique: ev.mitreTechnique,
              severityLevel: ev.ruleLevel,
              eventTimestamp: ev.eventTimestamp,
            },
          });
        }
      }
    }

    // Only include paths with at least 3 hops (vuln → package/endpoint → something else)
    if (hops.length >= 3) {
      const score = computePathScore(hops, maxCvss);
      const stages = Array.from(new Set(hops.map(h => h.stage)));

      paths.push({
        id: `path-${vuln.id}-${vuln.endpointId ?? 0}`,
        hops,
        score,
        maxCvss,
        killChainStages: stages,
        summary: buildPathSummary(hops, vuln.cveId, maxCvss),
      });
    }
  }

  // Sort by score descending
  paths.sort((a, b) => b.score - a.score);

  return {
    paths: paths.slice(0, limit),
    totalPaths: paths.length,
    maxScore: paths.length > 0 ? paths[0].score : 0,
    criticalPaths: paths.filter(p => p.score >= 75).length,
  };
}

function buildPathSummary(hops: AttackPathHop[], cveId: string, cvss: number): string {
  const endpoint = hops.find(h => h.nodeType === "endpoint");
  const pkg = hops.find(h => h.nodeType === "software_package");
  const adminIdent = hops.find(h => h.nodeType === "identity" && h.properties.isAdmin);
  const events = hops.filter(h => h.nodeType === "security_event");

  let summary = `${cveId} (CVSS ${cvss})`;
  if (pkg) summary += ` via ${pkg.label}`;
  if (endpoint) summary += ` on ${endpoint.label}`;
  if (adminIdent) summary += ` — admin user "${adminIdent.label}" exposed`;
  if (events.length > 0) summary += ` — ${events.length} related alert(s)`;

  return summary;
}

/**
 * Get attack paths formatted as graph data for D3 visualization.
 */
export async function getAttackPathGraphData(
  options: { minCvss?: number; limit?: number } = {}
): Promise<{
  nodes: Array<{ id: string; type: string; label: string; stage: string; severity?: string; properties: Record<string, unknown> }>;
  edges: Array<{ source: string; target: string; relationship: string; isAttackPath: boolean }>;
  paths: AttackPath[];
}> {
  const result = await detectAttackPaths(options);

  const nodeMap = new Map<string, AttackPathHop>();
  const edges: Array<{ source: string; target: string; relationship: string; isAttackPath: boolean }> = [];

  for (const path of result.paths) {
    // Add all nodes
    for (const hop of path.hops) {
      if (!nodeMap.has(hop.nodeId)) {
        nodeMap.set(hop.nodeId, hop);
      }
    }

    // Create edges between consecutive hops
    for (let i = 0; i < path.hops.length - 1; i++) {
      const from = path.hops[i];
      const to = path.hops[i + 1];
      const relationship = getRelationship(from.nodeType, to.nodeType);
      edges.push({
        source: from.nodeId,
        target: to.nodeId,
        relationship,
        isAttackPath: true,
      });
    }
  }

  const nodes = Array.from(nodeMap.values()).map(hop => ({
    id: hop.nodeId,
    type: hop.nodeType,
    label: hop.label,
    stage: hop.stage,
    severity: hop.severity,
    properties: hop.properties,
  }));

  return { nodes, edges, paths: result.paths };
}

function getRelationship(fromType: string, toType: string): string {
  const key = `${fromType}->${toType}`;
  const map: Record<string, string> = {
    "vulnerability->software_package": "EXPLOITS",
    "software_package->endpoint": "INSTALLED_ON",
    "vulnerability->endpoint": "AFFECTS",
    "endpoint->identity": "HAS_USER",
    "endpoint->security_event": "TRIGGERED",
    "identity->security_event": "CAUSED",
    "security_event->endpoint": "TRIGGERED_ON",
  };
  return map[key] ?? "CONNECTED_TO";
}
