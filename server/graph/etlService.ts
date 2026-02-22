/**
 * ETL Pipeline Service — Wazuh → Knowledge Graph Tables
 *
 * Syncs data from the Wazuh Server API (syscollector) and Wazuh Indexer
 * (alerts, vulnerabilities) into the MySQL Knowledge Graph tables.
 *
 * Architecture:
 * - Wazuh Server API → Endpoints, Processes, NetworkPorts, SoftwarePackages, Identities
 * - Wazuh Indexer (wazuh-alerts-*) → SecurityEvents
 * - Wazuh Indexer (wazuh-states-vulnerabilities-*) → Vulnerabilities
 *
 * All syncs are incremental where possible (using lastSyncAt timestamps).
 * Each entity type tracks its own sync status independently.
 */

import { eq, sql } from "drizzle-orm";
import { getDb } from "../db";
import {
  graphEndpoints,
  graphProcesses,
  graphNetworkPorts,
  graphSoftwarePackages,
  graphIdentities,
  graphVulnerabilities,
  graphSecurityEvents,
  graphSyncStatus,
} from "../../drizzle/schema";
import { isWazuhConfigured, getWazuhConfig, wazuhGet } from "../wazuh/wazuhClient";
import {
  isIndexerConfigured,
  getIndexerConfig,
  indexerSearch,
  INDEX_PATTERNS,
  boolQuery,
  timeRangeFilter,
} from "../indexer/indexerClient";

// ── Types ───────────────────────────────────────────────────────────────────

export interface SyncResult {
  entityType: string;
  status: "completed" | "error" | "skipped";
  count: number;
  durationMs: number;
  error?: string;
}

export interface FullSyncResult {
  results: SyncResult[];
  totalDurationMs: number;
  startedAt: string;
  completedAt: string;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async function updateSyncStatus(
  entityType: string,
  status: "idle" | "syncing" | "completed" | "error",
  count?: number,
  durationMs?: number,
  errorMessage?: string
): Promise<void> {
  const db = await getDb();
  if (!db) return;

  // Upsert sync status
  const existing = await db
    .select()
    .from(graphSyncStatus)
    .where(eq(graphSyncStatus.entityType, entityType))
    .limit(1);

  if (existing.length === 0) {
    await db.insert(graphSyncStatus).values({
      entityType,
      status,
      entityCount: count ?? 0,
      durationMs: durationMs ?? null,
      errorMessage: errorMessage ?? null,
      lastSyncAt: status === "completed" ? new Date() : null,
    });
  } else {
    const updates: Record<string, unknown> = { status };
    if (count !== undefined) updates.entityCount = count;
    if (durationMs !== undefined) updates.durationMs = durationMs;
    if (errorMessage !== undefined) updates.errorMessage = errorMessage;
    if (status === "completed") updates.lastSyncAt = new Date();
    await db
      .update(graphSyncStatus)
      .set(updates)
      .where(eq(graphSyncStatus.entityType, entityType));
  }
}

async function getLastSyncTime(entityType: string): Promise<Date | null> {
  const db = await getDb();
  if (!db) return null;
  const rows = await db
    .select({ lastSyncAt: graphSyncStatus.lastSyncAt })
    .from(graphSyncStatus)
    .where(eq(graphSyncStatus.entityType, entityType))
    .limit(1);
  return rows[0]?.lastSyncAt ?? null;
}

// ── Sync: Endpoints (from Wazuh Server API) ─────────────────────────────────

async function syncEndpoints(): Promise<SyncResult> {
  const start = Date.now();
  const entityType = "endpoints";

  try {
    await updateSyncStatus(entityType, "syncing");

    if (!isWazuhConfigured()) {
      await updateSyncStatus(entityType, "error", 0, Date.now() - start, "Wazuh not configured");
      return { entityType, status: "skipped", count: 0, durationMs: Date.now() - start, error: "Wazuh not configured" };
    }

    const config = getWazuhConfig();
    const response = await wazuhGet(config, {
      path: "/agents",
      params: { limit: 500, select: "id,name,ip,os.name,os.version,os.platform,os.arch,version,status,lastKeepAlive" },
    }) as { data?: { affected_items?: Array<Record<string, unknown>> } };

    const agents = response?.data?.affected_items ?? [];
    const db = await getDb();
    if (!db) throw new Error("Database unavailable");

    let count = 0;
    for (const agent of agents) {
      const agentId = String(agent.id ?? "");
      if (!agentId || agentId === "000") continue; // Skip manager

      const os = agent.os as Record<string, unknown> | undefined;

      // Upsert endpoint
      const existing = await db
        .select({ id: graphEndpoints.id })
        .from(graphEndpoints)
        .where(eq(graphEndpoints.agentId, agentId))
        .limit(1);

      const values = {
        agentId,
        hostname: String(agent.name ?? ""),
        ipAddress: String(agent.ip ?? ""),
        osName: String(os?.name ?? ""),
        osVersion: String(os?.version ?? ""),
        osPlatform: String(os?.platform ?? ""),
        architecture: String(os?.arch ?? ""),
        agentVersion: String(agent.version ?? ""),
        agentStatus: String(agent.status ?? ""),
        lastKeepAlive: agent.lastKeepAlive ? new Date(String(agent.lastKeepAlive)) : null,
        syncedAt: new Date(),
      };

      if (existing.length > 0) {
        await db.update(graphEndpoints).set(values).where(eq(graphEndpoints.id, existing[0].id));
      } else {
        await db.insert(graphEndpoints).values(values);
      }
      count++;
    }

    await updateSyncStatus(entityType, "completed", count, Date.now() - start);
    return { entityType, status: "completed", count, durationMs: Date.now() - start };
  } catch (err) {
    const error = (err as Error).message;
    await updateSyncStatus(entityType, "error", 0, Date.now() - start, error);
    return { entityType, status: "error", count: 0, durationMs: Date.now() - start, error };
  }
}

// ── Sync: Processes (from Wazuh Server API syscollector) ────────────────────

async function syncProcesses(): Promise<SyncResult> {
  const start = Date.now();
  const entityType = "processes";

  try {
    await updateSyncStatus(entityType, "syncing");

    if (!isWazuhConfigured()) {
      await updateSyncStatus(entityType, "error", 0, Date.now() - start, "Wazuh not configured");
      return { entityType, status: "skipped", count: 0, durationMs: Date.now() - start };
    }

    const config = getWazuhConfig();
    const db = await getDb();
    if (!db) throw new Error("Database unavailable");

    // Get all endpoints to iterate
    const endpoints = await db.select({ id: graphEndpoints.id, agentId: graphEndpoints.agentId }).from(graphEndpoints);

    let count = 0;
    for (const ep of endpoints) {
      try {
        const response = await wazuhGet(config, {
          path: `/syscollector/${ep.agentId}/processes`,
          params: { limit: 500 },
        }) as { data?: { affected_items?: Array<Record<string, unknown>> } };

        const processes = response?.data?.affected_items ?? [];

        // Clear old processes for this endpoint
        await db.delete(graphProcesses).where(eq(graphProcesses.endpointId, ep.id));

        for (const proc of processes) {
          await db.insert(graphProcesses).values({
            endpointId: ep.id,
            processName: String(proc.name ?? ""),
            pid: proc.pid ? Number(proc.pid) : null,
            ppid: proc.ppid ? Number(proc.ppid) : null,
            state: String(proc.state ?? ""),
            userName: String(proc.utime ?? proc.suser ?? ""),
            cmdLine: proc.cmd ? String(proc.cmd) : null,
            syncedAt: new Date(),
          });
          count++;
        }
      } catch {
        // Skip agents that don't support syscollector
        continue;
      }
    }

    await updateSyncStatus(entityType, "completed", count, Date.now() - start);
    return { entityType, status: "completed", count, durationMs: Date.now() - start };
  } catch (err) {
    const error = (err as Error).message;
    await updateSyncStatus(entityType, "error", 0, Date.now() - start, error);
    return { entityType, status: "error", count: 0, durationMs: Date.now() - start, error };
  }
}

// ── Sync: Network Ports (from Wazuh Server API syscollector) ────────────────

async function syncNetworkPorts(): Promise<SyncResult> {
  const start = Date.now();
  const entityType = "network_ports";

  try {
    await updateSyncStatus(entityType, "syncing");

    if (!isWazuhConfigured()) {
      await updateSyncStatus(entityType, "error", 0, Date.now() - start, "Wazuh not configured");
      return { entityType, status: "skipped", count: 0, durationMs: Date.now() - start };
    }

    const config = getWazuhConfig();
    const db = await getDb();
    if (!db) throw new Error("Database unavailable");

    const endpoints = await db.select({ id: graphEndpoints.id, agentId: graphEndpoints.agentId }).from(graphEndpoints);

    let count = 0;
    for (const ep of endpoints) {
      try {
        const response = await wazuhGet(config, {
          path: `/syscollector/${ep.agentId}/ports`,
          params: { limit: 500 },
        }) as { data?: { affected_items?: Array<Record<string, unknown>> } };

        const ports = response?.data?.affected_items ?? [];

        await db.delete(graphNetworkPorts).where(eq(graphNetworkPorts.endpointId, ep.id));

        for (const port of ports) {
          const local = port.local as Record<string, unknown> | undefined;
          const remote = port.remote as Record<string, unknown> | undefined;
          await db.insert(graphNetworkPorts).values({
            endpointId: ep.id,
            localPort: Number(local?.port ?? port.local_port ?? 0),
            localIp: String(local?.ip ?? port.local_ip ?? ""),
            remoteIp: String(remote?.ip ?? port.remote_ip ?? ""),
            remotePort: remote?.port ? Number(remote.port) : null,
            protocol: String(port.protocol ?? ""),
            state: String(port.state ?? ""),
            syncedAt: new Date(),
          });
          count++;
        }
      } catch {
        continue;
      }
    }

    await updateSyncStatus(entityType, "completed", count, Date.now() - start);
    return { entityType, status: "completed", count, durationMs: Date.now() - start };
  } catch (err) {
    const error = (err as Error).message;
    await updateSyncStatus(entityType, "error", 0, Date.now() - start, error);
    return { entityType, status: "error", count: 0, durationMs: Date.now() - start, error };
  }
}

// ── Sync: Software Packages (from Wazuh Server API syscollector) ────────────

async function syncSoftwarePackages(): Promise<SyncResult> {
  const start = Date.now();
  const entityType = "software_packages";

  try {
    await updateSyncStatus(entityType, "syncing");

    if (!isWazuhConfigured()) {
      await updateSyncStatus(entityType, "error", 0, Date.now() - start, "Wazuh not configured");
      return { entityType, status: "skipped", count: 0, durationMs: Date.now() - start };
    }

    const config = getWazuhConfig();
    const db = await getDb();
    if (!db) throw new Error("Database unavailable");

    const endpoints = await db.select({ id: graphEndpoints.id, agentId: graphEndpoints.agentId }).from(graphEndpoints);

    let count = 0;
    for (const ep of endpoints) {
      try {
        const response = await wazuhGet(config, {
          path: `/syscollector/${ep.agentId}/packages`,
          params: { limit: 500 },
        }) as { data?: { affected_items?: Array<Record<string, unknown>> } };

        const packages = response?.data?.affected_items ?? [];

        await db.delete(graphSoftwarePackages).where(eq(graphSoftwarePackages.endpointId, ep.id));

        for (const pkg of packages) {
          await db.insert(graphSoftwarePackages).values({
            endpointId: ep.id,
            packageName: String(pkg.name ?? ""),
            version: String(pkg.version ?? ""),
            architecture: String(pkg.architecture ?? ""),
            vendor: String(pkg.vendor ?? ""),
            format: String(pkg.format ?? ""),
            description: pkg.description ? String(pkg.description) : null,
            syncedAt: new Date(),
          });
          count++;
        }
      } catch {
        continue;
      }
    }

    await updateSyncStatus(entityType, "completed", count, Date.now() - start);
    return { entityType, status: "completed", count, durationMs: Date.now() - start };
  } catch (err) {
    const error = (err as Error).message;
    await updateSyncStatus(entityType, "error", 0, Date.now() - start, error);
    return { entityType, status: "error", count: 0, durationMs: Date.now() - start, error };
  }
}

// ── Sync: Identities (from Wazuh Server API syscollector) ───────────────────

async function syncIdentities(): Promise<SyncResult> {
  const start = Date.now();
  const entityType = "identities";

  try {
    await updateSyncStatus(entityType, "syncing");

    if (!isWazuhConfigured()) {
      await updateSyncStatus(entityType, "error", 0, Date.now() - start, "Wazuh not configured");
      return { entityType, status: "skipped", count: 0, durationMs: Date.now() - start };
    }

    const config = getWazuhConfig();
    const db = await getDb();
    if (!db) throw new Error("Database unavailable");

    const endpoints = await db.select({ id: graphEndpoints.id, agentId: graphEndpoints.agentId }).from(graphEndpoints);

    let count = 0;
    for (const ep of endpoints) {
      try {
        const response = await wazuhGet(config, {
          path: `/syscollector/${ep.agentId}/users`,
          params: { limit: 500 },
        }) as { data?: { affected_items?: Array<Record<string, unknown>> } };

        const users = response?.data?.affected_items ?? [];

        await db.delete(graphIdentities).where(eq(graphIdentities.endpointId, ep.id));

        for (const user of users) {
          const uid = String(user.uid ?? "");
          await db.insert(graphIdentities).values({
            endpointId: ep.id,
            username: String(user.name ?? ""),
            uid,
            gid: String(user.gid ?? ""),
            homeDir: user.homeDir ? String(user.homeDir) : null,
            shell: user.shell ? String(user.shell) : null,
            isAdmin: uid === "0" || String(user.name ?? "").toLowerCase() === "root" ? 1 : 0,
            userType: String(user.type ?? "local"),
            syncedAt: new Date(),
          });
          count++;
        }
      } catch {
        continue;
      }
    }

    await updateSyncStatus(entityType, "completed", count, Date.now() - start);
    return { entityType, status: "completed", count, durationMs: Date.now() - start };
  } catch (err) {
    const error = (err as Error).message;
    await updateSyncStatus(entityType, "error", 0, Date.now() - start, error);
    return { entityType, status: "error", count: 0, durationMs: Date.now() - start, error };
  }
}

// ── Sync: Security Events (from Wazuh Indexer) ─────────────────────────────

async function syncSecurityEvents(): Promise<SyncResult> {
  const start = Date.now();
  const entityType = "security_events";

  try {
    await updateSyncStatus(entityType, "syncing");

    if (!isIndexerConfigured()) {
      await updateSyncStatus(entityType, "error", 0, Date.now() - start, "Indexer not configured");
      return { entityType, status: "skipped", count: 0, durationMs: Date.now() - start };
    }

    const config = getIndexerConfig();
    const db = await getDb();
    if (!db) throw new Error("Database unavailable");

    // Get last sync time for incremental sync
    const lastSync = await getLastSyncTime(entityType);
    const filters: Array<Record<string, unknown>> = [];
    if (lastSync) {
      filters.push(timeRangeFilter(lastSync.toISOString(), "now", "timestamp"));
    } else {
      // First sync: last 24 hours
      filters.push(timeRangeFilter("now-24h", "now", "timestamp"));
    }

    const response = await indexerSearch(
      config,
      INDEX_PATTERNS.ALERTS,
      {
        query: filters.length > 0 ? boolQuery({ filter: filters }) : { match_all: {} },
        size: 1000,
        sort: [{ timestamp: { order: "desc" } }],
        _source: [
          "rule.id", "rule.level", "rule.description", "rule.mitre.tactic",
          "rule.mitre.technique", "rule.mitre.id", "agent.id", "agent.name",
          "data.srcip", "data.dstip", "timestamp", "id",
        ],
      },
      "alerts"
    );

    const hits = response.hits?.hits ?? [];
    let count = 0;

    // Look up endpoint IDs
    const endpointMap = new Map<string, number>();
    const allEndpoints = await db.select({ id: graphEndpoints.id, agentId: graphEndpoints.agentId }).from(graphEndpoints);
    for (const ep of allEndpoints) {
      endpointMap.set(ep.agentId, ep.id);
    }

    for (const hit of hits) {
      const src = hit._source;
      const rule = src.rule as Record<string, unknown> | undefined;
      const agent = src.agent as Record<string, unknown> | undefined;
      const data = src.data as Record<string, unknown> | undefined;
      const mitre = rule?.mitre as Record<string, unknown> | undefined;
      const agentId = String(agent?.id ?? "");

      const mitreTactics = mitre?.tactic;
      const mitreTechniques = mitre?.technique;
      const mitreIds = mitre?.id;

      await db.insert(graphSecurityEvents).values({
        endpointId: endpointMap.get(agentId) ?? null,
        alertId: String(src.id ?? hit._id),
        ruleId: String(rule?.id ?? ""),
        ruleLevel: rule?.level ? Number(rule.level) : null,
        ruleDescription: rule?.description ? String(rule.description) : null,
        mitreTactic: Array.isArray(mitreTactics) ? (mitreTactics as string[]).join(", ") : (mitreTactics ? String(mitreTactics) : null),
        mitreTechnique: Array.isArray(mitreTechniques) ? (mitreTechniques as string[]).join(", ") : (mitreTechniques ? String(mitreTechniques) : null),
        mitreId: Array.isArray(mitreIds) ? (mitreIds as string[]).join(", ") : (mitreIds ? String(mitreIds) : null),
        agentId,
        agentName: String(agent?.name ?? ""),
        srcIp: data?.srcip ? String(data.srcip) : null,
        dstIp: data?.dstip ? String(data.dstip) : null,
        eventTimestamp: src.timestamp ? new Date(String(src.timestamp)) : null,
        rawData: src as Record<string, unknown>,
        syncedAt: new Date(),
      });
      count++;
    }

    await updateSyncStatus(entityType, "completed", count, Date.now() - start);
    return { entityType, status: "completed", count, durationMs: Date.now() - start };
  } catch (err) {
    const error = (err as Error).message;
    await updateSyncStatus(entityType, "error", 0, Date.now() - start, error);
    return { entityType, status: "error", count: 0, durationMs: Date.now() - start, error };
  }
}

// ── Sync: Vulnerabilities (from Wazuh Indexer) ─────────────────────────────

async function syncVulnerabilities(): Promise<SyncResult> {
  const start = Date.now();
  const entityType = "vulnerabilities";

  try {
    await updateSyncStatus(entityType, "syncing");

    if (!isIndexerConfigured()) {
      await updateSyncStatus(entityType, "error", 0, Date.now() - start, "Indexer not configured");
      return { entityType, status: "skipped", count: 0, durationMs: Date.now() - start };
    }

    const config = getIndexerConfig();
    const db = await getDb();
    if (!db) throw new Error("Database unavailable");

    const response = await indexerSearch(
      config,
      INDEX_PATTERNS.VULNERABILITIES,
      {
        query: { match_all: {} },
        size: 1000,
        sort: [{ "vulnerability.severity": { order: "desc" } }],
        _source: [
          "vulnerability.id", "vulnerability.cvss3_score", "vulnerability.severity",
          "vulnerability.status", "vulnerability.title", "vulnerability.published_at",
          "vulnerability.detected_at", "agent.id", "package.name", "package.version",
        ],
      },
      "vulnerabilities"
    );

    const hits = response.hits?.hits ?? [];

    // Clear and re-sync all vulnerabilities
    await db.delete(graphVulnerabilities).where(sql`1=1`);

    // Look up endpoint IDs
    const endpointMap = new Map<string, number>();
    const allEndpoints = await db.select({ id: graphEndpoints.id, agentId: graphEndpoints.agentId }).from(graphEndpoints);
    for (const ep of allEndpoints) {
      endpointMap.set(ep.agentId, ep.id);
    }

    let count = 0;
    for (const hit of hits) {
      const src = hit._source;
      const vuln = src.vulnerability as Record<string, unknown> | undefined;
      const agent = src.agent as Record<string, unknown> | undefined;
      const pkg = src.package as Record<string, unknown> | undefined;
      const agentId = String(agent?.id ?? "");

      await db.insert(graphVulnerabilities).values({
        endpointId: endpointMap.get(agentId) ?? 0,
        cveId: String(vuln?.id ?? ""),
        cvssScore: vuln?.cvss3_score ? String(vuln.cvss3_score) : null,
        severity: vuln?.severity ? String(vuln.severity) : null,
        status: vuln?.status ? String(vuln.status) : null,
        packageName: pkg?.name ? String(pkg.name) : null,
        packageVersion: pkg?.version ? String(pkg.version) : null,
        title: vuln?.title ? String(vuln.title) : null,
        publishedAt: vuln?.published_at ? new Date(String(vuln.published_at)) : null,
        detectedAt: vuln?.detected_at ? new Date(String(vuln.detected_at)) : null,
        syncedAt: new Date(),
      });
      count++;
    }

    await updateSyncStatus(entityType, "completed", count, Date.now() - start);
    return { entityType, status: "completed", count, durationMs: Date.now() - start };
  } catch (err) {
    const error = (err as Error).message;
    await updateSyncStatus(entityType, "error", 0, Date.now() - start, error);
    return { entityType, status: "error", count: 0, durationMs: Date.now() - start, error };
  }
}

// ── Full Sync ───────────────────────────────────────────────────────────────

/**
 * Run a full ETL sync across all entity types.
 * Endpoints must sync first (other entities reference them).
 */
export async function runFullSync(): Promise<FullSyncResult> {
  const startedAt = new Date().toISOString();
  const start = Date.now();

  // Phase 1: Sync endpoints first (other entities depend on endpoint IDs)
  const endpointResult = await syncEndpoints();

  // Phase 2: Sync remaining Server API entities in parallel
  const [processResult, portResult, packageResult, identityResult] = await Promise.all([
    syncProcesses(),
    syncNetworkPorts(),
    syncSoftwarePackages(),
    syncIdentities(),
  ]);

  // Phase 3: Sync Indexer entities in parallel
  const [eventResult, vulnResult] = await Promise.all([
    syncSecurityEvents(),
    syncVulnerabilities(),
  ]);

  return {
    results: [endpointResult, processResult, portResult, packageResult, identityResult, eventResult, vulnResult],
    totalDurationMs: Date.now() - start,
    startedAt,
    completedAt: new Date().toISOString(),
  };
}

/**
 * Sync a single entity type.
 */
export async function syncEntityType(entityType: string): Promise<SyncResult> {
  switch (entityType) {
    case "endpoints": return syncEndpoints();
    case "processes": return syncProcesses();
    case "network_ports": return syncNetworkPorts();
    case "software_packages": return syncSoftwarePackages();
    case "identities": return syncIdentities();
    case "security_events": return syncSecurityEvents();
    case "vulnerabilities": return syncVulnerabilities();
    default:
      return { entityType, status: "error", count: 0, durationMs: 0, error: `Unknown entity type: ${entityType}` };
  }
}

/**
 * Get current sync status for all entity types.
 */
export async function getSyncStatus(): Promise<Array<{
  entityType: string;
  status: string;
  entityCount: number;
  lastSyncAt: Date | null;
  durationMs: number | null;
  errorMessage: string | null;
}>> {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(graphSyncStatus);
}
