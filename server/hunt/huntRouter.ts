/**
 * Threat Hunting tRPC Router — server-side multi-source IOC correlation.
 *
 * Searches across:
 *  1. Wazuh Indexer (alerts + archives) — full-text + field-specific
 *  2. Wazuh API (agents, rules, vulnerabilities, syscheck) — per-agent deep scan
 *  3. MITRE ATT&CK techniques
 *
 * All operations are read-only. No mutations, no writes.
 */

import { z } from "zod";
import { publicProcedure, router } from "../_core/trpc";
import {
  getEffectiveIndexerConfig,
  indexerSearch,
  INDEX_PATTERNS,
  timeRangeFilter,
  boolQuery,
  type ESSearchBody,
} from "../indexer/indexerClient";
import {
  getEffectiveWazuhConfig,
  wazuhGet,
} from "../wazuh/wazuhClient";

// ── Types ────────────────────────────────────────────────────────────────────
const iocTypeSchema = z.enum([
  "freetext", "ip", "hash", "cve", "filename", "username", "rule_id", "mitre_id",
]);

const huntInputSchema = z.object({
  query: z.string().min(1).max(500),
  iocType: iocTypeSchema,
  timeFrom: z.string().default("now-24h"),
  timeTo: z.string().default("now"),
  maxResults: z.number().int().min(1).max(200).default(50),
  // Optional: specific agent IDs to search vulns/syscheck on
  agentIds: z.array(z.string()).max(10).optional(),
});

// ── Indexer search builder ──────────────────────────────────────────────────
function buildIndexerQuery(
  query: string,
  iocType: z.infer<typeof iocTypeSchema>,
  timeFrom: string,
  timeTo: string,
  size: number
): ESSearchBody {
  const filters = [timeRangeFilter(timeFrom, timeTo)];
  const must: Array<Record<string, unknown>> = [];

  switch (iocType) {
    case "ip":
      must.push({
        multi_match: {
          query,
          fields: ["data.srcip", "data.dstip", "agent.ip", "data.src_ip", "data.dst_ip"],
          type: "best_fields",
        },
      });
      break;
    case "hash":
      must.push({
        multi_match: {
          query,
          fields: ["syscheck.md5_after", "syscheck.sha1_after", "syscheck.sha256_after", "data.*"],
          type: "best_fields",
        },
      });
      break;
    case "cve":
      must.push({
        multi_match: {
          query,
          fields: ["data.vulnerability.cve", "data.cve", "rule.description"],
          type: "best_fields",
        },
      });
      break;
    case "filename":
      must.push({
        multi_match: {
          query,
          fields: ["syscheck.path", "data.file", "data.filename", "data.path"],
          type: "best_fields",
        },
      });
      break;
    case "username":
      must.push({
        multi_match: {
          query,
          fields: ["data.srcuser", "data.dstuser", "data.user", "agent.name"],
          type: "best_fields",
        },
      });
      break;
    case "rule_id":
      filters.push({ term: { "rule.id": query } });
      break;
    case "mitre_id":
      filters.push({ term: { "rule.mitre.id": query.toUpperCase() } });
      break;
    case "freetext":
    default:
      must.push({
        multi_match: {
          query,
          fields: [
            "rule.description", "agent.name", "data.*", "full_log",
            "syscheck.path", "data.srcip", "data.dstip",
          ],
          type: "best_fields",
        },
      });
      break;
  }

  return {
    query: boolQuery({ must, filter: filters }),
    size,
    sort: [{ timestamp: { order: "desc" } }],
    _source: true,
  };
}

// ── Wazuh API search helpers ────────────────────────────────────────────────
async function searchWazuhAgents(query: string, iocType: string) {
  const config = await getEffectiveWazuhConfig();
  if (!config) return [];
  try {
    const params: Record<string, string | number> = { limit: 100, offset: 0 };
    if (iocType === "ip") params.search = query;
    else if (iocType === "username") params.search = query;
    else params.search = query;
    const res = await wazuhGet(config, { path: "/agents", params, rateLimitGroup: "agents" });
    return ((res as Record<string, unknown>)?.data as Record<string, unknown>)?.affected_items ?? [];
  } catch {
    return [];
  }
}

async function searchWazuhRules(query: string, iocType: string) {
  const config = await getEffectiveWazuhConfig();
  if (!config) return [];
  try {
    const params: Record<string, string | number> = { limit: 100, offset: 0 };
    if (iocType === "rule_id") params.rule_ids = query;
    else params.search = query;
    const res = await wazuhGet(config, { path: "/rules", params, rateLimitGroup: "rules" });
    return ((res as Record<string, unknown>)?.data as Record<string, unknown>)?.affected_items ?? [];
  } catch {
    return [];
  }
}

async function searchWazuhVulns(query: string, iocType: string, agentIds: string[]) {
  const config = await getEffectiveWazuhConfig();
  if (!config || agentIds.length === 0) return [];
  try {
    const allHits: unknown[] = [];
    // Search vulns per agent (max 10 agents)
    for (const agentId of agentIds.slice(0, 10)) {
      try {
        const params: Record<string, string | number> = { limit: 50, offset: 0 };
        if (iocType === "cve") params.search = query;
        else params.search = query;
        const res = await wazuhGet(config, {
          path: `/vulnerability/${agentId}`,
          params,
          rateLimitGroup: "vulnerabilities",
        });
        const items = ((res as Record<string, unknown>)?.data as Record<string, unknown>)?.affected_items;
        if (Array.isArray(items)) {
          allHits.push(...items.map((item) => ({ ...(item as Record<string, unknown>), _agentId: agentId })));
        }
      } catch {
        // Skip agents that fail
      }
    }
    return allHits;
  } catch {
    return [];
  }
}

async function searchWazuhSyscheck(query: string, iocType: string, agentIds: string[]) {
  const config = await getEffectiveWazuhConfig();
  if (!config || agentIds.length === 0) return [];
  try {
    const allHits: unknown[] = [];
    for (const agentId of agentIds.slice(0, 10)) {
      try {
        const params: Record<string, string | number> = { limit: 50, offset: 0 };
        if (iocType === "hash") params.hash = query;
        else if (iocType === "filename") params.search = query;
        else params.search = query;
        const res = await wazuhGet(config, {
          path: `/syscheck/${agentId}`,
          params,
          rateLimitGroup: "syscheck",
        });
        const items = ((res as Record<string, unknown>)?.data as Record<string, unknown>)?.affected_items;
        if (Array.isArray(items)) {
          allHits.push(...items.map((item) => ({ ...(item as Record<string, unknown>), _agentId: agentId })));
        }
      } catch {
        // Skip agents that fail
      }
    }
    return allHits;
  } catch {
    return [];
  }
}

async function searchWazuhMitre(query: string, iocType: string) {
  const config = await getEffectiveWazuhConfig();
  if (!config) return [];
  try {
    const params: Record<string, string | number> = { limit: 100, offset: 0 };
    if (iocType === "mitre_id") params.search = query;
    else params.search = query;
    const res = await wazuhGet(config, { path: "/mitre/techniques", params, rateLimitGroup: "mitre" });
    return ((res as Record<string, unknown>)?.data as Record<string, unknown>)?.affected_items ?? [];
  } catch {
    return [];
  }
}

async function searchWazuhLogs(query: string) {
  const config = await getEffectiveWazuhConfig();
  if (!config) return [];
  try {
    const params: Record<string, string | number> = { limit: 100, offset: 0, search: query };
    const res = await wazuhGet(config, { path: "/manager/logs", params, rateLimitGroup: "logs" });
    return ((res as Record<string, unknown>)?.data as Record<string, unknown>)?.affected_items ?? [];
  } catch {
    return [];
  }
}

// ── Router ──────────────────────────────────────────────────────────────────
export const huntRouter = router({

  /**
   * Execute a multi-source hunt — the main procedure.
   * Searches Indexer (alerts + archives) and Wazuh API (agents, rules, vulns, syscheck, MITRE, logs)
   * in parallel, then returns structured correlation results.
   */
  execute: publicProcedure
    .input(huntInputSchema)
    .query(async ({ input }) => {
      const startTime = Date.now();
      const sources: Array<{
        source: string;
        sourceLabel: string;
        matches: unknown[];
        count: number;
        searchTimeMs: number;
      }> = [];

      // ── Determine agent IDs for per-agent searches ─────────────────────
      let agentIds = input.agentIds ?? [];
      if (agentIds.length === 0) {
        // Auto-discover first 5 active agents for vuln/syscheck searches
        const wazuhConfig = await getEffectiveWazuhConfig();
        if (wazuhConfig) {
          try {
            const res = await wazuhGet(wazuhConfig, {
              path: "/agents",
              params: { limit: 5, offset: 0, status: "active" },
              rateLimitGroup: "agents",
            });
            const items = ((res as Record<string, unknown>)?.data as Record<string, unknown>)?.affected_items;
            if (Array.isArray(items)) {
              agentIds = items
                .map((a) => String((a as Record<string, unknown>).id ?? ""))
                .filter((id) => id && id !== "000");
            }
          } catch {
            // No agents available
          }
        }
      }

      // ── Run all searches in parallel ───────────────────────────────────
      const [
        indexerAlerts,
        indexerArchives,
        wazuhAgents,
        wazuhRules,
        wazuhVulns,
        wazuhSyscheck,
        wazuhMitre,
        wazuhLogs,
      ] = await Promise.allSettled([
        // 1. Indexer: alerts
        (async () => {
          const t = Date.now();
          const config = await getEffectiveIndexerConfig();
          if (!config) return { hits: [], time: 0 };
          const body = buildIndexerQuery(input.query, input.iocType, input.timeFrom, input.timeTo, input.maxResults);
          const res = await indexerSearch(config, INDEX_PATTERNS.ALERTS, body, "alerts");
          return {
            hits: res.hits.hits.map((h) => h._source),
            time: Date.now() - t,
            total: typeof res.hits.total === "number" ? res.hits.total : res.hits.total.value,
          };
        })(),
        // 2. Indexer: archives
        (async () => {
          const t = Date.now();
          const config = await getEffectiveIndexerConfig();
          if (!config) return { hits: [], time: 0 };
          const body = buildIndexerQuery(input.query, input.iocType, input.timeFrom, input.timeTo, Math.min(input.maxResults, 25));
          const res = await indexerSearch(config, INDEX_PATTERNS.ARCHIVES, body, "archives");
          return {
            hits: res.hits.hits.map((h) => h._source),
            time: Date.now() - t,
            total: typeof res.hits.total === "number" ? res.hits.total : res.hits.total.value,
          };
        })(),
        // 3. Wazuh API: agents
        (async () => {
          const t = Date.now();
          const hits = await searchWazuhAgents(input.query, input.iocType);
          return { hits: Array.isArray(hits) ? hits : [], time: Date.now() - t };
        })(),
        // 4. Wazuh API: rules
        (async () => {
          const t = Date.now();
          const hits = await searchWazuhRules(input.query, input.iocType);
          return { hits: Array.isArray(hits) ? hits : [], time: Date.now() - t };
        })(),
        // 5. Wazuh API: vulnerabilities (per-agent)
        (async () => {
          const t = Date.now();
          const hits = await searchWazuhVulns(input.query, input.iocType, agentIds);
          return { hits: Array.isArray(hits) ? hits : [], time: Date.now() - t };
        })(),
        // 6. Wazuh API: syscheck (per-agent)
        (async () => {
          const t = Date.now();
          const hits = await searchWazuhSyscheck(input.query, input.iocType, agentIds);
          return { hits: Array.isArray(hits) ? hits : [], time: Date.now() - t };
        })(),
        // 7. Wazuh API: MITRE techniques
        (async () => {
          const t = Date.now();
          const hits = await searchWazuhMitre(input.query, input.iocType);
          return { hits: Array.isArray(hits) ? hits : [], time: Date.now() - t };
        })(),
        // 8. Wazuh API: manager logs
        (async () => {
          const t = Date.now();
          const hits = await searchWazuhLogs(input.query);
          return { hits: Array.isArray(hits) ? hits : [], time: Date.now() - t };
        })(),
      ]);

      // ── Collect results ────────────────────────────────────────────────
      const collect = (
        result: PromiseSettledResult<{ hits: unknown[]; time: number; total?: number }>,
        source: string,
        sourceLabel: string
      ) => {
        if (result.status === "fulfilled" && result.value.hits.length > 0) {
          sources.push({
            source,
            sourceLabel,
            matches: result.value.hits,
            count: result.value.total ?? result.value.hits.length,
            searchTimeMs: result.value.time,
          });
        }
      };

      collect(indexerAlerts, "indexer_alerts", "Indexer: Alerts");
      collect(indexerArchives, "indexer_archives", "Indexer: Archives");
      collect(wazuhAgents, "agents", "Agents");
      collect(wazuhRules, "rules", "Rules");
      collect(wazuhVulns, "vulnerabilities", "Vulnerabilities");
      collect(wazuhSyscheck, "syscheck", "File Integrity");
      collect(wazuhMitre, "mitre", "MITRE ATT&CK");
      collect(wazuhLogs, "logs", "Manager Logs");

      const totalHits = sources.reduce((sum, s) => sum + s.count, 0);
      const totalTimeMs = Date.now() - startTime;

      return {
        query: input.query,
        iocType: input.iocType,
        timeRange: { from: input.timeFrom, to: input.timeTo },
        totalHits,
        totalTimeMs,
        sourcesSearched: 8,
        sourcesWithHits: sources.length,
        agentsSearched: agentIds,
        sources,
      };
    }),
});
