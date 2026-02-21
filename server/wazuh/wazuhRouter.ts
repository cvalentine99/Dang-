/**
 * Wazuh tRPC Router — read-only proxy to the Wazuh REST API.
 *
 * All procedures are public (no Manus auth required) but the Wazuh
 * credentials are server-side only and never passed to the browser.
 *
 * Write operations are explicitly NOT implemented per project policy.
 */

import { z } from "zod";
import { publicProcedure, router } from "../_core/trpc";
import { getWazuhConfig, isWazuhConfigured, wazuhGet } from "./wazuhClient";

// ── Shared input schemas ───────────────────────────────────────────────────────
const paginationSchema = z.object({
  limit: z.number().int().min(1).max(500).default(100),
  offset: z.number().int().min(0).default(0),
});

const agentIdSchema = z.string().regex(/^\d{3,}$/, "Invalid agent ID format");

// ── Helper: wrap with config check ────────────────────────────────────────────
async function proxyGet(path: string, params?: Record<string, string | number | boolean | undefined>, group?: string) {
  const config = getWazuhConfig();
  return wazuhGet(config, { path, params, rateLimitGroup: group });
}

// ── Router ────────────────────────────────────────────────────────────────────
export const wazuhRouter = router({

  // ── System status ──────────────────────────────────────────────────────────
  status: publicProcedure.query(async () => {
    if (!isWazuhConfigured()) {
      return { configured: false, data: null };
    }
    try {
      const data = await proxyGet("/manager/info");
      return { configured: true, data };
    } catch (err) {
      return { configured: true, data: null, error: (err as Error).message };
    }
  }),

  managerInfo: publicProcedure.query(() => proxyGet("/manager/info")),

  managerStatus: publicProcedure.query(() => proxyGet("/manager/status")),

  clusterStatus: publicProcedure.query(() => proxyGet("/cluster/status")),

  clusterNodes: publicProcedure.query(() => proxyGet("/cluster/nodes")),

  // ── Agents ─────────────────────────────────────────────────────────────────
  agents: publicProcedure
    .input(
      paginationSchema.extend({
        status: z.enum(["active", "disconnected", "never_connected", "pending"]).optional(),
        os_platform: z.string().optional(),
        search: z.string().optional(),
        group: z.string().optional(),
        sort: z.string().optional(),
      })
    )
    .query(({ input }) =>
      proxyGet("/agents", {
        limit: input.limit,
        offset: input.offset,
        status: input.status,
        "q": input.search ? `name~${input.search}` : undefined,
        group: input.group,
        sort: input.sort,
      })
    ),

  agentSummaryStatus: publicProcedure.query(() =>
    proxyGet("/agents/summary/status")
  ),

  agentSummaryOs: publicProcedure.query(() =>
    proxyGet("/agents/summary/os")
  ),

  agentOverview: publicProcedure.query(() =>
    proxyGet("/overview/agents")
  ),

  agentById: publicProcedure
    .input(z.object({ agentId: agentIdSchema }))
    .query(({ input }) =>
      proxyGet("/agents", { agents_list: input.agentId })
    ),

  agentDaemonStats: publicProcedure
    .input(z.object({ agentId: agentIdSchema }))
    .query(({ input }) =>
      proxyGet(`/agents/${input.agentId}/daemons/stats`)
    ),

  agentStats: publicProcedure
    .input(z.object({ agentId: agentIdSchema, component: z.string().default("logcollector") }))
    .query(({ input }) =>
      proxyGet(`/agents/${input.agentId}/stats/${input.component}`)
    ),

  agentOs: publicProcedure
    .input(z.object({ agentId: agentIdSchema }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/os`)
    ),

  agentHardware: publicProcedure
    .input(z.object({ agentId: agentIdSchema }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/hardware`)
    ),

  agentPackages: publicProcedure
    .input(z.object({ agentId: agentIdSchema, ...paginationSchema.shape }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/packages`, {
        limit: input.limit,
        offset: input.offset,
      })
    ),

  agentPorts: publicProcedure
    .input(z.object({ agentId: agentIdSchema }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/ports`)
    ),

  agentProcesses: publicProcedure
    .input(z.object({ agentId: agentIdSchema, ...paginationSchema.shape }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/processes`, {
        limit: input.limit,
        offset: input.offset,
      })
    ),

  agentGroups: publicProcedure.query(() => proxyGet("/groups")),

  // ── Alerts (via manager stats / syscheck overview) ─────────────────────────
  // Note: Wazuh 4.x exposes alert data via /manager/logs and index queries.
  // We proxy /manager/logs for recent alerts and /manager/stats/analysisd for metrics.
  managerLogs: publicProcedure
    .input(
      paginationSchema.extend({
        level: z.enum(["info", "error", "warning", "debug"]).optional(),
        search: z.string().optional(),
      })
    )
    .query(({ input }) =>
      proxyGet(
        "/manager/logs",
        { limit: input.limit, offset: input.offset, level: input.level },
        "alerts"
      )
    ),

  managerLogsSummary: publicProcedure.query(() =>
    proxyGet("/manager/logs/summary", {}, "alerts")
  ),

  analysisd: publicProcedure.query(() =>
    proxyGet("/manager/stats/analysisd")
  ),

  statsHourly: publicProcedure.query(() =>
    proxyGet("/manager/stats/hourly")
  ),

  statsWeekly: publicProcedure.query(() =>
    proxyGet("/manager/stats/weekly")
  ),

  // ── Rules (for alert context) ───────────────────────────────────────────────
  rules: publicProcedure
    .input(
      paginationSchema.extend({
        level: z.number().int().min(0).max(16).optional(),
        search: z.string().optional(),
        group: z.string().optional(),
        requirement: z.string().optional(),
      })
    )
    .query(({ input }) =>
      proxyGet("/rules", {
        limit: input.limit,
        offset: input.offset,
        level: input.level,
        search: input.search,
        group: input.group,
      })
    ),

  ruleGroups: publicProcedure.query(() => proxyGet("/rules/groups")),

  rulesByRequirement: publicProcedure
    .input(z.object({ requirement: z.string() }))
    .query(({ input }) =>
      proxyGet(`/rules/requirement/${input.requirement}`)
    ),

  // ── MITRE ATT&CK ───────────────────────────────────────────────────────────
  mitreTactics: publicProcedure.query(() =>
    proxyGet("/mitre/tactics")
  ),

  mitreTechniques: publicProcedure
    .input(paginationSchema.extend({ search: z.string().optional() }))
    .query(({ input }) =>
      proxyGet("/mitre/techniques", {
        limit: input.limit,
        offset: input.offset,
        search: input.search,
      })
    ),

  mitreMitigations: publicProcedure
    .input(paginationSchema)
    .query(({ input }) =>
      proxyGet("/mitre/mitigations", { limit: input.limit, offset: input.offset })
    ),

  mitreSoftware: publicProcedure
    .input(paginationSchema)
    .query(({ input }) =>
      proxyGet("/mitre/software", { limit: input.limit, offset: input.offset })
    ),

  mitreGroups: publicProcedure
    .input(paginationSchema)
    .query(({ input }) =>
      proxyGet("/mitre/groups", { limit: input.limit, offset: input.offset })
    ),

  mitreMetadata: publicProcedure.query(() => proxyGet("/mitre/metadata")),

  // ── Vulnerabilities ─────────────────────────────────────────────────────────
  // Note: Vulnerability data in Wazuh 4.x is accessed via syscollector packages
  // and the experimental endpoints. The /vulnerability/{agent_id} endpoint
  // requires the vulnerability detection module to be enabled.
  agentVulnerabilities: publicProcedure
    .input(
      z.object({
        agentId: agentIdSchema,
        severity: z.enum(["critical", "high", "medium", "low"]).optional(),
        ...paginationSchema.shape,
      })
    )
    .query(({ input }) =>
      proxyGet(
        `/vulnerability/${input.agentId}`,
        {
          limit: input.limit,
          offset: input.offset,
          severity: input.severity,
        },
        "vulnerabilities"
      )
    ),

  // ── SCA / Compliance ────────────────────────────────────────────────────────
  scaPolicies: publicProcedure
    .input(z.object({ agentId: agentIdSchema }))
    .query(({ input }) =>
      proxyGet(`/sca/${input.agentId}`)
    ),

  scaChecks: publicProcedure
    .input(
      z.object({
        agentId: agentIdSchema,
        policyId: z.string(),
        result: z.enum(["passed", "failed", "not applicable"]).optional(),
        ...paginationSchema.shape,
      })
    )
    .query(({ input }) =>
      proxyGet(`/sca/${input.agentId}/checks/${input.policyId}`, {
        limit: input.limit,
        offset: input.offset,
        result: input.result,
      })
    ),

  // CIS-CAT compliance
  ciscatResults: publicProcedure
    .input(z.object({ agentId: agentIdSchema, ...paginationSchema.shape }))
    .query(({ input }) =>
      proxyGet(`/ciscat/${input.agentId}/results`, {
        limit: input.limit,
        offset: input.offset,
      })
    ),

  // ── FIM / Syscheck ──────────────────────────────────────────────────────────
  syscheckFiles: publicProcedure
    .input(
      z.object({
        agentId: agentIdSchema,
        type: z.enum(["file", "registry"]).optional(),
        search: z.string().optional(),
        event: z.enum(["added", "modified", "deleted"]).optional(),
        ...paginationSchema.shape,
      })
    )
    .query(({ input }) =>
      proxyGet(
        `/syscheck/${input.agentId}`,
        {
          limit: input.limit,
          offset: input.offset,
          type: input.type,
          search: input.search,
          event: input.event,
        },
        "syscheck"
      )
    ),

  syscheckLastScan: publicProcedure
    .input(z.object({ agentId: agentIdSchema }))
    .query(({ input }) =>
      proxyGet(`/syscheck/${input.agentId}/last_scan`, {}, "syscheck")
    ),

  // ── Rootcheck ──────────────────────────────────────────────────────────────
  rootcheckResults: publicProcedure
    .input(z.object({ agentId: agentIdSchema, ...paginationSchema.shape }))
    .query(({ input }) =>
      proxyGet(`/rootcheck/${input.agentId}`, {
        limit: input.limit,
        offset: input.offset,
      })
    ),

  rootcheckLastScan: publicProcedure
    .input(z.object({ agentId: agentIdSchema }))
    .query(({ input }) =>
      proxyGet(`/rootcheck/${input.agentId}/last_scan`)
    ),

  // ── Decoders ───────────────────────────────────────────────────────────────
  decoders: publicProcedure
    .input(paginationSchema.extend({ search: z.string().optional() }))
    .query(({ input }) =>
      proxyGet("/decoders", { limit: input.limit, offset: input.offset, search: input.search })
    ),

  // ── Tasks ──────────────────────────────────────────────────────────────────
  taskStatus: publicProcedure
    .input(z.object({ taskIds: z.array(z.number()).optional() }))
    .query(({ input }) =>
      proxyGet("/tasks/status", {
        task_list: input.taskIds?.join(","),
      })
    ),

  // ── Configuration check ────────────────────────────────────────────────────
  isConfigured: publicProcedure.query(() => ({
    configured: isWazuhConfigured(),
    host: process.env.WAZUH_HOST ?? null,
    port: process.env.WAZUH_PORT ?? "55000",
  })),
});
