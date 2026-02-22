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

  // ══════════════════════════════════════════════════════════════════════════════
  // SYSTEM STATUS
  // ══════════════════════════════════════════════════════════════════════════════
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

  isConfigured: publicProcedure.query(() => ({
    configured: isWazuhConfigured(),
    host: process.env.WAZUH_HOST ?? null,
    port: process.env.WAZUH_PORT ?? "55000",
  })),

  // ══════════════════════════════════════════════════════════════════════════════
  // MANAGER
  // ══════════════════════════════════════════════════════════════════════════════
  managerInfo: publicProcedure.query(() => proxyGet("/manager/info")),
  managerStatus: publicProcedure.query(() => proxyGet("/manager/status")),
  managerConfiguration: publicProcedure.query(() => proxyGet("/manager/configuration")),
  managerConfigValidation: publicProcedure.query(() => proxyGet("/manager/configuration/validation")),

  // ── Manager stats ─────────────────────────────────────────────────────────
  managerStats: publicProcedure.query(() => proxyGet("/manager/stats")),
  statsHourly: publicProcedure.query(() => proxyGet("/manager/stats/hourly")),
  statsWeekly: publicProcedure.query(() => proxyGet("/manager/stats/weekly")),
  analysisd: publicProcedure.query(() => proxyGet("/manager/stats/analysisd")),
  remoted: publicProcedure.query(() => proxyGet("/manager/stats/remoted")),

  // ── Manager daemon stats (4.14+ enhanced) ─────────────────────────────────
  daemonStats: publicProcedure
    .input(z.object({
      daemons: z.array(z.string()).optional(),
    }).optional())
    .query(({ input }) =>
      proxyGet("/manager/daemons/stats", input?.daemons ? { daemons_list: input.daemons.join(",") } : {})
    ),

  // ── Manager logs ──────────────────────────────────────────────────────────
  managerLogs: publicProcedure
    .input(
      paginationSchema.extend({
        level: z.enum(["info", "error", "warning", "debug"]).optional(),
        tag: z.string().optional(),
        search: z.string().optional(),
      })
    )
    .query(({ input }) =>
      proxyGet("/manager/logs", {
        limit: input.limit,
        offset: input.offset,
        level: input.level,
        tag: input.tag,
        search: input.search,
      }, "alerts")
    ),

  managerLogsSummary: publicProcedure.query(() =>
    proxyGet("/manager/logs/summary", {}, "alerts")
  ),

  // ══════════════════════════════════════════════════════════════════════════════
  // CLUSTER
  // ══════════════════════════════════════════════════════════════════════════════
  clusterStatus: publicProcedure.query(() => proxyGet("/cluster/status")),
  clusterNodes: publicProcedure.query(() => proxyGet("/cluster/nodes")),
  clusterHealthcheck: publicProcedure.query(() => proxyGet("/cluster/healthcheck")),
  clusterLocalInfo: publicProcedure.query(() => proxyGet("/cluster/local/info")),
  clusterLocalConfig: publicProcedure.query(() => proxyGet("/cluster/local/config")),

  clusterNodeInfo: publicProcedure
    .input(z.object({ nodeId: z.string() }))
    .query(({ input }) => proxyGet(`/cluster/${input.nodeId}/info`)),

  clusterNodeStats: publicProcedure
    .input(z.object({ nodeId: z.string() }))
    .query(({ input }) => proxyGet(`/cluster/${input.nodeId}/stats`)),

  clusterNodeStatsHourly: publicProcedure
    .input(z.object({ nodeId: z.string() }))
    .query(({ input }) => proxyGet(`/cluster/${input.nodeId}/stats/hourly`)),

  // ══════════════════════════════════════════════════════════════════════════════
  // AGENTS
  // ══════════════════════════════════════════════════════════════════════════════
  agents: publicProcedure
    .input(
      paginationSchema.extend({
        status: z.enum(["active", "disconnected", "never_connected", "pending"]).optional(),
        os_platform: z.string().optional(),
        search: z.string().optional(),
        group: z.string().optional(),
        sort: z.string().optional(),
        q: z.string().optional(),
      })
    )
    .query(({ input }) =>
      proxyGet("/agents", {
        limit: input.limit,
        offset: input.offset,
        status: input.status,
        q: input.q ?? (input.search ? `name~${input.search}` : undefined),
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

  agentKey: publicProcedure
    .input(z.object({ agentId: agentIdSchema }))
    .query(({ input }) =>
      proxyGet(`/agents/${input.agentId}/key`)
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

  agentConfig: publicProcedure
    .input(z.object({
      agentId: agentIdSchema,
      component: z.string(),
      configuration: z.string(),
    }))
    .query(({ input }) =>
      proxyGet(`/agents/${input.agentId}/config/${input.component}/${input.configuration}`)
    ),

  agentGroups: publicProcedure.query(() => proxyGet("/groups")),

  agentGroupMembers: publicProcedure
    .input(z.object({ groupId: z.string(), ...paginationSchema.shape }))
    .query(({ input }) =>
      proxyGet(`/groups/${input.groupId}/agents`, {
        limit: input.limit,
        offset: input.offset,
      })
    ),

  // ══════════════════════════════════════════════════════════════════════════════
  // SYSCOLLECTOR (IT Hygiene)
  // ══════════════════════════════════════════════════════════════════════════════
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
    .input(z.object({
      agentId: agentIdSchema,
      search: z.string().optional(),
      ...paginationSchema.shape,
    }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/packages`, {
        limit: input.limit,
        offset: input.offset,
        search: input.search,
      })
    ),

  agentPorts: publicProcedure
    .input(z.object({
      agentId: agentIdSchema,
      ...paginationSchema.shape,
    }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/ports`, {
        limit: input.limit,
        offset: input.offset,
      })
    ),

  agentProcesses: publicProcedure
    .input(z.object({
      agentId: agentIdSchema,
      search: z.string().optional(),
      ...paginationSchema.shape,
    }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/processes`, {
        limit: input.limit,
        offset: input.offset,
        search: input.search,
      })
    ),

  agentNetaddr: publicProcedure
    .input(z.object({ agentId: agentIdSchema }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/netaddr`)
    ),

  agentNetiface: publicProcedure
    .input(z.object({ agentId: agentIdSchema }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/netiface`)
    ),

  agentHotfixes: publicProcedure
    .input(z.object({ agentId: agentIdSchema, ...paginationSchema.shape }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/hotfixes`, {
        limit: input.limit,
        offset: input.offset,
      })
    ),

  // ══════════════════════════════════════════════════════════════════════════════
  // SYSCOLLECTOR — EXTENSIONS / SERVICES / IDENTITY
  // ══════════════════════════════════════════════════════════════════════════════

  /** Browser extensions installed on the agent (Windows only) */
  agentBrowserExtensions: publicProcedure
    .input(z.object({ agentId: agentIdSchema, ...paginationSchema.shape }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/browser_extensions`, {
        limit: input.limit,
        offset: input.offset,
      }).catch(() => ({ data: { affected_items: [], total_affected_items: 0 } }))
    ),

  /** System services / daemons (Windows services, systemd units) */
  agentServices: publicProcedure
    .input(z.object({ agentId: agentIdSchema, ...paginationSchema.shape }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/services`, {
        limit: input.limit,
        offset: input.offset,
      }).catch(() => ({ data: { affected_items: [], total_affected_items: 0 } }))
    ),

  /** Local users on the agent */
  agentUsers: publicProcedure
    .input(z.object({ agentId: agentIdSchema, ...paginationSchema.shape }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/users`, {
        limit: input.limit,
        offset: input.offset,
      }).catch(() => ({ data: { affected_items: [], total_affected_items: 0 } }))
    ),

  /** Local groups on the agent */
  agentGroups2: publicProcedure
    .input(z.object({ agentId: agentIdSchema, ...paginationSchema.shape }))
    .query(({ input }) =>
      proxyGet(`/syscollector/${input.agentId}/groups`, {
        limit: input.limit,
        offset: input.offset,
      }).catch(() => ({ data: { affected_items: [], total_affected_items: 0 } }))
    ),

  // ══════════════════════════════════════════════════════════════════════════════
  // ALERTS / RULES
  // ══════════════════════════════════════════════════════════════════════════════
  rules: publicProcedure
    .input(
      paginationSchema.extend({
        level: z.number().int().min(0).max(16).optional(),
        search: z.string().optional(),
        group: z.string().optional(),
        requirement: z.string().optional(),
        sort: z.string().optional(),
      })
    )
    .query(({ input }) =>
      proxyGet("/rules", {
        limit: input.limit,
        offset: input.offset,
        level: input.level,
        search: input.search,
        group: input.group,
        sort: input.sort,
      })
    ),

  ruleGroups: publicProcedure.query(() => proxyGet("/rules/groups")),

  rulesByRequirement: publicProcedure
    .input(z.object({ requirement: z.string() }))
    .query(({ input }) =>
      proxyGet(`/rules/requirement/${input.requirement}`)
    ),

  rulesFiles: publicProcedure
    .input(paginationSchema)
    .query(({ input }) =>
      proxyGet("/rules/files", { limit: input.limit, offset: input.offset })
    ),

  // ══════════════════════════════════════════════════════════════════════════════
  // MITRE ATT&CK
  // ══════════════════════════════════════════════════════════════════════════════
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

  mitreReferences: publicProcedure
    .input(paginationSchema)
    .query(({ input }) =>
      proxyGet("/mitre/references", { limit: input.limit, offset: input.offset })
    ),

  // ══════════════════════════════════════════════════════════════════════════════
  // VULNERABILITIES
  // ══════════════════════════════════════════════════════════════════════════════
  agentVulnerabilities: publicProcedure
    .input(
      z.object({
        agentId: agentIdSchema,
        severity: z.enum(["critical", "high", "medium", "low"]).optional(),
        status: z.string().optional(),
        search: z.string().optional(),
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
          status: input.status,
          search: input.search,
        },
        "vulnerabilities"
      )
    ),

  // ══════════════════════════════════════════════════════════════════════════════
  // SCA / COMPLIANCE
  // ══════════════════════════════════════════════════════════════════════════════
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
        search: z.string().optional(),
        ...paginationSchema.shape,
      })
    )
    .query(({ input }) =>
      proxyGet(`/sca/${input.agentId}/checks/${input.policyId}`, {
        limit: input.limit,
        offset: input.offset,
        result: input.result,
        search: input.search,
      })
    ),

  ciscatResults: publicProcedure
    .input(z.object({ agentId: agentIdSchema, ...paginationSchema.shape }))
    .query(({ input }) =>
      proxyGet(`/ciscat/${input.agentId}/results`, {
        limit: input.limit,
        offset: input.offset,
      })
    ),

  // ══════════════════════════════════════════════════════════════════════════════
  // FIM / SYSCHECK
  // ══════════════════════════════════════════════════════════════════════════════
  syscheckFiles: publicProcedure
    .input(
      z.object({
        agentId: agentIdSchema,
        type: z.enum(["file", "registry"]).optional(),
        search: z.string().optional(),
        event: z.enum(["added", "modified", "deleted"]).optional(),
        hash: z.string().optional(),
        file: z.string().optional(),
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
          hash: input.hash,
          file: input.file,
        },
        "syscheck"
      )
    ),

  syscheckLastScan: publicProcedure
    .input(z.object({ agentId: agentIdSchema }))
    .query(({ input }) =>
      proxyGet(`/syscheck/${input.agentId}/last_scan`, {}, "syscheck")
    ),

  // ══════════════════════════════════════════════════════════════════════════════
  // ROOTCHECK
  // ══════════════════════════════════════════════════════════════════════════════
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

  // ══════════════════════════════════════════════════════════════════════════════
  // DECODERS
  // ══════════════════════════════════════════════════════════════════════════════
  decoders: publicProcedure
    .input(paginationSchema.extend({ search: z.string().optional() }))
    .query(({ input }) =>
      proxyGet("/decoders", { limit: input.limit, offset: input.offset, search: input.search })
    ),

  decoderFiles: publicProcedure
    .input(paginationSchema)
    .query(({ input }) =>
      proxyGet("/decoders/files", { limit: input.limit, offset: input.offset })
    ),

  // ══════════════════════════════════════════════════════════════════════════════
  // TASKS
  // ══════════════════════════════════════════════════════════════════════════════
  taskStatus: publicProcedure
    .input(z.object({ taskIds: z.array(z.number()).optional() }))
    .query(({ input }) =>
      proxyGet("/tasks/status", {
        task_list: input.taskIds?.join(","),
      })
    ),

  // ══════════════════════════════════════════════════════════════════════════════
  // ACTIVE RESPONSE (read-only audit view)
  // ══════════════════════════════════════════════════════════════════════════════
  activeResponseList: publicProcedure.query(() =>
    proxyGet("/active-response")
  ),

  // ══════════════════════════════════════════════════════════════════════════════
  // SECURITY (RBAC info — read-only)
  // ══════════════════════════════════════════════════════════════════════════════
  securityRoles: publicProcedure.query(() => proxyGet("/security/roles")),
  securityPolicies: publicProcedure.query(() => proxyGet("/security/policies")),
  securityUsers: publicProcedure.query(() => proxyGet("/security/users")),

  // ══════════════════════════════════════════════════════════════════════════════
  // LISTS (CDB Lists — read-only)
  // ══════════════════════════════════════════════════════════════════════════════
  lists: publicProcedure
    .input(paginationSchema)
    .query(({ input }) =>
      proxyGet("/lists", { limit: input.limit, offset: input.offset })
    ),

  listsFiles: publicProcedure
    .input(paginationSchema)
    .query(({ input }) =>
      proxyGet("/lists/files", { limit: input.limit, offset: input.offset })
    ),
});
