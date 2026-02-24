import { trpc } from "@/lib/trpc";
import { GlassPanel } from "@/components/shared/GlassPanel";
import { StatCard } from "@/components/shared/StatCard";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { ThreatBadge } from "@/components/shared/ThreatBadge";
import { RawJsonViewer } from "@/components/shared/RawJsonViewer";
import {
  MOCK_MANAGER_STATUS, MOCK_MANAGER_INFO, MOCK_MANAGER_STATS,
  MOCK_DAEMON_STATS, MOCK_CONFIG_VALIDATION, MOCK_CLUSTER_STATUS,
  MOCK_CLUSTER_NODES,
} from "@/lib/mockData";
import {
  Server, Activity, CheckCircle2,
  XCircle, AlertTriangle, Network, Gauge, BarChart3,
} from "lucide-react";
import { useMemo, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as ReTooltip,
  ResponsiveContainer, PieChart, Pie, Cell, Legend,
  AreaChart, Area,
} from "recharts";

const COLORS = {
  purple: "oklch(0.541 0.281 293.009)",
  cyan: "oklch(0.789 0.154 211.53)",
  green: "oklch(0.765 0.177 163.223)",
  yellow: "oklch(0.795 0.184 86.047)",
  red: "oklch(0.637 0.237 25.331)",
  orange: "oklch(0.705 0.191 22.216)",
};

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass-panel p-3 text-xs border border-glass-border">
      <p className="text-muted-foreground mb-1">{label}</p>
      {payload.map((p, i) => <p key={i} style={{ color: p.color }} className="font-medium">{p.name}: {p.value?.toLocaleString()}</p>)}
    </div>
  );
}

function QueueGauge({ label, used, total }: { label: string; used: number; total: number }) {
  const pct = total > 0 ? Math.round((used / total) * 100) : 0;
  const circumference = 2 * Math.PI * 36;
  const offset = circumference - (pct / 100) * circumference;
  const color = pct >= 90 ? COLORS.red : pct >= 70 ? COLORS.yellow : COLORS.green;

  return (
    <div className="flex flex-col items-center">
      <svg width="90" height="90" viewBox="0 0 90 90">
        <circle cx="45" cy="45" r="36" fill="none" stroke="oklch(0.3 0.04 286 / 20%)" strokeWidth="7" />
        <circle cx="45" cy="45" r="36" fill="none" stroke={color} strokeWidth="7" strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={offset} transform="rotate(-90 45 45)" className="transition-all duration-700" />
        <text x="45" y="42" textAnchor="middle" fill="oklch(0.93 0.005 286)" fontSize="16" fontWeight="bold">{pct}%</text>
        <text x="45" y="56" textAnchor="middle" fill="oklch(0.65 0.02 286)" fontSize="7">USED</text>
      </svg>
      <span className="text-xs font-medium text-muted-foreground mt-1 text-center">{label}</span>
      <span className="text-[10px] text-muted-foreground">{used.toLocaleString()} / {total.toLocaleString()}</span>
    </div>
  );
}

function extractItems(raw: unknown): Array<Record<string, unknown>> {
  const d = (raw as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
}

function SourceBadge({ source }: { source: "indexer" | "server" | "mock" }) {
  const config = {
    indexer: { label: "Indexer", color: "text-threat-low bg-threat-low/10 border-threat-low/20" },
    server: { label: "Server API", color: "text-primary bg-primary/10 border-primary/20" },
    mock: { label: "Mock", color: "text-muted-foreground bg-secondary/30 border-border/30" },
  }[source];
  return (
    <span className={`text-[9px] font-medium px-1.5 py-0.5 rounded border ${config.color}`}>
      {config.label}
    </span>
  );
}

export default function ClusterHealth() {
  const utils = trpc.useUtils();

  const statusQ = trpc.wazuh.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const isConnected = statusQ.data?.configured === true && statusQ.data?.data != null;

  const managerStatusQ = trpc.wazuh.managerStatus.useQuery(undefined, { retry: 1, staleTime: 15_000, enabled: isConnected });
  const managerInfoQ = trpc.wazuh.managerInfo.useQuery(undefined, { retry: 1, staleTime: 60_000, enabled: isConnected });
  const managerStatsHourlyQ = trpc.wazuh.statsHourly.useQuery(undefined, { retry: 1, staleTime: 30_000, enabled: isConnected });
  const daemonStatsQ = trpc.wazuh.daemonStats.useQuery({ daemons: ["wazuh-analysisd", "wazuh-remoted", "wazuh-db"] }, { retry: 1, staleTime: 15_000, enabled: isConnected });
  const configValidQ = trpc.wazuh.managerConfigValidation.useQuery(undefined, { retry: 1, staleTime: 60_000, enabled: isConnected });
  const clusterStatusQ = trpc.wazuh.clusterStatus.useQuery(undefined, { retry: 1, staleTime: 30_000, enabled: isConnected });
  const clusterNodesQ = trpc.wazuh.clusterNodes.useQuery(undefined, { retry: 1, staleTime: 30_000, enabled: isConnected });
  const clusterHealthQ = trpc.wazuh.clusterHealthcheck.useQuery(undefined, { retry: 1, staleTime: 30_000, enabled: isConnected });

  // ── Indexer statistics ───────────────────────────────────────────────
  const indexerStatusQ = trpc.indexer.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const isIndexerConnected = indexerStatusQ.data?.configured === true && indexerStatusQ.data?.healthy === true;
  const statisticsQ = trpc.indexer.statisticsPerformance.useQuery(
    { from: "now-24h", to: "now", interval: "1h" },
    { retry: 1, staleTime: 60_000, enabled: isIndexerConnected },
  );

  const handleRefresh = useCallback(() => { utils.wazuh.invalidate(); utils.indexer.invalidate(); }, [utils]);

  // ── Daemon status (real or fallback) ──────────────────────────────────
  const daemonStatuses = useMemo(() => {
    const src = isConnected && managerStatusQ.data ? managerStatusQ.data : MOCK_MANAGER_STATUS;
    const d = (src as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = (d?.affected_items as Array<Record<string, unknown>>) ?? [];
    if (items.length > 0) return items[0];
    if (d && typeof d === "object" && !Array.isArray(d)) {
      const keys = Object.keys(d).filter(k => !["affected_items", "total_affected_items", "total_failed_items", "failed_items"].includes(k));
      if (keys.length > 0) return d;
    }
    return {};
  }, [managerStatusQ.data, isConnected]);

  // ── Manager info (real or fallback) ───────────────────────────────────
  const managerInfo = useMemo(() => {
    const src = isConnected && managerInfoQ.data ? managerInfoQ.data : MOCK_MANAGER_INFO;
    const items = extractItems(src);
    return items[0] ?? {};
  }, [managerInfoQ.data, isConnected]);

  // ── Hourly stats (real or fallback) ───────────────────────────────────
  const hourlyData = useMemo(() => {
    const src = isConnected && managerStatsHourlyQ.data ? managerStatsHourlyQ.data : MOCK_MANAGER_STATS;
    const items = extractItems(src);
    return items.map((item, i) => ({
      hour: `${String(item.hour ?? i).toString().padStart(2, "0")}:00`,
      totalall: Number(item.totalall ?? 0),
      events: Number(item.events ?? 0),
      syscheck: Number(item.syscheck ?? 0),
      firewall: Number(item.firewall ?? 0),
    }));
  }, [managerStatsHourlyQ.data, isConnected]);

  // ── Daemon metrics (real or fallback) ─────────────────────────────────
  const daemonMetrics = useMemo(() => {
    const src = isConnected && daemonStatsQ.data ? daemonStatsQ.data : MOCK_DAEMON_STATS;
    return extractItems(src);
  }, [daemonStatsQ.data, isConnected]);

  // ── Config validation (real or fallback) ──────────────────────────────
  const configValid = useMemo(() => {
    const src = isConnected && configValidQ.data ? configValidQ.data : MOCK_CONFIG_VALIDATION;
    const items = extractItems(src);
    return items[0] ?? {};
  }, [configValidQ.data, isConnected]);

  // ── Cluster status (real or fallback) ─────────────────────────────────
  const clusterStatus = useMemo(() => {
    const src = isConnected && clusterStatusQ.data ? clusterStatusQ.data : MOCK_CLUSTER_STATUS;
    const d = (src as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return d ?? {};
  }, [clusterStatusQ.data, isConnected]);

  // ── Cluster nodes (real or fallback) ──────────────────────────────────
  const clusterNodes = useMemo(() => {
    const src = isConnected && clusterNodesQ.data ? clusterNodesQ.data : MOCK_CLUSTER_NODES;
    return extractItems(src);
  }, [clusterNodesQ.data, isConnected]);

  // ── Master node ID for per-node stats ──────────────────────────────
  const masterNodeId = useMemo(() => {
    const master = clusterNodes.find(n => String(n.type) === "master");
    return master ? String(master.name ?? "") : "";
  }, [clusterNodes]);

  const nodeStatsQ = trpc.wazuh.clusterNodeStats.useQuery(
    { nodeId: masterNodeId },
    { retry: 1, staleTime: 15_000, enabled: isConnected && !!masterNodeId },
  );

  // ── Cluster healthcheck data ──────────────────────────────────────────
  const healthcheckNodes = useMemo((): Array<Record<string, unknown>> => {
    if (!isConnected || !clusterHealthQ.data) return [];
    const d = (clusterHealthQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const nodes = d?.nodes as Record<string, unknown> | undefined;
    if (!nodes) {
      // Some Wazuh versions return affected_items
      return extractItems(clusterHealthQ.data);
    }
    return Object.entries(nodes).map(([name, info]) => ({
      name,
      ...(typeof info === "object" && info !== null ? info as Record<string, unknown> : {}),
    } as Record<string, unknown>));
  }, [clusterHealthQ.data, isConnected]);

  // ── Master node stats data ────────────────────────────────────────────
  const masterNodeStats = useMemo(() => {
    if (!isConnected || !nodeStatsQ.data) return [];
    return extractItems(nodeStatsQ.data);
  }, [nodeStatsQ.data, isConnected]);

  // ── Indexer statistics chart data ─────────────────────────────────────
  const statisticsData = useMemo(() => {
    if (!isIndexerConnected || !statisticsQ.data) return [];
    const d = (statisticsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const aggs = d?.aggregations as Record<string, unknown> | undefined;
    const buckets = (aggs?.metrics_over_time as Record<string, unknown>)?.buckets as Array<Record<string, unknown>> | undefined;
    if (!buckets) return [];
    return buckets.map(b => {
      const ts = b.key_as_string ?? b.key;
      const label = typeof ts === "string" ? ts.replace(/T/, " ").slice(11, 16) : String(ts);
      return {
        time: label,
        received: Number((b.avg_events as Record<string, unknown>)?.value ?? 0),
        decoded: Number((b.avg_decoded as Record<string, unknown>)?.value ?? 0),
        dropped: Number((b.avg_dropped as Record<string, unknown>)?.value ?? 0),
        written: Number((b.avg_written as Record<string, unknown>)?.value ?? 0),
      };
    });
  }, [statisticsQ.data, isIndexerConnected]);

  // Count running/stopped daemons
  const daemonEntries = Object.entries(daemonStatuses).filter(([k]) => !["affected_items", "total_affected_items", "total_failed_items", "failed_items"].includes(k));
  const runningCount = daemonEntries.filter(([, v]) => String(v) === "running").length;
  const stoppedCount = daemonEntries.filter(([, v]) => String(v) !== "running").length;

  const isLoading = statusQ.isLoading;

  const daemonPie = useMemo(() => [
    { name: "Running", value: runningCount, color: COLORS.green },
    { name: "Stopped", value: stoppedCount, color: COLORS.red },
  ].filter(d => d.value > 0), [runningCount, stoppedCount]);

  // Parse remoted queue for gauge
  const remotedDaemon = daemonMetrics.find(d => String(d.name) === "wazuh-remoted");
  const queueUsed = Number(remotedDaemon?.queue_size ?? 128);
  const queueTotal = Number(remotedDaemon?.total_queue_size ?? 131072);

  const analysisdDaemon = daemonMetrics.find(d => String(d.name) === "wazuh-analysisd");
  const dbDaemon = daemonMetrics.find(d => String(d.name) === "wazuh-db");

  return (
    <WazuhGuard>
      <div className="space-y-6">
        <PageHeader title="Cluster Health" subtitle="Manager daemons, event queues, cluster topology, and configuration validation" onRefresh={handleRefresh} isLoading={isLoading} />

        {/* KPIs */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatCard label="Daemons Running" value={runningCount} icon={CheckCircle2} colorClass="text-threat-low" />
          <StatCard label="Daemons Stopped" value={stoppedCount} icon={XCircle} colorClass={stoppedCount > 0 ? "text-threat-critical" : "text-muted-foreground"} />
          <StatCard label="Cluster" value={String(clusterStatus.enabled ?? "yes")} icon={Network} colorClass="text-primary" />
          <StatCard label="Config Status" value={String(configValid.status ?? "OK")} icon={String(configValid.status) === "OK" || !configValid.status ? CheckCircle2 : AlertTriangle} colorClass={String(configValid.status) === "OK" || !configValid.status ? "text-threat-low" : "text-threat-critical"} />
          <StatCard label="Version" value={String(managerInfo.version ?? "v4.7.2")} icon={Server} colorClass="text-primary" />
        </div>

        {/* Row: Daemon Status + Queue Gauges + Manager Info */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Daemon Status Grid */}
          <GlassPanel className="lg:col-span-5">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Activity className="h-4 w-4 text-primary" /> Daemon Status <SourceBadge source={isConnected && managerStatusQ.data ? "server" : "mock"} /></h3>
            <div className="grid grid-cols-2 gap-2">
              {daemonEntries.map(([name, status]) => {
                const isRunning = String(status) === "running";
                return (
                  <div key={name} className={`flex items-center gap-2 p-2.5 rounded-lg border ${isRunning ? "bg-threat-low/5 border-threat-low/20" : "bg-threat-critical/5 border-threat-critical/20"}`}>
                    <div className={`h-2 w-2 rounded-full ${isRunning ? "bg-threat-low animate-pulse" : "bg-threat-critical"}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-mono text-foreground truncate">{name}</p>
                      <p className={`text-[10px] ${isRunning ? "text-threat-low" : "text-threat-critical"}`}>{String(status)}</p>
                    </div>
                  </div>
                );
              })}
            </div>
            {managerStatusQ.data ? <div className="mt-3"><RawJsonViewer data={managerStatusQ.data as Record<string, unknown>} title="Manager Status JSON" /></div> : null}
          </GlassPanel>

          {/* Event Queue Gauges */}
          <GlassPanel className="lg:col-span-3">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Gauge className="h-4 w-4 text-primary" /> Event Queues <SourceBadge source={isConnected && daemonStatsQ.data ? "server" : "mock"} /></h3>
            <div className="flex flex-col items-center gap-4">
              <QueueGauge label="Remoted Queue" used={queueUsed} total={queueTotal} />
              {daemonPie.length > 0 ? (
                <ResponsiveContainer width="100%" height={120}>
                  <PieChart>
                    <Pie data={daemonPie} cx="50%" cy="50%" innerRadius={30} outerRadius={48} paddingAngle={3} dataKey="value" stroke="none">
                      {daemonPie.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                    </Pie>
                    <ReTooltip content={<ChartTooltip />} />
                    <Legend wrapperStyle={{ fontSize: 10, color: "oklch(0.65 0.02 286)" }} />
                  </PieChart>
                </ResponsiveContainer>
              ) : null}
            </div>
          </GlassPanel>

          {/* Manager Info */}
          <GlassPanel className="lg:col-span-4">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Server className="h-4 w-4 text-primary" /> Manager Info <SourceBadge source={isConnected && managerInfoQ.data ? "server" : "mock"} /></h3>
            <div className="space-y-2">
              {([
                ["Name", managerInfo.name],
                ["Version", managerInfo.version],
                ["Type", managerInfo.type],
                ["Compilation Date", managerInfo.compilation_date],
                ["Path", managerInfo.path],
                ["Max Agents", managerInfo.max_agents],
                ["OpenSSL", managerInfo.openssl_support],
                ["Ruleset Version", managerInfo.ruleset_version],
                ["TZ Name", managerInfo.tz_name],
                ["TZ Offset", managerInfo.tz_offset],
              ] as [string, unknown][]).filter(([, v]) => v != null).map(([label, val]) => (
                <div key={label} className="flex items-center justify-between py-1.5 border-b border-border/10">
                  <span className="text-xs text-muted-foreground">{label}</span>
                  <span className="text-xs font-mono text-foreground">{String(val)}</span>
                </div>
              ))}
            </div>
            {managerInfoQ.data ? <div className="mt-3"><RawJsonViewer data={managerInfoQ.data as Record<string, unknown>} title="Manager Info JSON" /></div> : null}
          </GlassPanel>
        </div>

        {/* Daemon Metrics Detail */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Analysisd */}
          <GlassPanel>
            <h3 className="text-sm font-medium text-muted-foreground mb-3 flex items-center gap-2"><Activity className="h-4 w-4 text-primary" /> wazuh-analysisd <SourceBadge source={isConnected && daemonStatsQ.data ? "server" : "mock"} /></h3>
            <div className="space-y-2">
              {([
                ["Events Received", analysisdDaemon?.events_received],
                ["Events Dropped", analysisdDaemon?.events_dropped],
                ["Alerts Written", analysisdDaemon?.alerts_written],
                ["Firewall Written", analysisdDaemon?.firewall_written],
                ["FTS Written", analysisdDaemon?.fts_written],
                ["Syscheck Decoded", analysisdDaemon?.syscheck_events_decoded],
                ["Syscheck EDPS", analysisdDaemon?.syscheck_edps],
                ["Rootcheck Decoded", analysisdDaemon?.rootcheck_events_decoded],
                ["SCA Decoded", analysisdDaemon?.sca_events_decoded],
              ] as [string, unknown][]).map(([label, val]) => (
                <div key={label} className="flex items-center justify-between py-1 border-b border-border/10">
                  <span className="text-[11px] text-muted-foreground">{label}</span>
                  <span className="text-[11px] font-mono text-foreground">{val != null ? Number(val).toLocaleString() : "—"}</span>
                </div>
              ))}
            </div>
          </GlassPanel>

          {/* Remoted */}
          <GlassPanel>
            <h3 className="text-sm font-medium text-muted-foreground mb-3 flex items-center gap-2"><Network className="h-4 w-4 text-primary" /> wazuh-remoted <SourceBadge source={isConnected && daemonStatsQ.data ? "server" : "mock"} /></h3>
            <div className="space-y-2">
              {([
                ["Queue Size", remotedDaemon?.queue_size],
                ["Total Queue", remotedDaemon?.total_queue_size],
                ["TCP Sessions", remotedDaemon?.tcp_sessions],
                ["Events Count", remotedDaemon?.evt_count],
                ["Control Messages", remotedDaemon?.ctrl_msg_count],
                ["Discarded", remotedDaemon?.discarded_count],
                ["Messages Sent", remotedDaemon?.msg_sent],
                ["Bytes Received", remotedDaemon?.recv_bytes],
              ] as [string, unknown][]).map(([label, val]) => (
                <div key={label} className="flex items-center justify-between py-1 border-b border-border/10">
                  <span className="text-[11px] text-muted-foreground">{label}</span>
                  <span className="text-[11px] font-mono text-foreground">{val != null ? Number(val).toLocaleString() : "—"}</span>
                </div>
              ))}
            </div>
          </GlassPanel>

          {/* wazuh-db */}
          <GlassPanel>
            <h3 className="text-sm font-medium text-muted-foreground mb-3 flex items-center gap-2"><Server className="h-4 w-4 text-primary" /> wazuh-db <SourceBadge source={isConnected && daemonStatsQ.data ? "server" : "mock"} /></h3>
            <div className="space-y-2">
              {(() => {
                const breakdown = (dbDaemon?.queries_breakdown as Record<string, unknown>) ?? {};
                return ([
                  ["Queries Received", dbDaemon?.queries_received],
                  ["Agent Queries", breakdown.agent],
                  ["Global Queries", breakdown.global],
                  ["Task Queries", breakdown.task],
                  ["MITRE Queries", breakdown.mitre],
                  ["Wazuh Queries", breakdown.wazuh],
                ] as [string, unknown][]).map(([label, val]) => (
                  <div key={label} className="flex items-center justify-between py-1 border-b border-border/10">
                    <span className="text-[11px] text-muted-foreground">{label}</span>
                    <span className="text-[11px] font-mono text-foreground">{val != null ? Number(val).toLocaleString() : "—"}</span>
                  </div>
                ));
              })()}
            </div>
          </GlassPanel>
        </div>

        {/* Master Node Stats */}
        {masterNodeId && masterNodeStats.length > 0 ? (
          <GlassPanel>
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2">
              <Gauge className="h-4 w-4 text-primary" /> Master Node Stats
              <span className="text-[10px] font-mono text-muted-foreground">({masterNodeId})</span>
              <SourceBadge source="server" />
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {masterNodeStats.map((stat, i) => {
                const hour = String(stat.hour ?? i);
                const totalAll = Number(stat.totalall ?? stat.total ?? 0);
                const events = Number(stat.events ?? 0);
                const syscheck = Number(stat.syscheck ?? 0);
                const firewall = Number(stat.firewall ?? 0);
                return (
                  <div key={i} className="bg-secondary/20 rounded-lg p-3 border border-border/20">
                    <p className="text-[10px] text-muted-foreground mb-1">Hour {hour}</p>
                    <div className="space-y-1 text-xs">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Total</span>
                        <span className="font-mono text-foreground">{totalAll.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Events</span>
                        <span className="font-mono text-foreground">{events.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Syscheck</span>
                        <span className="font-mono text-foreground">{syscheck.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Firewall</span>
                        <span className="font-mono text-foreground">{firewall.toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
            {nodeStatsQ.data ? <div className="mt-3"><RawJsonViewer data={nodeStatsQ.data as Record<string, unknown>} title="Master Node Stats JSON" /></div> : null}
          </GlassPanel>
        ) : null}

        {/* Hourly Stats Chart */}
        <GlassPanel>
          <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><BarChart3 className="h-4 w-4 text-primary" /> Hourly Event Ingestion <SourceBadge source={isConnected && managerStatsHourlyQ.data ? "server" : "mock"} /></h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={hourlyData}>
              <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
              <XAxis dataKey="hour" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
              <YAxis tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
              <ReTooltip content={<ChartTooltip />} />
              <Legend wrapperStyle={{ fontSize: 11, color: "oklch(0.65 0.02 286)" }} />
              <Bar dataKey="totalall" fill={COLORS.purple} name="Total" radius={[3, 3, 0, 0]} />
              <Bar dataKey="events" fill={COLORS.cyan} name="Events" radius={[3, 3, 0, 0]} />
              <Bar dataKey="syscheck" fill={COLORS.green} name="Syscheck" radius={[3, 3, 0, 0]} />
              <Bar dataKey="firewall" fill={COLORS.orange} name="Firewall" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </GlassPanel>

        {/* Indexer Statistics — Performance Over Time */}
        {statisticsData.length > 0 ? (
          <GlassPanel>
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-primary" /> Indexer Performance (24h)
              <SourceBadge source="indexer" />
            </h3>
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={statisticsData}>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
                <XAxis dataKey="time" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
                <YAxis tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
                <ReTooltip content={<ChartTooltip />} />
                <Legend wrapperStyle={{ fontSize: 11, color: "oklch(0.65 0.02 286)" }} />
                <Area type="monotone" dataKey="received" stroke={COLORS.cyan} fill={COLORS.cyan} fillOpacity={0.15} name="Received" />
                <Area type="monotone" dataKey="decoded" stroke={COLORS.green} fill={COLORS.green} fillOpacity={0.15} name="Decoded" />
                <Area type="monotone" dataKey="dropped" stroke={COLORS.red} fill={COLORS.red} fillOpacity={0.15} name="Dropped" />
                <Area type="monotone" dataKey="written" stroke={COLORS.purple} fill={COLORS.purple} fillOpacity={0.15} name="Written" />
              </AreaChart>
            </ResponsiveContainer>
          </GlassPanel>
        ) : null}

        {/* Cluster Nodes + Healthcheck */}
        <GlassPanel>
          <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2">
            <Network className="h-4 w-4 text-primary" /> Cluster Topology
            <SourceBadge source={isConnected && clusterNodesQ.data ? "server" : "mock"} />
          </h3>
          <div className="flex items-center gap-3 mb-4">
            <span className="text-xs text-muted-foreground">Cluster Enabled:</span>
            <ThreatBadge level={String(clusterStatus.enabled) === "yes" ? "low" : "info"} />
            <span className="text-xs text-muted-foreground ml-4">Running:</span>
            <ThreatBadge level={String(clusterStatus.running) === "yes" ? "low" : "critical"} />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {clusterNodes.map((node, i) => {
              const nodeType = String(node.type ?? "worker");
              const isMaster = nodeType === "master";
              const nodeName = String(node.name ?? "Unknown");
              const healthInfo = healthcheckNodes.find(h => String(h.name) === nodeName);
              return (
                <div key={i} className={`bg-secondary/20 rounded-lg p-4 border ${isMaster ? "border-primary/40 bg-primary/5" : "border-border/20"}`}>
                  <div className="flex items-center gap-2 mb-2">
                    <Server className={`h-4 w-4 ${isMaster ? "text-primary" : "text-muted-foreground"}`} />
                    <span className="text-sm font-medium text-foreground">{nodeName}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${isMaster ? "bg-primary/20 text-primary" : "bg-secondary/40 text-muted-foreground"}`}>{nodeType}</span>
                  </div>
                  <div className="space-y-1 text-xs">
                    <div className="flex justify-between"><span className="text-muted-foreground">IP</span><span className="font-mono text-foreground">{String(node.ip ?? "—")}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Version</span><span className="font-mono text-foreground">{String(node.version ?? "—")}</span></div>
                    {healthInfo ? (
                      <>
                        {healthInfo.info != null && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Health</span>
                            <span className={`font-mono ${String(healthInfo.info).toLowerCase().includes("error") ? "text-threat-critical" : "text-threat-low"}`}>
                              {String(healthInfo.info)}
                            </span>
                          </div>
                        )}
                        {healthInfo.status != null && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Status</span>
                            <span className={`font-mono ${String(healthInfo.status) === "connected" ? "text-threat-low" : "text-threat-high"}`}>
                              {String(healthInfo.status)}
                            </span>
                          </div>
                        )}
                        {healthInfo.n_active_agents != null && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Active Agents</span>
                            <span className="font-mono text-foreground">{Number(healthInfo.n_active_agents).toLocaleString()}</span>
                          </div>
                        )}
                      </>
                    ) : null}
                  </div>
                </div>
              );
            })}
          </div>
          {clusterHealthQ.data ? <div className="mt-3"><RawJsonViewer data={clusterHealthQ.data as Record<string, unknown>} title="Cluster Healthcheck JSON" /></div> : null}
          {clusterNodesQ.data ? <div className="mt-3"><RawJsonViewer data={clusterNodesQ.data as Record<string, unknown>} title="Cluster Nodes JSON" /></div> : null}
        </GlassPanel>

        {/* Config Validation */}
        <GlassPanel>
          <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-primary" /> Configuration Validation <SourceBadge source={isConnected && configValidQ.data ? "server" : "mock"} /></h3>
          <div className="flex items-center gap-3">
            <div className={`h-12 w-12 rounded-lg flex items-center justify-center ${String(configValid.status) === "OK" || !configValid.status ? "bg-threat-low/10 border border-threat-low/20" : "bg-threat-critical/10 border border-threat-critical/20"}`}>
              {String(configValid.status) === "OK" || !configValid.status ? <CheckCircle2 className="h-6 w-6 text-threat-low" /> : <XCircle className="h-6 w-6 text-threat-critical" />}
            </div>
            <div>
              <p className="text-sm font-medium text-foreground">Status: {String(configValid.status ?? "OK")}</p>
              {typeof configValid.details === "string" ? <p className="text-xs text-muted-foreground mt-0.5">{configValid.details}</p> : null}
            </div>
          </div>
          {configValidQ.data ? <div className="mt-3"><RawJsonViewer data={configValidQ.data as Record<string, unknown>} title="Config Validation JSON" /></div> : null}
        </GlassPanel>
      </div>
    </WazuhGuard>
  );
}
