import { trpc } from "@/lib/trpc";
import { GlassPanel } from "@/components/shared/GlassPanel";
import { StatCard } from "@/components/shared/StatCard";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { ThreatBadge } from "@/components/shared/ThreatBadge";
import { RawJsonViewer } from "@/components/shared/RawJsonViewer";
import {
  Server, Activity, Cpu, HardDrive, Clock, CheckCircle2,
  XCircle, AlertTriangle, Network, Gauge, BarChart3,
} from "lucide-react";
import { useMemo, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as ReTooltip,
  ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell, Legend,
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

export default function ClusterHealth() {
  const utils = trpc.useUtils();

  const statusQ = trpc.wazuh.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const enabled = statusQ.data?.configured === true;

  const managerStatusQ = trpc.wazuh.managerStatus.useQuery(undefined, { retry: 1, staleTime: 15_000, enabled });
  const managerInfoQ = trpc.wazuh.managerInfo.useQuery(undefined, { retry: 1, staleTime: 60_000, enabled });
  const managerStatsQ = trpc.wazuh.managerStats.useQuery(undefined, { retry: 1, staleTime: 15_000, enabled });
  const managerStatsHourlyQ = trpc.wazuh.statsHourly.useQuery(undefined, { retry: 1, staleTime: 30_000, enabled });
  const daemonStatsQ = trpc.wazuh.daemonStats.useQuery({ daemons: ["wazuh-analysisd", "wazuh-remoted", "wazuh-db"] }, { retry: 1, staleTime: 15_000, enabled });
  const configValidQ = trpc.wazuh.managerConfigValidation.useQuery(undefined, { retry: 1, staleTime: 60_000, enabled });
  const clusterStatusQ = trpc.wazuh.clusterStatus.useQuery(undefined, { retry: 1, staleTime: 30_000, enabled });
  const clusterNodesQ = trpc.wazuh.clusterNodes.useQuery(undefined, { retry: 1, staleTime: 30_000, enabled });

  const handleRefresh = useCallback(() => { utils.wazuh.invalidate(); }, [utils]);

  // Parse manager status (daemon running/stopped)
  const daemonStatuses = useMemo(() => {
    const d = (managerStatusQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = (d?.affected_items as Array<Record<string, unknown>>) ?? [];
    if (items.length > 0) return items[0];
    // Fallback: the data might be directly in the response
    if (d && typeof d === "object" && !Array.isArray(d)) {
      const keys = Object.keys(d).filter(k => k !== "affected_items" && k !== "total_affected_items" && k !== "total_failed_items" && k !== "failed_items");
      if (keys.length > 0) return d;
    }
    return {};
  }, [managerStatusQ.data]);

  // Parse manager info
  const managerInfo = useMemo(() => {
    const d = (managerInfoQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = (d?.affected_items as Array<Record<string, unknown>>) ?? [];
    return items[0] ?? {};
  }, [managerInfoQ.data]);

  // Parse hourly stats
  const hourlyData = useMemo(() => {
    const d = (managerStatsHourlyQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = (d?.affected_items as Array<Record<string, unknown>>) ?? [];
    return items.map((item, i) => ({
      hour: `${String(i).padStart(2, "0")}:00`,
      totalall: Number(item.totalall ?? 0),
      events: Number(item.events ?? 0),
      syscheck: Number(item.syscheck ?? 0),
      firewall: Number(item.firewall ?? 0),
    }));
  }, [managerStatsHourlyQ.data]);

  // Parse daemon stats
  const daemonMetrics = useMemo(() => {
    const d = (daemonStatsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = (d?.affected_items as Array<Record<string, unknown>>) ?? [];
    return items;
  }, [daemonStatsQ.data]);

  // Parse config validation
  const configValid = useMemo(() => {
    const d = (configValidQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = (d?.affected_items as Array<Record<string, unknown>>) ?? [];
    return items[0] ?? {};
  }, [configValidQ.data]);

  // Parse cluster status
  const clusterStatus = useMemo(() => {
    const d = (clusterStatusQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return d ?? {};
  }, [clusterStatusQ.data]);

  // Parse cluster nodes
  const clusterNodes = useMemo(() => {
    const d = (clusterNodesQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = (d?.affected_items as Array<Record<string, unknown>>) ?? [];
    return items;
  }, [clusterNodesQ.data]);

  // Count running/stopped daemons
  const daemonEntries = Object.entries(daemonStatuses).filter(([k]) => !["affected_items", "total_affected_items", "total_failed_items", "failed_items"].includes(k));
  const runningCount = daemonEntries.filter(([, v]) => String(v) === "running").length;
  const stoppedCount = daemonEntries.filter(([, v]) => String(v) !== "running").length;

  const isLoading = managerStatusQ.isLoading;

  // Daemon pie chart
  const daemonPie = useMemo(() => [
    { name: "Running", value: runningCount, color: COLORS.green },
    { name: "Stopped", value: stoppedCount, color: COLORS.red },
  ].filter(d => d.value > 0), [runningCount, stoppedCount]);

  return (
    <WazuhGuard>
      <div className="space-y-6">
        <PageHeader title="Cluster Health" subtitle="Manager daemons, event queues, cluster topology, and configuration validation" onRefresh={handleRefresh} isLoading={isLoading} />

        {/* KPIs */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatCard label="Daemons Running" value={runningCount} icon={CheckCircle2} colorClass="text-threat-low" />
          <StatCard label="Daemons Stopped" value={stoppedCount} icon={XCircle} colorClass={stoppedCount > 0 ? "text-threat-critical" : "text-muted-foreground"} />
          <StatCard label="Cluster" value={String(clusterStatus.enabled ?? "unknown")} icon={Network} colorClass="text-primary" />
          <StatCard label="Config Status" value={String(configValid.status ?? "unknown")} icon={configValid.status === "OK" ? CheckCircle2 : AlertTriangle} colorClass={String(configValid.status) === "OK" ? "text-threat-low" : "text-threat-critical"} />
          <StatCard label="Version" value={String(managerInfo.version ?? "—")} icon={Server} colorClass="text-primary" />
        </div>

        {/* Row: Daemon Status + Config Validation + Manager Info */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Daemon Status Grid */}
          <GlassPanel className="lg:col-span-5">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Activity className="h-4 w-4 text-primary" /> Daemon Status</h3>
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
              {daemonEntries.length === 0 ? <div className="col-span-2 text-sm text-muted-foreground text-center py-4">No daemon data</div> : null}
            </div>
            {managerStatusQ.data ? <div className="mt-3"><RawJsonViewer data={managerStatusQ.data as Record<string, unknown>} title="Manager Status JSON" /></div> : null}
          </GlassPanel>

          {/* Daemon Pie */}
          <GlassPanel className="lg:col-span-3">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Gauge className="h-4 w-4 text-primary" /> Daemon Health</h3>
            {daemonPie.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={daemonPie} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3} dataKey="value" stroke="none">
                    {daemonPie.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                  <ReTooltip content={<ChartTooltip />} />
                  <Legend wrapperStyle={{ fontSize: 11, color: "oklch(0.65 0.02 286)" }} />
                </PieChart>
              </ResponsiveContainer>
            ) : <div className="h-[200px] flex items-center justify-center text-sm text-muted-foreground">No data</div>}
          </GlassPanel>

          {/* Manager Info */}
          <GlassPanel className="lg:col-span-4">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Server className="h-4 w-4 text-primary" /> Manager Info</h3>
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

        {/* Hourly Stats Chart */}
        <GlassPanel>
          <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><BarChart3 className="h-4 w-4 text-primary" /> Hourly Event Ingestion</h3>
          {hourlyData.length > 0 ? (
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
          ) : <div className="h-[250px] flex items-center justify-center text-sm text-muted-foreground">{managerStatsHourlyQ.isLoading ? "Loading hourly stats..." : "No hourly data available"}</div>}
        </GlassPanel>

        {/* Cluster Nodes */}
        <GlassPanel>
          <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Network className="h-4 w-4 text-primary" /> Cluster Topology</h3>
          <div className="flex items-center gap-3 mb-4">
            <span className="text-xs text-muted-foreground">Cluster Enabled:</span>
            <ThreatBadge level={String(clusterStatus.enabled) === "yes" ? "low" : "info"} />
            <span className="text-xs text-muted-foreground ml-4">Running:</span>
            <ThreatBadge level={String(clusterStatus.running) === "yes" ? "low" : "critical"} />
          </div>
          {clusterNodes.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {clusterNodes.map((node, i) => {
                const nodeType = String(node.type ?? "worker");
                const isMaster = nodeType === "master";
                return (
                  <div key={i} className={`bg-secondary/20 rounded-lg p-4 border ${isMaster ? "border-primary/40 bg-primary/5" : "border-border/20"}`}>
                    <div className="flex items-center gap-2 mb-2">
                      <Server className={`h-4 w-4 ${isMaster ? "text-primary" : "text-muted-foreground"}`} />
                      <span className="text-sm font-medium text-foreground">{String(node.name ?? "Unknown")}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded ${isMaster ? "bg-primary/20 text-primary" : "bg-secondary/40 text-muted-foreground"}`}>{nodeType}</span>
                    </div>
                    <div className="space-y-1 text-xs">
                      <div className="flex justify-between"><span className="text-muted-foreground">IP</span><span className="font-mono text-foreground">{String(node.ip ?? "—")}</span></div>
                      <div className="flex justify-between"><span className="text-muted-foreground">Version</span><span className="font-mono text-foreground">{String(node.version ?? "—")}</span></div>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : <div className="text-sm text-muted-foreground text-center py-6">{clusterNodesQ.isLoading ? "Loading cluster nodes..." : "No cluster nodes found (standalone mode)"}</div>}
          {clusterNodesQ.data ? <div className="mt-3"><RawJsonViewer data={clusterNodesQ.data as Record<string, unknown>} title="Cluster Nodes JSON" /></div> : null}
        </GlassPanel>

        {/* Config Validation */}
        <GlassPanel>
          <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-primary" /> Configuration Validation</h3>
          <div className="flex items-center gap-3">
            <div className={`h-12 w-12 rounded-lg flex items-center justify-center ${String(configValid.status) === "OK" ? "bg-threat-low/10 border border-threat-low/20" : "bg-threat-critical/10 border border-threat-critical/20"}`}>
              {String(configValid.status) === "OK" ? <CheckCircle2 className="h-6 w-6 text-threat-low" /> : <XCircle className="h-6 w-6 text-threat-critical" />}
            </div>
            <div>
              <p className="text-sm font-medium text-foreground">Status: {String(configValid.status ?? "Unknown")}</p>
              {typeof configValid.details === "string" ? <p className="text-xs text-muted-foreground mt-0.5">{configValid.details}</p> : null}
            </div>
          </div>
          {configValidQ.data ? <div className="mt-3"><RawJsonViewer data={configValidQ.data as Record<string, unknown>} title="Config Validation JSON" /></div> : null}
        </GlassPanel>
      </div>
    </WazuhGuard>
  );
}
