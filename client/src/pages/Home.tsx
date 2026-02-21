import { trpc } from "@/lib/trpc";
import { GlassPanel } from "@/components/shared/GlassPanel";
import { StatCard } from "@/components/shared/StatCard";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { ThreatBadge, threatLevelFromNumber } from "@/components/shared/ThreatBadge";
import { RawJsonViewer } from "@/components/shared/RawJsonViewer";
import {
  MOCK_AGENT_SUMMARY, MOCK_MANAGER_STATS, MOCK_MANAGER_STATUS,
  MOCK_RULES, MOCK_AGENTS, MOCK_MITRE_TACTICS, MOCK_DAEMON_STATS,
} from "@/lib/mockData";
import {
  Activity, AlertTriangle, Shield, ShieldCheck, Bug, Server,
  Cpu, Zap, Users, Clock, Target, BarChart3, Wifi, WifiOff,
  ArrowUpRight, ArrowDownRight, Eye, FileSearch, Monitor,
  Database, Lock, Globe, TrendingUp, Layers, Radio,
} from "lucide-react";
import { useMemo, useCallback } from "react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as ReTooltip,
  ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, Legend,
} from "recharts";
import { useLocation } from "wouter";

const COLORS = {
  purple: "oklch(0.541 0.281 293.009)",
  cyan: "oklch(0.789 0.154 211.53)",
  green: "oklch(0.765 0.177 163.223)",
  yellow: "oklch(0.795 0.184 86.047)",
  red: "oklch(0.637 0.237 25.331)",
  orange: "oklch(0.705 0.191 22.216)",
};
const PIE_COLORS = [COLORS.green, COLORS.red, COLORS.yellow, COLORS.cyan, COLORS.purple, COLORS.orange];

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass-panel p-3 text-xs border border-glass-border">
      <p className="text-muted-foreground mb-1">{label}</p>
      {payload.map((p, i) => <p key={i} style={{ color: p.color }} className="font-medium">{p.name}: {p.value?.toLocaleString()}</p>)}
    </div>
  );
}

function EpsGauge({ eps, maxEps }: { eps: number; maxEps: number }) {
  const pct = Math.min((eps / maxEps) * 100, 100);
  const color = pct > 80 ? COLORS.red : pct > 50 ? COLORS.yellow : COLORS.green;
  const circumference = 2 * Math.PI * 45;
  const offset = circumference - (pct / 100) * circumference * 0.75;
  return (
    <div className="flex flex-col items-center justify-center">
      <svg width="150" height="130" viewBox="0 0 120 110">
        <circle cx="60" cy="60" r="45" fill="none" stroke="oklch(0.25 0.03 286 / 40%)" strokeWidth="10"
          strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`} strokeLinecap="round" transform="rotate(135 60 60)" />
        <circle cx="60" cy="60" r="45" fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`} strokeDashoffset={offset}
          strokeLinecap="round" transform="rotate(135 60 60)" className="transition-all duration-1000"
          style={{ filter: `drop-shadow(0 0 6px ${color})` }} />
        <text x="60" y="55" textAnchor="middle" className="fill-foreground text-2xl font-display font-bold" fontSize="22">{eps.toLocaleString()}</text>
        <text x="60" y="72" textAnchor="middle" className="fill-muted-foreground" fontSize="9">events/sec</text>
      </svg>
      <p className="text-xs text-muted-foreground mt-1">Capacity: {pct.toFixed(0)}% of {maxEps.toLocaleString()} EPS</p>
    </div>
  );
}

function ActionCard({ icon: Icon, label, path, color }: { icon: React.ElementType; label: string; path: string; color: string }) {
  const [, setLocation] = useLocation();
  return (
    <button onClick={() => setLocation(path)}
      className="flex items-center gap-3 px-4 py-3 rounded-lg border transition-all hover:scale-[1.02] text-left w-full"
      style={{ borderColor: `${color}33`, background: `${color}0a` }}>
      <Icon className="h-4 w-4 shrink-0" style={{ color }} />
      <span className="text-xs font-medium text-foreground">{label}</span>
      <ArrowUpRight className="h-3 w-3 ml-auto text-muted-foreground" />
    </button>
  );
}

function ConnectivityItem({ label, subtitle, connected }: { label: string; subtitle: string; connected: boolean }) {
  return (
    <div className="flex items-center justify-between py-2.5 px-3 rounded-lg bg-secondary/20 border border-border/20">
      <div className="flex items-center gap-3">
        <div className={`h-8 w-8 rounded-lg flex items-center justify-center ${connected ? "bg-threat-low/10 border border-threat-low/20" : "bg-threat-high/10 border border-threat-high/20"}`}>
          {connected ? <Wifi className="h-3.5 w-3.5 text-threat-low" /> : <WifiOff className="h-3.5 w-3.5 text-threat-high" />}
        </div>
        <div>
          <p className="text-xs font-medium text-foreground">{label}</p>
          <p className="text-[10px] text-muted-foreground">{subtitle}</p>
        </div>
      </div>
      <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full border ${connected ? "text-threat-low bg-threat-low/10 border-threat-low/20" : "text-threat-high bg-threat-high/10 border-threat-high/20"}`}>
        {connected ? "Online" : "Not Set"}
      </span>
    </div>
  );
}

// ── Helper: extract Wazuh response shape ────────────────────────────────────
function extractItems(raw: unknown): Array<Record<string, unknown>> {
  const d = (raw as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
}

export default function Home() {
  const utils = trpc.useUtils();
  const [, setLocation] = useLocation();

  const statusQ = trpc.wazuh.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const isConnected = statusQ.data?.configured === true && statusQ.data?.data != null;

  const agentSummaryQ = trpc.wazuh.agentSummaryStatus.useQuery(undefined, { retry: false, staleTime: 30_000, enabled: isConnected });
  const analysisdQ = trpc.wazuh.analysisd.useQuery(undefined, { retry: false, staleTime: 30_000, enabled: isConnected });
  const statsHourlyQ = trpc.wazuh.statsHourly.useQuery(undefined, { retry: false, staleTime: 60_000, enabled: isConnected });
  const managerStatusQ = trpc.wazuh.managerStatus.useQuery(undefined, { retry: false, staleTime: 60_000, enabled: isConnected });
  const rulesQ = trpc.wazuh.rules.useQuery({ limit: 10, sort: "-level" }, { retry: false, staleTime: 60_000, enabled: isConnected });
  const agentsQ = trpc.wazuh.agents.useQuery({ limit: 8, sort: "-dateAdd" }, { retry: false, staleTime: 30_000, enabled: isConnected });
  const mitreTacticsQ = trpc.wazuh.mitreTactics.useQuery(undefined, { retry: false, staleTime: 120_000, enabled: isConnected });
  const logsSummaryQ = trpc.wazuh.managerLogsSummary.useQuery(undefined, { retry: false, staleTime: 60_000, enabled: isConnected });

  const handleRefresh = useCallback(() => { utils.wazuh.invalidate(); }, [utils]);

  // ── Agent summary (real or fallback) ──────────────────────────────────────
  const agentData = useMemo(() => {
    const raw = isConnected ? agentSummaryQ.data : MOCK_AGENT_SUMMARY;
    const d = (raw as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    if (!d) return { total: 0, active: 0, disconnected: 0, never: 0, pending: 0 };
    const items = d.affected_items as Array<Record<string, unknown>> | undefined;
    const first = items?.[0] ?? d;
    const connection = (first as Record<string, unknown>)?.connection as Record<string, number> | undefined;
    if (connection) {
      return { total: Number((first as Record<string, unknown>).total ?? 0), active: connection.active ?? 0, disconnected: connection.disconnected ?? 0, never: connection.never_connected ?? 0, pending: connection.pending ?? 0 };
    }
    return { total: Number(first?.total ?? first?.active ?? 0) + Number(first?.disconnected ?? 0) + Number(first?.never_connected ?? 0), active: Number(first?.active ?? 0), disconnected: Number(first?.disconnected ?? 0), never: Number(first?.never_connected ?? 0), pending: Number(first?.pending ?? 0) };
  }, [agentSummaryQ.data, isConnected]);

  // ── EPS data ──────────────────────────────────────────────────────────────
  const epsData: { eps: number; totalEvents: number; decodedEvents: number; droppedEvents: number } = useMemo(() => {
    if (isConnected && analysisdQ.data) {
      const items = extractItems(analysisdQ.data);
      const first = items[0];
      return { eps: Number(first?.events_received ?? first?.total_events_decoded ?? 0), totalEvents: Number(first?.total_events ?? first?.events_received ?? 0), decodedEvents: Number(first?.total_events_decoded ?? 0), droppedEvents: Number(first?.events_dropped ?? 0) };
    }
    const ds = MOCK_DAEMON_STATS.data.affected_items[0];
    return { eps: Number(ds.events_received ?? 0), totalEvents: Number(ds.events_received ?? 0), decodedEvents: Number(ds.syscheck_events_decoded ?? 0) + Number(ds.alerts_written ?? 0), droppedEvents: Number(ds.events_dropped ?? 0) };
  }, [analysisdQ.data, isConnected]);

  // ── Hourly trend ──────────────────────────────────────────────────────────
  const hourlyData = useMemo(() => {
    const raw = isConnected ? statsHourlyQ.data : MOCK_MANAGER_STATS;
    const items = extractItems(raw);
    if (items.length === 0) return [];
    return items.map((item, i) => ({
      hour: `${String(item.hour ?? i).padStart(2, "0")}:00`,
      events: Number(item.totalall ?? item.totalItems ?? item.events ?? 0),
      alerts: Number(item.alerts ?? Math.round(Number(item.totalall ?? 0) * 0.12)),
    }));
  }, [statsHourlyQ.data, isConnected]);

  // ── Daemon status ─────────────────────────────────────────────────────────
  const daemonData = useMemo(() => {
    const raw = isConnected ? managerStatusQ.data : MOCK_MANAGER_STATUS;
    const items = extractItems(raw);
    const first = items[0];
    if (!first) return [];
    return Object.entries(first).filter(([k]) => !["affected_items", "total_affected_items", "total_failed_items", "failed_items"].includes(k)).map(([name, status]) => ({ name, status: String(status) }));
  }, [managerStatusQ.data, isConnected]);

  // ── Top rules ─────────────────────────────────────────────────────────────
  const topRules = useMemo(() => {
    const raw = isConnected ? rulesQ.data : MOCK_RULES;
    return extractItems(raw).slice(0, 8);
  }, [rulesQ.data, isConnected]);

  // ── Recent agents ─────────────────────────────────────────────────────────
  const recentAgents = useMemo(() => {
    const raw = isConnected ? agentsQ.data : MOCK_AGENTS;
    return extractItems(raw).slice(0, 8);
  }, [agentsQ.data, isConnected]);

  // ── MITRE tactics ─────────────────────────────────────────────────────────
  const mitreData = useMemo(() => {
    const raw = isConnected ? mitreTacticsQ.data : MOCK_MITRE_TACTICS;
    return extractItems(raw).slice(0, 14).map(t => ({
      name: String(t.name ?? "").replace(/^TA\d+\s*-?\s*/, "").slice(0, 22),
      id: String(t.external_id ?? t.id ?? ""),
      count: Number(t.techniques_count ?? 1),
    }));
  }, [mitreTacticsQ.data, isConnected]);

  // ── Log summary ───────────────────────────────────────────────────────────
  const logSummary = useMemo(() => {
    if (isConnected && logsSummaryQ.data) {
      const items = extractItems(logsSummaryQ.data);
      const first = items[0];
      if (first) {
        let errors = 0, warnings = 0, info = 0;
        for (const [, v] of Object.entries(first)) {
          if (v && typeof v === "object") { const sub = v as Record<string, number>; errors += sub.error ?? 0; warnings += sub.warning ?? 0; info += sub.info ?? 0; }
        }
        return { errors, warnings, info };
      }
    }
    return { errors: 11, warnings: 47, info: 18854 };
  }, [logsSummaryQ.data, isConnected]);

  const agentPieData = useMemo(() => [
    { name: "Active", value: agentData.active },
    { name: "Disconnected", value: agentData.disconnected },
    { name: "Never Connected", value: agentData.never },
    { name: "Pending", value: agentData.pending },
  ].filter(d => d.value > 0), [agentData]);

  const isLoading = statusQ.isLoading;

  return (
    <WazuhGuard>
      <div className="space-y-5">
        <PageHeader title="SOC Console" subtitle="Security Operations Center — Real-time threat intelligence and fleet telemetry" onRefresh={handleRefresh} isLoading={isLoading} />

        {/* ── KPI Row ───────────────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-3">
          <StatCard label="Total Agents" value={agentData.total} icon={Users} colorClass="text-primary" trend={agentData.active > 0 ? `${agentData.active} active` : undefined} trendUp={true} />
          <StatCard label="Active Agents" value={agentData.active} icon={Activity} colorClass="text-threat-low" />
          <StatCard label="Disconnected" value={agentData.disconnected} icon={AlertTriangle} colorClass="text-threat-high" trend={agentData.disconnected > 0 ? "Needs attention" : undefined} trendUp={false} />
          <StatCard label="Audit Events" value={logSummary.info.toLocaleString()} icon={Zap} colorClass="text-info-cyan" trend={logSummary.errors > 0 ? `${logSummary.errors} failures (24h)` : undefined} trendUp={false} />
          <StatCard label="Log Errors" value={logSummary.errors} icon={AlertTriangle} colorClass="text-threat-critical" trend={logSummary.warnings > 0 ? `${logSummary.warnings} warnings` : undefined} trendUp={false} />
          <StatCard label="Rules Loaded" value={topRules.length > 0 ? topRules.length : "—"} icon={Shield} colorClass="text-primary" />
        </div>

        {/* ── Row 2: EPS Gauge + Hourly Trends + Agent Distribution ─────── */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <GlassPanel className="lg:col-span-3 flex flex-col items-center justify-center py-6">
            <h3 className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-2"><Cpu className="h-4 w-4 text-primary" /> Events Per Second</h3>
            <EpsGauge eps={epsData.eps} maxEps={10000} />
            <div className="grid grid-cols-2 gap-4 mt-4 w-full text-center">
              <div><p className="text-lg font-display font-bold text-foreground">{epsData.totalEvents.toLocaleString()}</p><p className="text-[10px] text-muted-foreground">Total Events</p></div>
              <div><p className="text-lg font-display font-bold text-foreground">{epsData.decodedEvents.toLocaleString()}</p><p className="text-[10px] text-muted-foreground">Decoded</p></div>
            </div>
            {epsData.droppedEvents > 0 && <p className="text-[10px] text-threat-high mt-2 flex items-center gap-1"><ArrowDownRight className="h-3 w-3" /> {epsData.droppedEvents.toLocaleString()} dropped</p>}
          </GlassPanel>

          <GlassPanel className="lg:col-span-6">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2"><BarChart3 className="h-4 w-4 text-primary" /> Event Ingestion — Last 24h</h3>
              {(isConnected && statsHourlyQ.data) ? <RawJsonViewer data={statsHourlyQ.data as Record<string, unknown>} title="Hourly Stats" /> : null}
            </div>
            <ResponsiveContainer width="100%" height={210}>
              <AreaChart data={hourlyData}>
                <defs>
                  <linearGradient id="gradEvents" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={COLORS.purple} stopOpacity={0.4} /><stop offset="95%" stopColor={COLORS.purple} stopOpacity={0} /></linearGradient>
                  <linearGradient id="gradAlerts" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={COLORS.red} stopOpacity={0.3} /><stop offset="95%" stopColor={COLORS.red} stopOpacity={0} /></linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
                <XAxis dataKey="hour" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
                <YAxis tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
                <ReTooltip content={<ChartTooltip />} />
                <Area type="monotone" dataKey="events" stroke={COLORS.purple} fill="url(#gradEvents)" strokeWidth={2} name="Events" />
                <Area type="monotone" dataKey="alerts" stroke={COLORS.red} fill="url(#gradAlerts)" strokeWidth={2} name="Alerts" />
                <Legend wrapperStyle={{ fontSize: 11, color: "oklch(0.65 0.02 286)" }} />
              </AreaChart>
            </ResponsiveContainer>
          </GlassPanel>

          <GlassPanel className="lg:col-span-3">
            <h3 className="text-sm font-medium text-muted-foreground mb-3 flex items-center gap-2"><Users className="h-4 w-4 text-primary" /> Fleet Status</h3>
            <ResponsiveContainer width="100%" height={210}>
              <PieChart>
                <Pie data={agentPieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3} dataKey="value" stroke="none">
                  {agentPieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                </Pie>
                <ReTooltip content={<ChartTooltip />} />
                <Legend wrapperStyle={{ fontSize: 10, color: "oklch(0.65 0.02 286)" }} />
              </PieChart>
            </ResponsiveContainer>
          </GlassPanel>
        </div>

        {/* ── Row 3: Quick Actions + MITRE Tactics + API Connectivity ───── */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <GlassPanel className="lg:col-span-3">
            <h3 className="text-sm font-medium text-muted-foreground mb-3 flex items-center gap-2"><Layers className="h-4 w-4 text-primary" /> Quick Actions</h3>
            <div className="space-y-2">
              <ActionCard icon={Eye} label="View Alerts" path="/alerts" color={COLORS.red} />
              <ActionCard icon={Bug} label="Vulnerabilities" path="/vulnerabilities" color={COLORS.orange} />
              <ActionCard icon={Target} label="MITRE ATT&CK" path="/mitre" color={COLORS.purple} />
              <ActionCard icon={ShieldCheck} label="Compliance" path="/compliance" color={COLORS.green} />
              <ActionCard icon={FileSearch} label="File Integrity" path="/fim" color={COLORS.cyan} />
              <ActionCard icon={Monitor} label="IT Hygiene" path="/hygiene" color={COLORS.yellow} />
            </div>
          </GlassPanel>

          <GlassPanel className="lg:col-span-5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2"><Target className="h-4 w-4 text-primary" /> MITRE ATT&CK Tactic Coverage</h3>
            </div>
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={mitreData} layout="vertical" margin={{ left: 90 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
                <XAxis type="number" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
                <YAxis type="category" dataKey="name" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} width={85} />
                <ReTooltip content={<ChartTooltip />} />
                <Bar dataKey="count" fill={COLORS.purple} radius={[0, 4, 4, 0]} name="Techniques" />
              </BarChart>
            </ResponsiveContainer>
          </GlassPanel>

          <GlassPanel className="lg:col-span-4">
            <h3 className="text-sm font-medium text-muted-foreground mb-3 flex items-center gap-2"><Radio className="h-4 w-4 text-primary" /> API Connectivity</h3>
            <div className="space-y-2 mb-4">
              <ConnectivityItem label="Wazuh Manager" subtitle="REST API v4.x" connected={isConnected} />
              <ConnectivityItem label="Wazuh Indexer" subtitle="OpenSearch / Elasticsearch" connected={false} />
              <ConnectivityItem label="Nemotron LLM" subtitle="Local NVIDIA Inference" connected={false} />
            </div>
            <h3 className="text-sm font-medium text-muted-foreground mb-3 mt-4 flex items-center gap-2"><Server className="h-4 w-4 text-primary" /> Manager Daemons</h3>
            <div className="space-y-1.5 max-h-[140px] overflow-y-auto">
              {daemonData.map((d) => (
                <div key={d.name} className="flex items-center justify-between py-1.5 px-3 rounded bg-secondary/20 border border-border/20">
                  <span className="text-[11px] font-mono text-foreground">{d.name}</span>
                  <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full border ${d.status === "running" ? "text-threat-low bg-threat-low/10 border-threat-low/20" : "text-threat-critical bg-threat-critical/10 border-threat-critical/20"}`}>{d.status}</span>
                </div>
              ))}
            </div>
          </GlassPanel>
        </div>

        {/* ── Row 4: Top Rules + Recent Agents ─────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <GlassPanel>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2"><Shield className="h-4 w-4 text-primary" /> Top Rules by Severity</h3>
              {(isConnected && rulesQ.data) ? <RawJsonViewer data={rulesQ.data as Record<string, unknown>} title="Rules Data" /> : null}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead><tr className="border-b border-border/30">
                  <th className="text-left py-2 px-2 text-muted-foreground font-medium">Rule ID</th>
                  <th className="text-left py-2 px-2 text-muted-foreground font-medium">Level</th>
                  <th className="text-left py-2 px-2 text-muted-foreground font-medium">Description</th>
                  <th className="text-left py-2 px-2 text-muted-foreground font-medium">Groups</th>
                </tr></thead>
                <tbody>
                  {topRules.map((rule) => (
                    <tr key={String(rule.id)} className="border-b border-border/10 hover:bg-secondary/20 transition-colors">
                      <td className="py-2 px-2 font-mono text-primary">{String(rule.id)}</td>
                      <td className="py-2 px-2"><ThreatBadge level={threatLevelFromNumber(Number(rule.level ?? 0))} /></td>
                      <td className="py-2 px-2 text-foreground max-w-xs truncate">{String(rule.description ?? "")}</td>
                      <td className="py-2 px-2 text-muted-foreground max-w-[200px] truncate">{Array.isArray(rule.groups) ? (rule.groups as string[]).join(", ") : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </GlassPanel>

          <GlassPanel>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2"><Clock className="h-4 w-4 text-primary" /> Fleet Agents</h3>
              {(isConnected && agentsQ.data) ? <RawJsonViewer data={agentsQ.data as Record<string, unknown>} title="Agents Data" /> : null}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead><tr className="border-b border-border/30">
                  <th className="text-left py-2 px-2 text-muted-foreground font-medium">ID</th>
                  <th className="text-left py-2 px-2 text-muted-foreground font-medium">Name</th>
                  <th className="text-left py-2 px-2 text-muted-foreground font-medium">IP</th>
                  <th className="text-left py-2 px-2 text-muted-foreground font-medium">OS</th>
                  <th className="text-left py-2 px-2 text-muted-foreground font-medium">Status</th>
                </tr></thead>
                <tbody>
                  {recentAgents.map((agent) => {
                    const status = String(agent.status ?? "unknown");
                    return (
                      <tr key={String(agent.id)} className="border-b border-border/10 hover:bg-secondary/20 transition-colors cursor-pointer" onClick={() => setLocation("/agents")}>
                        <td className="py-2 px-2 font-mono text-primary">{String(agent.id)}</td>
                        <td className="py-2 px-2 text-foreground">{String(agent.name ?? "—")}</td>
                        <td className="py-2 px-2 font-mono text-muted-foreground">{String(agent.ip ?? "—")}</td>
                        <td className="py-2 px-2 text-muted-foreground truncate max-w-[120px]">{String((agent.os as Record<string, unknown>)?.name ?? (agent.os as Record<string, unknown>)?.platform ?? "—")}</td>
                        <td className="py-2 px-2">
                          <span className={`inline-flex items-center gap-1 text-xs font-medium ${status === "active" ? "text-threat-low" : status === "disconnected" ? "text-threat-high" : "text-muted-foreground"}`}>
                            <span className={`h-1.5 w-1.5 rounded-full ${status === "active" ? "bg-threat-low" : status === "disconnected" ? "bg-threat-high" : "bg-muted-foreground"}`} />
                            {status}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </GlassPanel>
        </div>
      </div>
    </WazuhGuard>
  );
}
