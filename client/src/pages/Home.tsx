import { trpc } from "@/lib/trpc";
import { GlassPanel } from "@/components/shared/GlassPanel";
import { StatCard } from "@/components/shared/StatCard";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { ThreatBadge, threatLevelFromNumber } from "@/components/shared/ThreatBadge";
import { RawJsonViewer } from "@/components/shared/RawJsonViewer";
import {
  Activity, AlertTriangle, Shield, ShieldCheck, Bug, Server,
  Cpu, Zap, Users, Clock, Target, BarChart3
} from "lucide-react";
import { useMemo, useCallback } from "react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as ReTooltip,
  ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, Legend,
} from "recharts";

// ── Chart colors (Amethyst Nexus palette) ────────────────────────────────────
const COLORS = {
  purple: "oklch(0.541 0.281 293.009)",
  cyan: "oklch(0.789 0.154 211.53)",
  green: "oklch(0.765 0.177 163.223)",
  yellow: "oklch(0.795 0.184 86.047)",
  red: "oklch(0.637 0.237 25.331)",
  orange: "oklch(0.705 0.191 22.216)",
};
const PIE_COLORS = [COLORS.green, COLORS.red, COLORS.yellow, COLORS.cyan, COLORS.purple];

const SEVERITY_COLORS: Record<string, string> = {
  critical: COLORS.red,
  high: COLORS.orange,
  medium: COLORS.yellow,
  low: COLORS.green,
  info: COLORS.cyan,
};

// ── Custom tooltip ───────────────────────────────────────────────────────────
function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass-panel p-3 text-xs border border-glass-border">
      <p className="text-muted-foreground mb-1">{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color }} className="font-medium">
          {p.name}: {p.value?.toLocaleString()}
        </p>
      ))}
    </div>
  );
}

// ── EPS Gauge ────────────────────────────────────────────────────────────────
function EpsGauge({ eps, maxEps }: { eps: number; maxEps: number }) {
  const pct = Math.min((eps / maxEps) * 100, 100);
  const color = pct > 80 ? COLORS.red : pct > 50 ? COLORS.yellow : COLORS.green;
  const circumference = 2 * Math.PI * 45;
  const offset = circumference - (pct / 100) * circumference * 0.75; // 270 degree arc

  return (
    <div className="flex flex-col items-center justify-center">
      <svg width="160" height="140" viewBox="0 0 120 110">
        {/* Background arc */}
        <circle
          cx="60" cy="60" r="45"
          fill="none"
          stroke="oklch(0.25 0.03 286 / 40%)"
          strokeWidth="10"
          strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
          strokeLinecap="round"
          transform="rotate(135 60 60)"
        />
        {/* Value arc */}
        <circle
          cx="60" cy="60" r="45"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(135 60 60)"
          className="transition-all duration-1000"
          style={{ filter: `drop-shadow(0 0 6px ${color})` }}
        />
        <text x="60" y="55" textAnchor="middle" className="fill-foreground text-2xl font-display font-bold" fontSize="22">
          {eps.toLocaleString()}
        </text>
        <text x="60" y="72" textAnchor="middle" className="fill-muted-foreground" fontSize="9">
          events/sec
        </text>
      </svg>
      <p className="text-xs text-muted-foreground mt-1">
        Capacity: {pct.toFixed(0)}% of {maxEps.toLocaleString()} EPS
      </p>
    </div>
  );
}

export default function Home() {
  const utils = trpc.useUtils();

  // ── Data queries ─────────────────────────────────────────────────────────
  const statusQ = trpc.wazuh.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const agentSummaryQ = trpc.wazuh.agentSummaryStatus.useQuery(undefined, { retry: 1, staleTime: 30_000, enabled: statusQ.data?.configured === true });
  const analysisdQ = trpc.wazuh.analysisd.useQuery(undefined, { retry: 1, staleTime: 30_000, enabled: statusQ.data?.configured === true });
  const statsHourlyQ = trpc.wazuh.statsHourly.useQuery(undefined, { retry: 1, staleTime: 60_000, enabled: statusQ.data?.configured === true });
  const managerStatusQ = trpc.wazuh.managerStatus.useQuery(undefined, { retry: 1, staleTime: 60_000, enabled: statusQ.data?.configured === true });
  const rulesQ = trpc.wazuh.rules.useQuery({ limit: 10, sort: "-level" }, { retry: 1, staleTime: 60_000, enabled: statusQ.data?.configured === true });
  const agentsQ = trpc.wazuh.agents.useQuery({ limit: 10, sort: "-dateAdd" }, { retry: 1, staleTime: 30_000, enabled: statusQ.data?.configured === true });
  const mitreTacticsQ = trpc.wazuh.mitreTactics.useQuery(undefined, { retry: 1, staleTime: 120_000, enabled: statusQ.data?.configured === true });

  const handleRefresh = useCallback(() => {
    utils.wazuh.invalidate();
  }, [utils]);

  // ── Derived data ─────────────────────────────────────────────────────────
  const agentData = useMemo(() => {
    const d = (agentSummaryQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    if (!d) return { total: 0, active: 0, disconnected: 0, never: 0, pending: 0 };
    const connection = d.connection as Record<string, number> | undefined;
    return {
      total: (d.total as number) ?? 0,
      active: connection?.active ?? 0,
      disconnected: connection?.disconnected ?? 0,
      never: connection?.never_connected ?? 0,
      pending: connection?.pending ?? 0,
    };
  }, [agentSummaryQ.data]);

  const epsData = useMemo(() => {
    const d = (analysisdQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    if (!d) return { eps: 0, totalEvents: 0, decodedEvents: 0, droppedEvents: 0 };
    const affected = d.affected_items as Array<Record<string, unknown>> | undefined;
    const first = affected?.[0];
    return {
      eps: Number(first?.events_received ?? first?.total_events_decoded ?? 0),
      totalEvents: Number(first?.total_events ?? first?.events_received ?? 0),
      decodedEvents: Number(first?.total_events_decoded ?? 0),
      droppedEvents: Number(first?.events_dropped ?? 0),
    };
  }, [analysisdQ.data]);

  const hourlyData = useMemo(() => {
    const d = (statsHourlyQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = d?.affected_items as Array<Record<string, unknown>> | undefined;
    if (!items) return [];
    return items.map((item, i) => ({
      hour: `${String(i).padStart(2, "0")}:00`,
      events: Number(item.totalItems ?? item.events ?? 0),
      alerts: Number(item.alerts ?? 0),
    }));
  }, [statsHourlyQ.data]);

  const daemonData = useMemo(() => {
    const d = (managerStatusQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = d?.affected_items as Array<Record<string, unknown>> | undefined;
    const first = items?.[0] ?? d;
    if (!first) return [];
    return Object.entries(first).map(([name, status]) => ({
      name,
      status: String(status),
    }));
  }, [managerStatusQ.data]);

  const topRules = useMemo(() => {
    const d = (rulesQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = d?.affected_items as Array<Record<string, unknown>> | undefined;
    return items?.slice(0, 8) ?? [];
  }, [rulesQ.data]);

  const recentAgents = useMemo(() => {
    const d = (agentsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = d?.affected_items as Array<Record<string, unknown>> | undefined;
    return items?.slice(0, 8) ?? [];
  }, [agentsQ.data]);

  const mitreData = useMemo(() => {
    const d = (mitreTacticsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = d?.affected_items as Array<Record<string, unknown>> | undefined;
    return items?.slice(0, 12).map(t => ({
      name: String((t.name as string) ?? "").replace(/^TA\d+\s*-?\s*/, ""),
      id: String(t.external_id ?? t.id ?? ""),
      count: Number(t.techniques_count ?? 0),
    })) ?? [];
  }, [mitreTacticsQ.data]);

  const agentPieData = useMemo(() => [
    { name: "Active", value: agentData.active },
    { name: "Disconnected", value: agentData.disconnected },
    { name: "Never Connected", value: agentData.never },
    { name: "Pending", value: agentData.pending },
  ].filter(d => d.value > 0), [agentData]);

  const isLoading = statusQ.isLoading || agentSummaryQ.isLoading;

  return (
    <WazuhGuard>
      <div className="space-y-6">
        <PageHeader
          title="SOC Console"
          subtitle="Security Operations Center — Real-time threat intelligence and fleet telemetry"
          onRefresh={handleRefresh}
          isLoading={isLoading}
        />

        {/* ── KPI Row ───────────────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 xl:grid-cols-6 gap-4">
          <StatCard label="Total Agents" value={agentData.total} icon={Users} colorClass="text-primary" />
          <StatCard label="Active" value={agentData.active} icon={Activity} colorClass="text-threat-low" />
          <StatCard label="Disconnected" value={agentData.disconnected} icon={AlertTriangle} colorClass="text-threat-high" />
          <StatCard label="Events Decoded" value={epsData.decodedEvents} icon={Zap} colorClass="text-info-cyan" />
          <StatCard label="Events Dropped" value={epsData.droppedEvents} icon={AlertTriangle} colorClass="text-threat-critical" />
          <StatCard label="Top Rules" value={topRules.length} icon={Shield} colorClass="text-primary" />
        </div>

        {/* ── Row 2: EPS Gauge + Hourly Trends + Agent Distribution ─────── */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* EPS Gauge */}
          <GlassPanel className="lg:col-span-3 flex flex-col items-center justify-center">
            <h3 className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-2">
              <Cpu className="h-4 w-4 text-primary" />
              Events Per Second
            </h3>
            <EpsGauge eps={epsData.eps} maxEps={10000} />
            <div className="grid grid-cols-2 gap-4 mt-4 w-full text-center">
              <div>
                <p className="text-lg font-display font-bold text-foreground">{epsData.totalEvents.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">Total Events</p>
              </div>
              <div>
                <p className="text-lg font-display font-bold text-foreground">{epsData.decodedEvents.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">Decoded</p>
              </div>
            </div>
          </GlassPanel>

          {/* Hourly Trend */}
          <GlassPanel className="lg:col-span-6">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-primary" />
              Hourly Event Ingestion
            </h3>
            {hourlyData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={hourlyData}>
                  <defs>
                    <linearGradient id="gradEvents" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={COLORS.purple} stopOpacity={0.4} />
                      <stop offset="95%" stopColor={COLORS.purple} stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gradAlerts" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={COLORS.red} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={COLORS.red} stopOpacity={0} />
                    </linearGradient>
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
            ) : (
              <div className="h-[220px] flex items-center justify-center text-sm text-muted-foreground">
                Awaiting hourly stats data...
              </div>
            )}
          </GlassPanel>

          {/* Agent Distribution Pie */}
          <GlassPanel className="lg:col-span-3">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2">
              <Users className="h-4 w-4 text-primary" />
              Fleet Status
            </h3>
            {agentPieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={agentPieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={3}
                    dataKey="value"
                    stroke="none"
                  >
                    {agentPieData.map((_, i) => (
                      <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <ReTooltip content={<ChartTooltip />} />
                  <Legend wrapperStyle={{ fontSize: 11, color: "oklch(0.65 0.02 286)" }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[220px] flex items-center justify-center text-sm text-muted-foreground">
                No agent data
              </div>
            )}
          </GlassPanel>
        </div>

        {/* ── Row 3: MITRE Tactics + Daemon Status ─────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* MITRE Tactic Distribution */}
          <GlassPanel className="lg:col-span-8">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2">
              <Target className="h-4 w-4 text-primary" />
              MITRE ATT&CK Tactic Coverage
            </h3>
            {mitreData.length > 0 ? (
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={mitreData} layout="vertical" margin={{ left: 100 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
                  <XAxis type="number" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
                  <YAxis type="category" dataKey="name" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} width={95} />
                  <ReTooltip content={<ChartTooltip />} />
                  <Bar dataKey="count" fill={COLORS.purple} radius={[0, 4, 4, 0]} name="Techniques" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[240px] flex items-center justify-center text-sm text-muted-foreground">
                Awaiting MITRE data...
              </div>
            )}
          </GlassPanel>

          {/* Daemon Status */}
          <GlassPanel className="lg:col-span-4">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2">
              <Server className="h-4 w-4 text-primary" />
              Manager Daemons
            </h3>
            <div className="space-y-2 max-h-[240px] overflow-y-auto">
              {daemonData.length > 0 ? daemonData.map((d) => (
                <div key={d.name} className="flex items-center justify-between py-2 px-3 rounded-lg bg-secondary/30 border border-border/30">
                  <span className="text-xs font-mono text-foreground">{d.name}</span>
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                    d.status === "running" ? "bg-threat-low/20 text-threat-low border border-threat-low/30" :
                    d.status === "stopped" ? "bg-threat-critical/20 text-threat-critical border border-threat-critical/30" :
                    "bg-threat-medium/20 text-threat-medium border border-threat-medium/30"
                  }`}>
                    {d.status}
                  </span>
                </div>
              )) : (
                <div className="text-sm text-muted-foreground text-center py-8">
                  Awaiting daemon data...
                </div>
              )}
            </div>
          </GlassPanel>
        </div>

        {/* ── Row 4: Top Rules + Recent Agents ─────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Top Rules */}
          <GlassPanel>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-primary" />
                Highest Severity Rules
              </h3>
              {rulesQ.data ? <RawJsonViewer data={rulesQ.data as Record<string, unknown>} title="Rules Data" /> : null}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/30">
                    <th className="text-left py-2 px-2 text-muted-foreground font-medium">Rule ID</th>
                    <th className="text-left py-2 px-2 text-muted-foreground font-medium">Level</th>
                    <th className="text-left py-2 px-2 text-muted-foreground font-medium">Description</th>
                    <th className="text-left py-2 px-2 text-muted-foreground font-medium">Groups</th>
                  </tr>
                </thead>
                <tbody>
                  {topRules.map((rule) => (
                    <tr key={String(rule.id)} className="border-b border-border/10 data-row">
                      <td className="py-2 px-2 font-mono text-primary">{String(rule.id)}</td>
                      <td className="py-2 px-2">
                        <ThreatBadge level={threatLevelFromNumber(Number(rule.level ?? 0))} />
                      </td>
                      <td className="py-2 px-2 text-foreground max-w-xs truncate">{String(rule.description ?? "")}</td>
                      <td className="py-2 px-2 text-muted-foreground max-w-[200px] truncate">
                        {Array.isArray(rule.groups) ? (rule.groups as string[]).join(", ") : "—"}
                      </td>
                    </tr>
                  ))}
                  {topRules.length === 0 && (
                    <tr><td colSpan={4} className="py-8 text-center text-muted-foreground">Awaiting rules data...</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </GlassPanel>

          {/* Recent Agents */}
          <GlassPanel>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                <Clock className="h-4 w-4 text-primary" />
                Recently Added Agents
              </h3>
              {agentsQ.data ? <RawJsonViewer data={agentsQ.data as Record<string, unknown>} title="Agents Data" /> : null}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/30">
                    <th className="text-left py-2 px-2 text-muted-foreground font-medium">ID</th>
                    <th className="text-left py-2 px-2 text-muted-foreground font-medium">Name</th>
                    <th className="text-left py-2 px-2 text-muted-foreground font-medium">IP</th>
                    <th className="text-left py-2 px-2 text-muted-foreground font-medium">OS</th>
                    <th className="text-left py-2 px-2 text-muted-foreground font-medium">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAgents.map((agent) => {
                    const status = String(agent.status ?? "unknown");
                    return (
                      <tr key={String(agent.id)} className="border-b border-border/10 data-row">
                        <td className="py-2 px-2 font-mono text-primary">{String(agent.id)}</td>
                        <td className="py-2 px-2 text-foreground">{String(agent.name ?? "—")}</td>
                        <td className="py-2 px-2 font-mono text-muted-foreground">{String(agent.ip ?? "—")}</td>
                        <td className="py-2 px-2 text-muted-foreground truncate max-w-[120px]">
                          {String((agent.os as Record<string, unknown>)?.name ?? (agent.os as Record<string, unknown>)?.platform ?? "—")}
                        </td>
                        <td className="py-2 px-2">
                          <span className={`inline-flex items-center gap-1 text-xs font-medium ${
                            status === "active" ? "text-threat-low" :
                            status === "disconnected" ? "text-threat-high" :
                            "text-muted-foreground"
                          }`}>
                            <span className={`h-1.5 w-1.5 rounded-full ${
                              status === "active" ? "bg-[oklch(0.765_0.177_163.223)]" :
                              status === "disconnected" ? "bg-[oklch(0.705_0.191_22.216)]" :
                              "bg-[oklch(0.65_0.02_286)]"
                            }`} />
                            {status}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                  {recentAgents.length === 0 && (
                    <tr><td colSpan={5} className="py-8 text-center text-muted-foreground">Awaiting agent data...</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </GlassPanel>
        </div>
      </div>
    </WazuhGuard>
  );
}
