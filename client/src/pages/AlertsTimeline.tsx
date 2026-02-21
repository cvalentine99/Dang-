import { trpc } from "@/lib/trpc";
import { GlassPanel } from "@/components/shared/GlassPanel";
import { StatCard } from "@/components/shared/StatCard";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { ThreatBadge, threatLevelFromNumber } from "@/components/shared/ThreatBadge";
import { RawJsonViewer } from "@/components/shared/RawJsonViewer";
import { MOCK_RULES, MOCK_STATS_HOURLY, MOCK_MANAGER_LOGS } from "@/lib/mockData";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  AlertTriangle, Shield, Search, ChevronLeft, ChevronRight,
  BarChart3, Clock, Layers, TrendingUp, FileWarning,
} from "lucide-react";
import { useState, useMemo, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as ReTooltip,
  ResponsiveContainer, Legend, AreaChart, Area,
} from "recharts";

const COLORS = {
  purple: "oklch(0.541 0.281 293.009)",
  cyan: "oklch(0.789 0.154 211.53)",
  green: "oklch(0.765 0.177 163.223)",
  yellow: "oklch(0.795 0.184 86.047)",
  red: "oklch(0.637 0.237 25.331)",
  orange: "oklch(0.705 0.191 22.216)",
};

const HOURS = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, "0")}:00`);
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass-panel p-3 text-xs border border-glass-border">
      <p className="text-muted-foreground mb-1">{label}</p>
      {payload.map((p, i) => <p key={i} style={{ color: p.color }} className="font-medium">{p.name}: {p.value?.toLocaleString()}</p>)}
    </div>
  );
}

function extractItems(raw: unknown): Array<Record<string, unknown>> {
  const d = (raw as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
}

export default function AlertsTimeline() {
  const utils = trpc.useUtils();
  const [levelFilter, setLevelFilter] = useState<string>("all");
  const [groupFilter, setGroupFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 50;

  const statusQ = trpc.wazuh.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const isConnected = statusQ.data?.configured === true && statusQ.data?.data != null;

  const rulesQ = trpc.wazuh.rules.useQuery({
    limit: pageSize, offset: page * pageSize,
    level: levelFilter !== "all" ? Number(levelFilter) : undefined,
    group: groupFilter !== "all" ? groupFilter : undefined,
    search: search || undefined, sort: "-level",
  }, { retry: 1, staleTime: 15_000, enabled: isConnected });

  const ruleGroupsQ = trpc.wazuh.ruleGroups.useQuery(undefined, { retry: 1, staleTime: 120_000, enabled: isConnected });
  const statsHourlyQ = trpc.wazuh.statsHourly.useQuery(undefined, { retry: 1, staleTime: 60_000, enabled: isConnected });
  const statsWeeklyQ = trpc.wazuh.statsWeekly.useQuery(undefined, { retry: 1, staleTime: 120_000, enabled: isConnected });
  const logsQ = trpc.wazuh.managerLogs.useQuery({ limit: 15 }, { retry: 1, staleTime: 30_000, enabled: isConnected });

  const handleRefresh = useCallback(() => { utils.wazuh.invalidate(); }, [utils]);

  // ── Rules (real or fallback) ──────────────────────────────────────────
  const rules = useMemo(() => {
    if (isConnected && rulesQ.data) return extractItems(rulesQ.data);
    let items = MOCK_RULES.data.affected_items as unknown as Array<Record<string, unknown>>;
    if (levelFilter !== "all") items = items.filter(r => Number(r.level) === Number(levelFilter));
    if (groupFilter !== "all") items = items.filter(r => Array.isArray(r.groups) && (r.groups as string[]).includes(groupFilter));
    if (search) items = items.filter(r => String(r.description ?? "").toLowerCase().includes(search.toLowerCase()) || String(r.id).includes(search));
    return items;
  }, [rulesQ.data, isConnected, levelFilter, groupFilter, search]);

  const totalRules = useMemo(() => {
    if (isConnected && rulesQ.data) {
      const d = (rulesQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
      return Number(d?.total_affected_items ?? rules.length);
    }
    return MOCK_RULES.data.total_affected_items;
  }, [rulesQ.data, isConnected, rules.length]);

  // ── Rule groups (real or fallback) ────────────────────────────────────
  const ruleGroups = useMemo(() => {
    if (isConnected && ruleGroupsQ.data) {
      const d = (ruleGroupsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
      return (d?.affected_items as string[]) ?? [];
    }
    const groups = new Set<string>();
    MOCK_RULES.data.affected_items.forEach(r => r.groups.forEach(g => groups.add(g)));
    return Array.from(groups).sort();
  }, [ruleGroupsQ.data, isConnected]);

  // ── Hourly data (real or fallback) ────────────────────────────────────
  const hourlyData = useMemo(() => {
    if (isConnected && statsHourlyQ.data) {
      const items = extractItems(statsHourlyQ.data);
      return items.map((item, i) => ({ hour: HOURS[i] ?? `${i}`, events: Number(item.totalItems ?? item.totalall ?? item.events ?? 0), syscheck: Number(item.syscheck ?? 0), firewall: Number(item.firewall ?? 0) }));
    }
    return MOCK_STATS_HOURLY.data.affected_items.map(item => ({ hour: HOURS[item.hour] ?? `${item.hour}`, events: item.events, syscheck: item.syscheck, firewall: item.firewall }));
  }, [statsHourlyQ.data, isConnected]);

  // ── Weekly heatmap (real or fallback) ─────────────────────────────────
  const weeklyHeatmap = useMemo(() => {
    if (isConnected && statsWeeklyQ.data) {
      const items = extractItems(statsWeeklyQ.data);
      return items.map((item, i) => ({ day: DAYS[Math.floor(i / 24)] ?? `Day ${Math.floor(i / 24)}`, hour: HOURS[i % 24] ?? `${i % 24}`, value: Number(item.totalItems ?? item.events ?? 0) }));
    }
    // Generate fallback weekly heatmap from hourly data
    const grid: Array<{ day: string; hour: string; value: number }> = [];
    DAYS.forEach(day => {
      MOCK_STATS_HOURLY.data.affected_items.forEach(item => {
        const jitter = Math.floor(Math.random() * 200) - 100;
        const dayMult = day === "Sat" || day === "Sun" ? 0.4 : 1.0;
        grid.push({ day, hour: HOURS[item.hour] ?? `${item.hour}`, value: Math.max(0, Math.floor(item.events * dayMult + jitter)) });
      });
    });
    return grid;
  }, [statsWeeklyQ.data, isConnected]);

  const maxHeatVal = useMemo(() => Math.max(...weeklyHeatmap.map(h => h.value), 1), [weeklyHeatmap]);

  // ── Manager logs (real or fallback) ───────────────────────────────────
  const logs = useMemo(() => {
    if (isConnected && logsQ.data) return extractItems(logsQ.data);
    return MOCK_MANAGER_LOGS.data.affected_items as unknown as Array<Record<string, unknown>>;
  }, [logsQ.data, isConnected]);

  // ── Level distribution ────────────────────────────────────────────────
  const levelDistribution = useMemo(() => {
    const counts: Record<number, number> = {};
    rules.forEach(r => { const lvl = Number(r.level ?? 0); counts[lvl] = (counts[lvl] ?? 0) + 1; });
    return Object.entries(counts).map(([level, count]) => ({ level: `Lvl ${level}`, count })).sort((a, b) => Number(b.level.replace("Lvl ", "")) - Number(a.level.replace("Lvl ", "")));
  }, [rules]);

  const criticalCount = rules.filter(r => Number(r.level ?? 0) >= 12).length;
  const highCount = rules.filter(r => { const l = Number(r.level ?? 0); return l >= 8 && l < 12; }).length;
  const mediumCount = rules.filter(r => { const l = Number(r.level ?? 0); return l >= 4 && l < 8; }).length;
  const totalPages = Math.ceil(totalRules / pageSize);

  return (
    <WazuhGuard>
      <div className="space-y-6">
        <PageHeader title="Alert Intelligence" subtitle="Rule-based alert analysis — severity distribution, hourly trends, and weekly heatmap" onRefresh={handleRefresh} isLoading={statusQ.isLoading} />

        {/* KPI Row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Total Rules" value={totalRules} icon={Shield} colorClass="text-primary" />
          <StatCard label="Critical (12+)" value={criticalCount} icon={AlertTriangle} colorClass="text-threat-critical" />
          <StatCard label="High (8-11)" value={highCount} icon={TrendingUp} colorClass="text-threat-high" />
          <StatCard label="Medium (4-7)" value={mediumCount} icon={BarChart3} colorClass="text-threat-medium" />
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <GlassPanel className="lg:col-span-7">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Clock className="h-4 w-4 text-primary" /> Hourly Event Ingestion</h3>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={hourlyData}>
                <defs>
                  <linearGradient id="evtGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={COLORS.purple} stopOpacity={0.4} /><stop offset="95%" stopColor={COLORS.purple} stopOpacity={0} /></linearGradient>
                  <linearGradient id="sysGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={COLORS.cyan} stopOpacity={0.4} /><stop offset="95%" stopColor={COLORS.cyan} stopOpacity={0} /></linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
                <XAxis dataKey="hour" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 9 }} interval={2} />
                <YAxis tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
                <ReTooltip content={<ChartTooltip />} />
                <Area type="monotone" dataKey="events" stroke={COLORS.purple} fill="url(#evtGrad)" name="Events" strokeWidth={2} />
                <Area type="monotone" dataKey="syscheck" stroke={COLORS.cyan} fill="url(#sysGrad)" name="Syscheck" strokeWidth={2} />
                <Legend wrapperStyle={{ fontSize: 11, color: "oklch(0.65 0.02 286)" }} />
              </AreaChart>
            </ResponsiveContainer>
          </GlassPanel>

          <GlassPanel className="lg:col-span-5">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Layers className="h-4 w-4 text-primary" /> Rule Level Distribution</h3>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={levelDistribution} layout="vertical" margin={{ left: 50 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
                <XAxis type="number" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
                <YAxis type="category" dataKey="level" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} width={45} />
                <ReTooltip content={<ChartTooltip />} />
                <Bar dataKey="count" fill={COLORS.purple} name="Rules" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </GlassPanel>
        </div>

        {/* Weekly Heatmap */}
        <GlassPanel>
          <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><BarChart3 className="h-4 w-4 text-primary" /> Weekly Alert Heatmap</h3>
          <div className="overflow-x-auto">
            <div className="min-w-[700px]">
              <div className="flex ml-12 mb-1">
                {HOURS.filter((_, i) => i % 3 === 0).map(h => <span key={h} className="text-[9px] text-muted-foreground" style={{ width: `${100 / 8}%` }}>{h}</span>)}
              </div>
              {DAYS.map(day => (
                <div key={day} className="flex items-center gap-1 mb-1">
                  <span className="text-[10px] text-muted-foreground w-10 text-right">{day}</span>
                  <div className="flex gap-[2px] flex-1">
                    {Array.from({ length: 24 }, (_, hourIdx) => {
                      const cell = weeklyHeatmap.find(h => h.day === day && h.hour === HOURS[hourIdx]);
                      const val = cell?.value ?? 0;
                      const intensity = val / maxHeatVal;
                      return (
                        <div key={hourIdx} className="flex-1 h-6 rounded-sm cursor-default" style={{
                          backgroundColor: intensity > 0.7 ? `oklch(0.637 ${0.237 * intensity} 25.331 / ${0.3 + intensity * 0.7})` : intensity > 0.3 ? `oklch(0.795 ${0.184 * intensity} 86.047 / ${0.3 + intensity * 0.7})` : `oklch(0.541 ${0.281 * intensity} 293.009 / ${0.15 + intensity * 0.5})`,
                        }} title={`${day} ${HOURS[hourIdx]}: ${val} events`} />
                      );
                    })}
                  </div>
                </div>
              ))}
              <div className="flex items-center justify-end gap-2 mt-2">
                <span className="text-[9px] text-muted-foreground">Less</span>
                {[0.1, 0.3, 0.5, 0.7, 0.9].map(i => (
                  <div key={i} className="w-4 h-4 rounded-sm" style={{ backgroundColor: i > 0.7 ? `oklch(0.637 ${0.237 * i} 25.331 / ${0.3 + i * 0.7})` : i > 0.3 ? `oklch(0.795 ${0.184 * i} 86.047 / ${0.3 + i * 0.7})` : `oklch(0.541 ${0.281 * i} 293.009 / ${0.15 + i * 0.5})` }} />
                ))}
                <span className="text-[9px] text-muted-foreground">More</span>
              </div>
            </div>
          </div>
        </GlassPanel>

        {/* Recent Alert Logs */}
        <GlassPanel>
          <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><FileWarning className="h-4 w-4 text-primary" /> Recent Alert Log ({logs.length})</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="border-b border-border/30">
                {["Timestamp", "Tag", "Level", "Description"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
              </tr></thead>
              <tbody>
                {logs.map((log, i) => {
                  const level = String(log.level ?? "info");
                  return (
                    <tr key={i} className="border-b border-border/10 hover:bg-secondary/20 transition-colors">
                      <td className="py-2 px-3 font-mono text-[10px] text-muted-foreground whitespace-nowrap">{log.timestamp ? new Date(String(log.timestamp)).toLocaleString() : "—"}</td>
                      <td className="py-2 px-3 font-mono text-primary text-[10px]">{String(log.tag ?? "—")}</td>
                      <td className="py-2 px-3">
                        <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${level === "error" ? "bg-threat-critical/20 text-threat-critical" : level === "warning" ? "bg-threat-medium/20 text-threat-medium" : "bg-primary/10 text-primary"}`}>{level}</span>
                      </td>
                      <td className="py-2 px-3 text-foreground max-w-lg truncate">{String(log.description ?? "—")}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </GlassPanel>

        {/* Rules Table */}
        <GlassPanel>
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4">
            <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2"><Shield className="h-4 w-4 text-primary" /> Rules ({totalRules})</h3>
            <div className="flex items-center gap-2 flex-wrap">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input placeholder="Search rules..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(0); }} className="h-8 w-48 pl-8 text-xs bg-secondary/50 border-border" />
              </div>
              <Select value={levelFilter} onValueChange={(v) => { setLevelFilter(v); setPage(0); }}>
                <SelectTrigger className="w-[120px] h-8 text-xs bg-secondary/50 border-border"><SelectValue placeholder="Level" /></SelectTrigger>
                <SelectContent className="bg-popover border-border max-h-60">
                  <SelectItem value="all">All Levels</SelectItem>
                  {Array.from({ length: 16 }, (_, i) => <SelectItem key={i} value={String(i)}>{`Level ${i}`}</SelectItem>)}
                </SelectContent>
              </Select>
              <Select value={groupFilter} onValueChange={(v) => { setGroupFilter(v); setPage(0); }}>
                <SelectTrigger className="w-[160px] h-8 text-xs bg-secondary/50 border-border"><SelectValue placeholder="Group" /></SelectTrigger>
                <SelectContent className="bg-popover border-border max-h-60">
                  <SelectItem value="all">All Groups</SelectItem>
                  {ruleGroups.slice(0, 50).map(g => <SelectItem key={g} value={g}>{g}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="border-b border-border/30">
                {["ID", "Level", "Description", "Groups", "MITRE", "File", "GDPR", "PCI DSS"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
              </tr></thead>
              <tbody>
                {rules.map((rule) => {
                  const mitre = rule.mitre as Record<string, unknown> | undefined;
                  const mitreIds = Array.isArray(mitre?.id) ? (mitre.id as string[]) : [];
                  return (
                    <tr key={String(rule.id)} className="border-b border-border/10 hover:bg-secondary/20 transition-colors">
                      <td className="py-2 px-3 font-mono text-primary">{String(rule.id)}</td>
                      <td className="py-2 px-3"><ThreatBadge level={threatLevelFromNumber(Number(rule.level ?? 0))} /></td>
                      <td className="py-2 px-3 text-foreground max-w-xs truncate">{String(rule.description ?? "—")}</td>
                      <td className="py-2 px-3 text-muted-foreground max-w-[150px] truncate">{Array.isArray(rule.groups) ? (rule.groups as string[]).join(", ") : "—"}</td>
                      <td className="py-2 px-3 text-muted-foreground max-w-[120px] truncate">{mitreIds.length > 0 ? mitreIds.join(", ") : "—"}</td>
                      <td className="py-2 px-3 font-mono text-muted-foreground text-[10px]">{String(rule.filename ?? "—")}</td>
                      <td className="py-2 px-3 text-muted-foreground text-[10px] max-w-[80px] truncate">{Array.isArray(rule.gdpr) ? (rule.gdpr as string[]).join(", ") : "—"}</td>
                      <td className="py-2 px-3 text-muted-foreground text-[10px] max-w-[80px] truncate">{Array.isArray(rule.pci_dss) ? (rule.pci_dss as string[]).join(", ") : "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-4 pt-4 border-t border-border/30">
              <p className="text-xs text-muted-foreground">Page {page + 1} of {totalPages}</p>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(p => p - 1)} className="h-7 bg-transparent border-border"><ChevronLeft className="h-3.5 w-3.5" /></Button>
                <Button variant="outline" size="sm" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)} className="h-7 bg-transparent border-border"><ChevronRight className="h-3.5 w-3.5" /></Button>
              </div>
            </div>
          )}
        </GlassPanel>
      </div>
    </WazuhGuard>
  );
}
