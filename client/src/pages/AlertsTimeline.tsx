import { trpc } from "@/lib/trpc";
import { GlassPanel } from "@/components/shared/GlassPanel";
import { StatCard } from "@/components/shared/StatCard";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { ThreatBadge, threatLevelFromNumber } from "@/components/shared/ThreatBadge";
import { RawJsonViewer } from "@/components/shared/RawJsonViewer";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  AlertTriangle, Shield, Search, ChevronLeft, ChevronRight,
  BarChart3, Clock, Layers, TrendingUp,
} from "lucide-react";
import { useState, useMemo, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as ReTooltip,
  ResponsiveContainer, Legend,
} from "recharts";

const COLORS = {
  purple: "oklch(0.541 0.281 293.009)",
  cyan: "oklch(0.789 0.154 211.53)",
  green: "oklch(0.765 0.177 163.223)",
  yellow: "oklch(0.795 0.184 86.047)",
  red: "oklch(0.637 0.237 25.331)",
  orange: "oklch(0.705 0.191 22.216)",
};

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const HOURS = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, "0")}:00`);

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass-panel p-3 text-xs border border-glass-border">
      <p className="text-muted-foreground mb-1">{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color }} className="font-medium">{p.name}: {p.value?.toLocaleString()}</p>
      ))}
    </div>
  );
}

export default function AlertsTimeline() {
  const utils = trpc.useUtils();
  const [levelFilter, setLevelFilter] = useState<string>("all");
  const [groupFilter, setGroupFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 50;

  const statusQ = trpc.wazuh.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const enabled = statusQ.data?.configured === true;

  const rulesQ = trpc.wazuh.rules.useQuery({
    limit: pageSize, offset: page * pageSize,
    level: levelFilter !== "all" ? Number(levelFilter) : undefined,
    group: groupFilter !== "all" ? groupFilter : undefined,
    search: search || undefined, sort: "-level",
  }, { retry: 1, staleTime: 15_000, enabled });

  const ruleGroupsQ = trpc.wazuh.ruleGroups.useQuery(undefined, { retry: 1, staleTime: 120_000, enabled });
  const statsHourlyQ = trpc.wazuh.statsHourly.useQuery(undefined, { retry: 1, staleTime: 60_000, enabled });
  const statsWeeklyQ = trpc.wazuh.statsWeekly.useQuery(undefined, { retry: 1, staleTime: 120_000, enabled });

  const handleRefresh = useCallback(() => { utils.wazuh.invalidate(); }, [utils]);

  const rules = useMemo(() => {
    const d = (rulesQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
  }, [rulesQ.data]);

  const totalRules = useMemo(() => {
    const d = (rulesQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return Number(d?.total_affected_items ?? rules.length);
  }, [rulesQ.data, rules.length]);

  const ruleGroups = useMemo(() => {
    const d = (ruleGroupsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return (d?.affected_items as string[]) ?? [];
  }, [ruleGroupsQ.data]);

  const levelDistribution = useMemo(() => {
    const counts: Record<number, number> = {};
    rules.forEach(r => { const lvl = Number(r.level ?? 0); counts[lvl] = (counts[lvl] ?? 0) + 1; });
    return Object.entries(counts).map(([level, count]) => ({ level: `Lvl ${level}`, count })).sort((a, b) => Number(b.level.replace("Lvl ", "")) - Number(a.level.replace("Lvl ", "")));
  }, [rules]);

  const hourlyData = useMemo(() => {
    const d = (statsHourlyQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = d?.affected_items as Array<Record<string, unknown>> | undefined;
    if (!items) return [];
    return items.map((item, i) => ({ hour: HOURS[i] ?? `${i}`, events: Number(item.totalItems ?? item.events ?? 0), alerts: Number(item.alerts ?? 0) }));
  }, [statsHourlyQ.data]);

  const weeklyHeatmap = useMemo(() => {
    const d = (statsWeeklyQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = d?.affected_items as Array<Record<string, unknown>> | undefined;
    if (!items) return [];
    const grid: Array<{ day: string; hour: string; value: number }> = [];
    items.forEach((item, i) => {
      const dayIdx = Math.floor(i / 24);
      const hourIdx = i % 24;
      grid.push({ day: DAYS[dayIdx] ?? `Day ${dayIdx}`, hour: HOURS[hourIdx] ?? `${hourIdx}`, value: Number(item.totalItems ?? item.events ?? 0) });
    });
    return grid;
  }, [statsWeeklyQ.data]);

  const maxHeatVal = useMemo(() => Math.max(...weeklyHeatmap.map(h => h.value), 1), [weeklyHeatmap]);

  const criticalCount = rules.filter(r => Number(r.level ?? 0) >= 12).length;
  const highCount = rules.filter(r => { const l = Number(r.level ?? 0); return l >= 8 && l < 12; }).length;
  const mediumCount = rules.filter(r => { const l = Number(r.level ?? 0); return l >= 4 && l < 8; }).length;

  const isLoading = rulesQ.isLoading;
  const totalPages = Math.ceil(totalRules / pageSize);

  return (
    <WazuhGuard>
      <div className="space-y-6">
        <PageHeader title="Alert Intelligence" subtitle="Rule-based alert analysis — severity distribution, hourly trends, and weekly heatmap" onRefresh={handleRefresh} isLoading={isLoading} />

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Total Rules" value={totalRules} icon={Shield} colorClass="text-primary" />
          <StatCard label="Critical (12+)" value={criticalCount} icon={AlertTriangle} colorClass="text-threat-critical" />
          <StatCard label="High (8-11)" value={highCount} icon={TrendingUp} colorClass="text-threat-high" />
          <StatCard label="Medium (4-7)" value={mediumCount} icon={BarChart3} colorClass="text-threat-medium" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <GlassPanel className="lg:col-span-7">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Clock className="h-4 w-4 text-primary" /> Hourly Event Ingestion</h3>
            {hourlyData.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={hourlyData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
                  <XAxis dataKey="hour" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 9 }} interval={2} />
                  <YAxis tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
                  <ReTooltip content={<ChartTooltip />} />
                  <Bar dataKey="events" fill={COLORS.purple} name="Events" radius={[2, 2, 0, 0]} />
                  <Bar dataKey="alerts" fill={COLORS.red} name="Alerts" radius={[2, 2, 0, 0]} />
                  <Legend wrapperStyle={{ fontSize: 11, color: "oklch(0.65 0.02 286)" }} />
                </BarChart>
              </ResponsiveContainer>
            ) : <div className="h-[200px] flex items-center justify-center text-sm text-muted-foreground">Awaiting hourly data...</div>}
          </GlassPanel>

          <GlassPanel className="lg:col-span-5">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Layers className="h-4 w-4 text-primary" /> Rule Level Distribution</h3>
            {levelDistribution.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={levelDistribution} layout="vertical" margin={{ left: 50 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
                  <XAxis type="number" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
                  <YAxis type="category" dataKey="level" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} width={45} />
                  <ReTooltip content={<ChartTooltip />} />
                  <Bar dataKey="count" fill={COLORS.purple} name="Rules" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : <div className="h-[200px] flex items-center justify-center text-sm text-muted-foreground">No level data</div>}
          </GlassPanel>
        </div>

        {weeklyHeatmap.length > 0 && (
          <GlassPanel>
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><BarChart3 className="h-4 w-4 text-primary" /> Weekly Alert Heatmap</h3>
            <div className="overflow-x-auto">
              <div className="min-w-[700px]">
                <div className="flex ml-12 mb-1">
                  {HOURS.filter((_, i) => i % 3 === 0).map(h => <span key={h} className="text-[9px] text-muted-foreground" style={{ width: `${100 / 8}%` }}>{h}</span>)}
                </div>
                {DAYS.map((day) => (
                  <div key={day} className="flex items-center gap-1 mb-1">
                    <span className="text-[10px] text-muted-foreground w-10 text-right">{day}</span>
                    <div className="flex gap-[2px] flex-1">
                      {Array.from({ length: 24 }, (_, hourIdx) => {
                        const cell = weeklyHeatmap.find(h => h.day === day && h.hour === HOURS[hourIdx]);
                        const val = cell?.value ?? 0;
                        const intensity = val / maxHeatVal;
                        return (
                          <div key={hourIdx} className="flex-1 h-6 rounded-sm transition-colors cursor-default" style={{
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
        )}

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
                  {Array.from({ length: 16 }, (_, i) => <SelectItem key={i} value={String(i)}>Level {i}</SelectItem>)}
                </SelectContent>
              </Select>
              <Select value={groupFilter} onValueChange={(v) => { setGroupFilter(v); setPage(0); }}>
                <SelectTrigger className="w-[160px] h-8 text-xs bg-secondary/50 border-border"><SelectValue placeholder="Group" /></SelectTrigger>
                <SelectContent className="bg-popover border-border max-h-60">
                  <SelectItem value="all">All Groups</SelectItem>
                  {ruleGroups.slice(0, 50).map(g => <SelectItem key={g} value={g}>{g}</SelectItem>)}
                </SelectContent>
              </Select>
              {rulesQ.data ? <RawJsonViewer data={rulesQ.data as Record<string, unknown>} title="Rules JSON" /> : null}
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="border-b border-border/30">
                {["ID", "Level", "Description", "Groups", "MITRE", "File", "GDPR", "PCI DSS"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
              </tr></thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={String(rule.id)} className="border-b border-border/10 data-row">
                    <td className="py-2 px-3 font-mono text-primary">{String(rule.id)}</td>
                    <td className="py-2 px-3"><ThreatBadge level={threatLevelFromNumber(Number(rule.level ?? 0))} /></td>
                    <td className="py-2 px-3 text-foreground max-w-xs truncate">{String(rule.description ?? "—")}</td>
                    <td className="py-2 px-3 text-muted-foreground max-w-[150px] truncate">{Array.isArray(rule.groups) ? (rule.groups as string[]).join(", ") : "—"}</td>
                    <td className="py-2 px-3 text-muted-foreground max-w-[120px] truncate">{Array.isArray(rule.mitre) ? (rule.mitre as Array<Record<string, unknown>>).map(m => String(m.id ?? "")).join(", ") : "—"}</td>
                    <td className="py-2 px-3 font-mono text-muted-foreground text-[10px]">{String(rule.filename ?? "—")}</td>
                    <td className="py-2 px-3 text-muted-foreground text-[10px] max-w-[80px] truncate">{Array.isArray(rule.gdpr) ? (rule.gdpr as string[]).join(", ") : "—"}</td>
                    <td className="py-2 px-3 text-muted-foreground text-[10px] max-w-[80px] truncate">{Array.isArray(rule.pci_dss) ? (rule.pci_dss as string[]).join(", ") : "—"}</td>
                  </tr>
                ))}
                {rules.length === 0 && <tr><td colSpan={8} className="py-12 text-center text-muted-foreground">{rulesQ.isLoading ? "Loading rules..." : "No rules found"}</td></tr>}
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
