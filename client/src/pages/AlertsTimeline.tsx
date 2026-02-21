import { GlassPanel, RawJsonViewer, ThreatBadge } from "@/components/shared";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { trpc } from "@/lib/trpc";
import { Search } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const HOURS = Array.from({ length: 24 }, (_, i) => `${i}:00`);

export default function AlertsTimeline() {
  const [levelFilter, setLevelFilter] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [page, setPage] = useState(0);
  const utils = trpc.useUtils();

  const logsQ = trpc.wazuh.managerLogs.useQuery(
    {
      limit: 100,
      offset: page * 100,
      level: levelFilter !== "all" ? (levelFilter as "info" | "error" | "warning" | "debug") : undefined,
      search: searchTerm || undefined,
    },
    { staleTime: 15_000 }
  );

  const logsSummaryQ = trpc.wazuh.managerLogsSummary.useQuery(undefined, { staleTime: 30_000 });
  const statsHourlyQ = trpc.wazuh.statsHourly.useQuery(undefined, { staleTime: 60_000 });
  const statsWeeklyQ = trpc.wazuh.statsWeekly.useQuery(undefined, { staleTime: 60_000 });

  const handleRefresh = useCallback(() => {
    utils.wazuh.managerLogs.invalidate();
    utils.wazuh.managerLogsSummary.invalidate();
    utils.wazuh.statsHourly.invalidate();
    utils.wazuh.statsWeekly.invalidate();
  }, [utils]);

  const isLoading = logsQ.isLoading;

  // Parse logs
  const logsData = (logsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const logs = (logsData?.affected_items as Array<Record<string, unknown>>) ?? [];
  const totalLogs = (logsData?.total_affected_items as number) ?? 0;

  // Parse summary
  const summaryData = (logsSummaryQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const summaryItems = (summaryData?.affected_items as Array<Record<string, unknown>>) ?? [];

  // Build hourly chart data
  const hourlyData = useMemo(() => {
    const raw = (statsHourlyQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = (raw?.affected_items as Array<Record<string, unknown>>) ?? [];
    if (items.length === 0) {
      return HOURS.map((h) => ({ hour: h, events: 0 }));
    }
    return HOURS.map((h, i) => ({
      hour: h,
      events: (items[0]?.averages as number[])?.at(i) ?? 0,
    }));
  }, [statsHourlyQ.data]);

  // Build heatmap data (day × hour)
  const heatmapData = useMemo(() => {
    const raw = (statsWeeklyQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = (raw?.affected_items as Array<Record<string, unknown>>) ?? [];
    const grid: { day: string; hour: string; value: number }[] = [];
    DAYS.forEach((day, di) => {
      HOURS.forEach((hour, hi) => {
        const dayData = items[0] as Record<string, unknown> | undefined;
        const dayArr = dayData?.[day] as Record<string, number[]> | undefined;
        const val = dayArr?.hours?.[hi] ?? 0;
        grid.push({ day, hour, value: val });
      });
    });
    return grid;
  }, [statsWeeklyQ.data]);

  const maxHeatVal = Math.max(1, ...heatmapData.map((d) => d.value));

  return (
    <div>
      <PageHeader
        title="Alerts Timeline"
        subtitle="Manager logs and event analysis"
        onRefresh={handleRefresh}
        isLoading={isLoading}
      />

      <WazuhGuard>
        {/* ── Hourly distribution chart ───────────────────── */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 mb-6">
          <GlassPanel className="p-5">
            <h3 className="font-display font-semibold text-foreground text-sm mb-4">
              Hourly Event Distribution
            </h3>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={hourlyData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 30%)" />
                  <XAxis dataKey="hour" tick={{ fontSize: 10, fill: "oklch(0.65 0.02 286)" }} />
                  <YAxis tick={{ fontSize: 10, fill: "oklch(0.65 0.02 286)" }} />
                  <Tooltip
                    contentStyle={{
                      background: "oklch(0.17 0.025 286)",
                      border: "1px solid oklch(0.3 0.04 286 / 40%)",
                      borderRadius: "8px",
                      color: "oklch(0.93 0.005 286)",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="events" fill="oklch(0.541 0.281 293)" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </GlassPanel>

          {/* ── Heatmap ───────────────────────────────────── */}
          <GlassPanel className="p-5">
            <h3 className="font-display font-semibold text-foreground text-sm mb-4">
              Weekly Heatmap
            </h3>
            <div className="overflow-x-auto">
              <div className="min-w-[600px]">
                <div className="flex gap-0.5">
                  <div className="w-10" />
                  {HOURS.filter((_, i) => i % 3 === 0).map((h) => (
                    <div key={h} className="flex-1 text-[9px] text-muted-foreground text-center">
                      {h}
                    </div>
                  ))}
                </div>
                {DAYS.map((day) => (
                  <div key={day} className="flex gap-0.5 mb-0.5">
                    <div className="w-10 text-[10px] text-muted-foreground flex items-center">
                      {day}
                    </div>
                    {HOURS.map((hour) => {
                      const cell = heatmapData.find(
                        (d) => d.day === day && d.hour === hour
                      );
                      const intensity = cell ? cell.value / maxHeatVal : 0;
                      return (
                        <div
                          key={`${day}-${hour}`}
                          className="flex-1 h-5 rounded-sm transition-colors"
                          style={{
                            background: `oklch(0.541 0.281 293 / ${Math.max(0.05, intensity * 0.8)})`,
                          }}
                          title={`${day} ${hour}: ${cell?.value ?? 0} events`}
                        />
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>
          </GlassPanel>
        </div>

        {/* ── Log summary cards ───────────────────────────── */}
        {summaryItems.length > 0 && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
            {summaryItems.map((item, i) => {
              const daemon = Object.keys(item)[0] ?? "unknown";
              const counts = item[daemon] as Record<string, number> | undefined;
              return (
                <GlassPanel key={i} className="p-3">
                  <p className="text-xs text-muted-foreground font-mono truncate">{daemon}</p>
                  <div className="flex gap-3 mt-1">
                    {counts &&
                      Object.entries(counts).map(([level, count]) => (
                        <span key={level} className="text-xs">
                          <span className="text-muted-foreground">{level}: </span>
                          <span className="text-foreground font-medium">{count}</span>
                        </span>
                      ))}
                  </div>
                </GlassPanel>
              );
            })}
          </div>
        )}

        {/* ── Logs table ──────────────────────────────────── */}
        <GlassPanel className="p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
            <h3 className="font-display font-semibold text-foreground text-sm">
              Manager Logs
            </h3>
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search logs..."
                  value={searchTerm}
                  onChange={(e) => { setSearchTerm(e.target.value); setPage(0); }}
                  className="pl-8 h-8 text-xs w-48 bg-secondary/50 border-border"
                />
              </div>
              <Select value={levelFilter} onValueChange={(v) => { setLevelFilter(v); setPage(0); }}>
                <SelectTrigger className="w-[120px] h-8 text-xs bg-secondary/50 border-border">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-popover border-border">
                  <SelectItem value="all">All Levels</SelectItem>
                  <SelectItem value="error">Error</SelectItem>
                  <SelectItem value="warning">Warning</SelectItem>
                  <SelectItem value="info">Info</SelectItem>
                  <SelectItem value="debug">Debug</SelectItem>
                </SelectContent>
              </Select>
              <RawJsonViewer data={logsQ.data} title="Logs Raw Data" />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-muted-foreground">
                  <th className="text-left py-2 px-3 font-medium w-44">Timestamp</th>
                  <th className="text-left py-2 px-3 font-medium w-20">Level</th>
                  <th className="text-left py-2 px-3 font-medium w-32">Tag</th>
                  <th className="text-left py-2 px-3 font-medium">Description</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log, i) => {
                  const level = (log.level as string) ?? "info";
                  const threatLevel = level === "error" ? "critical" : level === "warning" ? "medium" : "info";
                  return (
                    <tr key={i} className="border-b border-border/50 data-row">
                      <td className="py-2 px-3 font-mono text-muted-foreground text-[10px]">
                        {log.timestamp as string}
                      </td>
                      <td className="py-2 px-3">
                        <ThreatBadge level={threatLevel as "critical" | "medium" | "info"} />
                      </td>
                      <td className="py-2 px-3 font-mono text-primary text-[10px]">
                        {log.tag as string}
                      </td>
                      <td className="py-2 px-3 text-foreground truncate max-w-md">
                        {log.description as string}
                      </td>
                    </tr>
                  );
                })}
                {logs.length === 0 && (
                  <tr>
                    <td colSpan={4} className="py-8 text-center text-muted-foreground">
                      {isLoading ? "Loading logs..." : "No logs found"}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {totalLogs > 100 && (
            <div className="flex items-center justify-between mt-4 pt-3 border-t border-border">
              <span className="text-xs text-muted-foreground">
                Showing {page * 100 + 1}–{Math.min((page + 1) * 100, totalLogs)} of {totalLogs}
              </span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0} className="h-7 text-xs bg-transparent border-border">Previous</Button>
                <Button variant="outline" size="sm" onClick={() => setPage((p) => p + 1)} disabled={(page + 1) * 100 >= totalLogs} className="h-7 text-xs bg-transparent border-border">Next</Button>
              </div>
            </div>
          )}
        </GlassPanel>
      </WazuhGuard>
    </div>
  );
}
