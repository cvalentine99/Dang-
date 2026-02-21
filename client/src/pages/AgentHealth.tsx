import { GlassPanel, StatCard, RawJsonViewer } from "@/components/shared";
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
import {
  Activity,
  Search,
  Wifi,
  WifiOff,
  Clock,
  Monitor,
} from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from "recharts";

const STATUS_COLORS: Record<string, string> = {
  active: "#22c55e",
  disconnected: "#ef4444",
  never_connected: "#f59e0b",
  pending: "#8b5cf6",
};

export default function AgentHealth() {
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [page, setPage] = useState(0);
  const utils = trpc.useUtils();

  const summaryQ = trpc.wazuh.agentSummaryStatus.useQuery(undefined, { staleTime: 30_000 });
  const osQ = trpc.wazuh.agentSummaryOs.useQuery(undefined, { staleTime: 60_000 });

  const agentsQ = trpc.wazuh.agents.useQuery(
    {
      limit: 50,
      offset: page * 50,
      status: statusFilter !== "all" ? (statusFilter as "active" | "disconnected" | "never_connected" | "pending") : undefined,
      search: search || undefined,
    },
    { staleTime: 15_000 }
  );

  const handleRefresh = useCallback(() => {
    utils.wazuh.agentSummaryStatus.invalidate();
    utils.wazuh.agentSummaryOs.invalidate();
    utils.wazuh.agents.invalidate();
  }, [utils]);

  const isLoading = summaryQ.isLoading || agentsQ.isLoading;

  // Parse agent summary
  const agentData = (summaryQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const connection = agentData?.connection as Record<string, number> | undefined;
  const activeAgents = connection?.active ?? 0;
  const disconnectedAgents = connection?.disconnected ?? 0;
  const neverConnected = connection?.never_connected ?? 0;
  const totalAgents = activeAgents + disconnectedAgents + neverConnected;

  // Parse OS distribution
  const osData = (osQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const osItems = (osData?.affected_items as Array<Record<string, unknown>>) ?? [];

  const pieData = useMemo(
    () => [
      { name: "Active", value: activeAgents, color: STATUS_COLORS.active },
      { name: "Disconnected", value: disconnectedAgents, color: STATUS_COLORS.disconnected },
      { name: "Never Connected", value: neverConnected, color: STATUS_COLORS.never_connected },
    ].filter((d) => d.value > 0),
    [activeAgents, disconnectedAgents, neverConnected]
  );

  // Parse agents list
  const agentsData = (agentsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const agents = (agentsData?.affected_items as Array<Record<string, unknown>>) ?? [];
  const agentsTotal = (agentsData?.total_affected_items as number) ?? 0;

  return (
    <div>
      <PageHeader
        title="Agent Health"
        subtitle={`${totalAgents} agents registered`}
        onRefresh={handleRefresh}
        isLoading={isLoading}
      />

      <WazuhGuard>
        {/* ── Stat cards ──────────────────────────────────── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
          <StatCard label="Total Agents" value={totalAgents} icon={Monitor} />
          <StatCard label="Active" value={activeAgents} icon={Wifi} colorClass="text-threat-low" />
          <StatCard label="Disconnected" value={disconnectedAgents} icon={WifiOff} colorClass="text-threat-high" />
          <StatCard label="Never Connected" value={neverConnected} icon={Clock} colorClass="text-threat-medium" />
        </div>

        {/* ── Charts row ──────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
          {/* Status distribution */}
          <GlassPanel className="p-5">
            <h3 className="font-display font-semibold text-foreground text-sm mb-4">
              Connection Status
            </h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    dataKey="value"
                    stroke="none"
                  >
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "oklch(0.17 0.025 286)",
                      border: "1px solid oklch(0.3 0.04 286 / 40%)",
                      borderRadius: "8px",
                      color: "oklch(0.93 0.005 286)",
                      fontSize: "12px",
                    }}
                  />
                  <Legend
                    wrapperStyle={{ fontSize: "12px", color: "oklch(0.65 0.02 286)" }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </GlassPanel>

          {/* OS distribution */}
          <GlassPanel className="p-5">
            <h3 className="font-display font-semibold text-foreground text-sm mb-4">
              OS Distribution
            </h3>
            {osItems.length > 0 ? (
              <div className="space-y-3 max-h-64 overflow-y-auto">
                {osItems.map((os, i) => {
                  const osObj = os.os as Record<string, unknown> | undefined;
                  const platform = (osObj?.platform as string) ?? "Unknown";
                  const count = (os.count as number) ?? 0;
                  const pct = totalAgents > 0 ? Math.round((count / totalAgents) * 100) : 0;
                  return (
                    <div key={i} className="flex items-center gap-3">
                      <span className="text-xs text-muted-foreground w-24 truncate">{platform}</span>
                      <div className="flex-1 h-2 bg-secondary rounded-full overflow-hidden">
                        <div
                          className="h-full bg-primary rounded-full transition-all"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="text-xs text-foreground font-mono w-12 text-right">{count}</span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No OS data available</p>
            )}
          </GlassPanel>
        </div>

        {/* ── Agents table ────────────────────────────────── */}
        <GlassPanel className="p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
            <h3 className="font-display font-semibold text-foreground text-sm">
              Agent List
            </h3>
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search agents..."
                  value={search}
                  onChange={(e) => { setSearch(e.target.value); setPage(0); }}
                  className="pl-8 h-8 text-xs w-48 bg-secondary/50 border-border"
                />
              </div>
              <Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v); setPage(0); }}>
                <SelectTrigger className="w-[140px] h-8 text-xs bg-secondary/50 border-border">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-popover border-border">
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="active">Active</SelectItem>
                  <SelectItem value="disconnected">Disconnected</SelectItem>
                  <SelectItem value="never_connected">Never Connected</SelectItem>
                </SelectContent>
              </Select>
              <RawJsonViewer data={agentsQ.data} title="Agents Raw Data" />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-muted-foreground">
                  <th className="text-left py-2 px-3 font-medium">ID</th>
                  <th className="text-left py-2 px-3 font-medium">Name</th>
                  <th className="text-left py-2 px-3 font-medium">IP</th>
                  <th className="text-left py-2 px-3 font-medium">Status</th>
                  <th className="text-left py-2 px-3 font-medium">OS</th>
                  <th className="text-left py-2 px-3 font-medium">Version</th>
                  <th className="text-left py-2 px-3 font-medium">Last Keep Alive</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((agent) => {
                  const status = (agent.status as string) ?? "unknown";
                  return (
                    <tr key={agent.id as string} className="border-b border-border/50 data-row">
                      <td className="py-2 px-3 font-mono text-primary">{agent.id as string}</td>
                      <td className="py-2 px-3 text-foreground">{agent.name as string}</td>
                      <td className="py-2 px-3 font-mono text-muted-foreground">{agent.ip as string}</td>
                      <td className="py-2 px-3">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${
                            status === "active"
                              ? "bg-threat-low text-[oklch(0.765_0.177_163.223)]"
                              : status === "disconnected"
                              ? "bg-threat-critical text-[oklch(0.637_0.237_25.331)]"
                              : "bg-threat-medium text-[oklch(0.795_0.184_86.047)]"
                          }`}
                        >
                          <span
                            className={`h-1.5 w-1.5 rounded-full ${
                              status === "active" ? "bg-[oklch(0.765_0.177_163.223)]" : status === "disconnected" ? "bg-[oklch(0.637_0.237_25.331)]" : "bg-[oklch(0.795_0.184_86.047)]"
                            }`}
                          />
                          {status}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-muted-foreground">
                        {(agent.os as Record<string, unknown>)?.name as string ?? "—"}
                      </td>
                      <td className="py-2 px-3 font-mono text-muted-foreground">{agent.version as string ?? "—"}</td>
                      <td className="py-2 px-3 font-mono text-muted-foreground text-[10px]">
                        {agent.lastKeepAlive as string ?? "—"}
                      </td>
                    </tr>
                  );
                })}
                {agents.length === 0 && (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-muted-foreground">
                      {agentsQ.isLoading ? "Loading agents..." : "No agents found"}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {agentsTotal > 50 && (
            <div className="flex items-center justify-between mt-4 pt-3 border-t border-border">
              <span className="text-xs text-muted-foreground">
                Showing {page * 50 + 1}–{Math.min((page + 1) * 50, agentsTotal)} of {agentsTotal}
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                  className="h-7 text-xs bg-transparent border-border"
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => p + 1)}
                  disabled={(page + 1) * 50 >= agentsTotal}
                  className="h-7 text-xs bg-transparent border-border"
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </GlassPanel>
      </WazuhGuard>
    </div>
  );
}
