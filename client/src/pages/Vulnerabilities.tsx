import { GlassPanel, StatCard, ThreatBadge, RawJsonViewer } from "@/components/shared";
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
import { Bug, Search, Shield, AlertTriangle } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#22c55e",
  None: "#6b7280",
};

export default function Vulnerabilities() {
  const [agentId, setAgentId] = useState("000");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const utils = trpc.useUtils();

  const vulnsQ = trpc.wazuh.agentVulnerabilities.useQuery(
    {
      agentId,
      limit: 50,
      offset: page * 50,
      severity: severityFilter !== "all" ? (severityFilter as "critical" | "high" | "medium" | "low") : undefined,
    },
    { staleTime: 30_000 }
  );

  const handleRefresh = useCallback(() => {
    utils.wazuh.agentVulnerabilities.invalidate();
  }, [utils]);

  const isLoading = vulnsQ.isLoading;

  // Parse vulnerabilities
  const vulnData = (vulnsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const vulns = (vulnData?.affected_items as Array<Record<string, unknown>>) ?? [];
  const totalVulns = (vulnData?.total_affected_items as number) ?? 0;

  // Severity distribution
  const severityDist = useMemo(() => {
    const counts: Record<string, number> = {};
    vulns.forEach((v) => {
      const sev = (v.severity as string) ?? "None";
      counts[sev] = (counts[sev] ?? 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({
      name,
      value,
      color: SEVERITY_COLORS[name] ?? "#6b7280",
    }));
  }, [vulns]);

  // Status distribution
  const statusDist = useMemo(() => {
    const counts: Record<string, number> = {};
    vulns.forEach((v) => {
      const status = (v.status as string) ?? "Unknown";
      counts[status] = (counts[status] ?? 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [vulns]);

  const criticalCount = severityDist.find((s) => s.name === "Critical")?.value ?? 0;
  const highCount = severityDist.find((s) => s.name === "High")?.value ?? 0;

  return (
    <div>
      <PageHeader
        title="Vulnerabilities"
        subtitle={`Agent ${agentId} — ${totalVulns} CVEs found`}
        onRefresh={handleRefresh}
        isLoading={isLoading}
      >
        <Input
          placeholder="Agent ID"
          value={agentId}
          onChange={(e) => { setAgentId(e.target.value); setPage(0); }}
          className="h-8 text-xs w-24 bg-secondary/50 border-border font-mono"
        />
      </PageHeader>

      <WazuhGuard>
        {/* ── Stat cards ──────────────────────────────────── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
          <StatCard label="Total CVEs" value={totalVulns} icon={Bug} />
          <StatCard label="Critical" value={criticalCount} icon={AlertTriangle} colorClass="text-threat-critical" />
          <StatCard label="High" value={highCount} icon={Shield} colorClass="text-threat-high" />
          <StatCard label="Unique Severities" value={severityDist.length} icon={Shield} colorClass="text-primary" />
        </div>

        {/* ── Charts ──────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
          <GlassPanel className="p-5">
            <h3 className="font-display font-semibold text-foreground text-sm mb-4">
              Severity Distribution
            </h3>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={severityDist} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" stroke="none">
                    {severityDist.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "oklch(0.17 0.025 286)", border: "1px solid oklch(0.3 0.04 286 / 40%)", borderRadius: "8px", color: "oklch(0.93 0.005 286)", fontSize: "12px" }} />
                  <Legend wrapperStyle={{ fontSize: "11px", color: "oklch(0.65 0.02 286)" }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </GlassPanel>

          <GlassPanel className="p-5">
            <h3 className="font-display font-semibold text-foreground text-sm mb-4">
              Status Breakdown
            </h3>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={statusDist}>
                  <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 30%)" />
                  <XAxis dataKey="name" tick={{ fontSize: 10, fill: "oklch(0.65 0.02 286)" }} />
                  <YAxis tick={{ fontSize: 10, fill: "oklch(0.65 0.02 286)" }} />
                  <Tooltip contentStyle={{ background: "oklch(0.17 0.025 286)", border: "1px solid oklch(0.3 0.04 286 / 40%)", borderRadius: "8px", color: "oklch(0.93 0.005 286)", fontSize: "12px" }} />
                  <Bar dataKey="value" fill="oklch(0.541 0.281 293)" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </GlassPanel>
        </div>

        {/* ── CVE table ───────────────────────────────────── */}
        <GlassPanel className="p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
            <h3 className="font-display font-semibold text-foreground text-sm">CVE Details</h3>
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input placeholder="Search CVEs..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(0); }} className="pl-8 h-8 text-xs w-48 bg-secondary/50 border-border" />
              </div>
              <Select value={severityFilter} onValueChange={(v) => { setSeverityFilter(v); setPage(0); }}>
                <SelectTrigger className="w-[120px] h-8 text-xs bg-secondary/50 border-border"><SelectValue /></SelectTrigger>
                <SelectContent className="bg-popover border-border">
                  <SelectItem value="all">All Severity</SelectItem>
                  <SelectItem value="Critical">Critical</SelectItem>
                  <SelectItem value="High">High</SelectItem>
                  <SelectItem value="Medium">Medium</SelectItem>
                  <SelectItem value="Low">Low</SelectItem>
                </SelectContent>
              </Select>
              <RawJsonViewer data={vulnsQ.data} title="Vulnerabilities Raw" />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-muted-foreground">
                  <th className="text-left py-2 px-3 font-medium">CVE</th>
                  <th className="text-left py-2 px-3 font-medium">Severity</th>
                  <th className="text-left py-2 px-3 font-medium">Package</th>
                  <th className="text-left py-2 px-3 font-medium">Version</th>
                  <th className="text-left py-2 px-3 font-medium">Status</th>
                  <th className="text-left py-2 px-3 font-medium">CVSS</th>
                  <th className="text-left py-2 px-3 font-medium">Title</th>
                </tr>
              </thead>
              <tbody>
                {vulns.map((vuln, i) => {
                  const sev = ((vuln.severity as string) ?? "info").toLowerCase() as "critical" | "high" | "medium" | "low" | "info";
                  return (
                    <tr key={i} className="border-b border-border/50 data-row">
                      <td className="py-2 px-3 font-mono text-primary">{vuln.cve as string}</td>
                      <td className="py-2 px-3"><ThreatBadge level={sev} /></td>
                      <td className="py-2 px-3 font-mono text-foreground">{vuln.name as string ?? "—"}</td>
                      <td className="py-2 px-3 font-mono text-muted-foreground">{vuln.version as string ?? "—"}</td>
                      <td className="py-2 px-3 text-muted-foreground">{vuln.status as string ?? "—"}</td>
                      <td className="py-2 px-3 font-mono text-foreground">
                        {typeof vuln.cvss2_score === "number" ? (vuln.cvss2_score as number).toFixed(1) : typeof vuln.cvss3_score === "number" ? (vuln.cvss3_score as number).toFixed(1) : "—"}
                      </td>
                      <td className="py-2 px-3 text-muted-foreground truncate max-w-xs">{vuln.title as string ?? "—"}</td>
                    </tr>
                  );
                })}
                {vulns.length === 0 && (
                  <tr><td colSpan={7} className="py-8 text-center text-muted-foreground">{isLoading ? "Loading..." : "No vulnerabilities found"}</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {totalVulns > 50 && (
            <div className="flex items-center justify-between mt-4 pt-3 border-t border-border">
              <span className="text-xs text-muted-foreground">Showing {page * 50 + 1}–{Math.min((page + 1) * 50, totalVulns)} of {totalVulns}</span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0} className="h-7 text-xs bg-transparent border-border">Previous</Button>
                <Button variant="outline" size="sm" onClick={() => setPage((p) => p + 1)} disabled={(page + 1) * 50 >= totalVulns} className="h-7 text-xs bg-transparent border-border">Next</Button>
              </div>
            </div>
          )}
        </GlassPanel>
      </WazuhGuard>
    </div>
  );
}
