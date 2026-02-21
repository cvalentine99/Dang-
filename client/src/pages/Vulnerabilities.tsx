import { trpc } from "@/lib/trpc";
import { GlassPanel } from "@/components/shared/GlassPanel";
import { StatCard } from "@/components/shared/StatCard";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { ThreatBadge } from "@/components/shared/ThreatBadge";
import { RawJsonViewer } from "@/components/shared/RawJsonViewer";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  Bug, Shield, Search, ChevronLeft, ChevronRight,
  ExternalLink, AlertTriangle, TrendingDown, Layers,
} from "lucide-react";
import { useState, useMemo, useCallback } from "react";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip as ReTooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend,
} from "recharts";

const COLORS = {
  purple: "oklch(0.541 0.281 293.009)",
  cyan: "oklch(0.789 0.154 211.53)",
  green: "oklch(0.765 0.177 163.223)",
  yellow: "oklch(0.795 0.184 86.047)",
  red: "oklch(0.637 0.237 25.331)",
  orange: "oklch(0.705 0.191 22.216)",
};
const SEV_COLORS: Record<string, string> = {
  Critical: COLORS.red, High: COLORS.orange, Medium: COLORS.yellow, Low: COLORS.green, Untriaged: COLORS.cyan,
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

function sevToThreat(sev: string): "critical" | "high" | "medium" | "low" | "info" {
  const s = sev.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "info";
}

export default function Vulnerabilities() {
  const utils = trpc.useUtils();
  const [agentId, setAgentId] = useState("001");
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [selectedVuln, setSelectedVuln] = useState<Record<string, unknown> | null>(null);
  const pageSize = 50;

  const statusQ = trpc.wazuh.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const enabled = statusQ.data?.configured === true;

  const agentsQ = trpc.wazuh.agents.useQuery({ limit: 100, offset: 0, status: "active" }, { retry: 1, staleTime: 30_000, enabled });
  const agentList = useMemo(() => {
    const d = (agentsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
  }, [agentsQ.data]);

  const vulnsQ = trpc.wazuh.agentVulnerabilities.useQuery({
    agentId, limit: pageSize, offset: page * pageSize,
    severity: sevFilter !== "all" ? sevFilter as "critical" | "high" | "medium" | "low" : undefined,
  }, { retry: 1, staleTime: 15_000, enabled });

  const handleRefresh = useCallback(() => { utils.wazuh.invalidate(); }, [utils]);

  const vulns = useMemo(() => {
    const d = (vulnsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
  }, [vulnsQ.data]);

  const totalVulns = useMemo(() => {
    const d = (vulnsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return Number(d?.total_affected_items ?? vulns.length);
  }, [vulnsQ.data, vulns.length]);

  const sevDistribution = useMemo(() => {
    const counts: Record<string, number> = {};
    vulns.forEach(v => { const s = String(v.severity ?? "Untriaged"); counts[s] = (counts[s] ?? 0) + 1; });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [vulns]);

  const topPackages = useMemo(() => {
    const counts: Record<string, number> = {};
    vulns.forEach(v => { const pkg = String(v.name ?? "unknown"); counts[pkg] = (counts[pkg] ?? 0) + 1; });
    return Object.entries(counts).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count).slice(0, 10);
  }, [vulns]);

  const criticalCount = vulns.filter(v => String(v.severity) === "Critical").length;
  const highCount = vulns.filter(v => String(v.severity) === "High").length;
  const mediumCount = vulns.filter(v => String(v.severity) === "Medium").length;

  const filteredVulns = useMemo(() => {
    if (!search) return vulns;
    const q = search.toLowerCase();
    return vulns.filter(v => String(v.cve ?? "").toLowerCase().includes(q) || String(v.name ?? "").toLowerCase().includes(q) || String(v.title ?? "").toLowerCase().includes(q));
  }, [vulns, search]);

  const isLoading = vulnsQ.isLoading;
  const totalPages = Math.ceil(totalVulns / pageSize);

  return (
    <WazuhGuard>
      <div className="space-y-6">
        <PageHeader title="Vulnerability Intelligence" subtitle="CVE analysis — severity scoring, affected packages, and NVD deep-links" onRefresh={handleRefresh} isLoading={isLoading} />

        <GlassPanel className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <div className="flex items-center gap-2"><Layers className="h-4 w-4 text-primary" /><span className="text-sm font-medium text-muted-foreground">Target Agent:</span></div>
          <Select value={agentId} onValueChange={(v) => { setAgentId(v); setPage(0); }}>
            <SelectTrigger className="w-[280px] h-8 text-xs bg-secondary/50 border-border"><SelectValue /></SelectTrigger>
            <SelectContent className="bg-popover border-border max-h-60">
              {agentList.map(a => <SelectItem key={String(a.id)} value={String(a.id)}>{String(a.id)} — {String(a.name ?? "Unknown")} ({String(a.ip ?? "")})</SelectItem>)}
              {agentList.length === 0 && <SelectItem value="001" disabled>No active agents</SelectItem>}
            </SelectContent>
          </Select>
        </GlassPanel>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Total CVEs" value={totalVulns} icon={Bug} colorClass="text-primary" />
          <StatCard label="Critical" value={criticalCount} icon={AlertTriangle} colorClass="text-threat-critical" />
          <StatCard label="High" value={highCount} icon={Shield} colorClass="text-threat-high" />
          <StatCard label="Medium" value={mediumCount} icon={TrendingDown} colorClass="text-threat-medium" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <GlassPanel className="lg:col-span-4">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Shield className="h-4 w-4 text-primary" /> Severity Distribution</h3>
            {sevDistribution.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={sevDistribution} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3} dataKey="value" stroke="none">
                    {sevDistribution.map((entry, i) => <Cell key={i} fill={SEV_COLORS[entry.name] ?? COLORS.purple} />)}
                  </Pie>
                  <ReTooltip content={<ChartTooltip />} />
                  <Legend wrapperStyle={{ fontSize: 11, color: "oklch(0.65 0.02 286)" }} />
                </PieChart>
              </ResponsiveContainer>
            ) : <div className="h-[200px] flex items-center justify-center text-sm text-muted-foreground">No data</div>}
          </GlassPanel>

          <GlassPanel className="lg:col-span-8">
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Bug className="h-4 w-4 text-primary" /> Top Affected Packages</h3>
            {topPackages.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={topPackages}>
                  <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
                  <XAxis dataKey="name" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 9 }} angle={-15} textAnchor="end" height={50} />
                  <YAxis tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
                  <ReTooltip content={<ChartTooltip />} />
                  <Bar dataKey="count" fill={COLORS.orange} name="CVEs" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : <div className="h-[200px] flex items-center justify-center text-sm text-muted-foreground">No package data</div>}
          </GlassPanel>
        </div>

        <GlassPanel>
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4">
            <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2"><Bug className="h-4 w-4 text-primary" /> CVE Database ({totalVulns})</h3>
            <div className="flex items-center gap-2 flex-wrap">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input placeholder="Search CVEs..." value={search} onChange={(e) => setSearch(e.target.value)} className="h-8 w-48 pl-8 text-xs bg-secondary/50 border-border" />
              </div>
              <Select value={sevFilter} onValueChange={(v) => { setSevFilter(v); setPage(0); }}>
                <SelectTrigger className="w-[130px] h-8 text-xs bg-secondary/50 border-border"><SelectValue placeholder="Severity" /></SelectTrigger>
                <SelectContent className="bg-popover border-border">
                  <SelectItem value="all">All Severity</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
              {vulnsQ.data ? <RawJsonViewer data={vulnsQ.data as Record<string, unknown>} title="Vulnerabilities JSON" /> : null}
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="border-b border-border/30">
                {["CVE", "Severity", "CVSS2", "CVSS3", "Package", "Version", "Title", "Status", "NVD"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
              </tr></thead>
              <tbody>
                {filteredVulns.map((v, i) => {
                  const cve = String(v.cve ?? "—");
                  const cvss2 = v.cvss2_score != null ? Number(v.cvss2_score).toFixed(1) : "—";
                  const cvss3 = v.cvss3_score != null ? Number(v.cvss3_score).toFixed(1) : "—";
                  return (
                    <tr key={i} className="border-b border-border/10 data-row cursor-pointer" onClick={() => setSelectedVuln(v)}>
                      <td className="py-2 px-3 font-mono text-primary">{cve}</td>
                      <td className="py-2 px-3"><ThreatBadge level={sevToThreat(String(v.severity ?? ""))} /></td>
                      <td className="py-2 px-3 font-mono text-muted-foreground">{cvss2}</td>
                      <td className="py-2 px-3 font-mono text-muted-foreground">{cvss3}</td>
                      <td className="py-2 px-3 text-foreground font-medium">{String(v.name ?? "—")}</td>
                      <td className="py-2 px-3 font-mono text-muted-foreground">{String(v.version ?? "—")}</td>
                      <td className="py-2 px-3 text-muted-foreground max-w-[250px] truncate">{String(v.title ?? v.description ?? "—")}</td>
                      <td className="py-2 px-3 text-muted-foreground">{String(v.status ?? v.condition ?? "—")}</td>
                      <td className="py-2 px-3">
                        {cve.startsWith("CVE-") && (
                          <a href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()} className="text-primary hover:text-primary/80 transition-colors">
                            <ExternalLink className="h-3.5 w-3.5" />
                          </a>
                        )}
                      </td>
                    </tr>
                  );
                })}
                {filteredVulns.length === 0 && <tr><td colSpan={9} className="py-12 text-center text-muted-foreground">{isLoading ? "Loading CVEs..." : "No vulnerabilities found"}</td></tr>}
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

        <Dialog open={!!selectedVuln} onOpenChange={(open) => !open && setSelectedVuln(null)}>
          <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto bg-card border-border">
            <DialogHeader>
              <DialogTitle className="font-display text-foreground flex items-center gap-2">
                <Bug className="h-5 w-5 text-primary" /> {String(selectedVuln?.cve ?? "CVE Detail")}
              </DialogTitle>
            </DialogHeader>
            {selectedVuln && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3">
                  {([["Severity", selectedVuln.severity], ["CVSS v2", selectedVuln.cvss2_score], ["CVSS v3", selectedVuln.cvss3_score], ["Package", selectedVuln.name], ["Version", selectedVuln.version], ["Architecture", selectedVuln.architecture], ["Status", selectedVuln.status ?? selectedVuln.condition], ["Published", selectedVuln.published], ["Updated", selectedVuln.updated], ["Detection Time", selectedVuln.detection_time]] as [string, unknown][]).map(([label, val]) => (
                    <div key={label} className="bg-secondary/30 rounded-lg p-3 border border-border/30">
                      <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</p>
                      <p className="text-sm font-medium text-foreground mt-1 truncate">{String(val ?? "—")}</p>
                    </div>
                  ))}
                </div>
                {selectedVuln.title ? <div className="bg-secondary/20 rounded-lg p-3 border border-border/20"><p className="text-[10px] text-muted-foreground uppercase tracking-wider">Title</p><p className="text-sm text-foreground mt-1">{String(selectedVuln.title)}</p></div> : null}
                {selectedVuln.external_references ? (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-2">External References</p>
                    <div className="space-y-1">
                      {(selectedVuln.external_references as Array<Record<string, unknown>>).map((ref, i) => (
                        <a key={i} href={String(ref.url ?? "#")} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-xs text-primary hover:text-primary/80 transition-colors">
                          <ExternalLink className="h-3 w-3" /> {String(ref.url ?? ref.source ?? "Link")}
                        </a>
                      ))}
                    </div>
                  </div>
                ) : null}
                <RawJsonViewer data={selectedVuln} title="Full CVE JSON" />
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>
    </WazuhGuard>
  );
}
