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
  Tabs, TabsContent, TabsList, TabsTrigger,
} from "@/components/ui/tabs";
import {
  ShieldCheck, ShieldAlert, CheckCircle2, XCircle, MinusCircle,
  Search, Layers, ChevronLeft, ChevronRight,
} from "lucide-react";
import { useState, useMemo, useCallback } from "react";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip as ReTooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend,
} from "recharts";

const COLORS = {
  purple: "oklch(0.541 0.281 293.009)",
  green: "oklch(0.765 0.177 163.223)",
  red: "oklch(0.637 0.237 25.331)",
  yellow: "oklch(0.795 0.184 86.047)",
  cyan: "oklch(0.789 0.154 211.53)",
  gray: "oklch(0.551 0.02 286)",
};

const FRAMEWORKS = [
  { id: "pci_dss", label: "PCI DSS", icon: "\uD83D\uDCB3" },
  { id: "nist_800_53", label: "NIST 800-53", icon: "\uD83C\uDFDB\uFE0F" },
  { id: "hipaa", label: "HIPAA", icon: "\uD83C\uDFE5" },
  { id: "gdpr", label: "GDPR", icon: "\uD83C\uDDEA\uD83C\uDDFA" },
  { id: "tsc", label: "TSC", icon: "\uD83D\uDCCB" },
];

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass-panel p-3 text-xs border border-glass-border">
      <p className="text-muted-foreground mb-1">{label}</p>
      {payload.map((p, i) => <p key={i} style={{ color: p.color }} className="font-medium">{p.name}: {p.value?.toLocaleString()}</p>)}
    </div>
  );
}

function ScoreGauge({ score, label }: { score: number; label: string }) {
  const circumference = 2 * Math.PI * 40;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 80 ? COLORS.green : score >= 60 ? COLORS.yellow : COLORS.red;
  return (
    <div className="flex flex-col items-center">
      <svg width="100" height="100" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="40" fill="none" stroke="oklch(0.3 0.04 286 / 20%)" strokeWidth="8" />
        <circle cx="50" cy="50" r="40" fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={offset} transform="rotate(-90 50 50)" className="transition-all duration-1000" />
        <text x="50" y="46" textAnchor="middle" fill="oklch(0.93 0.005 286)" fontSize="18" fontWeight="bold">{score}%</text>
        <text x="50" y="62" textAnchor="middle" fill="oklch(0.65 0.02 286)" fontSize="8">SCORE</text>
      </svg>
      <span className="text-xs font-medium text-muted-foreground mt-1 text-center max-w-[100px] truncate">{label}</span>
    </div>
  );
}

export default function Compliance() {
  const utils = trpc.useUtils();
  const [agentId, setAgentId] = useState("001");
  const [activeTab, setActiveTab] = useState("overview");
  const [selectedPolicy, setSelectedPolicy] = useState<string | null>(null);
  const [checkFilter, setCheckFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 50;

  const statusQ = trpc.wazuh.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const enabled = statusQ.data?.configured === true;

  const agentsQ = trpc.wazuh.agents.useQuery({ limit: 100, offset: 0, status: "active" }, { retry: 1, staleTime: 30_000, enabled });
  const agentList = useMemo(() => {
    const d = (agentsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
  }, [agentsQ.data]);

  const scaQ = trpc.wazuh.scaPolicies.useQuery({ agentId }, { retry: 1, staleTime: 30_000, enabled });
  const checksQ = trpc.wazuh.scaChecks.useQuery(
    { agentId, policyId: selectedPolicy ?? "" },
    { retry: 1, staleTime: 30_000, enabled: enabled && !!selectedPolicy }
  );

  const handleRefresh = useCallback(() => { utils.wazuh.invalidate(); }, [utils]);

  const policies = useMemo(() => {
    const d = (scaQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
  }, [scaQ.data]);

  const checks = useMemo(() => {
    const d = (checksQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
  }, [checksQ.data]);

  const { totalPolicies, avgScore, totalPass, totalFail, totalNA } = useMemo(() => {
    let pass = 0, fail = 0, na = 0, scoreSum = 0;
    policies.forEach(p => {
      pass += Number(p.pass ?? 0);
      fail += Number(p.fail ?? 0);
      na += Number(p.not_applicable ?? p.invalid ?? 0);
      scoreSum += Number(p.score ?? 0);
    });
    return { totalPolicies: policies.length, avgScore: policies.length > 0 ? Math.round(scoreSum / policies.length) : 0, totalPass: pass, totalFail: fail, totalNA: na };
  }, [policies]);

  const policyScoreData = useMemo(() => policies.map(p => ({ name: String(p.name ?? "").slice(0, 30), score: Number(p.score ?? 0), pass: Number(p.pass ?? 0), fail: Number(p.fail ?? 0) })), [policies]);

  const resultPie = useMemo(() => [
    { name: "Pass", value: totalPass, color: COLORS.green },
    { name: "Fail", value: totalFail, color: COLORS.red },
    { name: "N/A", value: totalNA, color: COLORS.gray },
  ].filter(d => d.value > 0), [totalPass, totalFail, totalNA]);

  const filteredChecks = useMemo(() => {
    let filtered = checks;
    if (checkFilter !== "all") filtered = filtered.filter(c => String(c.result ?? "").toLowerCase() === checkFilter);
    if (search) { const q = search.toLowerCase(); filtered = filtered.filter(c => String(c.title ?? "").toLowerCase().includes(q) || String(c.description ?? "").toLowerCase().includes(q) || String(c.id ?? "").toLowerCase().includes(q)); }
    return filtered;
  }, [checks, checkFilter, search]);

  const totalChecks = filteredChecks.length;
  const totalPages = Math.ceil(totalChecks / pageSize);
  const pagedChecks = filteredChecks.slice(page * pageSize, (page + 1) * pageSize);
  const isLoading = scaQ.isLoading;

  return (
    <WazuhGuard>
      <div className="space-y-6">
        <PageHeader title="Compliance Posture" subtitle="SCA policy assessment — framework scores, check results, and remediation tracking" onRefresh={handleRefresh} isLoading={isLoading} />

        <GlassPanel className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <div className="flex items-center gap-2"><Layers className="h-4 w-4 text-primary" /><span className="text-sm font-medium text-muted-foreground">Target Agent:</span></div>
          <Select value={agentId} onValueChange={(v) => { setAgentId(v); setSelectedPolicy(null); setPage(0); }}>
            <SelectTrigger className="w-[280px] h-8 text-xs bg-secondary/50 border-border"><SelectValue /></SelectTrigger>
            <SelectContent className="bg-popover border-border max-h-60">
              {agentList.map(a => <SelectItem key={String(a.id)} value={String(a.id)}>{String(a.id)} — {String(a.name ?? "Unknown")} ({String(a.ip ?? "")})</SelectItem>)}
              {agentList.length === 0 ? <SelectItem value="001" disabled>No active agents</SelectItem> : null}
            </SelectContent>
          </Select>
          {scaQ.data ? <RawJsonViewer data={scaQ.data as Record<string, unknown>} title="SCA Policies JSON" /> : null}
        </GlassPanel>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatCard label="Avg Score" value={`${avgScore}%`} icon={ShieldCheck} colorClass={avgScore >= 80 ? "text-threat-low" : avgScore >= 60 ? "text-threat-medium" : "text-threat-critical"} />
          <StatCard label="Policies" value={totalPolicies} icon={Layers} colorClass="text-primary" />
          <StatCard label="Passed" value={totalPass} icon={CheckCircle2} colorClass="text-threat-low" />
          <StatCard label="Failed" value={totalFail} icon={XCircle} colorClass="text-threat-critical" />
          <StatCard label="N/A" value={totalNA} icon={MinusCircle} colorClass="text-muted-foreground" />
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-secondary/30 border border-border/30">
            <TabsTrigger value="overview" className="text-xs data-[state=active]:bg-primary/20 data-[state=active]:text-primary">Overview</TabsTrigger>
            <TabsTrigger value="policies" className="text-xs data-[state=active]:bg-primary/20 data-[state=active]:text-primary">Policies</TabsTrigger>
            <TabsTrigger value="checks" className="text-xs data-[state=active]:bg-primary/20 data-[state=active]:text-primary">Checks</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4 mt-4">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              <GlassPanel className="lg:col-span-5">
                <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-primary" /> Policy Scores</h3>
                <div className="flex flex-wrap justify-center gap-4">
                  {policies.slice(0, 6).map((p, i) => <ScoreGauge key={i} score={Number(p.score ?? 0)} label={String(p.name ?? "").slice(0, 20)} />)}
                  {policies.length === 0 ? <div className="text-sm text-muted-foreground py-8">No SCA policies found</div> : null}
                </div>
              </GlassPanel>

              <GlassPanel className="lg:col-span-3">
                <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-primary" /> Check Results</h3>
                {resultPie.length > 0 ? (
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie data={resultPie} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3} dataKey="value" stroke="none">
                        {resultPie.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                      </Pie>
                      <ReTooltip content={<ChartTooltip />} />
                      <Legend wrapperStyle={{ fontSize: 11, color: "oklch(0.65 0.02 286)" }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : <div className="h-[200px] flex items-center justify-center text-sm text-muted-foreground">No data</div>}
              </GlassPanel>

              <GlassPanel className="lg:col-span-4">
                <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><ShieldAlert className="h-4 w-4 text-primary" /> Score by Policy</h3>
                {policyScoreData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart data={policyScoreData} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
                      <XAxis type="number" domain={[0, 100]} tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
                      <YAxis type="category" dataKey="name" width={120} tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 9 }} />
                      <ReTooltip content={<ChartTooltip />} />
                      <Bar dataKey="score" fill={COLORS.purple} name="Score %" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : <div className="h-[200px] flex items-center justify-center text-sm text-muted-foreground">No policy data</div>}
              </GlassPanel>
            </div>

            <GlassPanel>
              <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Layers className="h-4 w-4 text-primary" /> Regulatory Frameworks</h3>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                {FRAMEWORKS.map(fw => {
                  const matchingPolicy = policies.find(p => String(p.policy_id ?? "").toLowerCase().includes(fw.id.replace(/_/g, "")) || String(p.name ?? "").toLowerCase().includes(fw.id.replace(/_/g, " ")));
                  const score = matchingPolicy ? Number(matchingPolicy.score ?? 0) : null;
                  return (
                    <div key={fw.id} className="bg-secondary/20 rounded-lg p-4 border border-border/20 text-center">
                      <span className="text-2xl">{fw.icon}</span>
                      <p className="text-xs font-medium text-foreground mt-2">{fw.label}</p>
                      {score !== null ? (
                        <p className={`text-lg font-bold mt-1 ${score >= 80 ? "text-threat-low" : score >= 60 ? "text-threat-medium" : "text-threat-critical"}`}>{score}%</p>
                      ) : <p className="text-xs text-muted-foreground mt-1">No policy</p>}
                    </div>
                  );
                })}
              </div>
            </GlassPanel>
          </TabsContent>

          <TabsContent value="policies" className="space-y-4 mt-4">
            <GlassPanel>
              <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Layers className="h-4 w-4 text-primary" /> SCA Policies ({policies.length})</h3>
              <div className="space-y-3">
                {policies.map((p, i) => {
                  const score = Number(p.score ?? 0);
                  const policyId = String(p.policy_id ?? "");
                  return (
                    <div key={i} className={`bg-secondary/20 rounded-lg p-4 border transition-all cursor-pointer ${selectedPolicy === policyId ? "border-primary/50 bg-primary/5" : "border-border/20 hover:border-border/40"}`} onClick={() => { setSelectedPolicy(policyId); setActiveTab("checks"); setPage(0); }}>
                      <div className="flex items-center justify-between">
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-foreground truncate">{String(p.name ?? "")}</p>
                          <p className="text-[10px] font-mono text-muted-foreground mt-0.5">{policyId}</p>
                          {typeof p.description === "string" ? <p className="text-xs text-muted-foreground mt-1 line-clamp-1">{p.description}</p> : null}
                        </div>
                        <div className="flex items-center gap-4 ml-4">
                          <div className="text-center"><p className="text-xs text-muted-foreground">Pass</p><p className="text-sm font-bold text-threat-low">{String(p.pass ?? 0)}</p></div>
                          <div className="text-center"><p className="text-xs text-muted-foreground">Fail</p><p className="text-sm font-bold text-threat-critical">{String(p.fail ?? 0)}</p></div>
                          <div className="text-center"><p className="text-xs text-muted-foreground">Score</p><p className={`text-lg font-bold ${score >= 80 ? "text-threat-low" : score >= 60 ? "text-threat-medium" : "text-threat-critical"}`}>{score}%</p></div>
                        </div>
                      </div>
                      <div className="mt-3 h-1.5 bg-secondary/40 rounded-full overflow-hidden">
                        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${score}%`, backgroundColor: score >= 80 ? COLORS.green : score >= 60 ? COLORS.yellow : COLORS.red }} />
                      </div>
                    </div>
                  );
                })}
                {policies.length === 0 ? <div className="text-center text-sm text-muted-foreground py-8">{isLoading ? "Loading policies..." : "No SCA policies found for this agent"}</div> : null}
              </div>
            </GlassPanel>
          </TabsContent>

          <TabsContent value="checks" className="space-y-4 mt-4">
            <GlassPanel>
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4">
                <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-primary" /> Policy Checks
                  {selectedPolicy ? <span className="font-mono text-primary">({selectedPolicy})</span> : null}
                </h3>
                <div className="flex items-center gap-2 flex-wrap">
                  {!selectedPolicy ? (
                    <Select value={selectedPolicy ?? "none"} onValueChange={(v) => { setSelectedPolicy(v === "none" ? null : v); setPage(0); }}>
                      <SelectTrigger className="w-[200px] h-8 text-xs bg-secondary/50 border-border"><SelectValue placeholder="Select policy..." /></SelectTrigger>
                      <SelectContent className="bg-popover border-border">
                        <SelectItem value="none" disabled>Select policy...</SelectItem>
                        {policies.map((p, i) => <SelectItem key={i} value={String(p.policy_id ?? `policy-${i}`)}>{String(p.name ?? "").slice(0, 40)}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  ) : null}
                  <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                    <Input placeholder="Search checks..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(0); }} className="h-8 w-48 pl-8 text-xs bg-secondary/50 border-border" />
                  </div>
                  <Select value={checkFilter} onValueChange={(v) => { setCheckFilter(v); setPage(0); }}>
                    <SelectTrigger className="w-[110px] h-8 text-xs bg-secondary/50 border-border"><SelectValue /></SelectTrigger>
                    <SelectContent className="bg-popover border-border">
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="passed">Passed</SelectItem>
                      <SelectItem value="failed">Failed</SelectItem>
                      <SelectItem value="not applicable">N/A</SelectItem>
                    </SelectContent>
                  </Select>
                  {checksQ.data ? <RawJsonViewer data={checksQ.data as Record<string, unknown>} title="SCA Checks JSON" /> : null}
                </div>
              </div>

              {!selectedPolicy ? (
                <div className="text-center text-sm text-muted-foreground py-12">Select a policy from the Policies tab to view checks</div>
              ) : (
                <>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead><tr className="border-b border-border/30">
                        {["ID", "Result", "Title", "Rationale", "Remediation", "Compliance"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
                      </tr></thead>
                      <tbody>
                        {pagedChecks.map((c, i) => {
                          const result = String(c.result ?? "").toLowerCase();
                          return (
                            <tr key={i} className="border-b border-border/10 data-row">
                              <td className="py-2 px-3 font-mono text-primary">{String(c.id ?? "")}</td>
                              <td className="py-2 px-3"><ThreatBadge level={result === "passed" ? "low" : result === "failed" ? "critical" : "info"} /></td>
                              <td className="py-2 px-3 text-foreground max-w-[300px]">{String(c.title ?? "\u2014")}</td>
                              <td className="py-2 px-3 text-muted-foreground max-w-[200px] truncate">{String(c.rationale ?? "\u2014")}</td>
                              <td className="py-2 px-3 text-muted-foreground max-w-[200px] truncate">{String(c.remediation ?? "\u2014")}</td>
                              <td className="py-2 px-3 text-muted-foreground max-w-[150px] truncate">
                                {c.compliance ? (c.compliance as Array<Record<string, unknown>>).map((comp, j) => (
                                  <span key={j} className="text-[10px] px-1.5 py-0.5 rounded bg-primary/10 text-primary mr-1">{String(comp.key ?? "")}: {String(comp.value ?? "")}</span>
                                )) : "\u2014"}
                              </td>
                            </tr>
                          );
                        })}
                        {pagedChecks.length === 0 ? <tr><td colSpan={6} className="py-12 text-center text-muted-foreground">{checksQ.isLoading ? "Loading checks..." : "No checks found"}</td></tr> : null}
                      </tbody>
                    </table>
                  </div>
                  {totalPages > 1 ? (
                    <div className="flex items-center justify-between mt-4 pt-4 border-t border-border/30">
                      <p className="text-xs text-muted-foreground">Page {page + 1} of {totalPages} ({totalChecks} checks)</p>
                      <div className="flex items-center gap-2">
                        <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(p => p - 1)} className="h-7 bg-transparent border-border"><ChevronLeft className="h-3.5 w-3.5" /></Button>
                        <Button variant="outline" size="sm" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)} className="h-7 bg-transparent border-border"><ChevronRight className="h-3.5 w-3.5" /></Button>
                      </div>
                    </div>
                  ) : null}
                </>
              )}
            </GlassPanel>
          </TabsContent>
        </Tabs>
      </div>
    </WazuhGuard>
  );
}
