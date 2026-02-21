import { GlassPanel, StatCard, ThreatBadge, RawJsonViewer } from "@/components/shared";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { trpc } from "@/lib/trpc";
import { ShieldCheck, AlertTriangle, CheckCircle, XCircle } from "lucide-react";
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

export default function Compliance() {
  const [agentId, setAgentId] = useState("000");
  const [selectedPolicy, setSelectedPolicy] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const utils = trpc.useUtils();

  const policiesQ = trpc.wazuh.scaPolicies.useQuery(
    { agentId },
    { staleTime: 60_000 }
  );

  const checksQ = trpc.wazuh.scaChecks.useQuery(
    { agentId, policyId: selectedPolicy ?? "" },
    { staleTime: 30_000, enabled: !!selectedPolicy }
  );

  const handleRefresh = useCallback(() => {
    utils.wazuh.scaPolicies.invalidate();
    utils.wazuh.scaChecks.invalidate();
  }, [utils]);

  const isLoading = policiesQ.isLoading;

  // Parse policies
  const polData = (policiesQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const policies = (polData?.affected_items as Array<Record<string, unknown>>) ?? [];

  // Parse checks
  const chkData = (checksQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const checks = (chkData?.affected_items as Array<Record<string, unknown>>) ?? [];
  const totalChecks = (chkData?.total_affected_items as number) ?? 0;

  // Aggregate compliance scores
  const complianceChart = useMemo(() => {
    return policies.map((p) => ({
      name: ((p.name as string) ?? "Unknown").slice(0, 30),
      pass: (p.pass as number) ?? 0,
      fail: (p.fail as number) ?? 0,
      score: (p.score as number) ?? 0,
    }));
  }, [policies]);

  const totalPass = complianceChart.reduce((s, c) => s + c.pass, 0);
  const totalFail = complianceChart.reduce((s, c) => s + c.fail, 0);
  const avgScore = complianceChart.length > 0
    ? Math.round(complianceChart.reduce((s, c) => s + c.score, 0) / complianceChart.length)
    : 0;

  return (
    <div>
      <PageHeader
        title="Compliance Posture"
        subtitle={`Agent ${agentId} — SCA policy assessment`}
        onRefresh={handleRefresh}
        isLoading={isLoading}
      >
        <Input
          placeholder="Agent ID"
          value={agentId}
          onChange={(e) => { setAgentId(e.target.value); setSelectedPolicy(null); }}
          className="h-8 text-xs w-24 bg-secondary/50 border-border font-mono"
        />
      </PageHeader>

      <WazuhGuard>
        {/* ── Stat cards ──────────────────────────────────── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
          <StatCard label="Policies" value={policies.length} icon={ShieldCheck} />
          <StatCard label="Avg Score" value={`${avgScore}%`} icon={ShieldCheck} colorClass={avgScore >= 70 ? "text-threat-low" : avgScore >= 40 ? "text-threat-medium" : "text-threat-high"} />
          <StatCard label="Passed Checks" value={totalPass} icon={CheckCircle} colorClass="text-threat-low" />
          <StatCard label="Failed Checks" value={totalFail} icon={XCircle} colorClass="text-threat-high" />
        </div>

        {/* ── Score chart ─────────────────────────────────── */}
        {complianceChart.length > 0 && (
          <GlassPanel className="p-5 mb-6">
            <h3 className="font-display font-semibold text-foreground text-sm mb-4">
              Policy Compliance Scores
            </h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={complianceChart} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 30%)" />
                  <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 10, fill: "oklch(0.65 0.02 286)" }} />
                  <YAxis type="category" dataKey="name" width={180} tick={{ fontSize: 9, fill: "oklch(0.65 0.02 286)" }} />
                  <Tooltip contentStyle={{ background: "oklch(0.17 0.025 286)", border: "1px solid oklch(0.3 0.04 286 / 40%)", borderRadius: "8px", color: "oklch(0.93 0.005 286)", fontSize: "12px" }} />
                  <Bar dataKey="score" fill="oklch(0.541 0.281 293)" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </GlassPanel>
        )}

        {/* ── Policy cards ────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4 mb-6">
          {policies.map((policy, i) => {
            const policyId = (policy.policy_id as string) ?? "";
            const isSelected = selectedPolicy === policyId;
            const score = (policy.score as number) ?? 0;
            return (
              <button
                key={i}
                onClick={() => { setSelectedPolicy(policyId); setPage(0); }}
                className={`glass-card p-4 text-left transition-all ${isSelected ? "ring-1 ring-primary amethyst-glow" : ""}`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <p className="font-display font-semibold text-foreground text-sm truncate">
                      {policy.name as string}
                    </p>
                    <p className="text-[10px] font-mono text-primary mt-0.5">{policyId}</p>
                    {typeof policy.description === 'string' && (
                      <p className="text-[10px] text-muted-foreground mt-1 line-clamp-2">
                        {policy.description}
                      </p>
                    )}
                  </div>
                  <div className="text-right shrink-0">
                    <p className={`text-lg font-display font-bold ${score >= 70 ? "text-[oklch(0.765_0.177_163.223)]" : score >= 40 ? "text-[oklch(0.795_0.184_86.047)]" : "text-[oklch(0.637_0.237_25.331)]"}`}>
                      {score}%
                    </p>
                  </div>
                </div>
                <div className="flex gap-4 mt-3 text-[10px]">
                  <span className="text-muted-foreground">
                    Pass: <span className="text-[oklch(0.765_0.177_163.223)] font-medium">{policy.pass as number ?? 0}</span>
                  </span>
                  <span className="text-muted-foreground">
                    Fail: <span className="text-[oklch(0.637_0.237_25.331)] font-medium">{policy.fail as number ?? 0}</span>
                  </span>
                  <span className="text-muted-foreground">
                    N/A: <span className="text-foreground font-medium">{policy.invalid as number ?? 0}</span>
                  </span>
                </div>
              </button>
            );
          })}
          {policies.length === 0 && (
            <GlassPanel className="p-8 col-span-full text-center">
              <AlertTriangle className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">
                {isLoading ? "Loading policies..." : "No SCA policies found for this agent"}
              </p>
            </GlassPanel>
          )}
        </div>

        {/* ── Policy checks table ─────────────────────────── */}
        {selectedPolicy && (
          <GlassPanel className="p-5">
            <div className="flex items-center justify-between gap-3 mb-4">
              <h3 className="font-display font-semibold text-foreground text-sm">
                Checks for: <span className="text-primary font-mono">{selectedPolicy}</span>
              </h3>
              <RawJsonViewer data={checksQ.data} title="SCA Checks Raw" />
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border text-muted-foreground">
                    <th className="text-left py-2 px-3 font-medium">ID</th>
                    <th className="text-left py-2 px-3 font-medium">Title</th>
                    <th className="text-left py-2 px-3 font-medium">Result</th>
                    <th className="text-left py-2 px-3 font-medium">Rationale</th>
                    <th className="text-left py-2 px-3 font-medium">Remediation</th>
                  </tr>
                </thead>
                <tbody>
                  {checks.map((check, i) => {
                    const result = (check.result as string) ?? "unknown";
                    const level = result === "passed" ? "low" : result === "failed" ? "critical" : "info";
                    return (
                      <tr key={i} className="border-b border-border/50 data-row">
                        <td className="py-2 px-3 font-mono text-primary">{String(check.id ?? "")}</td>
                        <td className="py-2 px-3 text-foreground max-w-xs truncate">{check.title as string}</td>
                        <td className="py-2 px-3">
                          <ThreatBadge level={level as "low" | "critical" | "info"} />
                        </td>
                        <td className="py-2 px-3 text-muted-foreground max-w-xs truncate text-[10px]">
                          {typeof check.rationale === 'string' ? check.rationale : "—"}
                        </td>
                        <td className="py-2 px-3 text-muted-foreground max-w-xs truncate text-[10px]">
                          {typeof check.remediation === 'string' ? check.remediation : "—"}
                        </td>
                      </tr>
                    );
                  })}
                  {checks.length === 0 && (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-muted-foreground">
                        {checksQ.isLoading ? "Loading checks..." : "No checks found"}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </GlassPanel>
        )}
      </WazuhGuard>
    </div>
  );
}
