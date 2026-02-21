import { trpc } from "@/lib/trpc";
import { GlassPanel } from "@/components/shared/GlassPanel";
import { StatCard } from "@/components/shared/StatCard";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { RawJsonViewer } from "@/components/shared/RawJsonViewer";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  Crosshair, Shield, Layers, Grid3X3, Target,
} from "lucide-react";
import { useState, useMemo, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as ReTooltip,
  ResponsiveContainer,
} from "recharts";

const COLORS = {
  purple: "oklch(0.541 0.281 293.009)",
};

const MITRE_TACTICS = [
  "initial-access", "execution", "persistence", "privilege-escalation",
  "defense-evasion", "credential-access", "discovery", "lateral-movement",
  "collection", "command-and-control", "exfiltration", "impact",
  "reconnaissance", "resource-development",
];

const TACTIC_LABELS: Record<string, string> = {
  "initial-access": "Initial Access", "execution": "Execution", "persistence": "Persistence",
  "privilege-escalation": "Privilege Escalation", "defense-evasion": "Defense Evasion",
  "credential-access": "Credential Access", "discovery": "Discovery",
  "lateral-movement": "Lateral Movement", "collection": "Collection",
  "command-and-control": "Command & Control", "exfiltration": "Exfiltration",
  "impact": "Impact", "reconnaissance": "Reconnaissance", "resource-development": "Resource Development",
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

interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[];
  ruleIds: string[];
  ruleCount: number;
}

export default function MitreAttack() {
  const utils = trpc.useUtils();
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);

  const statusQ = trpc.wazuh.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const enabled = statusQ.data?.configured === true;

  // Also try the dedicated MITRE endpoints
  const tacticsQ = trpc.wazuh.mitreTactics.useQuery(undefined, { retry: 1, staleTime: 120_000, enabled });
  const techniquesQ = trpc.wazuh.mitreTechniques.useQuery({ limit: 500 }, { retry: 1, staleTime: 60_000, enabled });
  const groupsQ = trpc.wazuh.mitreGroups.useQuery({ limit: 100 }, { retry: 1, staleTime: 120_000, enabled });
  const rulesQ = trpc.wazuh.rules.useQuery({ limit: 500, offset: 0, sort: "-level" }, { retry: 1, staleTime: 60_000, enabled });

  const handleRefresh = useCallback(() => { utils.wazuh.invalidate(); }, [utils]);

  // Parse dedicated MITRE tactics
  const mitreTactics = useMemo(() => {
    const d = (tacticsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
  }, [tacticsQ.data]);

  // Parse dedicated MITRE techniques
  const mitreTechniques = useMemo(() => {
    const d = (techniquesQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
  }, [techniquesQ.data]);

  // Parse threat groups
  const threatGroups = useMemo(() => {
    const d = (groupsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
  }, [groupsQ.data]);

  // Build technique map from rules
  const { techniques, tacticCounts, totalTechniques, totalRulesWithMitre } = useMemo(() => {
    const d = (rulesQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const rules = (d?.affected_items as Array<Record<string, unknown>>) ?? [];

    const techMap = new Map<string, MitreTechnique>();
    const tacticCounts: Record<string, number> = {};
    let rulesWithMitre = 0;

    rules.forEach(rule => {
      const mitre = rule.mitre as Record<string, unknown> | undefined;
      if (!mitre) return;
      const ids = (mitre.id as string[]) ?? [];
      const tactics = (mitre.tactic as string[]) ?? [];
      const techNames = (mitre.technique as string[]) ?? [];
      if (ids.length === 0 && tactics.length === 0) return;
      rulesWithMitre++;
      tactics.forEach(t => { const key = t.toLowerCase().replace(/\s+/g, "-"); tacticCounts[key] = (tacticCounts[key] ?? 0) + 1; });
      ids.forEach((id, idx) => {
        const existing = techMap.get(id);
        const techName = techNames[idx] ?? id;
        if (existing) {
          existing.ruleCount++;
          existing.ruleIds.push(String(rule.id));
          tactics.forEach(t => { const key = t.toLowerCase().replace(/\s+/g, "-"); if (!existing.tactics.includes(key)) existing.tactics.push(key); });
        } else {
          techMap.set(id, { id, name: techName, tactics: tactics.map(t => t.toLowerCase().replace(/\s+/g, "-")), ruleIds: [String(rule.id)], ruleCount: 1 });
        }
      });
    });

    return { techniques: Array.from(techMap.values()), tacticCounts, totalTechniques: techMap.size, totalRulesWithMitre: rulesWithMitre };
  }, [rulesQ.data]);

  const tacticChartData = useMemo(() => {
    return MITRE_TACTICS.filter(t => (tacticCounts[t] ?? 0) > 0).map(t => ({ name: TACTIC_LABELS[t] ?? t, count: tacticCounts[t] ?? 0 })).sort((a, b) => b.count - a.count);
  }, [tacticCounts]);

  const tacticMatrix = useMemo(() => {
    const matrix: Record<string, MitreTechnique[]> = {};
    MITRE_TACTICS.forEach(t => { matrix[t] = []; });
    techniques.forEach(tech => { tech.tactics.forEach(t => { if (matrix[t]) matrix[t].push(tech); }); });
    return matrix;
  }, [techniques]);

  const maxTechPerTactic = useMemo(() => Math.max(...Object.values(tacticMatrix).map(arr => arr.length), 1), [tacticMatrix]);
  const activeTactics = MITRE_TACTICS.filter(t => (tacticMatrix[t]?.length ?? 0) > 0);
  const isLoading = rulesQ.isLoading || tacticsQ.isLoading;

  // Use dedicated MITRE data if available, otherwise fall back to rule-based
  const hasDedicatedMitre = mitreTactics.length > 0;

  return (
    <WazuhGuard>
      <div className="space-y-6">
        <PageHeader title="MITRE ATT&CK" subtitle="Adversary technique mapping — tactic coverage, technique frequency, and rule correlation" onRefresh={handleRefresh} isLoading={isLoading} />

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Techniques Detected" value={hasDedicatedMitre ? mitreTechniques.length : totalTechniques} icon={Crosshair} colorClass="text-primary" />
          <StatCard label="Rules with MITRE" value={totalRulesWithMitre} icon={Shield} colorClass="text-threat-medium" />
          <StatCard label="Tactics Covered" value={hasDedicatedMitre ? mitreTactics.length : activeTactics.length} icon={Grid3X3} colorClass="text-info-cyan" />
          <StatCard label="Threat Groups" value={threatGroups.length} icon={Target} colorClass="text-threat-high" />
        </div>

        {/* Tactic Distribution */}
        <GlassPanel>
          <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Target className="h-4 w-4 text-primary" /> Tactic Distribution</h3>
          {tacticChartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={tacticChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
                <XAxis dataKey="name" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 9 }} angle={-20} textAnchor="end" height={60} />
                <YAxis tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
                <ReTooltip content={<ChartTooltip />} />
                <Bar dataKey="count" fill={COLORS.purple} name="Rules" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="h-[220px] flex items-center justify-center text-sm text-muted-foreground">No MITRE data from rules</div>}
        </GlassPanel>

        {/* Dedicated MITRE Tactic Columns (if available) */}
        {hasDedicatedMitre ? (
          <GlassPanel>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2"><Grid3X3 className="h-4 w-4 text-primary" /> ATT&CK Matrix (Wazuh MITRE DB)</h3>
              {techniquesQ.data ? <RawJsonViewer data={techniquesQ.data as Record<string, unknown>} title="MITRE Techniques JSON" /> : null}
            </div>
            <div className="overflow-x-auto pb-4">
              <div className="flex gap-3 min-w-max">
                {mitreTactics.map((tactic) => {
                  const tacticName = String(tactic.name ?? "Unknown");
                  const tacticId = String(tactic.external_id ?? "");
                  const techs = mitreTechniques.filter(t => {
                    const phases = (t.tactics as string[]) ?? [];
                    return phases.includes(tacticName) || phases.includes(tacticId);
                  });
                  return (
                    <div key={tacticId} className="w-52 shrink-0">
                      <div className="bg-primary/10 border border-primary/20 rounded-t-lg p-2 text-center">
                        <p className="text-[10px] font-medium text-primary uppercase tracking-wider truncate">{tacticName}</p>
                        <p className="text-[9px] font-mono text-muted-foreground">{tacticId} · {techs.length} techniques</p>
                      </div>
                      <div className="space-y-1 pt-1 max-h-[50vh] overflow-y-auto">
                        {techs.slice(0, 30).map((tech, i) => (
                          <div key={i} className="p-1.5 rounded border border-border/20 bg-secondary/20 hover:bg-secondary/40 transition-colors">
                            <span className="text-[9px] font-mono text-primary block">{String(tech.external_id ?? "")}</span>
                            <span className="text-[9px] text-foreground block truncate">{String(tech.name ?? "")}</span>
                          </div>
                        ))}
                        {techs.length === 0 && <div className="text-[10px] text-muted-foreground text-center py-4">No techniques</div>}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </GlassPanel>
        ) : null}

        {/* Rule-based ATT&CK Matrix */}
        {activeTactics.length > 0 ? (
          <GlassPanel>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2"><Grid3X3 className="h-4 w-4 text-primary" /> ATT&CK Matrix (Rule-Based)</h3>
              {rulesQ.data ? <RawJsonViewer data={rulesQ.data as Record<string, unknown>} title="Rules with MITRE JSON" /> : null}
            </div>
            <div className="overflow-x-auto">
              <div className="min-w-[1200px]">
                <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(${activeTactics.length}, minmax(120px, 1fr))` }}>
                  {activeTactics.map(tactic => (
                    <div key={tactic} className="bg-primary/10 border border-primary/20 rounded-t-lg p-2 text-center">
                      <span className="text-[10px] font-medium text-primary uppercase tracking-wider">{TACTIC_LABELS[tactic] ?? tactic}</span>
                      <span className="block text-[9px] text-muted-foreground mt-0.5">{tacticMatrix[tactic]?.length ?? 0} techniques</span>
                    </div>
                  ))}
                </div>
                <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(${activeTactics.length}, minmax(120px, 1fr))` }}>
                  {activeTactics.map(tactic => (
                    <div key={tactic} className="space-y-1 pt-1">
                      {(tacticMatrix[tactic] ?? []).sort((a, b) => b.ruleCount - a.ruleCount).map(tech => {
                        const intensity = Math.min(tech.ruleCount / maxTechPerTactic, 1);
                        return (
                          <button key={tech.id} onClick={() => setSelectedTechnique(tech)} className="w-full text-left p-1.5 rounded border transition-all hover:scale-[1.02]" style={{
                            backgroundColor: `oklch(0.541 ${0.281 * (0.2 + intensity * 0.8)} 293.009 / ${0.1 + intensity * 0.3})`,
                            borderColor: `oklch(0.541 0.281 293.009 / ${0.2 + intensity * 0.4})`,
                          }}>
                            <span className="text-[9px] font-mono text-primary block">{tech.id}</span>
                            <span className="text-[9px] text-foreground block truncate">{tech.name}</span>
                            <span className="text-[8px] text-muted-foreground">{tech.ruleCount} rules</span>
                          </button>
                        );
                      })}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </GlassPanel>
        ) : null}

        {/* Threat Groups */}
        {threatGroups.length > 0 ? (
          <GlassPanel>
            <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Target className="h-4 w-4 text-primary" /> Threat Groups ({threatGroups.length})</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
              {threatGroups.slice(0, 18).map((group, i) => (
                <div key={i} className="bg-secondary/20 rounded-lg p-3 border border-border/20">
                  <p className="text-xs font-medium text-foreground">{String(group.name ?? "")}</p>
                  <p className="text-[10px] font-mono text-primary mt-0.5">{String(group.external_id ?? "")}</p>
                  {typeof group.description === "string" && group.description ? (
                    <p className="text-[10px] text-muted-foreground mt-1 line-clamp-2">{group.description.slice(0, 150)}</p>
                  ) : null}
                </div>
              ))}
            </div>
          </GlassPanel>
        ) : null}

        {/* Technique Detail Dialog */}
        <Dialog open={!!selectedTechnique} onOpenChange={(open) => !open && setSelectedTechnique(null)}>
          <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto bg-card border-border">
            <DialogHeader>
              <DialogTitle className="font-display text-foreground flex items-center gap-2">
                <Crosshair className="h-5 w-5 text-primary" /> {selectedTechnique?.id} — {selectedTechnique?.name}
              </DialogTitle>
            </DialogHeader>
            {selectedTechnique ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-secondary/30 rounded-lg p-3 border border-border/30">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Technique ID</p>
                    <p className="text-sm font-mono text-primary mt-1">{selectedTechnique.id}</p>
                  </div>
                  <div className="bg-secondary/30 rounded-lg p-3 border border-border/30">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Rule Count</p>
                    <p className="text-sm font-medium text-foreground mt-1">{selectedTechnique.ruleCount}</p>
                  </div>
                </div>
                <div className="bg-secondary/20 rounded-lg p-3 border border-border/20">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Tactics</p>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedTechnique.tactics.map(t => (
                      <span key={t} className="text-[10px] px-2 py-0.5 rounded-full bg-primary/15 text-primary border border-primary/20">{TACTIC_LABELS[t] ?? t}</span>
                    ))}
                  </div>
                </div>
                <div className="bg-secondary/20 rounded-lg p-3 border border-border/20">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Associated Rule IDs</p>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedTechnique.ruleIds.slice(0, 30).map(id => (
                      <span key={id} className="text-[10px] px-2 py-0.5 rounded-full bg-secondary/50 text-foreground font-mono border border-border/30">{id}</span>
                    ))}
                    {selectedTechnique.ruleIds.length > 30 ? <span className="text-[10px] text-muted-foreground">+{selectedTechnique.ruleIds.length - 30} more</span> : null}
                  </div>
                </div>
                <a href={`https://attack.mitre.org/techniques/${selectedTechnique.id.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-xs text-primary hover:text-primary/80 transition-colors">
                  <Shield className="h-3.5 w-3.5" /> View on MITRE ATT&CK
                </a>
              </div>
            ) : null}
          </DialogContent>
        </Dialog>
      </div>
    </WazuhGuard>
  );
}
