import { trpc } from "@/lib/trpc";
import { GlassPanel } from "@/components/shared/GlassPanel";
import { StatCard } from "@/components/shared/StatCard";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { RawJsonViewer } from "@/components/shared/RawJsonViewer";
import { MOCK_MITRE_TACTICS, MOCK_MITRE_TECHNIQUES, MOCK_MITRE_GROUPS, MOCK_RULES } from "@/lib/mockData";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  Crosshair, Shield, Layers, Grid3X3, Target, ExternalLink,
} from "lucide-react";
import { useState, useMemo, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as ReTooltip,
  ResponsiveContainer,
} from "recharts";

const COLORS = {
  purple: "oklch(0.541 0.281 293.009)",
  cyan: "oklch(0.789 0.154 211.53)",
  red: "oklch(0.637 0.237 25.331)",
  orange: "oklch(0.705 0.191 22.216)",
  green: "oklch(0.765 0.177 163.223)",
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
  description?: string;
  ruleIds: string[];
  ruleCount: number;
}

function extractItems(raw: unknown): Array<Record<string, unknown>> {
  const d = (raw as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
}

export default function MitreAttack() {
  const utils = trpc.useUtils();
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);

  const statusQ = trpc.wazuh.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const isConnected = statusQ.data?.configured === true && statusQ.data?.data != null;

  const tacticsQ = trpc.wazuh.mitreTactics.useQuery(undefined, { retry: 1, staleTime: 120_000, enabled: isConnected });
  const techniquesQ = trpc.wazuh.mitreTechniques.useQuery({ limit: 500 }, { retry: 1, staleTime: 60_000, enabled: isConnected });
  const groupsQ = trpc.wazuh.mitreGroups.useQuery({ limit: 100 }, { retry: 1, staleTime: 120_000, enabled: isConnected });
  const rulesQ = trpc.wazuh.rules.useQuery({ limit: 500, offset: 0, sort: "-level" }, { retry: 1, staleTime: 60_000, enabled: isConnected });

  const handleRefresh = useCallback(() => { utils.wazuh.invalidate(); }, [utils]);

  // ── Tactics (real or fallback) ────────────────────────────────────────
  const mitreTactics = useMemo(() => {
    if (isConnected && tacticsQ.data) return extractItems(tacticsQ.data);
    return MOCK_MITRE_TACTICS.data.affected_items as unknown as Array<Record<string, unknown>>;
  }, [tacticsQ.data, isConnected]);

  // ── Techniques (real or fallback) ─────────────────────────────────────
  const mitreTechniques = useMemo(() => {
    if (isConnected && techniquesQ.data) return extractItems(techniquesQ.data);
    return MOCK_MITRE_TECHNIQUES.data.affected_items as unknown as Array<Record<string, unknown>>;
  }, [techniquesQ.data, isConnected]);

  // ── Threat Groups (real or fallback) ──────────────────────────────────
  const threatGroups = useMemo(() => {
    if (isConnected && groupsQ.data) return extractItems(groupsQ.data);
    return MOCK_MITRE_GROUPS.data.affected_items as unknown as Array<Record<string, unknown>>;
  }, [groupsQ.data, isConnected]);

  // ── Build technique map from rules (real or fallback) ─────────────────
  const { techniques, tacticCounts, totalTechniques, totalRulesWithMitre } = useMemo(() => {
    let rules: Array<Record<string, unknown>>;
    if (isConnected && rulesQ.data) {
      rules = extractItems(rulesQ.data);
    } else {
      rules = MOCK_RULES.data.affected_items as unknown as Array<Record<string, unknown>>;
    }

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
  }, [rulesQ.data, isConnected]);

  // ── Also build tactic counts from dedicated MITRE techniques ──────────
  const dedicatedTacticCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    mitreTechniques.forEach(t => {
      const tactics = (t.tactics as string[]) ?? [];
      tactics.forEach(tac => {
        const key = tac.toLowerCase().replace(/\s+/g, "-");
        counts[key] = (counts[key] ?? 0) + 1;
      });
    });
    return counts;
  }, [mitreTechniques]);

  const tacticChartData = useMemo(() => {
    // Merge both rule-based and dedicated counts
    const merged: Record<string, number> = { ...tacticCounts };
    Object.entries(dedicatedTacticCounts).forEach(([k, v]) => { merged[k] = Math.max(merged[k] ?? 0, v); });
    return MITRE_TACTICS.filter(t => (merged[t] ?? 0) > 0).map(t => ({ name: TACTIC_LABELS[t] ?? t, count: merged[t] ?? 0 })).sort((a, b) => b.count - a.count);
  }, [tacticCounts, dedicatedTacticCounts]);

  const tacticMatrix = useMemo(() => {
    const matrix: Record<string, MitreTechnique[]> = {};
    MITRE_TACTICS.forEach(t => { matrix[t] = []; });
    // Use dedicated techniques to build matrix
    mitreTechniques.forEach(tech => {
      const tactics = (tech.tactics as string[]) ?? [];
      const techId = String(tech.external_id ?? "");
      const techName = String(tech.name ?? "");
      const techDesc = String(tech.description ?? "");
      tactics.forEach(tac => {
        const key = tac.toLowerCase().replace(/\s+/g, "-");
        if (matrix[key]) {
          matrix[key].push({ id: techId, name: techName, description: techDesc, tactics: [key], ruleIds: [], ruleCount: 1 });
        }
      });
    });
    // Also add rule-based techniques
    techniques.forEach(tech => {
      tech.tactics.forEach(t => {
        if (matrix[t] && !matrix[t].find(m => m.id === tech.id)) {
          matrix[t].push(tech);
        }
      });
    });
    return matrix;
  }, [mitreTechniques, techniques]);

  const activeTactics = MITRE_TACTICS.filter(t => (tacticMatrix[t]?.length ?? 0) > 0);
  const maxTechPerTactic = useMemo(() => Math.max(...Object.values(tacticMatrix).map(arr => arr.length), 1), [tacticMatrix]);
  const isLoading = statusQ.isLoading;

  return (
    <WazuhGuard>
      <div className="space-y-6">
        <PageHeader title="MITRE ATT&CK" subtitle="Adversary technique mapping — tactic coverage, technique frequency, and rule correlation" onRefresh={handleRefresh} isLoading={isLoading} />

        {/* KPIs */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatCard label="Techniques Detected" value={mitreTechniques.length || totalTechniques} icon={Crosshair} colorClass="text-primary" />
          <StatCard label="Rules with MITRE" value={totalRulesWithMitre} icon={Shield} colorClass="text-threat-medium" />
          <StatCard label="Tactics Covered" value={activeTactics.length} icon={Grid3X3} colorClass="text-info-cyan" />
          <StatCard label="Threat Groups" value={threatGroups.length} icon={Target} colorClass="text-threat-high" />
          <StatCard label="Coverage" value={`${Math.round((activeTactics.length / 14) * 100)}%`} icon={Layers} colorClass="text-primary" />
        </div>

        {/* Tactic Distribution Bar Chart */}
        <GlassPanel>
          <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Target className="h-4 w-4 text-primary" /> Tactic Distribution</h3>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={tacticChartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
              <XAxis dataKey="name" tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 9 }} angle={-20} textAnchor="end" height={65} />
              <YAxis tick={{ fill: "oklch(0.65 0.02 286)", fontSize: 10 }} />
              <ReTooltip content={<ChartTooltip />} />
              <Bar dataKey="count" fill={COLORS.purple} name="Techniques" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </GlassPanel>

        {/* Full ATT&CK Matrix */}
        <GlassPanel>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2"><Grid3X3 className="h-4 w-4 text-primary" /> ATT&CK Technique Matrix</h3>
            <span className="text-[10px] text-muted-foreground">{activeTactics.length} active tactics · {mitreTechniques.length || totalTechniques} techniques</span>
          </div>
          <div className="overflow-x-auto pb-4">
            <div className="flex gap-2 min-w-max">
              {activeTactics.map(tactic => {
                const techs = tacticMatrix[tactic] ?? [];
                return (
                  <div key={tactic} className="w-48 shrink-0">
                    <div className="bg-primary/10 border border-primary/20 rounded-t-lg p-2 text-center">
                      <p className="text-[10px] font-medium text-primary uppercase tracking-wider truncate">{TACTIC_LABELS[tactic] ?? tactic}</p>
                      <p className="text-[9px] font-mono text-muted-foreground">{techs.length} techniques</p>
                    </div>
                    <div className="space-y-1 pt-1 max-h-[50vh] overflow-y-auto">
                      {techs.sort((a, b) => b.ruleCount - a.ruleCount).map((tech, i) => {
                        const intensity = Math.min(tech.ruleCount / maxTechPerTactic, 1);
                        return (
                          <button key={`${tech.id}-${i}`} onClick={() => setSelectedTechnique(tech)} className="w-full text-left p-1.5 rounded border transition-all hover:scale-[1.02]" style={{
                            backgroundColor: `oklch(0.541 ${0.281 * (0.2 + intensity * 0.8)} 293.009 / ${0.1 + intensity * 0.3})`,
                            borderColor: `oklch(0.541 0.281 293.009 / ${0.2 + intensity * 0.4})`,
                          }}>
                            <span className="text-[9px] font-mono text-primary block">{tech.id}</span>
                            <span className="text-[9px] text-foreground block truncate">{tech.name}</span>
                            {tech.ruleCount > 0 && <span className="text-[8px] text-muted-foreground">{tech.ruleCount} rules</span>}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </GlassPanel>

        {/* Threat Groups */}
        <GlassPanel>
          <h3 className="text-sm font-medium text-muted-foreground mb-4 flex items-center gap-2"><Target className="h-4 w-4 text-primary" /> Threat Groups ({threatGroups.length})</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
            {threatGroups.map((group, i) => (
              <div key={i} className="bg-secondary/20 rounded-lg p-3 border border-border/20 hover:bg-secondary/30 transition-colors">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-medium text-foreground">{String(group.name ?? "")}</p>
                  <a href={`https://attack.mitre.org/groups/${String(group.external_id ?? "")}/`} target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary/80">
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
                <p className="text-[10px] font-mono text-primary mt-0.5">{String(group.external_id ?? "")}</p>
                {typeof group.description === "string" && group.description ? (
                  <p className="text-[10px] text-muted-foreground mt-1 line-clamp-2">{group.description.slice(0, 150)}</p>
                ) : null}
              </div>
            ))}
          </div>
        </GlassPanel>

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
                {selectedTechnique.description ? (
                  <div className="bg-secondary/20 rounded-lg p-3 border border-border/20">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Description</p>
                    <p className="text-xs text-foreground">{selectedTechnique.description}</p>
                  </div>
                ) : null}
                <div className="bg-secondary/20 rounded-lg p-3 border border-border/20">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Tactics</p>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedTechnique.tactics.map(t => (
                      <span key={t} className="text-[10px] px-2 py-0.5 rounded-full bg-primary/15 text-primary border border-primary/20">{TACTIC_LABELS[t] ?? t}</span>
                    ))}
                  </div>
                </div>
                {selectedTechnique.ruleIds.length > 0 ? (
                  <div className="bg-secondary/20 rounded-lg p-3 border border-border/20">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Associated Rule IDs</p>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedTechnique.ruleIds.slice(0, 30).map(id => (
                        <span key={id} className="text-[10px] px-2 py-0.5 rounded-full bg-secondary/50 text-foreground font-mono border border-border/30">{id}</span>
                      ))}
                      {selectedTechnique.ruleIds.length > 30 ? <span className="text-[10px] text-muted-foreground">+{selectedTechnique.ruleIds.length - 30} more</span> : null}
                    </div>
                  </div>
                ) : null}
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
