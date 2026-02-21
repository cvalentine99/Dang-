import { GlassPanel, RawJsonViewer } from "@/components/shared";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { Input } from "@/components/ui/input";
import { trpc } from "@/lib/trpc";
import { Search, Target } from "lucide-react";
import { useCallback, useMemo, useState } from "react";

export default function MitreAttack() {
  const [search, setSearch] = useState("");
  const utils = trpc.useUtils();

  const tacticsQ = trpc.wazuh.mitreTactics.useQuery(undefined, { staleTime: 120_000 });
  const techniquesQ = trpc.wazuh.mitreTechniques.useQuery(
    { limit: 500, search: search || undefined },
    { staleTime: 60_000 }
  );
  const metadataQ = trpc.wazuh.mitreMetadata.useQuery(undefined, { staleTime: 300_000 });
  const groupsQ = trpc.wazuh.mitreGroups.useQuery({ limit: 100 }, { staleTime: 120_000 });

  const handleRefresh = useCallback(() => {
    utils.wazuh.mitreTactics.invalidate();
    utils.wazuh.mitreTechniques.invalidate();
    utils.wazuh.mitreMetadata.invalidate();
    utils.wazuh.mitreGroups.invalidate();
  }, [utils]);

  const isLoading = tacticsQ.isLoading || techniquesQ.isLoading;

  // Parse tactics
  const tacticsData = (tacticsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const tactics = (tacticsData?.affected_items as Array<Record<string, unknown>>) ?? [];

  // Parse techniques
  const techData = (techniquesQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const techniques = (techData?.affected_items as Array<Record<string, unknown>>) ?? [];
  const totalTechniques = (techData?.total_affected_items as number) ?? 0;

  // Parse groups (threat actors)
  const grpData = (groupsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const groups = (grpData?.affected_items as Array<Record<string, unknown>>) ?? [];

  // Group techniques by tactic
  const tacticTechMap = useMemo(() => {
    const map: Record<string, Array<Record<string, unknown>>> = {};
    techniques.forEach((tech) => {
      const phases = (tech.tactics as string[]) ?? [];
      phases.forEach((tactic) => {
        if (!map[tactic]) map[tactic] = [];
        map[tactic].push(tech);
      });
    });
    return map;
  }, [techniques]);

  // Parse metadata
  const metaData = (metadataQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;

  return (
    <div>
      <PageHeader
        title="MITRE ATT&CK"
        subtitle={`${totalTechniques} techniques mapped`}
        onRefresh={handleRefresh}
        isLoading={isLoading}
      >
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            placeholder="Search techniques..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8 h-8 text-xs w-56 bg-secondary/50 border-border"
          />
        </div>
        <RawJsonViewer data={techniquesQ.data} title="MITRE Techniques Raw" />
      </PageHeader>

      <WazuhGuard>
        {/* ── Metadata bar ────────────────────────────────── */}
        {metaData && (
          <GlassPanel className="p-4 mb-6">
            <div className="flex flex-wrap gap-6 text-xs">
              {Object.entries(metaData).map(([key, val]) => (
                <div key={key}>
                  <span className="text-muted-foreground uppercase tracking-wider">{key.replace(/_/g, " ")}</span>
                  <p className="text-foreground font-mono mt-0.5">{String(val ?? '')}</p>
                </div>
              ))}
            </div>
          </GlassPanel>
        )}

        {/* ── Tactic columns (ATT&CK matrix style) ────────── */}
        <div className="overflow-x-auto pb-4">
          <div className="flex gap-3 min-w-max">
            {tactics.map((tactic) => {
              const tacticName = (tactic.name as string) ?? "Unknown";
              const tacticId = (tactic.external_id as string) ?? "";
              const techs = tacticTechMap[tacticName] ?? tacticTechMap[tacticId] ?? [];
              return (
                <div key={tacticId} className="w-56 shrink-0">
                  <div className="glass-panel p-3 mb-2 text-center">
                    <p className="text-xs font-display font-semibold text-primary truncate">
                      {tacticName}
                    </p>
                    <p className="text-[10px] font-mono text-muted-foreground">{tacticId}</p>
                  </div>
                  <div className="space-y-1.5 max-h-[60vh] overflow-y-auto pr-1">
                    {techs.length > 0 ? (
                      techs.slice(0, 30).map((tech, i) => (
                        <div
                          key={i}
                          className="glass-card p-2.5 text-xs group"
                        >
                          <p className="font-medium text-foreground truncate">
                            {tech.name as string}
                          </p>
                          <p className="font-mono text-[10px] text-primary mt-0.5">
                            {tech.external_id as string}
                          </p>
                          {typeof tech.description === 'string' && tech.description && (
                            <p className="text-[10px] text-muted-foreground mt-1 line-clamp-2">
                              {tech.description.slice(0, 120)}
                            </p>
                          )}
                        </div>
                      ))
                    ) : (
                      <div className="text-[10px] text-muted-foreground text-center py-4">
                        No techniques
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
            {tactics.length === 0 && (
              <div className="flex items-center justify-center w-full h-40 text-muted-foreground text-sm">
                {isLoading ? "Loading MITRE data..." : "No MITRE data available"}
              </div>
            )}
          </div>
        </div>

        {/* ── Threat Groups ───────────────────────────────── */}
        {groups.length > 0 && (
          <GlassPanel className="p-5 mt-6">
            <h3 className="font-display font-semibold text-foreground text-sm mb-4 flex items-center gap-2">
              <Target className="h-4 w-4 text-primary" />
              Threat Groups
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
              {groups.slice(0, 18).map((group, i) => (
                <div key={i} className="glass-card p-3 text-xs">
                  <p className="font-medium text-foreground">{group.name as string}</p>
                  <p className="font-mono text-[10px] text-primary mt-0.5">
                    {group.external_id as string}
                  </p>
                    {typeof group.description === 'string' && group.description && (
                    <p className="text-[10px] text-muted-foreground mt-1 line-clamp-2">
                      {group.description.slice(0, 150)}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </GlassPanel>
        )}
      </WazuhGuard>
    </div>
  );
}
