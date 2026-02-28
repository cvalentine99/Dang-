/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * Triage Pipeline Dashboard
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * Displays triage pipeline results, stats, and allows running triage on alerts.
 * This is the analyst-facing view of the agentic SOC pipeline Step 1.
 * ═══════════════════════════════════════════════════════════════════════════════
 */

import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { GlassPanel, StatCard, RawJsonViewer, ThreatBadge } from "@/components/shared";
import { PageHeader } from "@/components/shared/PageHeader";
import { useLocation } from "wouter";
import {
  Brain,
  ChevronDown,
  ChevronRight,
  Clock,
  AlertTriangle,
  Shield,
  Target,
  Zap,
  FileSearch,
  ArrowRight,
  RefreshCw,
  Loader2,
  CheckCircle2,
  XCircle,
  Info,
  Network,
  User,
  Globe,
  Hash,
  Cpu,
  FileText,
} from "lucide-react";

// ── Severity & Route Colors ──────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/15 border-red-500/30",
  high: "text-orange-400 bg-orange-500/15 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/15 border-yellow-500/30",
  low: "text-blue-400 bg-blue-500/15 border-blue-500/30",
  info: "text-slate-400 bg-slate-500/15 border-slate-500/30",
};

const ROUTE_LABELS: Record<string, { label: string; color: string; description: string }> = {
  A_DUPLICATE_NOISY: { label: "Duplicate/Noisy", color: "text-slate-400 bg-slate-500/10", description: "Suppression candidate" },
  B_LOW_CONFIDENCE: { label: "Low Confidence", color: "text-yellow-400 bg-yellow-500/10", description: "Needs enrichment" },
  C_HIGH_CONFIDENCE: { label: "High Confidence", color: "text-red-400 bg-red-500/10", description: "Proceed to correlation" },
  D_LIKELY_BENIGN: { label: "Likely Benign", color: "text-green-400 bg-green-500/10", description: "Closure candidate" },
};

const ENTITY_ICONS: Record<string, typeof Globe> = {
  host: Cpu,
  user: User,
  ip: Globe,
  domain: Globe,
  hash: Hash,
  process: Cpu,
  file_path: FileText,
  rule_id: Shield,
  mitre_technique: Target,
  cve: AlertTriangle,
  port: Network,
  registry_key: FileSearch,
};

// ── Triage Stats Panel ───────────────────────────────────────────────────────

function TriageStatsPanel() {
  const { data: stats, isLoading } = trpc.pipeline.triageStats.useQuery();

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <GlassPanel key={i} className="p-4 animate-pulse h-20">&nbsp;</GlassPanel>
        ))}
      </div>
    );
  }

  if (!stats) return null;

  const severityOrder = ["critical", "high", "medium", "low", "info"];

  return (
    <div className="space-y-4">
      {/* Total + Status */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <GlassPanel className="p-4">
          <div className="text-xs text-muted-foreground/70 uppercase tracking-wider mb-1">Total Triages</div>
          <div className="text-2xl font-bold font-[Space_Grotesk]">{stats.total}</div>
        </GlassPanel>
        {["completed", "processing", "pending", "failed"].map(status => (
          <GlassPanel key={status} className="p-4">
            <div className="text-xs text-muted-foreground/70 uppercase tracking-wider mb-1 flex items-center gap-1.5">
              {status === "completed" && <CheckCircle2 className="w-3 h-3 text-green-400" />}
              {status === "processing" && <Loader2 className="w-3 h-3 text-blue-400 animate-spin" />}
              {status === "pending" && <Clock className="w-3 h-3 text-yellow-400" />}
              {status === "failed" && <XCircle className="w-3 h-3 text-red-400" />}
              {status}
            </div>
            <div className="text-xl font-bold font-[Space_Grotesk]">
              {(stats.byStatus as Record<string, number>)[status] ?? 0}
            </div>
          </GlassPanel>
        ))}
      </div>

      {/* Severity Distribution */}
      <div className="grid grid-cols-5 gap-3">
        {severityOrder.map(sev => (
          <GlassPanel key={sev} className="p-3">
            <div className={`text-xs uppercase tracking-wider mb-1 ${SEVERITY_COLORS[sev]?.split(" ")[0]}`}>
              {sev}
            </div>
            <div className="text-lg font-bold font-[Space_Grotesk]">
              {(stats.bySeverity as Record<string, number>)[sev] ?? 0}
            </div>
          </GlassPanel>
        ))}
      </div>

      {/* Route Distribution */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {Object.entries(ROUTE_LABELS).map(([route, info]) => (
          <GlassPanel key={route} className="p-3">
            <div className={`text-xs uppercase tracking-wider mb-1 ${info.color.split(" ")[0]}`}>
              {info.label}
            </div>
            <div className="text-lg font-bold font-[Space_Grotesk]">
              {(stats.byRoute as Record<string, number>)[route] ?? 0}
            </div>
            <div className="text-[10px] text-muted-foreground/50">{info.description}</div>
          </GlassPanel>
        ))}
      </div>
    </div>
  );
}

// ── Triage Result Card ───────────────────────────────────────────────────────

function TriageResultCard({ triage }: { triage: any }) {
  const [expanded, setExpanded] = useState(false);
  const [showRawJson, setShowRawJson] = useState(false);
  const [, navigate] = useLocation();

  const triageData = triage.triageData as any;
  const severity = triage.severity || "info";
  const route = triage.route || "B_LOW_CONFIDENCE";
  const routeInfo = ROUTE_LABELS[route] || ROUTE_LABELS.B_LOW_CONFIDENCE;

  return (
    <GlassPanel className="p-0 overflow-hidden">
      {/* Header Row */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-4 hover:bg-white/[0.02] transition-colors text-left"
      >
        {expanded ? <ChevronDown className="w-4 h-4 text-muted-foreground/50 shrink-0" /> : <ChevronRight className="w-4 h-4 text-muted-foreground/50 shrink-0" />}

        {/* Severity Badge */}
        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${SEVERITY_COLORS[severity]}`}>
          {severity}
        </span>

        {/* Route Badge */}
        <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${routeInfo.color}`}>
          {routeInfo.label}
        </span>

        {/* Alert Family */}
        <span className="text-xs font-mono text-violet-300/80">
          {triage.alertFamily || "unknown"}
        </span>

        {/* Rule ID */}
        <span className="text-xs font-mono text-muted-foreground/60">
          Rule {triage.ruleId}
        </span>

        {/* Agent */}
        {triage.agentName && (
          <span className="text-xs text-muted-foreground/50">
            {triage.agentName} ({triage.agentId})
          </span>
        )}

        {/* Confidence */}
        <span className="ml-auto text-xs text-muted-foreground/40">
          {Math.round((triage.severityConfidence ?? 0) * 100)}% conf
        </span>

        {/* Status */}
        <span className={`text-xs ${triage.status === "completed" ? "text-green-400" : triage.status === "failed" ? "text-red-400" : "text-yellow-400"}`}>
          {triage.status}
        </span>

        {/* Latency */}
        {triage.latencyMs && (
          <span className="text-[10px] text-muted-foreground/30 font-mono">
            {(triage.latencyMs / 1000).toFixed(1)}s
          </span>
        )}
      </button>

      {/* Expanded Details */}
      {expanded && triageData && (
        <div className="border-t border-white/[0.06] p-4 space-y-4">
          {/* Summary */}
          {triageData.summary && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1">Summary</div>
              <p className="text-sm text-foreground/80 leading-relaxed">{triageData.summary}</p>
            </div>
          )}

          {/* Severity Reasoning */}
          {triageData.severityReasoning && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1">Severity Reasoning</div>
              <p className="text-xs text-foreground/60 leading-relaxed">{triageData.severityReasoning}</p>
            </div>
          )}

          {/* Route Reasoning */}
          {triageData.routeReasoning && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1">Route Reasoning</div>
              <p className="text-xs text-foreground/60 leading-relaxed">{triageData.routeReasoning}</p>
            </div>
          )}

          {/* Entities */}
          {triageData.entities?.length > 0 && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-2">Extracted Entities ({triageData.entities.length})</div>
              <div className="flex flex-wrap gap-2">
                {triageData.entities.map((entity: any, i: number) => {
                  const Icon = ENTITY_ICONS[entity.type] || Info;
                  return (
                    <span key={i} className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-white/[0.04] border border-white/[0.06] text-xs">
                      <Icon className="w-3 h-3 text-violet-400/60" />
                      <span className="text-muted-foreground/50 text-[10px]">{entity.type}</span>
                      <span className="font-mono text-foreground/80">{entity.value}</span>
                      <span className="text-[9px] text-muted-foreground/30">{Math.round(entity.confidence * 100)}%</span>
                    </span>
                  );
                })}
              </div>
            </div>
          )}

          {/* MITRE Mapping */}
          {triageData.mitreMapping?.length > 0 && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-2">MITRE ATT&CK Mapping</div>
              <div className="flex flex-wrap gap-2">
                {triageData.mitreMapping.map((m: any, i: number) => (
                  <span key={i} className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-violet-500/10 border border-violet-500/20 text-xs">
                    <Target className="w-3 h-3 text-violet-400" />
                    <span className="font-mono text-violet-300">{m.techniqueId}</span>
                    <span className="text-muted-foreground/60">{m.techniqueName}</span>
                    <span className="text-[9px] text-muted-foreground/30">{m.tactic}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Dedup Assessment */}
          {triageData.dedup && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1">Deduplication</div>
              <div className="flex items-center gap-3 text-xs">
                <span className={triageData.dedup.isDuplicate ? "text-yellow-400" : "text-green-400"}>
                  {triageData.dedup.isDuplicate ? "Likely Duplicate" : "Unique Alert"}
                </span>
                <span className="text-muted-foreground/40">
                  Similarity: {Math.round((triageData.dedup.similarityScore ?? 0) * 100)}%
                </span>
                {triageData.dedup.similarTriageId && (
                  <span className="font-mono text-muted-foreground/40">
                    Similar to: {triageData.dedup.similarTriageId}
                  </span>
                )}
              </div>
              <p className="text-[11px] text-foreground/50 mt-1">{triageData.dedup.reasoning}</p>
            </div>
          )}

          {/* Case Link */}
          {triageData.caseLink?.shouldLink && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1">Case Link Suggestion</div>
              <div className="flex items-center gap-2 text-xs">
                <FileSearch className="w-3.5 h-3.5 text-violet-400" />
                {triageData.caseLink.suggestedCaseId ? (
                  <button
                    onClick={() => navigate(`/investigations`)}
                    className="text-violet-400 hover:text-violet-300 underline underline-offset-2"
                  >
                    Case #{triageData.caseLink.suggestedCaseId}: {triageData.caseLink.suggestedCaseTitle || "View Case"}
                  </button>
                ) : (
                  <span className="text-foreground/60">{triageData.caseLink.suggestedCaseTitle || "New case recommended"}</span>
                )}
                <span className="text-muted-foreground/30">
                  ({Math.round((triageData.caseLink.confidence ?? 0) * 100)}% conf)
                </span>
              </div>
              <p className="text-[11px] text-foreground/50 mt-1">{triageData.caseLink.reasoning}</p>
            </div>
          )}

          {/* Uncertainties */}
          {triageData.uncertainties?.length > 0 && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-2">Uncertainties</div>
              <div className="space-y-2">
                {triageData.uncertainties.map((u: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-xs bg-yellow-500/5 border border-yellow-500/10 rounded p-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-yellow-400/60 mt-0.5 shrink-0" />
                    <div>
                      <p className="text-foreground/70">{u.description}</p>
                      <p className="text-muted-foreground/40 mt-0.5">Impact: {u.impact}</p>
                      {u.suggestedAction && (
                        <p className="text-violet-400/60 mt-0.5">Suggested: {u.suggestedAction}</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Raw JSON Toggle */}
          <div>
            <button
              onClick={() => setShowRawJson(!showRawJson)}
              className="text-[10px] uppercase tracking-wider text-muted-foreground/40 hover:text-muted-foreground/60 transition-colors"
            >
              {showRawJson ? "Hide" : "Show"} Full Triage Object JSON
            </button>
            {showRawJson && (
              <div className="mt-2">
                <RawJsonViewer data={triageData} title="Triage Object" />
              </div>
            )}
          </div>
        </div>
      )}
    </GlassPanel>
  );
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function TriagePipeline() {
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [routeFilter, setRouteFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [page, setPage] = useState(0);
  const pageSize = 25;

  const { data, isLoading, refetch, isFetching } = trpc.pipeline.listTriages.useQuery({
    limit: pageSize,
    offset: page * pageSize,
    severity: severityFilter || undefined,
    route: routeFilter || undefined,
    status: statusFilter || undefined,
  } as any);

  const triages = data?.triages ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="space-y-6 p-6 max-w-[2400px] mx-auto">
      <PageHeader
        title="Triage Pipeline"
        subtitle="Agentic SOC Pipeline — Step 1: Structured Alert Triage"
      />

      {/* Stats */}
      <TriageStatsPanel />

      {/* Filters */}
      <GlassPanel className="p-4">
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-xs text-muted-foreground/50 uppercase tracking-wider">Filters:</span>

          <select
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value); setPage(0); }}
            className="bg-white/[0.04] border border-white/[0.08] rounded px-2 py-1 text-xs text-foreground/80 focus:outline-none focus:border-violet-500/40"
          >
            <option value="">All Severities</option>
            {["critical", "high", "medium", "low", "info"].map(s => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>

          <select
            value={routeFilter}
            onChange={(e) => { setRouteFilter(e.target.value); setPage(0); }}
            className="bg-white/[0.04] border border-white/[0.08] rounded px-2 py-1 text-xs text-foreground/80 focus:outline-none focus:border-violet-500/40"
          >
            <option value="">All Routes</option>
            {Object.entries(ROUTE_LABELS).map(([k, v]) => (
              <option key={k} value={k}>{v.label}</option>
            ))}
          </select>

          <select
            value={statusFilter}
            onChange={(e) => { setStatusFilter(e.target.value); setPage(0); }}
            className="bg-white/[0.04] border border-white/[0.08] rounded px-2 py-1 text-xs text-foreground/80 focus:outline-none focus:border-violet-500/40"
          >
            <option value="">All Statuses</option>
            {["completed", "processing", "pending", "failed"].map(s => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>

          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="ml-auto flex items-center gap-1.5 px-3 py-1 rounded bg-violet-500/10 hover:bg-violet-500/20 text-violet-300 text-xs transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3 h-3 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </GlassPanel>

      {/* Triage List */}
      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <GlassPanel key={i} className="p-4 animate-pulse h-16">&nbsp;</GlassPanel>
          ))}
        </div>
      ) : triages.length === 0 ? (
        <GlassPanel className="p-12 text-center">
          <Brain className="w-12 h-12 text-violet-400/30 mx-auto mb-4" />
          <h3 className="text-lg font-[Space_Grotesk] text-foreground/60 mb-2">No Triage Objects Yet</h3>
          <p className="text-sm text-muted-foreground/40 max-w-md mx-auto">
            Triage objects are created when alerts are processed through the agentic pipeline.
            Use the "AI Triage" button on any alert, or send alerts from the Walter Queue.
          </p>
        </GlassPanel>
      ) : (
        <div className="space-y-2">
          {triages.map((triage: any) => (
            <TriageResultCard key={triage.id} triage={triage} />
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground/40">
            Showing {page * pageSize + 1}–{Math.min((page + 1) * pageSize, total)} of {total}
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-3 py-1 rounded bg-white/[0.04] text-xs text-foreground/60 hover:bg-white/[0.08] disabled:opacity-30 transition-colors"
            >
              Previous
            </button>
            <span className="text-xs text-muted-foreground/40">
              Page {page + 1} of {totalPages}
            </span>
            <button
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="px-3 py-1 rounded bg-white/[0.04] text-xs text-foreground/60 hover:bg-white/[0.08] disabled:opacity-30 transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
