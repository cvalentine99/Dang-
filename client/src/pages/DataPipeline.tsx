import React, { useState } from "react";
import { trpc } from "@/lib/trpc";
import {
  Database, RefreshCw, Play, CheckCircle2, XCircle, Clock, Loader2,
  Server, Cpu, Globe, Package, UserCheck, ShieldAlert, AlertTriangle,
  ArrowRight, Info,
} from "lucide-react";

// ── Entity Config ───────────────────────────────────────────────────────────

const ENTITY_CONFIG: Record<string, { label: string; icon: typeof Server; color: string; description: string }> = {
  endpoints: { label: "Endpoints", icon: Server, color: "#a78bfa", description: "Agent hosts from Wazuh Server API" },
  processes: { label: "Processes", icon: Cpu, color: "#60a5fa", description: "Running processes via syscollector" },
  network_ports: { label: "Network Ports", icon: Globe, color: "#34d399", description: "Listening ports via syscollector" },
  software_packages: { label: "Software Packages", icon: Package, color: "#fbbf24", description: "Installed packages via syscollector" },
  identities: { label: "Identities", icon: UserCheck, color: "#f472b6", description: "System users via syscollector" },
  vulnerabilities: { label: "Vulnerabilities", icon: ShieldAlert, color: "#ef4444", description: "CVEs from vulnerability index" },
  security_events: { label: "Security Events", icon: AlertTriangle, color: "#f97316", description: "Alerts from wazuh-alerts index" },
};

// ── Sync Status Card ────────────────────────────────────────────────────────

function SyncEntityCard({
  entityType,
  syncStatus,
  isRunning,
}: {
  entityType: string;
  syncStatus?: { lastSyncAt: string | Date | null; entityCount: number; status: string; errorMessage: string | null };
  isRunning: boolean;
}): React.JSX.Element {
  const config = ENTITY_CONFIG[entityType] || { label: entityType, icon: Database, color: "#888", description: "" };
  const Icon = config.icon;

  const statusColor = !syncStatus ? "text-muted-foreground" :
    syncStatus.status === "completed" ? "text-green-400" :
    syncStatus.status === "failed" ? "text-red-400" :
    syncStatus.status === "running" ? "text-blue-400" : "text-muted-foreground";

  const StatusIcon = !syncStatus ? Clock :
    syncStatus.status === "completed" ? CheckCircle2 :
    syncStatus.status === "failed" ? XCircle :
    syncStatus.status === "running" ? Loader2 : Clock;

  return (
    <div className="glass-panel rounded-xl border border-white/10 p-4 hover:border-white/15 transition-colors">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2.5">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ backgroundColor: `${config.color}15`, border: `1px solid ${config.color}30` }}
          >
            <Icon className="w-4 h-4" style={{ color: config.color }} />
          </div>
          <div>
            <h3 className="text-sm font-medium text-foreground">{config.label}</h3>
            <p className="text-[10px] text-muted-foreground">{config.description}</p>
          </div>
        </div>
        <div className={`flex items-center gap-1 ${statusColor}`}>
          <StatusIcon className={`w-3.5 h-3.5 ${isRunning || syncStatus?.status === "running" ? "animate-spin" : ""}`} />
          <span className="text-[10px] font-mono">
            {isRunning ? "syncing" : syncStatus?.status ?? "never synced"}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <p className="text-[10px] text-muted-foreground mb-0.5">Entities</p>
          <p className="text-lg font-display font-bold text-foreground">
            {syncStatus?.entityCount?.toLocaleString() ?? "—"}
          </p>
        </div>
        <div>
          <p className="text-[10px] text-muted-foreground mb-0.5">Last Sync</p>
          <p className="text-xs font-mono text-foreground">
            {syncStatus?.lastSyncAt ? new Date(syncStatus.lastSyncAt).toLocaleString() : "Never"}
          </p>
        </div>
      </div>

      {syncStatus?.errorMessage && (
        <div className="mt-3 px-2.5 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20">
          <p className="text-[10px] text-red-300 font-mono">{syncStatus.errorMessage}</p>
        </div>
      )}
    </div>
  );
}

// ── Main Data Pipeline Page ─────────────────────────────────────────────────

export default function DataPipeline(): React.JSX.Element {
  const [isRunning, setIsRunning] = useState(false);
  const [syncResults, setSyncResults] = useState<Record<string, { success: boolean; count: number; error?: string }> | null>(null);

  const syncStatusQuery = trpc.graph.etlStatus.useQuery();
  const graphStatsQuery = trpc.graph.graphStats.useQuery();

  const syncMutation = trpc.graph.etlFullSync.useMutation({
    onMutate: () => {
      setIsRunning(true);
      setSyncResults(null);
    },
    onSuccess: (data: any) => {
      setIsRunning(false);
      setSyncResults(data.results as Record<string, { success: boolean; count: number; error?: string }>);
      syncStatusQuery.refetch();
      graphStatsQuery.refetch();
    },
    onError: () => {
      setIsRunning(false);
    },
  });

  const statusMap: Record<string, { lastSyncAt: string | Date | null; entityCount: number; status: string; errorMessage: string | null }> = {};
  if (syncStatusQuery.data) {
    for (const s of syncStatusQuery.data) {
      statusMap[s.entityType] = s;
    }
  }

  const totalEntities = graphStatsQuery.data
    ? Object.values(graphStatsQuery.data).reduce((a: number, b: number) => a + b, 0)
    : 0;

  const lastSync = syncStatusQuery.data?.length
    ? syncStatusQuery.data.reduce((latest: Date | null, s: { lastSyncAt: string | Date | null }) => {
        if (!s.lastSyncAt) return latest;
        const d = new Date(s.lastSyncAt);
        return !latest || d > latest ? d : latest;
      }, null as Date | null)
    : null;

  return (
    <div className="px-6 py-6 max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-purple-500/15 border border-purple-500/30 flex items-center justify-center">
            <Database className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <h1 className="text-lg font-display font-bold text-foreground">Data Pipeline</h1>
            <p className="text-xs text-muted-foreground">ETL sync from Wazuh to Knowledge Graph</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
        <button
          onClick={() => { syncStatusQuery.refetch(); graphStatsQuery.refetch(); }}
          disabled={syncStatusQuery.isLoading || graphStatsQuery.isLoading}
          className="p-2 rounded-lg border border-white/10 text-muted-foreground hover:bg-white/5 hover:text-foreground transition-colors"
          title="Refresh status"
        >
          <RefreshCw className={`w-4 h-4 ${syncStatusQuery.isLoading || graphStatsQuery.isLoading ? "animate-spin" : ""}`} />
        </button>
        <button
          onClick={() => syncMutation.mutate()}
          disabled={isRunning}
          className="flex items-center gap-2 px-4 py-2 text-sm rounded-lg bg-purple-500/20 border border-purple-500/30 text-purple-200 hover:bg-purple-500/30 disabled:opacity-50 transition-colors"
        >
          {isRunning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Syncing...
            </>
          ) : (
            <>
              <Play className="w-4 h-4" />
              Run Full Sync
            </>
          )}
        </button>
        </div>
      </div>

      {/* Overview stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="glass-panel rounded-xl border border-white/10 px-4 py-3">
          <p className="text-[10px] text-muted-foreground mb-1">Total Entities</p>
          <p className="text-2xl font-display font-bold text-foreground">{totalEntities.toLocaleString()}</p>
        </div>
        <div className="glass-panel rounded-xl border border-white/10 px-4 py-3">
          <p className="text-[10px] text-muted-foreground mb-1">Entity Types</p>
          <p className="text-2xl font-display font-bold text-foreground">{Object.keys(ENTITY_CONFIG).length}</p>
        </div>
        <div className="glass-panel rounded-xl border border-white/10 px-4 py-3">
          <p className="text-[10px] text-muted-foreground mb-1">Last Sync</p>
          <p className="text-sm font-mono text-foreground">{lastSync ? lastSync.toLocaleString() : "Never"}</p>
        </div>
      </div>

      {/* Pipeline flow diagram */}
      <div className="glass-panel rounded-xl border border-white/10 px-4 py-3">
        <p className="text-[10px] text-muted-foreground mb-2 font-medium">Pipeline Flow</p>
        <div className="flex items-center justify-center gap-3 py-2">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-500/10 border border-blue-500/20">
            <Server className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-xs text-blue-300">Wazuh Server API</span>
          </div>
          <ArrowRight className="w-4 h-4 text-muted-foreground" />
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-green-500/10 border border-green-500/20">
            <Database className="w-3.5 h-3.5 text-green-400" />
            <span className="text-xs text-green-300">Wazuh Indexer</span>
          </div>
          <ArrowRight className="w-4 h-4 text-muted-foreground" />
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-500/10 border border-purple-500/20">
            <Database className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-xs text-purple-300">Knowledge Graph</span>
          </div>
          <ArrowRight className="w-4 h-4 text-muted-foreground" />
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-500/10 border border-orange-500/20">
            <RefreshCw className="w-3.5 h-3.5 text-orange-400" />
            <span className="text-xs text-orange-300">LLM Analysis</span>
          </div>
        </div>
      </div>

      {/* Sync results banner */}
      {syncResults && (
        <div className="glass-panel rounded-xl border border-white/10 px-4 py-3">
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle2 className="w-4 h-4 text-green-400" />
            <p className="text-sm font-medium text-foreground">Sync Complete</p>
          </div>
          <div className="grid grid-cols-4 gap-2">
            {Object.entries(syncResults).map(([key, result]) => (
              <div key={key} className={`px-2.5 py-1.5 rounded-lg border ${result.success ? "bg-green-500/5 border-green-500/20" : "bg-red-500/5 border-red-500/20"}`}>
                <p className="text-[10px] text-muted-foreground">{key}</p>
                <p className={`text-xs font-mono ${result.success ? "text-green-300" : "text-red-300"}`}>
                  {result.success ? `${result.count} synced` : result.error || "failed"}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Entity cards grid */}
      <div>
        <h2 className="text-sm font-medium text-foreground mb-3">Entity Sync Status</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {Object.keys(ENTITY_CONFIG).map(entityType => (
            <SyncEntityCard
              key={entityType}
              entityType={entityType}
              syncStatus={statusMap[entityType]}
              isRunning={isRunning}
            />
          ))}
        </div>
      </div>

      {/* Info note */}
      <div className="flex items-start gap-2 px-4 py-3 rounded-lg bg-blue-500/5 border border-blue-500/10">
        <Info className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-xs text-blue-300">
            The ETL pipeline syncs data from your Wazuh environment into the local Knowledge Graph database.
            This enables the Security Analyst chat and Knowledge Graph visualization to work with structured, queryable data.
          </p>
          <p className="text-[10px] text-muted-foreground mt-1">
            Sync is incremental for security events (only new alerts since last sync). All other entities are fully refreshed.
          </p>
        </div>
      </div>
    </div>
  );
}
