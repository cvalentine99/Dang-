import React from "react";
import { trpc } from "@/lib/trpc";
import {
  Cpu, Activity, Gauge, HardDrive, Zap, Clock, Server,
  CheckCircle2, XCircle, AlertTriangle, Loader2, RefreshCw,
  BarChart3, Layers, MemoryStick,
} from "lucide-react";

// ── Helper ──────────────────────────────────────────────────────────────────

function formatBytes(mb: number | null): string {
  if (mb === null) return "—";
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
  return `${mb.toFixed(0)} MB`;
}

function StatusDot({ status }: { status: string }) {
  const colors: Record<string, string> = {
    online: "bg-emerald-400 shadow-emerald-400/50",
    offline: "bg-red-400 shadow-red-400/50",
    degraded: "bg-amber-400 shadow-amber-400/50",
    unknown: "bg-zinc-400 shadow-zinc-400/50",
  };
  return (
    <span className={`inline-block w-2.5 h-2.5 rounded-full shadow-lg ${colors[status] ?? colors.unknown}`} />
  );
}

// ── Main Page ───────────────────────────────────────────────────────────────

export default function DGXHealth(): React.JSX.Element {
  const dgxHealth = trpc.enhancedLLM.dgxHealth.useQuery(undefined, {
    refetchInterval: 15_000,
    staleTime: 10_000,
  });
  const queueStats = trpc.enhancedLLM.queueStats.useQuery(undefined, {
    refetchInterval: 5_000,
    staleTime: 3_000,
  });
  const sessionTypes = trpc.enhancedLLM.sessionTypes.useQuery();

  const h = dgxHealth.data;
  const q = queueStats.data;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-purple-500/15 border border-purple-500/30 flex items-center justify-center">
            <Cpu className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <h1 className="text-xl font-display font-bold text-foreground">DGX Spark Health</h1>
            <p className="text-xs text-muted-foreground">Nemotron-3 Nano inference engine monitoring</p>
          </div>
        </div>
        <button
          onClick={() => { dgxHealth.refetch(); queueStats.refetch(); }}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/10 text-xs text-muted-foreground hover:bg-white/5 hover:text-foreground transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${dgxHealth.isFetching ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {dgxHealth.isLoading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-8 h-8 animate-spin text-purple-400" />
        </div>
      ) : !h ? (
        <div className="glass-panel rounded-xl p-8 text-center">
          <XCircle className="w-10 h-10 text-red-400 mx-auto mb-3" />
          <p className="text-sm text-muted-foreground">Unable to fetch DGX health metrics</p>
        </div>
      ) : (
        <>
          {/* Model Status Banner */}
          <div className={`glass-panel rounded-xl p-5 border ${
            h.modelStatus === "online" ? "border-emerald-500/30" :
            h.modelStatus === "degraded" ? "border-amber-500/30" :
            "border-red-500/30"
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <StatusDot status={h.modelStatus} />
                <div>
                  <p className="text-sm font-medium text-foreground capitalize">{h.modelStatus}</p>
                  <p className="text-xs text-muted-foreground">{h.endpoint || "No endpoint configured"}</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-xs text-muted-foreground">Last check</p>
                <p className="text-xs font-mono text-foreground">
                  {new Date(h.lastHealthCheck).toLocaleTimeString()}
                </p>
              </div>
            </div>
          </div>

          {/* KPI Cards Row */}
          <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
            {/* Model Name */}
            <div className="glass-panel rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Server className="w-4 h-4 text-purple-400" />
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Model</span>
              </div>
              <p className="text-sm font-mono text-foreground truncate" title={h.modelName}>{h.modelName}</p>
              <p className="text-[10px] text-muted-foreground mt-1">{h.quantization}</p>
            </div>

            {/* Context Size */}
            <div className="glass-panel rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Context</span>
              </div>
              <p className="text-lg font-display font-bold text-foreground">{(h.contextSize / 1024).toFixed(0)}K</p>
              <p className="text-[10px] text-muted-foreground mt-1">tokens max</p>
            </div>

            {/* Decode Speed */}
            <div className="glass-panel rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Zap className="w-4 h-4 text-amber-400" />
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Decode</span>
              </div>
              <p className="text-lg font-display font-bold text-foreground">
                {h.decodeTokensPerSec !== null ? `${h.decodeTokensPerSec}` : "—"}
              </p>
              <p className="text-[10px] text-muted-foreground mt-1">tok/s</p>
            </div>

            {/* Prefill Speed */}
            <div className="glass-panel rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <BarChart3 className="w-4 h-4 text-emerald-400" />
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Prefill</span>
              </div>
              <p className="text-lg font-display font-bold text-foreground">
                {h.prefillTokensPerSec !== null ? `${h.prefillTokensPerSec}` : "—"}
              </p>
              <p className="text-[10px] text-muted-foreground mt-1">tok/s</p>
            </div>

            {/* Active Requests */}
            <div className="glass-panel rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Activity className="w-4 h-4 text-pink-400" />
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Active</span>
              </div>
              <p className="text-lg font-display font-bold text-foreground">{h.activeRequests}</p>
              <p className="text-[10px] text-muted-foreground mt-1">requests</p>
            </div>

            {/* Queue Depth */}
            <div className="glass-panel rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Gauge className="w-4 h-4 text-violet-400" />
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Queue</span>
              </div>
              <p className="text-lg font-display font-bold text-foreground">{q?.queueDepth ?? h.queueDepth}</p>
              <p className="text-[10px] text-muted-foreground mt-1">pending</p>
            </div>
          </div>

          {/* Memory Usage */}
          <div className="glass-panel rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <MemoryStick className="w-4 h-4 text-purple-400" />
              <h2 className="text-sm font-display font-semibold text-foreground">Memory Usage</h2>
              <span className="text-[10px] text-muted-foreground ml-auto">
                {formatBytes(h.memoryUsage.totalMB)} total (Grace Blackwell unified memory)
              </span>
            </div>

            {/* Memory bar */}
            <div className="h-6 rounded-lg bg-white/5 overflow-hidden flex">
              {h.memoryUsage.modelWeightsMB !== null && (
                <div
                  className="h-full bg-purple-500/60 flex items-center justify-center text-[9px] font-mono text-white/80"
                  style={{ width: `${((h.memoryUsage.modelWeightsMB ?? 0) / h.memoryUsage.totalMB) * 100}%` }}
                  title={`Model Weights: ${formatBytes(h.memoryUsage.modelWeightsMB)}`}
                >
                  Weights
                </div>
              )}
              {h.memoryUsage.kvCacheMB !== null && h.memoryUsage.kvCacheMB > 0 && (
                <div
                  className="h-full bg-cyan-500/60 flex items-center justify-center text-[9px] font-mono text-white/80"
                  style={{ width: `${Math.max(((h.memoryUsage.kvCacheMB ?? 0) / h.memoryUsage.totalMB) * 100, 1)}%` }}
                  title={`KV Cache: ${formatBytes(h.memoryUsage.kvCacheMB)}`}
                >
                  KV
                </div>
              )}
              {h.memoryUsage.availableMB !== null && (
                <div
                  className="h-full bg-emerald-500/20 flex items-center justify-center text-[9px] font-mono text-white/40 flex-1"
                  title={`Available: ${formatBytes(h.memoryUsage.availableMB)}`}
                >
                  Available
                </div>
              )}
            </div>

            {/* Memory legend */}
            <div className="flex items-center gap-6 mt-3">
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded bg-purple-500/60" />
                <span className="text-[10px] text-muted-foreground">
                  Model Weights: {formatBytes(h.memoryUsage.modelWeightsMB)}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded bg-cyan-500/60" />
                <span className="text-[10px] text-muted-foreground">
                  KV Cache: {formatBytes(h.memoryUsage.kvCacheMB)}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded bg-emerald-500/20" />
                <span className="text-[10px] text-muted-foreground">
                  Available: {formatBytes(h.memoryUsage.availableMB)}
                </span>
              </div>
            </div>
          </div>

          {/* Session Types Reference */}
          <div className="glass-panel rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <Layers className="w-4 h-4 text-purple-400" />
              <h2 className="text-sm font-display font-semibold text-foreground">Session Type Allocation</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-white/5">
                    <th className="text-left py-2 px-3 text-muted-foreground font-medium">Session Type</th>
                    <th className="text-right py-2 px-3 text-muted-foreground font-medium">Context Size</th>
                    <th className="text-right py-2 px-3 text-muted-foreground font-medium">Max Tokens</th>
                    <th className="text-center py-2 px-3 text-muted-foreground font-medium">Reasoning</th>
                    <th className="text-left py-2 px-3 text-muted-foreground font-medium">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {(sessionTypes.data ?? []).map(st => (
                    <tr key={st.type} className="border-b border-white/5 hover:bg-white/[0.02]">
                      <td className="py-2.5 px-3 font-mono text-foreground capitalize">{st.type.replace(/_/g, " ")}</td>
                      <td className="py-2.5 px-3 text-right font-mono text-cyan-400">{(st.ctxSize / 1024).toFixed(0)}K</td>
                      <td className="py-2.5 px-3 text-right font-mono text-amber-400">{(st.maxTokens / 1024).toFixed(0)}K</td>
                      <td className="py-2.5 px-3 text-center">
                        {st.enableReasoning ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mx-auto" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-zinc-500 mx-auto" />
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-muted-foreground">{st.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Architecture Info */}
          <div className="glass-panel rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <HardDrive className="w-4 h-4 text-purple-400" />
              <h2 className="text-sm font-display font-semibold text-foreground">Architecture Reference</h2>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
              <div className="space-y-2">
                <p className="text-muted-foreground font-medium">Model Architecture</p>
                <div className="space-y-1 font-mono text-foreground">
                  <p>Nemotron-3 Nano 30B (A3B active)</p>
                  <p>Hybrid Mamba-2 + Transformer MoE</p>
                  <p>52 layers: 46 Mamba-2, 6 Attention</p>
                  <p>8 experts per MoE, top-1 routing</p>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-muted-foreground font-medium">Quantization</p>
                <div className="space-y-1 font-mono text-foreground">
                  <p>Q8_K_XL (8-bit K-quant, extra-large)</p>
                  <p>~30 GB model weights</p>
                  <p>Optimized for accuracy over speed</p>
                  <p>Full tool-calling fidelity</p>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-muted-foreground font-medium">DGX Spark Hardware</p>
                <div className="space-y-1 font-mono text-foreground">
                  <p>Grace Blackwell GB10 (SM 12.0)</p>
                  <p>128 GB unified LPDDR5x</p>
                  <p>273 GB/s memory bandwidth</p>
                  <p>20 ARM Neoverse V2 cores</p>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
