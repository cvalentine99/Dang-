import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import * as d3 from "d3";
import {
  Network, Search, ZoomIn, ZoomOut, Maximize2, RefreshCw,
  Globe, Box, Layers, AlertTriangle, Database, FileText, Key,
  X, ChevronRight, Loader2, Info, Route, EyeOff, Shield,
  Lock, Unlock, Activity, Zap, Filter, List, GitBranch,
  ArrowUpDown, ChevronDown, ChevronUp, MousePointerClick,
  Copy, Pin, PinOff, Eye, Image as ImageIcon, FileCode2, FolderPlus, Check, Download,
  SquareMousePointer, Trash2, CheckSquare, Square,
} from "lucide-react";
import { toast } from "sonner";
import { ChartSkeleton, TableSkeleton } from "@/components/shared";

// ── Types ───────────────────────────────────────────────────────────────────

interface GraphNode {
  id: string;
  type: string;
  label: string;
  properties: Record<string, unknown>;
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
}

interface GraphEdge {
  source: string | GraphNode;
  target: string | GraphNode;
  relationship: string;
}

interface RiskPath {
  id: string;
  hops: Array<{ nodeId: string; nodeType: string; label: string; stage: string; riskLevel?: string; properties: Record<string, unknown> }>;
  score: number;
  riskLevel: string;
  summary: string;
}

// ── Node Config ─────────────────────────────────────────────────────────────

const NODE_CONFIG: Record<string, { color: string; icon: typeof Globe; size: number; layer: string }> = {
  resource:      { color: "#a78bfa", icon: Box,           size: 28, layer: "API Ontology" },
  endpoint:      { color: "#818cf8", icon: Globe,         size: 18, layer: "API Ontology" },
  parameter:     { color: "#60a5fa", icon: FileText,      size: 12, layer: "API Ontology" },
  response:      { color: "#38bdf8", icon: FileText,      size: 12, layer: "API Ontology" },
  auth_method:   { color: "#c084fc", icon: Key,           size: 20, layer: "API Ontology" },
  use_case:      { color: "#34d399", icon: Activity,      size: 22, layer: "Operational Semantics" },
  index:         { color: "#fbbf24", icon: Database,       size: 22, layer: "Schema Lineage" },
  field:         { color: "#fb923c", icon: Layers,         size: 12, layer: "Schema Lineage" },
  error_pattern: { color: "#f87171", icon: AlertTriangle,  size: 20, layer: "Error & Failure" },
};

const RISK_COLORS: Record<string, string> = {
  SAFE: "#34d399",
  MUTATING: "#fbbf24",
  DESTRUCTIVE: "#ef4444",
};

const LAYER_COLORS: Record<string, string> = {
  "API Ontology": "#818cf8",
  "Operational Semantics": "#34d399",
  "Schema Lineage": "#fbbf24",
  "Error & Failure": "#f87171",
};

const METHOD_COLORS: Record<string, string> = {
  GET: "#34d399",
  POST: "#60a5fa",
  PUT: "#fbbf24",
  DELETE: "#ef4444",
};

// ── Detail Panel ────────────────────────────────────────────────────────────

function NodeDetailPanel({
  node,
  onClose,
  onExpand,
  isExpanded,
  expandLoading,
  onAddToInvestigation,
}: {
  node: GraphNode;
  onClose: () => void;
  onExpand: (node: GraphNode) => void;
  isExpanded: boolean;
  expandLoading: boolean;
  onAddToInvestigation: (node: GraphNode) => void;
}): React.JSX.Element {
  const config = NODE_CONFIG[node.type] || NODE_CONFIG.endpoint;
  const Icon = config.icon;
  const riskLevel = node.properties.riskLevel as string | undefined;
  const riskColor = riskLevel ? RISK_COLORS[riskLevel] ?? "#888" : undefined;
  const canExpand = node.type === "resource" || node.type === "endpoint";

  const properties = Object.entries(node.properties).filter(
    ([key]) => !["x", "y", "fx", "fy", "index", "vx", "vy"].includes(key)
  );

  return (
    <div className="absolute top-4 right-4 w-96 glass-panel rounded-xl border border-white/10 shadow-2xl z-20 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/5">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${config.color}20`, border: `1px solid ${config.color}40` }}>
            <Icon className="w-4 h-4" style={{ color: config.color }} />
          </div>
          <div>
            <p className="text-sm font-medium text-foreground truncate max-w-[220px]">{node.label}</p>
            <div className="flex items-center gap-2">
              <p className="text-[10px] text-muted-foreground font-mono">{node.type}</p>
              {riskLevel && (
                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded" style={{ color: riskColor, backgroundColor: `${riskColor}15`, border: `1px solid ${riskColor}30` }}>
                  {riskLevel}
                </span>
              )}
              {node.properties.llmAllowed !== undefined && (
                <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded flex items-center gap-0.5 ${
                  node.properties.llmAllowed ? "text-green-400 bg-green-500/10 border border-green-500/20" : "text-red-400 bg-red-500/10 border border-red-500/20"
                }`}>
                  {node.properties.llmAllowed ? <Unlock className="w-2.5 h-2.5" /> : <Lock className="w-2.5 h-2.5" />}
                  {node.properties.llmAllowed ? "LLM OK" : "LLM Blocked"}
                </span>
              )}
            </div>
          </div>
        </div>
        <button onClick={onClose} className="p-1 rounded hover:bg-white/10 transition-colors text-muted-foreground">
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Expand button */}
      {canExpand && (
        <div className="px-4 py-2 border-b border-white/5">
          <button
            onClick={() => onExpand(node)}
            disabled={expandLoading || isExpanded}
            className={`w-full flex items-center justify-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              isExpanded
                ? "bg-purple-500/10 text-purple-300 border border-purple-500/20 cursor-default"
                : expandLoading
                  ? "bg-white/5 text-muted-foreground border border-white/10 cursor-wait"
                  : "bg-purple-500/15 text-purple-300 border border-purple-500/30 hover:bg-purple-500/25"
            }`}
          >
            {expandLoading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : isExpanded ? (
              <GitBranch className="w-3.5 h-3.5" />
            ) : (
              <MousePointerClick className="w-3.5 h-3.5" />
            )}
            {isExpanded
              ? `Expanded — ${node.type === "resource" ? "endpoints visible" : "params & responses visible"}`
              : `Expand ${node.type === "resource" ? "endpoints" : "params & responses"}`}
          </button>
        </div>
      )}

      <div className="px-4 py-3 max-h-80 overflow-y-auto space-y-1.5">
        {properties.map(([key, value]) => (
          <div key={key} className="flex items-start gap-2">
            <span className="text-[11px] text-muted-foreground font-mono flex-shrink-0 w-32 truncate">{key}</span>
            <span className="text-[11px] text-foreground font-mono break-all">
              {value === null || value === undefined
                ? <span className="text-muted-foreground italic">null</span>
                : Array.isArray(value)
                  ? value.join(", ")
                  : String(value)}
            </span>
          </div>
        ))}
        {properties.length === 0 && (
          <p className="text-xs text-muted-foreground italic">No properties available</p>
        )}
      </div>
      {/* Add to Investigation */}
      <div className="px-4 py-2 border-t border-white/5">
        <button
          onClick={() => onAddToInvestigation(node)}
          className="w-full flex items-center justify-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 hover:bg-indigo-500/25"
        >
          <FolderPlus className="w-3.5 h-3.5" />
          Add to Investigation
        </button>
      </div>

      <details className="border-t border-white/5">
        <summary className="px-4 py-2 text-[11px] text-muted-foreground cursor-pointer hover:text-foreground transition-colors flex items-center gap-1.5">
          <ChevronRight className="w-3 h-3" />
          Raw JSON
        </summary>
        <pre className="px-4 pb-3 text-[10px] font-mono text-muted-foreground overflow-x-auto max-h-40 overflow-y-auto">
          {JSON.stringify(node.properties, null, 2)}
        </pre>
      </details>
    </div>
  );
}

// ── Legend ───────────────────────────────────────────────────────────────────

function GraphLegend({ activeFilters, onToggle }: { activeFilters: Set<string>; onToggle: (type: string) => void }): React.JSX.Element {
  const layers = [
    { name: "API Ontology", types: ["resource", "endpoint", "parameter", "response", "auth_method"] },
    { name: "Operational Semantics", types: ["use_case"] },
    { name: "Schema Lineage", types: ["index", "field"] },
    { name: "Error & Failure", types: ["error_pattern"] },
  ];

  return (
    <div className="absolute bottom-4 left-4 glass-panel rounded-xl border border-white/10 px-3 py-2 z-10 max-w-xs">
      <p className="text-[10px] text-muted-foreground mb-1.5 font-medium">KG Layers</p>
      <div className="space-y-1.5">
        {layers.map(layer => (
          <div key={layer.name}>
            <p className="text-[9px] font-mono mb-0.5" style={{ color: LAYER_COLORS[layer.name] }}>{layer.name}</p>
            <div className="flex flex-wrap gap-1">
              {layer.types.map(type => {
                const config = NODE_CONFIG[type];
                const active = activeFilters.has(type);
                return (
                  <button
                    key={type}
                    onClick={() => onToggle(type)}
                    className={`flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono transition-all border ${
                      active ? "border-white/20 bg-white/5 text-foreground" : "border-transparent bg-white/[0.02] text-muted-foreground opacity-50"
                    }`}
                  >
                    <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: active ? config.color : `${config.color}40` }} />
                    {type.replace("_", " ")}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Risk Path Panel ─────────────────────────────────────────────────────────

function RiskPathPanel({
  paths,
  selectedPathId,
  onSelectPath,
  isLoading,
  onClose,
}: {
  paths: RiskPath[];
  selectedPathId: string | null;
  onSelectPath: (id: string | null) => void;
  isLoading: boolean;
  onClose: () => void;
}): React.JSX.Element {
  return (
    <div className="absolute top-4 left-14 w-80 glass-panel rounded-xl border border-white/10 shadow-2xl z-20 overflow-hidden max-h-[calc(100%-2rem)]">
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/5">
        <div className="flex items-center gap-2">
          <Route className="w-4 h-4 text-red-400" />
          <h3 className="text-sm font-medium text-foreground">Risk Paths</h3>
        </div>
        <button onClick={onClose} className="p-1 rounded hover:bg-white/10 text-muted-foreground">
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      {isLoading ? (
        <div className="px-4 py-8 flex items-center justify-center">
          <Loader2 className="w-5 h-5 text-purple-400 animate-spin" />
        </div>
      ) : paths.length === 0 ? (
        <div className="px-4 py-6 text-center">
          <Shield className="w-8 h-8 text-green-400 mx-auto mb-2" />
          <p className="text-xs text-muted-foreground">No high-risk paths detected.</p>
          <p className="text-[10px] text-muted-foreground mt-1">All endpoints are within acceptable risk thresholds.</p>
        </div>
      ) : (
        <div className="overflow-y-auto max-h-[calc(100vh-12rem)]">
          {paths.map((path) => {
            const isSelected = selectedPathId === path.id;
            const riskColor = RISK_COLORS[path.riskLevel] ?? "#fbbf24";

            return (
              <button
                key={path.id}
                onClick={() => onSelectPath(isSelected ? null : path.id)}
                className={`w-full text-left px-4 py-3 border-b border-white/5 transition-all hover:bg-white/[0.03] ${
                  isSelected ? "bg-purple-500/10 border-l-2 border-l-purple-500" : ""
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium text-foreground truncate">{path.hops[0]?.label ?? "Unknown"}</p>
                    <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-2">{path.summary}</p>
                  </div>
                  <div className="flex-shrink-0 flex flex-col items-end gap-1">
                    <span
                      className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded"
                      style={{ color: riskColor, backgroundColor: `${riskColor}15`, border: `1px solid ${riskColor}30` }}
                    >
                      {path.score}
                    </span>
                    <span className="text-[10px] text-muted-foreground">{path.hops.length} nodes</span>
                  </div>
                </div>

                {isSelected && (
                  <div className="mt-2 space-y-1">
                    {path.hops.map((hop, i) => {
                      const hopColor = RISK_COLORS[hop.riskLevel ?? "SAFE"] ?? "#888";
                      return (
                        <div key={`${hop.nodeId}-${i}`} className="flex items-center gap-2">
                          <div className="w-4 flex flex-col items-center">
                            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: hopColor }} />
                            {i < path.hops.length - 1 && (
                              <div className="w-px h-3 mt-0.5" style={{ backgroundColor: `${hopColor}40` }} />
                            )}
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-[10px] text-foreground truncate">{hop.label}</p>
                            <p className="text-[9px] text-muted-foreground font-mono">{hop.stage} &middot; {hop.nodeType}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Stats Overlay ───────────────────────────────────────────────────────────

function StatsOverlay({ stats }: { stats: any }): React.JSX.Element {
  return (
    <div className="absolute top-4 right-4 glass-panel rounded-xl border border-white/10 px-4 py-3 z-10 w-64">
      <p className="text-[10px] text-muted-foreground mb-2 font-medium">Knowledge Graph</p>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1">
        <div className="flex items-center justify-between">
          <span className="text-[10px] text-muted-foreground">Endpoints</span>
          <span className="text-[10px] font-mono text-foreground">{stats.endpoints}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[10px] text-muted-foreground">Resources</span>
          <span className="text-[10px] font-mono text-foreground">{stats.resources}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[10px] text-muted-foreground">Use Cases</span>
          <span className="text-[10px] font-mono text-foreground">{stats.useCases}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[10px] text-muted-foreground">Indices</span>
          <span className="text-[10px] font-mono text-foreground">{stats.indices}</span>
        </div>
      </div>
      <div className="mt-2 pt-2 border-t border-white/5">
        <p className="text-[9px] text-muted-foreground mb-1">Risk Breakdown</p>
        <div className="flex gap-2">
          <span className="text-[10px] font-mono" style={{ color: RISK_COLORS.SAFE }}>
            {stats.byRiskLevel?.safe ?? 0} safe
          </span>
          <span className="text-[10px] font-mono" style={{ color: RISK_COLORS.MUTATING }}>
            {stats.byRiskLevel?.mutating ?? 0} mut
          </span>
          <span className="text-[10px] font-mono" style={{ color: RISK_COLORS.DESTRUCTIVE }}>
            {stats.byRiskLevel?.destructive ?? 0} destr
          </span>
        </div>
      </div>
      <div className="mt-2 pt-2 border-t border-white/5">
        <p className="text-[9px] text-muted-foreground mb-1">HTTP Methods</p>
        <div className="flex gap-2">
          {["GET", "POST", "PUT", "DELETE"].map(m => (
            <span key={m} className="text-[10px] font-mono text-foreground">
              <span className="text-muted-foreground">{m}:</span> {stats.byMethod?.[m] ?? 0}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Endpoint Table View ─────────────────────────────────────────────────────

type SortField = "method" | "path" | "resource" | "riskLevel" | "trustScore";
type SortDir = "asc" | "desc";

function EndpointTableView(): React.JSX.Element {
  const [page, setPage] = useState(0);
  const [methodFilter, setMethodFilter] = useState<string>("");
  const [riskFilter, setRiskFilter] = useState<string>("");
  const [resourceFilter, setResourceFilter] = useState<string>("");
  const [sortField, setSortField] = useState<SortField>("path");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const pageSize = 50;

  const endpointsQ = trpc.graph.endpoints.useQuery({
    method: methodFilter || undefined,
    riskLevel: riskFilter || undefined,
    resource: resourceFilter || undefined,
    limit: 200,
    offset: 0,
  });

  const resourcesQ = trpc.graph.resourceOverview.useQuery();

  const sortedEndpoints = useMemo(() => {
    if (!endpointsQ.data?.endpoints) return [];
    const eps = [...endpointsQ.data.endpoints];
    eps.sort((a: any, b: any) => {
      let va = a[sortField] ?? "";
      let vb = b[sortField] ?? "";
      if (typeof va === "number" && typeof vb === "number") {
        return sortDir === "asc" ? va - vb : vb - va;
      }
      va = String(va).toLowerCase();
      vb = String(vb).toLowerCase();
      return sortDir === "asc" ? va.localeCompare(vb) : vb.localeCompare(va);
    });
    return eps;
  }, [endpointsQ.data, sortField, sortDir]);

  const pagedEndpoints = useMemo(() => {
    return sortedEndpoints.slice(page * pageSize, (page + 1) * pageSize);
  }, [sortedEndpoints, page]);

  const totalPages = Math.ceil(sortedEndpoints.length / pageSize);

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir(d => d === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDir("asc");
    }
  };

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <ArrowUpDown className="w-3 h-3 text-muted-foreground/40" />;
    return sortDir === "asc" ? <ChevronUp className="w-3 h-3 text-purple-400" /> : <ChevronDown className="w-3 h-3 text-purple-400" />;
  };

  const resources: string[] = useMemo(() => {
    if (!resourcesQ.data) return [];
    return (resourcesQ.data as any[]).map((r: any) => r.name).sort();
  }, [resourcesQ.data]);

  if (endpointsQ.isLoading) {
    return (
      <div className="p-6">
        <TableSkeleton columns={6} rows={12} />
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Filters */}
      <div className="flex-shrink-0 px-6 py-3 border-b border-white/5 flex items-center gap-3 flex-wrap">
        <select
          value={methodFilter}
          onChange={e => { setMethodFilter(e.target.value); setPage(0); }}
          className="text-xs bg-white/5 border border-white/10 rounded-lg px-2 py-1.5 text-foreground outline-none focus:border-purple-500/30"
        >
          <option value="">All Methods</option>
          {["GET", "POST", "PUT", "DELETE"].map(m => <option key={m} value={m}>{m}</option>)}
        </select>

        <select
          value={riskFilter}
          onChange={e => { setRiskFilter(e.target.value); setPage(0); }}
          className="text-xs bg-white/5 border border-white/10 rounded-lg px-2 py-1.5 text-foreground outline-none focus:border-purple-500/30"
        >
          <option value="">All Risk</option>
          <option value="SAFE">SAFE</option>
          <option value="MUTATING">MUTATING</option>
          <option value="DESTRUCTIVE">DESTRUCTIVE</option>
        </select>

        <select
          value={resourceFilter}
          onChange={e => { setResourceFilter(e.target.value); setPage(0); }}
          className="text-xs bg-white/5 border border-white/10 rounded-lg px-2 py-1.5 text-foreground outline-none focus:border-purple-500/30 max-w-[200px]"
        >
          <option value="">All Resources</option>
          {resources.map(r => <option key={r} value={r}>{r}</option>)}
        </select>

        <span className="text-[10px] text-muted-foreground ml-auto font-mono">
          {sortedEndpoints.length} / {endpointsQ.data?.total ?? 0} endpoints
        </span>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 z-10">
            <tr className="bg-black/40 backdrop-blur-sm border-b border-white/5">
              {[
                { field: "method" as SortField, label: "Method", width: "w-20" },
                { field: "path" as SortField, label: "Path", width: "flex-1" },
                { field: "resource" as SortField, label: "Resource", width: "w-36" },
                { field: "riskLevel" as SortField, label: "Risk", width: "w-28" },
                { field: "trustScore" as SortField, label: "Trust", width: "w-20" },
              ].map(col => (
                <th
                  key={col.field}
                  onClick={() => toggleSort(col.field)}
                  className={`px-3 py-2 text-left text-[10px] font-medium text-muted-foreground uppercase tracking-wider cursor-pointer hover:text-foreground transition-colors ${col.width}`}
                >
                  <div className="flex items-center gap-1">
                    {col.label}
                    <SortIcon field={col.field} />
                  </div>
                </th>
              ))}
              <th className="px-3 py-2 text-left text-[10px] font-medium text-muted-foreground uppercase tracking-wider w-20">LLM</th>
              <th className="px-3 py-2 text-left text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Summary</th>
            </tr>
          </thead>
          <tbody>
            {pagedEndpoints.map((ep: any) => {
              const riskColor = RISK_COLORS[ep.riskLevel] ?? "#888";
              const methodColor = METHOD_COLORS[ep.method] ?? "#888";
              return (
                <tr key={ep.id} className="border-b border-white/[0.03] hover:bg-white/[0.02] transition-colors">
                  <td className="px-3 py-2">
                    <span className="font-mono font-bold text-[10px]" style={{ color: methodColor }}>{ep.method}</span>
                  </td>
                  <td className="px-3 py-2 font-mono text-foreground truncate max-w-[400px]" title={ep.path}>{ep.path}</td>
                  <td className="px-3 py-2 text-muted-foreground truncate max-w-[150px]">{ep.resource}</td>
                  <td className="px-3 py-2">
                    <span
                      className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                      style={{ color: riskColor, backgroundColor: `${riskColor}15`, border: `1px solid ${riskColor}30` }}
                    >
                      {ep.riskLevel}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-foreground">{ep.trustScore ?? "—"}</td>
                  <td className="px-3 py-2">
                    {ep.allowedForLlm ? (
                      <span className="text-green-400 flex items-center gap-0.5 text-[10px]"><Unlock className="w-3 h-3" /> OK</span>
                    ) : (
                      <span className="text-red-400 flex items-center gap-0.5 text-[10px]"><Lock className="w-3 h-3" /> No</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-muted-foreground truncate max-w-[300px]" title={ep.summary ?? ""}>{ep.summary ?? "—"}</td>
                </tr>
              );
            })}
            {pagedEndpoints.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-12 text-center text-muted-foreground">
                  No endpoints match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex-shrink-0 px-6 py-2 border-t border-white/5 flex items-center justify-between">
          <span className="text-[10px] text-muted-foreground">
            Page {page + 1} of {totalPages}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-2 py-1 text-[10px] rounded border border-white/10 text-muted-foreground hover:bg-white/5 disabled:opacity-30 transition-colors"
            >
              Prev
            </button>
            <button
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="px-2 py-1 text-[10px] rounded border border-white/10 text-muted-foreground hover:bg-white/5 disabled:opacity-30 transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Add to Investigation Dialog ────────────────────────────────────────────

function AddToInvestigationDialog({ node, onClose }: { node: GraphNode; onClose: () => void }): React.JSX.Element {
  const [selectedInvId, setSelectedInvId] = useState<number | null>(null);
  const [adding, setAdding] = useState(false);
  const [added, setAdded] = useState(false);

  const investigationsQ = trpc.graph.listInvestigations.useQuery({ status: "active" });
  const updateMutation = trpc.graph.updateInvestigation.useMutation();
  const utils = trpc.useUtils();

  const investigations = (investigationsQ.data as any)?.sessions ?? (Array.isArray(investigationsQ.data) ? investigationsQ.data : []);

  const handleAdd = async () => {
    if (!selectedInvId) return;
    setAdding(true);
    try {
      const inv = investigations.find((i: any) => i.id === selectedInvId);
      if (!inv) return;
      const existingEvidence = Array.isArray((inv as any).evidence) ? (inv as any).evidence : [];
      const newEvidence = {
        type: node.type,
        label: node.label,
        data: { ...node.properties, nodeId: node.id },
        addedAt: new Date().toISOString(),
      };
      await updateMutation.mutateAsync({
        id: selectedInvId,
        evidence: [...existingEvidence, newEvidence],
      });
      utils.graph.listInvestigations.invalidate();
      setAdded(true);
      toast.success("Evidence added", { description: `"${node.label}" added to investigation` });
      setTimeout(onClose, 1200);
    } catch (err) {
      toast.error("Failed to add evidence");
    } finally {
      setAdding(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="glass-panel rounded-2xl border border-white/10 w-full max-w-md mx-4 shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/5">
          <div className="flex items-center gap-2">
            <FolderPlus className="w-5 h-5 text-indigo-400" />
            <h2 className="text-lg font-display font-bold text-foreground">Add to Investigation</h2>
          </div>
          <button onClick={onClose} className="p-1 rounded hover:bg-white/10 text-muted-foreground"><X className="w-4 h-4" /></button>
        </div>

        <div className="px-6 py-4 space-y-4">
          {/* Node preview */}
          <div className="glass-panel rounded-lg border border-white/5 px-3 py-2">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: NODE_CONFIG[node.type]?.color ?? "#888" }} />
              <span className="text-sm text-foreground font-medium truncate">{node.label}</span>
              <span className="text-[10px] text-muted-foreground font-mono ml-auto">{node.type}</span>
            </div>
          </div>

          {/* Investigation selector */}
          <div>
            <label className="block text-xs text-muted-foreground mb-1.5">Select Active Investigation</label>
            {investigationsQ.isLoading ? (
              <div className="flex items-center gap-2 py-3">
                <Loader2 className="w-4 h-4 animate-spin text-purple-400" />
                <span className="text-xs text-muted-foreground">Loading investigations...</span>
              </div>
            ) : investigations.length === 0 ? (
              <div className="text-xs text-muted-foreground py-3">
                No active investigations. Create one from the Investigations page first.
              </div>
            ) : (
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {investigations.map((inv: any) => (
                  <button
                    key={inv.id}
                    onClick={() => setSelectedInvId(inv.id)}
                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-left transition-colors ${
                      selectedInvId === inv.id
                        ? "bg-purple-500/15 border border-purple-500/30"
                        : "bg-white/5 border border-white/5 hover:bg-white/10"
                    }`}
                  >
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-foreground truncate">{inv.title}</p>
                      <p className="text-[10px] text-muted-foreground">
                        {new Date(inv.createdAt).toLocaleDateString()}
                        {inv.tags?.length > 0 && ` \u2022 ${(inv.tags as string[]).join(", ")}`}
                      </p>
                    </div>
                    {selectedInvId === inv.id && <Check className="w-4 h-4 text-purple-400 flex-shrink-0" />}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="px-6 py-4 border-t border-white/5 flex justify-end gap-2">
          <button onClick={onClose} className="px-4 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors">
            Cancel
          </button>
          <button
            onClick={handleAdd}
            disabled={!selectedInvId || adding || added}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
              added
                ? "bg-green-500/15 text-green-300 border border-green-500/30"
                : !selectedInvId || adding
                  ? "bg-white/5 text-muted-foreground border border-white/10 cursor-not-allowed"
                  : "bg-purple-500/15 text-purple-300 border border-purple-500/30 hover:bg-purple-500/25"
            }`}
          >
            {adding ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : added ? <Check className="w-3.5 h-3.5" /> : <FolderPlus className="w-3.5 h-3.5" />}
            {added ? "Added" : adding ? "Adding..." : "Add Evidence"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main Knowledge Graph Page ───────────────────────────────────────────────

export default function KnowledgeGraph(): React.JSX.Element {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const simulationRef = useRef<d3.Simulation<GraphNode, GraphEdge> | null>(null);
  const zoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const nodesRef = useRef<GraphNode[]>([]);

  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeFilters, setActiveFilters] = useState<Set<string>>(new Set(Object.keys(NODE_CONFIG)));
  const [showRiskPaths, setShowRiskPaths] = useState(false);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [layerFilter, setLayerFilter] = useState<string>("all");
  const [riskFilter, setRiskFilter] = useState<string | undefined>(undefined);
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");

  // Expansion state: tracks which nodes have been expanded
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  const [extraNodes, setExtraNodes] = useState<GraphNode[]>([]);
  const [extraEdges, setExtraEdges] = useState<GraphEdge[]>([]);
  const [expandLoading, setExpandLoading] = useState(false);

  // Pulse-highlight state for search-to-focus
  const [focusNodeId, setFocusNodeId] = useState<string | null>(null);

  // Context menu state
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; node: GraphNode } | null>(null);

  // Hidden and pinned nodes
  const [hiddenNodes, setHiddenNodes] = useState<Set<string>>(new Set());
  const [pinnedNodes, setPinnedNodes] = useState<Set<string>>(new Set());

  // Add to Investigation dialog
  const [investigationDialog, setInvestigationDialog] = useState<{ node: GraphNode } | null>(null);

  // Multi-select mode
  const [multiSelectMode, setMultiSelectMode] = useState(false);
  const [selectedNodes, setSelectedNodes] = useState<Set<string>>(new Set());

  // Fetch graph data
  const overviewQuery = trpc.graph.overviewGraph.useQuery(
    { layer: layerFilter as any, riskLevel: riskFilter as any, limit: 100 },
  );

  const statsQuery = trpc.graph.graphStats.useQuery();
  const searchResults = trpc.graph.searchGraph.useQuery(
    { query: searchQuery, limit: 30 },
    { enabled: searchQuery.length >= 2 }
  );

  // Risk path data
  const riskPathQuery = trpc.graph.detectRiskPaths.useQuery(
    { minScore: 40, limit: 20 },
    { enabled: showRiskPaths }
  );

  const riskPaths: RiskPath[] = useMemo(() => {
    if (!riskPathQuery.data) return [];
    return (riskPathQuery.data as any).paths ?? [];
  }, [riskPathQuery.data]);

  const graphData = overviewQuery.data;
  const isLoading = overviewQuery.isLoading;

  const selectedPath = useMemo(() => {
    if (!selectedPathId) return null;
    return riskPaths.find(p => p.id === selectedPathId) ?? null;
  }, [selectedPathId, riskPaths]);

  const riskPathNodeIds = useMemo(() => {
    if (!selectedPath) return new Set<string>();
    return new Set(selectedPath.hops.map(h => h.nodeId));
  }, [selectedPath]);

  // Merge base graph with expanded nodes
  const filteredData = useMemo(() => {
    if (!graphData) return { nodes: [], edges: [] };
    const allNodes = [...graphData.nodes, ...extraNodes];
    const allEdges = [...graphData.edges, ...extraEdges];
    const filteredNodes = allNodes.filter((n: any) => activeFilters.has(n.type) && !hiddenNodes.has(n.id));
    const nodeIds = new Set(filteredNodes.map((n: any) => n.id));
    const filteredEdges = allEdges.filter((e: any) => {
      const sourceId = typeof e.source === "string" ? e.source : e.source.id;
      const targetId = typeof e.target === "string" ? e.target : e.target.id;
      return nodeIds.has(sourceId) && nodeIds.has(targetId);
    });
    // Deduplicate nodes by id
    const seen = new Set<string>();
    const uniqueNodes = filteredNodes.filter((n: any) => {
      if (seen.has(n.id)) return false;
      seen.add(n.id);
      return true;
    });
    return { nodes: uniqueNodes, edges: filteredEdges };
  }, [graphData, extraNodes, extraEdges, activeFilters, hiddenNodes]);

  // Reset expansion when base graph changes
  useEffect(() => {
    setExpandedNodes(new Set());
    setExtraNodes([]);
    setExtraEdges([]);
  }, [graphData]);

  // ── Node Expansion Handler ──────────────────────────────────────────────

  const utils = trpc.useUtils();

  const handleExpand = useCallback(async (node: GraphNode) => {
    if (expandedNodes.has(node.id)) return;
    setExpandLoading(true);

    try {
      let newData: { nodes: any[]; edges: any[] } = { nodes: [], edges: [] };

      if (node.type === "resource") {
        // Expand resource → show all its endpoints
        const resourceName = node.properties.endpointCount !== undefined
          ? node.label
          : (node.properties.name as string) ?? node.label;
        newData = await utils.graph.endpointsByResource.fetch({ resource: resourceName });
      } else if (node.type === "endpoint") {
        // Expand endpoint → show params and responses
        const idStr = node.id.replace("endpoint-", "");
        const endpointId = parseInt(idStr, 10);
        if (!isNaN(endpointId)) {
          newData = await utils.graph.endpointDetail.fetch({ endpointId });
        }
      }

      if (newData.nodes.length > 0) {
        // Filter out nodes that already exist
        const existingIds = new Set([
          ...filteredData.nodes.map((n: any) => n.id),
          ...extraNodes.map(n => n.id),
        ]);
        const brandNew = newData.nodes.filter((n: any) => !existingIds.has(n.id));
        const brandNewEdges = newData.edges.filter((e: any) => {
          const sid = typeof e.source === "string" ? e.source : e.source.id;
          const tid = typeof e.target === "string" ? e.target : e.target.id;
          // Only add edges where at least one end is new or connects to the expanded node
          return !extraEdges.some((ee: any) => {
            const esid = typeof ee.source === "string" ? ee.source : ee.source.id;
            const etid = typeof ee.target === "string" ? ee.target : ee.target.id;
            return esid === sid && etid === tid;
          });
        });

        // Position new nodes near the parent
        const parentNode = nodesRef.current.find(n => n.id === node.id);
        const px = parentNode?.x ?? 0;
        const py = parentNode?.y ?? 0;
        for (const n of brandNew) {
          (n as any).x = px + (Math.random() - 0.5) * 80;
          (n as any).y = py + (Math.random() - 0.5) * 80;
        }

        setExtraNodes(prev => [...prev, ...brandNew]);
        setExtraEdges(prev => [...prev, ...brandNewEdges]);
      }

      setExpandedNodes(prev => { const next = new Set(Array.from(prev)); next.add(node.id); return next; });
    } catch (err) {
      console.error("Expansion failed:", err);
    } finally {
      setExpandLoading(false);
    }
  }, [expandedNodes, filteredData, extraNodes, extraEdges, utils]);

  // ── Search-to-Focus Handler ─────────────────────────────────────────────

  const handleSearchSelect = useCallback((searchNode: any) => {
    setSelectedNode(searchNode);
    setSearchQuery("");

    // Find the node in the current simulation
    const targetNode = nodesRef.current.find(n => n.id === searchNode.id);
    if (targetNode && svgRef.current && zoomRef.current) {
      const svg = d3.select(svgRef.current);
      const container = containerRef.current;
      if (!container) return;
      const width = container.clientWidth;
      const height = container.clientHeight;

      // Animate zoom to center on the node
      const scale = 1.8;
      const tx = width / 2 - scale * (targetNode.x ?? 0);
      const ty = height / 2 - scale * (targetNode.y ?? 0);

      svg.transition().duration(750).call(
        zoomRef.current.transform,
        d3.zoomIdentity.translate(tx, ty).scale(scale)
      );

      // Trigger pulse highlight
      setFocusNodeId(searchNode.id);
      setTimeout(() => setFocusNodeId(null), 2500);
    }
  }, []);

  // ── D3 Force Simulation ─────────────────────────────────────────────────

  useEffect(() => {
    if (viewMode !== "graph") return;
    if (!svgRef.current || !containerRef.current || filteredData.nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    const container = containerRef.current;
    const width = container.clientWidth;
    const height = container.clientHeight;

    svg.selectAll("*").remove();

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on("zoom", (event) => { g.attr("transform", event.transform); });

    zoomRef.current = zoom;
    svg.call(zoom);
    const g = svg.append("g");

    // Defs for glow effects
    const defs = svg.append("defs");
    const glowFilter = defs.append("filter").attr("id", "risk-glow");
    glowFilter.append("feGaussianBlur").attr("stdDeviation", "4").attr("result", "coloredBlur");
    const feMerge = glowFilter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "coloredBlur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    // Pulse glow for search-to-focus
    const pulseFilter = defs.append("filter").attr("id", "pulse-glow");
    pulseFilter.append("feGaussianBlur").attr("stdDeviation", "6").attr("result", "coloredBlur");
    const pulseMerge = pulseFilter.append("feMerge");
    pulseMerge.append("feMergeNode").attr("in", "coloredBlur");
    pulseMerge.append("feMergeNode").attr("in", "SourceGraphic");

    defs.append("style").text(`
      @keyframes dash-flow { to { stroke-dashoffset: -20; } }
      .risk-path-edge { animation: dash-flow 1s linear infinite; }
      @keyframes pulse-ring { 
        0% { r: 16; opacity: 0.8; } 
        50% { r: 28; opacity: 0.3; } 
        100% { r: 16; opacity: 0.8; } 
      }
      .pulse-ring { animation: pulse-ring 1s ease-in-out infinite; }
    `);

    const nodes = filteredData.nodes.map((n: any) => ({ ...n })) as GraphNode[];
    const edges = filteredData.edges.map((e: any) => ({ ...e })) as GraphEdge[];

    nodesRef.current = nodes;

    const simulation = d3.forceSimulation(nodes)
      .force("link", d3.forceLink<GraphNode, GraphEdge>(edges).id(d => d.id).distance((d: any) => {
        const sourceType = typeof d.source === "string" ? "" : (d.source as GraphNode).type;
        return sourceType === "resource" ? 120 : sourceType === "index" ? 100 : 60;
      }))
      .force("charge", d3.forceManyBody().strength((d: any) => {
        return d.type === "resource" ? -400 : d.type === "use_case" || d.type === "index" ? -250 : -120;
      }))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius((d: any) => (NODE_CONFIG[d.type]?.size ?? 16) / 2 + 8));

    simulationRef.current = simulation;

    // Draw edges
    const link = g.append("g")
      .selectAll("line")
      .data(edges)
      .join("line")
      .attr("stroke", (d: any) => {
        const rel = d.relationship;
        if (rel === "CONTAINS") return "rgba(129,140,248,0.15)";
        if (rel === "USES") return "rgba(52,211,153,0.15)";
        if (rel === "WRITES_TO") return "rgba(251,191,36,0.15)";
        if (rel === "CAN_THROW") return "rgba(248,113,113,0.15)";
        if (rel === "HAS_FIELD") return "rgba(251,146,60,0.12)";
        if (rel === "ACCEPTS") return "rgba(96,165,250,0.15)";
        if (rel === "RETURNS") return "rgba(56,189,248,0.15)";
        return "rgba(255,255,255,0.06)";
      })
      .attr("stroke-width", (d: any) => d.relationship === "CONTAINS" ? 1.5 : 1);

    // Edge labels
    const linkLabel = g.append("g")
      .selectAll("text")
      .data(edges)
      .join("text")
      .text((d: any) => d.relationship)
      .attr("font-size", "7px")
      .attr("fill", "rgba(255,255,255,0.15)")
      .attr("font-family", "'JetBrains Mono', monospace")
      .attr("text-anchor", "middle");

    // Risk path overlay group
    const riskEdgeGroup = g.append("g").attr("class", "risk-edges");

    // Draw nodes
    const node = g.append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .attr("class", "kg-node")
      .style("cursor", "pointer")
      .call(d3.drag<any, GraphNode>()
        .on("start", (event: any, d: GraphNode) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on("drag", (event: any, d: GraphNode) => { d.fx = event.x; d.fy = event.y; })
        .on("end", (event: any, d: GraphNode) => {
          if (!event.active) simulation.alphaTarget(0);
          // Keep pinned nodes fixed
          if (!pinnedNodes.has(d.id)) {
            d.fx = null; d.fy = null;
          }
        })
      );

    // Node circles
    node.append("circle")
      .attr("r", (d: any) => (NODE_CONFIG[d.type]?.size ?? 16) / 2 + 4)
      .attr("fill", (d: any) => {
        if (d.type === "endpoint" && d.properties.riskLevel) {
          const rc = RISK_COLORS[d.properties.riskLevel as string] ?? NODE_CONFIG[d.type]?.color ?? "#888";
          return `${rc}15`;
        }
        return `${NODE_CONFIG[d.type]?.color ?? "#888"}15`;
      })
      .attr("stroke", (d: any) => {
        if (d.type === "endpoint" && d.properties.riskLevel) {
          return `${RISK_COLORS[d.properties.riskLevel as string] ?? "#888"}60`;
        }
        return `${NODE_CONFIG[d.type]?.color ?? "#888"}60`;
      })
      .attr("stroke-width", 1.5);

    // Risk glow ring (hidden by default)
    node.append("circle")
      .attr("class", "risk-glow")
      .attr("r", (d: any) => (NODE_CONFIG[d.type]?.size ?? 16) / 2 + 8)
      .attr("fill", "none")
      .attr("stroke", "transparent")
      .attr("stroke-width", 0)
      .attr("filter", "url(#risk-glow)");

    // Pulse ring for search-to-focus (hidden by default)
    node.append("circle")
      .attr("class", (d: any) => `focus-ring focus-ring-${d.id.replace(/[^a-zA-Z0-9-]/g, "_")}`)
      .attr("r", 16)
      .attr("fill", "none")
      .attr("stroke", "transparent")
      .attr("stroke-width", 0);

    // Multi-select ring (hidden by default, shown via useEffect)
    node.append("circle")
      .attr("class", (d: any) => `select-ring select-ring-${d.id.replace(/[^a-zA-Z0-9-]/g, "_")}`)
      .attr("r", (d: any) => (NODE_CONFIG[d.type]?.size ?? 16) / 2 + 10)
      .attr("fill", "none")
      .attr("stroke", "transparent")
      .attr("stroke-width", 0)
      .attr("stroke-dasharray", "4 2");

    // Method badge for endpoints
    node.filter((d: any) => d.type === "endpoint")
      .append("text")
      .text((d: any) => d.properties.method ?? "")
      .attr("dy", "0.35em")
      .attr("text-anchor", "middle")
      .attr("font-size", "7px")
      .attr("font-weight", "bold")
      .attr("fill", (d: any) => METHOD_COLORS[d.properties.method as string] ?? "#888")
      .attr("font-family", "'JetBrains Mono', monospace");

    // LLM lock icon for blocked endpoints
    node.filter((d: any) => d.type === "endpoint" && !d.properties.llmAllowed)
      .append("text")
      .text("🔒")
      .attr("dx", (d: any) => (NODE_CONFIG[d.type]?.size ?? 16) / 2 + 4)
      .attr("dy", "-4")
      .attr("font-size", "8px");

    // Expansion indicator for expandable nodes
    node.filter((d: any) => d.type === "resource" || d.type === "endpoint")
      .append("text")
      .text((d: any) => expandedNodes.has(d.id) ? "−" : "+")
      .attr("dx", (d: any) => -((NODE_CONFIG[d.type]?.size ?? 16) / 2 + 6))
      .attr("dy", "-4")
      .attr("font-size", "10px")
      .attr("font-weight", "bold")
      .attr("fill", (d: any) => expandedNodes.has(d.id) ? "#34d399" : "#a78bfa")
      .attr("font-family", "'JetBrains Mono', monospace")
      .style("pointer-events", "none");

    // Node labels
    node.append("text")
      .text((d: any) => {
        const label = d.label;
        if (d.type === "endpoint") {
          const path = d.properties.path as string ?? label;
          return path.length > 24 ? path.slice(0, 22) + "…" : path;
        }
        return label.length > 20 ? label.slice(0, 18) + "…" : label;
      })
      .attr("dy", (d: any) => (NODE_CONFIG[d.type]?.size ?? 16) / 2 + 14)
      .attr("text-anchor", "middle")
      .attr("font-size", "8px")
      .attr("fill", "rgba(255,255,255,0.45)")
      .attr("font-family", (d: any) => d.type === "endpoint" ? "'JetBrains Mono', monospace" : "'Inter', sans-serif");

    // Click handler — single click selects, double-click expands, multi-select toggles
    let clickTimer: ReturnType<typeof setTimeout> | null = null;

    node.on("click", (event: any, d: any) => {
      if (clickTimer) {
        clearTimeout(clickTimer);
        clickTimer = null;
        // Double-click → expand (even in multi-select mode)
        if (d.type === "resource" || d.type === "endpoint") {
          handleExpand(d);
        }
      } else {
        clickTimer = setTimeout(() => {
          clickTimer = null;
          if (multiSelectMode || event.shiftKey) {
            // Multi-select: toggle this node
            setSelectedNodes(prev => {
              const next = new Set(Array.from(prev));
              if (next.has(d.id)) next.delete(d.id);
              else next.add(d.id);
              return next;
            });
            // Auto-enable multi-select mode on shift+click
            if (!multiSelectMode && event.shiftKey) setMultiSelectMode(true);
          } else {
            setSelectedNode(d);
          }
        }, 250);
      }
    });

    // Right-click context menu
    node.on("contextmenu", (event: any, d: any) => {
      event.preventDefault();
      event.stopPropagation();
      const containerRect = container.getBoundingClientRect();
      setContextMenu({
        x: event.clientX - containerRect.left,
        y: event.clientY - containerRect.top,
        node: d,
      });
    });

    // Close context menu on background click
    svg.on("click.contextmenu", () => setContextMenu(null));
    svg.on("contextmenu", (event: any) => {
      // Only close if clicking on background (not on a node)
      if (!(event.target as Element).closest(".kg-node")) {
        event.preventDefault();
        setContextMenu(null);
      }
    });

    // Hover effects
    node.on("mouseenter", function (_event: any, d: any) {
      d3.select(this).select("circle:first-child")
        .transition().duration(200)
        .attr("stroke-width", 3)
        .attr("fill", `${NODE_CONFIG[d.type]?.color ?? "#888"}30`);
    });
    node.on("mouseleave", function (_event: any, d: any) {
      d3.select(this).select("circle:first-child")
        .transition().duration(200)
        .attr("stroke-width", 1.5)
        .attr("fill", `${NODE_CONFIG[d.type]?.color ?? "#888"}15`);
    });

    // Tick
    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => (d.source as GraphNode).x ?? 0)
        .attr("y1", (d: any) => (d.source as GraphNode).y ?? 0)
        .attr("x2", (d: any) => (d.target as GraphNode).x ?? 0)
        .attr("y2", (d: any) => (d.target as GraphNode).y ?? 0);

      linkLabel
        .attr("x", (d: any) => (((d.source as GraphNode).x ?? 0) + ((d.target as GraphNode).x ?? 0)) / 2)
        .attr("y", (d: any) => (((d.source as GraphNode).y ?? 0) + ((d.target as GraphNode).y ?? 0)) / 2);

      node.attr("transform", (d: any) => `translate(${d.x ?? 0},${d.y ?? 0})`);

      riskEdgeGroup.selectAll("line").each(function () {
        const el = d3.select(this);
        const sourceId = el.attr("data-source");
        const targetId = el.attr("data-target");
        const sourceNode = nodes.find(n => n.id === sourceId);
        const targetNode = nodes.find(n => n.id === targetId);
        if (sourceNode && targetNode) {
          el.attr("x1", sourceNode.x ?? 0).attr("y1", sourceNode.y ?? 0)
            .attr("x2", targetNode.x ?? 0).attr("y2", targetNode.y ?? 0);
        }
      });
    });

    // Initial zoom to fit
    setTimeout(() => {
      const bounds = (g.node() as SVGGElement)?.getBBox();
      if (bounds) {
        const dx = bounds.width + 100;
        const dy = bounds.height + 100;
        const x = bounds.x - 50;
        const y = bounds.y - 50;
        const scale = Math.min(0.9, Math.min(width / dx, height / dy));
        const translate = [width / 2 - scale * (x + dx / 2), height / 2 - scale * (y + dy / 2)];
        svg.transition().duration(750).call(
          zoom.transform,
          d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale)
        );
      }
    }, 1000);

    return () => { simulation.stop(); };
  }, [filteredData, viewMode, expandedNodes, handleExpand, multiSelectMode]);

  // ── Focus pulse effect ────────────────────────────────────────────────

  useEffect(() => {
    if (!focusNodeId || !svgRef.current) return;
    const svg = d3.select(svgRef.current);
    const safeId = focusNodeId.replace(/[^a-zA-Z0-9-]/g, "_");

    svg.selectAll(`.focus-ring-${safeId}`)
      .attr("stroke", "#c084fc")
      .attr("stroke-width", 3)
      .attr("filter", "url(#pulse-glow)")
      .classed("pulse-ring", true);

    return () => {
      svg.selectAll(`.focus-ring-${safeId}`)
        .attr("stroke", "transparent")
        .attr("stroke-width", 0)
        .attr("filter", null)
        .classed("pulse-ring", false);
    };
  }, [focusNodeId]);

  // ── Multi-select visual highlighting ──────────────────────────────────

  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);

    // Reset all select rings
    svg.selectAll(".select-ring")
      .attr("stroke", "transparent")
      .attr("stroke-width", 0);

    // Highlight selected nodes
    selectedNodes.forEach(nodeId => {
      const safeId = nodeId.replace(/[^a-zA-Z0-9-]/g, "_");
      svg.selectAll(`.select-ring-${safeId}`)
        .attr("stroke", "#22d3ee")
        .attr("stroke-width", 2);
    });
  }, [selectedNodes]);

  // ── Escape key to clear multi-select ──────────────────────────────────

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && multiSelectMode) {
        setMultiSelectMode(false);
        setSelectedNodes(new Set());
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [multiSelectMode]);

  // Risk path highlighting
  useEffect(() => {
    if (!svgRef.current || viewMode !== "graph") return;
    const svg = d3.select(svgRef.current);
    const riskEdgeGroup = svg.select(".risk-edges");

    riskEdgeGroup.selectAll("*").remove();
    svg.selectAll(".risk-glow").attr("stroke", "transparent").attr("stroke-width", 0);

    if (selectedPath && riskPathNodeIds.size > 0) {
      svg.selectAll(".kg-node").each(function () {
        const el = d3.select(this);
        const datum = el.datum() as GraphNode | undefined;
        if (datum && datum.id) {
          if (riskPathNodeIds.has(datum.id)) {
            el.attr("opacity", 1);
            const riskLevel = selectedPath.hops.find(h => h.nodeId === datum.id)?.riskLevel ?? "SAFE";
            const glowColor = RISK_COLORS[riskLevel] ?? RISK_COLORS.SAFE;
            el.select(".risk-glow").transition().duration(400).attr("stroke", glowColor).attr("stroke-width", 3);
          } else {
            el.transition().duration(400).attr("opacity", 0.15);
          }
        }
      });

      svg.selectAll("g > g:first-child line").transition().duration(400).attr("stroke", "rgba(255,255,255,0.03)");

      const hopIds = selectedPath.hops.map(h => h.nodeId);
      for (let i = 0; i < hopIds.length - 1; i++) {
        const riskLevel = selectedPath.hops[i + 1]?.riskLevel ?? "SAFE";
        const edgeColor = RISK_COLORS[riskLevel] ?? "#fbbf24";
        riskEdgeGroup.append("line")
          .attr("data-source", hopIds[i])
          .attr("data-target", hopIds[i + 1])
          .attr("stroke", edgeColor)
          .attr("stroke-width", 2.5)
          .attr("stroke-dasharray", "6 4")
          .attr("class", "risk-path-edge")
          .attr("opacity", 0)
          .transition().duration(400)
          .attr("opacity", 0.9);
      }
    } else {
      svg.selectAll(".kg-node").transition().duration(300).attr("opacity", 1);
      svg.selectAll("g > g:first-child line").transition().duration(300).attr("stroke", "rgba(255,255,255,0.08)");
    }
  }, [selectedPath, riskPathNodeIds, viewMode]);

  const toggleFilter = useCallback((type: string) => {
    setActiveFilters(prev => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type); else next.add(type);
      return next;
    });
  }, []);

  const handleZoomIn = () => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(zoomRef.current.scaleBy, 1.3);
  };

  const handleZoomOut = () => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(zoomRef.current.scaleBy, 0.7);
  };

  // ── Context Menu Handlers ────────────────────────────────────────────

  const handleShowConnected = useCallback((node: GraphNode) => {
    setContextMenu(null);
    if (node.type === "resource" || node.type === "endpoint") {
      handleExpand(node);
    }
  }, [handleExpand]);

  const handleHideNode = useCallback((nodeId: string) => {
    setContextMenu(null);
    setHiddenNodes(prev => { const next = new Set(Array.from(prev)); next.add(nodeId); return next; });
    if (selectedNode?.id === nodeId) setSelectedNode(null);
    toast.success("Node hidden", { description: "Click \"Show All\" to restore hidden nodes." });
  }, [selectedNode]);

  const handleTogglePin = useCallback((node: GraphNode) => {
    setContextMenu(null);
    const isPinned = pinnedNodes.has(node.id);
    setPinnedNodes(prev => {
      const next = new Set(Array.from(prev));
      if (isPinned) { next.delete(node.id); } else { next.add(node.id); }
      return next;
    });
    // Update the D3 node's fixed position
    const simNode = nodesRef.current.find(n => n.id === node.id);
    if (simNode) {
      if (isPinned) { simNode.fx = null; simNode.fy = null; }
      else { simNode.fx = simNode.x; simNode.fy = simNode.y; }
    }
    toast.success(isPinned ? "Node unpinned" : "Node pinned");
  }, [pinnedNodes]);

  const handleCopyNodeId = useCallback((nodeId: string) => {
    setContextMenu(null);
    navigator.clipboard.writeText(nodeId).then(() => {
      toast.success("Copied to clipboard", { description: nodeId });
    });
  }, []);

  const handleShowAll = useCallback(() => {
    setHiddenNodes(new Set());
    toast.success("All hidden nodes restored");
  }, []);

  // ── Graph Export Handlers ─────────────────────────────────────────────

  const handleExportPNG = useCallback(() => {
    if (!svgRef.current) return;
    const svgEl = svgRef.current;
    const serializer = new XMLSerializer();
    const svgStr = serializer.serializeToString(svgEl);
    const canvas = document.createElement("canvas");
    const rect = svgEl.getBoundingClientRect();
    const scale = 2; // retina
    canvas.width = rect.width * scale;
    canvas.height = rect.height * scale;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.scale(scale, scale);
    const img = new window.Image();
    img.onload = () => {
      ctx.fillStyle = "#0a0a0f";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0, rect.width, rect.height);
      const link = document.createElement("a");
      link.download = `knowledge-graph-${Date.now()}.png`;
      link.href = canvas.toDataURL("image/png");
      link.click();
      toast.success("Graph exported as PNG");
    };
    img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svgStr);
  }, []);

  const handleExportSVG = useCallback(() => {
    if (!svgRef.current) return;
    const serializer = new XMLSerializer();
    const svgStr = serializer.serializeToString(svgRef.current);
    const blob = new Blob([svgStr], { type: "image/svg+xml;charset=utf-8" });
    const link = document.createElement("a");
    link.download = `knowledge-graph-${Date.now()}.svg`;
    link.href = URL.createObjectURL(blob);
    link.click();
    URL.revokeObjectURL(link.href);
    toast.success("Graph exported as SVG");
  }, []);

  // ── Add to Investigation Handler ──────────────────────────────────────

  const handleAddToInvestigation = useCallback((node: GraphNode) => {
    setInvestigationDialog({ node });
  }, []);

  // ── Multi-select bulk action handlers ────────────────────────────────

  const handleBulkHide = useCallback(() => {
    setHiddenNodes(prev => {
      const next = new Set(Array.from(prev));
      selectedNodes.forEach(id => next.add(id));
      return next;
    });
    if (selectedNode && selectedNodes.has(selectedNode.id)) setSelectedNode(null);
    toast.success(`${selectedNodes.size} node(s) hidden`);
    setSelectedNodes(new Set());
  }, [selectedNodes, selectedNode]);

  const handleBulkPin = useCallback(() => {
    const allPinned = Array.from(selectedNodes).every(id => pinnedNodes.has(id));
    setPinnedNodes(prev => {
      const next = new Set(Array.from(prev));
      selectedNodes.forEach(id => {
        if (allPinned) next.delete(id);
        else next.add(id);
      });
      return next;
    });
    // Update D3 node positions
    nodesRef.current.forEach(n => {
      if (selectedNodes.has(n.id)) {
        if (allPinned) { n.fx = null; n.fy = null; }
        else { n.fx = n.x; n.fy = n.y; }
      }
    });
    toast.success(allPinned ? `${selectedNodes.size} node(s) unpinned` : `${selectedNodes.size} node(s) pinned`);
  }, [selectedNodes, pinnedNodes]);

  const handleBulkCopyIds = useCallback(() => {
    const ids = Array.from(selectedNodes).join("\n");
    navigator.clipboard.writeText(ids).then(() => {
      toast.success(`${selectedNodes.size} node ID(s) copied`);
    });
  }, [selectedNodes]);

  const handleBulkAddToInvestigation = useCallback(() => {
    // Create a synthetic "multi" node to pass to the investigation dialog
    const multiNode: GraphNode = {
      id: `multi-select-${Date.now()}`,
      type: "multi_select",
      label: `${selectedNodes.size} selected nodes`,
      properties: {
        nodeIds: Array.from(selectedNodes),
        nodeLabels: Array.from(selectedNodes).map(id => {
          const n = nodesRef.current.find(nd => nd.id === id) ?? filteredData.nodes.find((nd: any) => nd.id === id);
          return n ? n.label : id;
        }),
      },
    };
    setInvestigationDialog({ node: multiNode });
  }, [selectedNodes, filteredData]);

  const handleSelectAll = useCallback(() => {
    const allIds = new Set(filteredData.nodes.map((n: any) => n.id));
    setSelectedNodes(allIds);
  }, [filteredData]);

  const handleDeselectAll = useCallback(() => {
    setSelectedNodes(new Set());
  }, []);

  const toggleMultiSelect = useCallback(() => {
    setMultiSelectMode(prev => {
      if (prev) setSelectedNodes(new Set()); // Clear selection when exiting
      return !prev;
    });
  }, []);

  return (
    <div className="flex flex-col h-[calc(100vh-3.5rem)]">
      {/* Header */}
      <div className="flex-shrink-0 px-6 py-4 border-b border-white/5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-purple-500/15 border border-purple-500/30 flex items-center justify-center">
              <Network className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <h1 className="text-lg font-display font-bold text-foreground">Knowledge Graph</h1>
              <p className="text-xs text-muted-foreground">
                4-Layer API Ontology
                {statsQuery.data && ` \u2022 ${statsQuery.data.endpoints} endpoints \u2022 ${statsQuery.data.resources} resources`}
                {expandedNodes.size > 0 && ` \u2022 ${expandedNodes.size} expanded`}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* View mode toggle */}
            <div className="flex items-center rounded-lg border border-white/10 overflow-hidden">
              <button
                onClick={() => setViewMode("graph")}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs transition-colors ${
                  viewMode === "graph"
                    ? "bg-purple-500/15 text-purple-300 border-r border-white/10"
                    : "text-muted-foreground hover:bg-white/5 border-r border-white/10"
                }`}
              >
                <Network className="w-3.5 h-3.5" />
                Graph
              </button>
              <button
                onClick={() => setViewMode("table")}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs transition-colors ${
                  viewMode === "table"
                    ? "bg-purple-500/15 text-purple-300"
                    : "text-muted-foreground hover:bg-white/5"
                }`}
              >
                <List className="w-3.5 h-3.5" />
                Table
              </button>
            </div>

            {viewMode === "graph" && (
              <>
                {/* Layer filter */}
                <select
                  value={layerFilter}
                  onChange={e => setLayerFilter(e.target.value)}
                  className="text-xs bg-white/5 border border-white/10 rounded-lg px-2 py-1.5 text-foreground outline-none focus:border-purple-500/30"
                >
                  <option value="all">All Layers</option>
                  <option value="api_ontology">API Ontology</option>
                  <option value="operational_semantics">Operational Semantics</option>
                  <option value="schema_lineage">Schema Lineage</option>
                  <option value="error_failure">Error & Failure</option>
                </select>

                {/* Risk filter */}
                <select
                  value={riskFilter ?? ""}
                  onChange={e => setRiskFilter(e.target.value || undefined)}
                  className="text-xs bg-white/5 border border-white/10 rounded-lg px-2 py-1.5 text-foreground outline-none focus:border-purple-500/30"
                >
                  <option value="">All Risk</option>
                  <option value="SAFE">SAFE</option>
                  <option value="MUTATING">MUTATING</option>
                  <option value="DESTRUCTIVE">DESTRUCTIVE</option>
                </select>

                {/* Search */}
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                  <input
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    placeholder="Search KG..."
                    className="pl-8 pr-3 py-1.5 text-xs bg-white/5 border border-white/10 rounded-lg text-foreground placeholder:text-muted-foreground outline-none focus:border-purple-500/30 w-44"
                  />
                  {searchResults.data && searchResults.data.length > 0 && searchQuery.length >= 2 && (
                    <div className="absolute top-full mt-1 left-0 w-72 glass-panel rounded-lg border border-white/10 shadow-2xl z-30 max-h-60 overflow-y-auto">
                      {searchResults.data.slice(0, 10).map((node: any) => {
                        const config = NODE_CONFIG[node.type] || NODE_CONFIG.endpoint;
                        return (
                          <button
                            key={node.id}
                            onClick={() => handleSearchSelect(node)}
                            className="w-full flex items-center gap-2 px-3 py-2 text-xs hover:bg-white/5 transition-colors"
                          >
                            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: config.color }} />
                            <span className="text-foreground truncate">{node.label}</span>
                            <span className="text-[10px] text-muted-foreground font-mono ml-auto">{node.type}</span>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Risk Paths toggle */}
                <button
                  onClick={() => { setShowRiskPaths(!showRiskPaths); if (showRiskPaths) setSelectedPathId(null); }}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg border transition-colors ${
                    showRiskPaths
                      ? "border-red-500/30 bg-red-500/15 text-red-300"
                      : "border-white/10 text-muted-foreground hover:bg-white/5 hover:text-foreground"
                  }`}
                >
                  <Route className="w-3.5 h-3.5" />
                  Risk Paths
                  {riskPaths.length > 0 && (
                    <span className="ml-1 px-1.5 py-0.5 rounded-full text-[9px] font-mono bg-red-500/20 text-red-300">
                      {riskPaths.length}
                    </span>
                  )}
                </button>

                {/* Multi-select toggle */}
                <button
                  onClick={toggleMultiSelect}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg border transition-colors ${
                    multiSelectMode
                      ? "border-cyan-500/30 bg-cyan-500/15 text-cyan-300"
                      : "border-white/10 text-muted-foreground hover:bg-white/5 hover:text-foreground"
                  }`}
                  title="Toggle multi-select mode (or hold Shift+click)"
                >
                  <SquareMousePointer className="w-3.5 h-3.5" />
                  Select
                  {selectedNodes.size > 0 && (
                    <span className="ml-1 px-1.5 py-0.5 rounded-full text-[9px] font-mono bg-cyan-500/20 text-cyan-300">
                      {selectedNodes.size}
                    </span>
                  )}
                </button>
              </>
            )}

            {/* Export */}
            {viewMode === "graph" && (
              <div className="flex items-center rounded-lg border border-white/10 overflow-hidden">
                <button
                  onClick={handleExportPNG}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 text-[10px] text-muted-foreground hover:bg-white/5 hover:text-foreground transition-colors border-r border-white/10"
                  title="Export as PNG"
                >
                  <ImageIcon className="w-3.5 h-3.5" />
                  PNG
                </button>
                <button
                  onClick={handleExportSVG}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 text-[10px] text-muted-foreground hover:bg-white/5 hover:text-foreground transition-colors"
                  title="Export as SVG"
                >
                  <Download className="w-3.5 h-3.5" />
                  SVG
                </button>
              </div>
            )}

            {/* Refresh */}
            <button
              onClick={() => overviewQuery.refetch()}
              className="p-1.5 rounded-lg border border-white/10 text-muted-foreground hover:bg-white/5 hover:text-foreground transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>
      </div>

      {/* Content area */}
      {viewMode === "table" ? (
        <EndpointTableView />
      ) : (
        <div ref={containerRef} className="flex-1 relative bg-black/20 overflow-hidden">
          {isLoading ? (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="flex flex-col items-center gap-3">
                <Loader2 className="w-8 h-8 text-purple-400 animate-spin" />
                <p className="text-sm text-muted-foreground">Loading Knowledge Graph...</p>
              </div>
            </div>
          ) : filteredData.nodes.length === 0 ? (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="flex flex-col items-center gap-3 text-center px-8">
                <div className="w-16 h-16 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center">
                  <Database className="w-8 h-8 text-muted-foreground" />
                </div>
                <h3 className="text-lg font-display font-bold text-foreground">No Graph Data</h3>
                <p className="text-sm text-muted-foreground max-w-md">
                  The Knowledge Graph is empty. Run the KG extraction pipeline from the Data Pipeline page to populate the 4-layer API ontology.
                </p>
                <div className="flex items-center gap-1.5 text-xs text-muted-foreground mt-2">
                  <Info className="w-3.5 h-3.5" />
                  <span>Navigate to Intelligence &rarr; Data Pipeline to start extraction</span>
                </div>
              </div>
            </div>
          ) : (
            <svg ref={svgRef} className="w-full h-full" />
          )}

          {/* Zoom controls */}
          <div className="absolute top-4 left-4 flex flex-col gap-1 z-10">
            <button onClick={handleZoomIn} className="p-1.5 glass-panel rounded-lg border border-white/10 text-muted-foreground hover:text-foreground transition-colors">
              <ZoomIn className="w-4 h-4" />
            </button>
            <button onClick={handleZoomOut} className="p-1.5 glass-panel rounded-lg border border-white/10 text-muted-foreground hover:text-foreground transition-colors">
              <ZoomOut className="w-4 h-4" />
            </button>
            <button
              onClick={() => {
                if (svgRef.current && zoomRef.current) {
                  d3.select(svgRef.current).transition().duration(500).call(
                    zoomRef.current.transform, d3.zoomIdentity
                  );
                }
              }}
              className="p-1.5 glass-panel rounded-lg border border-white/10 text-muted-foreground hover:text-foreground transition-colors"
            >
              <Maximize2 className="w-4 h-4" />
            </button>
          </div>

          {/* Expansion hint */}
          {!selectedNode && !showRiskPaths && !multiSelectMode && filteredData.nodes.length > 0 && expandedNodes.size === 0 && (
            <div className="absolute top-4 left-1/2 -translate-x-1/2 glass-panel rounded-lg border border-white/10 px-3 py-1.5 z-10 flex items-center gap-2">
              <MousePointerClick className="w-3.5 h-3.5 text-purple-400" />
              <span className="text-[10px] text-muted-foreground">Double-click a resource or endpoint to expand its neighbors</span>
            </div>
          )}

          {/* Multi-select floating toolbar */}
          {multiSelectMode && (
            <div className="absolute top-4 left-1/2 -translate-x-1/2 glass-panel rounded-xl border border-cyan-500/20 px-2 py-1.5 z-20 flex items-center gap-1">
              <div className="flex items-center gap-1.5 px-2 border-r border-white/10">
                <SquareMousePointer className="w-3.5 h-3.5 text-cyan-400" />
                <span className="text-xs text-cyan-300 font-mono">
                  {selectedNodes.size > 0 ? `${selectedNodes.size} selected` : "Click nodes to select"}
                </span>
              </div>

              {/* Select All / Deselect All */}
              <button
                onClick={handleSelectAll}
                className="flex items-center gap-1 px-2 py-1 text-[10px] text-muted-foreground hover:bg-white/5 hover:text-foreground rounded transition-colors"
                title="Select all visible nodes"
              >
                <CheckSquare className="w-3 h-3" />
                All
              </button>
              <button
                onClick={handleDeselectAll}
                className="flex items-center gap-1 px-2 py-1 text-[10px] text-muted-foreground hover:bg-white/5 hover:text-foreground rounded transition-colors"
                title="Deselect all"
              >
                <Square className="w-3 h-3" />
                None
              </button>

              <div className="w-px h-5 bg-white/10" />

              {/* Bulk actions — only enabled when nodes are selected */}
              <button
                onClick={handleBulkHide}
                disabled={selectedNodes.size === 0}
                className={`flex items-center gap-1 px-2 py-1 text-[10px] rounded transition-colors ${
                  selectedNodes.size > 0
                    ? "text-orange-300 hover:bg-orange-500/10"
                    : "text-muted-foreground/40 cursor-not-allowed"
                }`}
                title="Hide selected nodes"
              >
                <EyeOff className="w-3 h-3" />
                Hide
              </button>
              <button
                onClick={handleBulkPin}
                disabled={selectedNodes.size === 0}
                className={`flex items-center gap-1 px-2 py-1 text-[10px] rounded transition-colors ${
                  selectedNodes.size > 0
                    ? "text-blue-300 hover:bg-blue-500/10"
                    : "text-muted-foreground/40 cursor-not-allowed"
                }`}
                title="Pin/Unpin selected nodes"
              >
                <Pin className="w-3 h-3" />
                Pin
              </button>
              <button
                onClick={handleBulkCopyIds}
                disabled={selectedNodes.size === 0}
                className={`flex items-center gap-1 px-2 py-1 text-[10px] rounded transition-colors ${
                  selectedNodes.size > 0
                    ? "text-green-300 hover:bg-green-500/10"
                    : "text-muted-foreground/40 cursor-not-allowed"
                }`}
                title="Copy node IDs"
              >
                <Copy className="w-3 h-3" />
                IDs
              </button>
              <button
                onClick={handleBulkAddToInvestigation}
                disabled={selectedNodes.size === 0}
                className={`flex items-center gap-1 px-2 py-1 text-[10px] rounded transition-colors ${
                  selectedNodes.size > 0
                    ? "text-indigo-300 hover:bg-indigo-500/10"
                    : "text-muted-foreground/40 cursor-not-allowed"
                }`}
                title="Add selected to investigation"
              >
                <FolderPlus className="w-3 h-3" />
                Investigate
              </button>

              <div className="w-px h-5 bg-white/10" />

              {/* Exit multi-select */}
              <button
                onClick={toggleMultiSelect}
                className="flex items-center gap-1 px-2 py-1 text-[10px] text-muted-foreground hover:bg-white/5 hover:text-foreground rounded transition-colors"
                title="Exit multi-select (Esc)"
              >
                <X className="w-3 h-3" />
                Exit
              </button>
            </div>
          )}

          {/* Stats overlay */}
          {statsQuery.data && !showRiskPaths && !selectedNode && (
            <StatsOverlay stats={statsQuery.data} />
          )}

          {/* Risk Path Panel */}
          {showRiskPaths && (
            <RiskPathPanel
              paths={riskPaths}
              selectedPathId={selectedPathId}
              onSelectPath={setSelectedPathId}
              isLoading={riskPathQuery.isLoading}
              onClose={() => { setShowRiskPaths(false); setSelectedPathId(null); }}
            />
          )}

          {/* Active risk path indicator */}
          {selectedPath && (
            <div className="absolute bottom-4 right-4 glass-panel rounded-xl border border-red-500/20 px-4 py-3 z-10 max-w-xs">
              <div className="flex items-center gap-2 mb-1">
                <Route className="w-3.5 h-3.5 text-red-400" />
                <p className="text-xs font-medium text-foreground">Active Risk Path</p>
                <button onClick={() => setSelectedPathId(null)} className="ml-auto p-0.5 rounded hover:bg-white/10 text-muted-foreground">
                  <EyeOff className="w-3 h-3" />
                </button>
              </div>
              <p className="text-[10px] text-muted-foreground">{selectedPath.summary}</p>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-[10px] font-mono" style={{ color: RISK_COLORS[selectedPath.riskLevel] ?? "#fbbf24" }}>
                  Score: {selectedPath.score}/100
                </span>
                <span className="text-[10px] text-muted-foreground">{selectedPath.hops.length} nodes</span>
              </div>
            </div>
          )}

          {/* Legend */}
          <GraphLegend activeFilters={activeFilters} onToggle={toggleFilter} />

          {/* Node detail panel */}
          {selectedNode && !showRiskPaths && (
            <NodeDetailPanel
              node={selectedNode}
              onClose={() => setSelectedNode(null)}
              onExpand={handleExpand}
              isExpanded={expandedNodes.has(selectedNode.id)}
              expandLoading={expandLoading}
              onAddToInvestigation={handleAddToInvestigation}
            />
          )}

          {/* Context Menu */}
          {contextMenu && (
            <div
              className="absolute z-50 glass-panel rounded-xl border border-white/10 shadow-2xl py-1 min-w-[200px]"
              style={{ left: contextMenu.x, top: contextMenu.y }}
              onClick={e => e.stopPropagation()}
            >
              <div className="px-3 py-1.5 border-b border-white/5">
                <p className="text-[10px] text-muted-foreground font-mono truncate max-w-[180px]">{contextMenu.node.label}</p>
                <p className="text-[9px] text-muted-foreground">{contextMenu.node.type}</p>
              </div>
              {(contextMenu.node.type === "resource" || contextMenu.node.type === "endpoint") && (
                <button
                  onClick={() => handleShowConnected(contextMenu.node)}
                  className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-white/5 transition-colors"
                >
                  <Eye className="w-3.5 h-3.5 text-purple-400" />
                  Show Connected Nodes
                </button>
              )}
              <button
                onClick={() => handleHideNode(contextMenu.node.id)}
                className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-white/5 transition-colors"
              >
                <EyeOff className="w-3.5 h-3.5 text-orange-400" />
                Hide This Node
              </button>
              <button
                onClick={() => handleTogglePin(contextMenu.node)}
                className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-white/5 transition-colors"
              >
                {pinnedNodes.has(contextMenu.node.id) ? (
                  <><PinOff className="w-3.5 h-3.5 text-blue-400" /> Unpin Position</>
                ) : (
                  <><Pin className="w-3.5 h-3.5 text-blue-400" /> Pin Position</>
                )}
              </button>
              <button
                onClick={() => handleCopyNodeId(contextMenu.node.id)}
                className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-white/5 transition-colors"
              >
                <Copy className="w-3.5 h-3.5 text-green-400" />
                Copy Node ID
              </button>
              <div className="border-t border-white/5 mt-1 pt-1">
                <button
                  onClick={() => { setContextMenu(null); handleAddToInvestigation(contextMenu.node); }}
                  className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-white/5 transition-colors"
                >
                  <FolderPlus className="w-3.5 h-3.5 text-indigo-400" />
                  Add to Investigation
                </button>
              </div>
              <div className="border-t border-white/5 mt-1 pt-1">
                <button
                  onClick={() => {
                    setContextMenu(null);
                    if (!multiSelectMode) setMultiSelectMode(true);
                    setSelectedNodes(prev => {
                      const next = new Set(Array.from(prev));
                      if (next.has(contextMenu.node.id)) next.delete(contextMenu.node.id);
                      else next.add(contextMenu.node.id);
                      return next;
                    });
                  }}
                  className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-white/5 transition-colors"
                >
                  {selectedNodes.has(contextMenu.node.id) ? (
                    <><Square className="w-3.5 h-3.5 text-cyan-400" /> Deselect Node</>
                  ) : (
                    <><CheckSquare className="w-3.5 h-3.5 text-cyan-400" /> Select Node</>
                  )}
                </button>
              </div>
            </div>
          )}

          {/* Hidden nodes indicator */}
          {hiddenNodes.size > 0 && (
            <div className="absolute bottom-4 right-4 glass-panel rounded-xl border border-orange-500/20 px-4 py-2.5 z-10 flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                <EyeOff className="w-3.5 h-3.5 text-orange-400" />
                <span className="text-xs text-orange-300 font-mono">{hiddenNodes.size} hidden</span>
              </div>
              <button
                onClick={handleShowAll}
                className="text-xs text-purple-300 hover:text-purple-200 transition-colors font-medium"
              >
                Show All
              </button>
            </div>
          )}
        </div>
      )}

      {/* Add to Investigation Dialog */}
      {investigationDialog && (
        <AddToInvestigationDialog
          node={investigationDialog.node}
          onClose={() => setInvestigationDialog(null)}
        />
      )}
    </div>
  );
}
