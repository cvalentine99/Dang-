import React, { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import * as d3 from "d3";
import {
  Network, Search, ZoomIn, ZoomOut, Maximize2, RefreshCw,
  Globe, Box, Layers, AlertTriangle, Database, FileText, Key,
  X, ChevronRight, Loader2, Info, Route, EyeOff, Shield,
  Lock, Unlock, Activity, Zap, Filter,
} from "lucide-react";

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

// ── Detail Panel ────────────────────────────────────────────────────────────

function NodeDetailPanel({ node, onClose }: { node: GraphNode; onClose: () => void }): React.JSX.Element {
  const config = NODE_CONFIG[node.type] || NODE_CONFIG.endpoint;
  const Icon = config.icon;
  const riskLevel = node.properties.riskLevel as string | undefined;
  const riskColor = riskLevel ? RISK_COLORS[riskLevel] ?? "#888" : undefined;

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

// ── Main Knowledge Graph Page ───────────────────────────────────────────────

export default function KnowledgeGraph(): React.JSX.Element {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const simulationRef = useRef<d3.Simulation<GraphNode, GraphEdge> | null>(null);

  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeFilters, setActiveFilters] = useState<Set<string>>(new Set(Object.keys(NODE_CONFIG)));
  const [showRiskPaths, setShowRiskPaths] = useState(false);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [layerFilter, setLayerFilter] = useState<string>("all");
  const [riskFilter, setRiskFilter] = useState<string | undefined>(undefined);

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

  // Filter nodes based on active type filters
  const filteredData = useMemo(() => {
    if (!graphData) return { nodes: [], edges: [] };
    const filteredNodes = graphData.nodes.filter((n: any) => activeFilters.has(n.type));
    const nodeIds = new Set(filteredNodes.map((n: any) => n.id));
    const filteredEdges = graphData.edges.filter((e: any) => {
      const sourceId = typeof e.source === "string" ? e.source : e.source.id;
      const targetId = typeof e.target === "string" ? e.target : e.target.id;
      return nodeIds.has(sourceId) && nodeIds.has(targetId);
    });
    return { nodes: filteredNodes, edges: filteredEdges };
  }, [graphData, activeFilters]);

  // D3 Force Simulation
  useEffect(() => {
    if (!svgRef.current || !containerRef.current || filteredData.nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    const container = containerRef.current;
    const width = container.clientWidth;
    const height = container.clientHeight;

    svg.selectAll("*").remove();

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on("zoom", (event) => { g.attr("transform", event.transform); });

    svg.call(zoom);
    const g = svg.append("g");

    // Defs for glow effects
    const defs = svg.append("defs");
    const glowFilter = defs.append("filter").attr("id", "risk-glow");
    glowFilter.append("feGaussianBlur").attr("stdDeviation", "4").attr("result", "coloredBlur");
    const feMerge = glowFilter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "coloredBlur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    defs.append("style").text(`
      @keyframes dash-flow { to { stroke-dashoffset: -20; } }
      .risk-path-edge { animation: dash-flow 1s linear infinite; }
    `);

    const nodes = filteredData.nodes.map((n: any) => ({ ...n })) as GraphNode[];
    const edges = filteredData.edges.map((e: any) => ({ ...e })) as GraphEdge[];

    // Vary force based on node type — resources are hubs
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
      .style("cursor", "pointer")
      .call(d3.drag<any, GraphNode>()
        .on("start", (event: any, d: GraphNode) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on("drag", (event: any, d: GraphNode) => { d.fx = event.x; d.fy = event.y; })
        .on("end", (event: any, d: GraphNode) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null; d.fy = null;
        })
      );

    // Node circles — color by risk level for endpoints, by type for others
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

    // Method badge for endpoints
    node.filter((d: any) => d.type === "endpoint")
      .append("text")
      .text((d: any) => d.properties.method ?? "")
      .attr("dy", "0.35em")
      .attr("text-anchor", "middle")
      .attr("font-size", "7px")
      .attr("font-weight", "bold")
      .attr("fill", (d: any) => {
        const m = d.properties.method;
        if (m === "GET") return "#34d399";
        if (m === "POST") return "#60a5fa";
        if (m === "PUT") return "#fbbf24";
        if (m === "DELETE") return "#ef4444";
        return "#888";
      })
      .attr("font-family", "'JetBrains Mono', monospace");

    // LLM lock icon for blocked endpoints
    node.filter((d: any) => d.type === "endpoint" && !d.properties.llmAllowed)
      .append("text")
      .text("🔒")
      .attr("dx", (d: any) => (NODE_CONFIG[d.type]?.size ?? 16) / 2 + 4)
      .attr("dy", "-4")
      .attr("font-size", "8px");

    // Node labels
    node.append("text")
      .text((d: any) => {
        const label = d.label;
        if (d.type === "endpoint") {
          // Show just the path, not the method (method is shown in badge)
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

    // Click handler
    node.on("click", (_event: any, d: any) => { setSelectedNode(d); });

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
  }, [filteredData]);

  // Risk path highlighting
  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    const riskEdgeGroup = svg.select(".risk-edges");

    riskEdgeGroup.selectAll("*").remove();
    svg.selectAll(".risk-glow").attr("stroke", "transparent").attr("stroke-width", 0);

    if (selectedPath && riskPathNodeIds.size > 0) {
      svg.selectAll("g > g > g").each(function () {
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
      svg.selectAll("g > g > g").transition().duration(300).attr("opacity", 1);
      svg.selectAll("g > g:first-child line").transition().duration(300).attr("stroke", "rgba(255,255,255,0.08)");
    }
  }, [selectedPath, riskPathNodeIds]);

  const toggleFilter = useCallback((type: string) => {
    setActiveFilters(prev => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type); else next.add(type);
      return next;
    });
  }, []);

  const handleZoomIn = () => {
    if (!svgRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(d3.zoom<SVGSVGElement, unknown>().scaleBy as never, 1.3);
  };

  const handleZoomOut = () => {
    if (!svgRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(d3.zoom<SVGSVGElement, unknown>().scaleBy as never, 0.7);
  };

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
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
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
                        onClick={() => { setSelectedNode(node); setSearchQuery(""); }}
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

      {/* Graph area */}
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
              if (svgRef.current) {
                d3.select(svgRef.current).transition().duration(500).call(
                  d3.zoom<SVGSVGElement, unknown>().transform as never, d3.zoomIdentity
                );
              }
            }}
            className="p-1.5 glass-panel rounded-lg border border-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
        </div>

        {/* Stats overlay */}
        {statsQuery.data && !showRiskPaths && (
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
          <NodeDetailPanel node={selectedNode} onClose={() => setSelectedNode(null)} />
        )}
      </div>
    </div>
  );
}
