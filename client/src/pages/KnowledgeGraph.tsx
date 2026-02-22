import React, { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import * as d3 from "d3";
import {
  Network, Search, ZoomIn, ZoomOut, Maximize2, RefreshCw,
  Server, Cpu, Globe, Package, UserCheck, ShieldAlert, AlertTriangle,
  X, ChevronRight, Loader2, Database, Info, Route, Eye, EyeOff,
} from "lucide-react";

// ── Types ───────────────────────────────────────────────────────────────────

interface GraphNode {
  id: string;
  type: "endpoint" | "process" | "network_port" | "software_package" | "identity" | "vulnerability" | "security_event";
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

interface AttackPathHop {
  nodeId: string;
  nodeType: string;
  label: string;
  stage: string;
  severity: "critical" | "high" | "medium" | "low";
  properties: Record<string, unknown>;
}

interface AttackPath {
  id: string;
  name: string;
  riskScore: number;
  hops: AttackPathHop[];
  description: string;
}

// ── Node Config ─────────────────────────────────────────────────────────────

const NODE_CONFIG: Record<string, { color: string; icon: typeof Server; size: number }> = {
  endpoint: { color: "#a78bfa", icon: Server, size: 24 },
  process: { color: "#60a5fa", icon: Cpu, size: 16 },
  network_port: { color: "#34d399", icon: Globe, size: 14 },
  software_package: { color: "#fbbf24", icon: Package, size: 14 },
  identity: { color: "#f472b6", icon: UserCheck, size: 16 },
  vulnerability: { color: "#ef4444", icon: ShieldAlert, size: 18 },
  security_event: { color: "#f97316", icon: AlertTriangle, size: 16 },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#fbbf24",
  low: "#34d399",
};

// ── Detail Panel ────────────────────────────────────────────────────────────

function NodeDetailPanel({
  node,
  onClose,
}: {
  node: GraphNode;
  onClose: () => void;
}): React.JSX.Element {
  const config = NODE_CONFIG[node.type] || NODE_CONFIG.endpoint;
  const Icon = config.icon;

  const properties = Object.entries(node.properties).filter(
    ([key]) => !["x", "y", "fx", "fy", "index", "vx", "vy"].includes(key)
  );

  return (
    <div className="absolute top-4 right-4 w-80 glass-panel rounded-xl border border-white/10 shadow-2xl z-20 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/5">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${config.color}20`, border: `1px solid ${config.color}40` }}>
            <Icon className="w-4 h-4" style={{ color: config.color }} />
          </div>
          <div>
            <p className="text-sm font-medium text-foreground truncate max-w-[180px]">{node.label}</p>
            <p className="text-[10px] text-muted-foreground font-mono">{node.type}</p>
          </div>
        </div>
        <button onClick={onClose} className="p-1 rounded hover:bg-white/10 transition-colors text-muted-foreground">
          <X className="w-4 h-4" />
        </button>
      </div>
      <div className="px-4 py-3 max-h-80 overflow-y-auto space-y-1.5">
        {properties.map(([key, value]) => (
          <div key={key} className="flex items-start gap-2">
            <span className="text-[11px] text-muted-foreground font-mono flex-shrink-0 w-28 truncate">{key}</span>
            <span className="text-[11px] text-foreground font-mono break-all">
              {value === null || value === undefined ? <span className="text-muted-foreground italic">null</span> : String(value)}
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
  return (
    <div className="absolute bottom-4 left-4 glass-panel rounded-xl border border-white/10 px-3 py-2 z-10">
      <p className="text-[10px] text-muted-foreground mb-1.5 font-medium">Entity Types</p>
      <div className="flex flex-wrap gap-1.5">
        {Object.entries(NODE_CONFIG).map(([type, config]) => {
          const active = activeFilters.has(type);
          return (
            <button
              key={type}
              onClick={() => onToggle(type)}
              className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono transition-all border ${
                active
                  ? "border-white/20 bg-white/5 text-foreground"
                  : "border-transparent bg-white/[0.02] text-muted-foreground opacity-50"
              }`}
            >
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: active ? config.color : `${config.color}40` }} />
              {type.replace("_", " ")}
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ── Attack Path Panel ───────────────────────────────────────────────────────

function AttackPathPanel({
  paths,
  selectedPathId,
  onSelectPath,
  isLoading,
  onClose,
}: {
  paths: AttackPath[];
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
          <h3 className="text-sm font-medium text-foreground">Attack Paths</h3>
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
          <ShieldAlert className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
          <p className="text-xs text-muted-foreground">No attack paths detected.</p>
          <p className="text-[10px] text-muted-foreground mt-1">Run the ETL pipeline to populate graph data.</p>
        </div>
      ) : (
        <div className="overflow-y-auto max-h-[calc(100vh-12rem)]">
          {paths.map((path) => {
            const isSelected = selectedPathId === path.id;
            const riskColor = path.riskScore >= 8 ? SEVERITY_COLORS.critical
              : path.riskScore >= 6 ? SEVERITY_COLORS.high
              : path.riskScore >= 4 ? SEVERITY_COLORS.medium
              : SEVERITY_COLORS.low;

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
                    <p className="text-xs font-medium text-foreground truncate">{path.name}</p>
                    <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-2">{path.description}</p>
                  </div>
                  <div className="flex-shrink-0 flex flex-col items-end gap-1">
                    <span
                      className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded"
                      style={{ color: riskColor, backgroundColor: `${riskColor}15`, border: `1px solid ${riskColor}30` }}
                    >
                      {path.riskScore.toFixed(1)}
                    </span>
                    <span className="text-[10px] text-muted-foreground">{path.hops.length} hops</span>
                  </div>
                </div>

                {/* Kill chain stages */}
                {isSelected && (
                  <div className="mt-2 space-y-1">
                    {path.hops.map((hop, i) => {
                      const hopColor = SEVERITY_COLORS[hop.severity] || SEVERITY_COLORS.low;
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

// ── Main Knowledge Graph Page ───────────────────────────────────────────────

export default function KnowledgeGraph(): React.JSX.Element {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const simulationRef = useRef<d3.Simulation<GraphNode, GraphEdge> | null>(null);

  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeFilters, setActiveFilters] = useState<Set<string>>(new Set(Object.keys(NODE_CONFIG)));
  const [viewMode, setViewMode] = useState<"overview" | "endpoint">("overview");
  const [selectedAgent, setSelectedAgent] = useState<string>("");
  const [showAttackPaths, setShowAttackPaths] = useState(false);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);

  // Fetch graph data
  const overviewQuery = trpc.graph.overviewGraph.useQuery(
    { limit: 50 },
    { enabled: viewMode === "overview" }
  );

  const endpointQuery = trpc.graph.endpointGraph.useQuery(
    { agentId: selectedAgent },
    { enabled: viewMode === "endpoint" && !!selectedAgent }
  );

  const statsQuery = trpc.graph.graphStats.useQuery();
  const searchResults = trpc.graph.searchGraph.useQuery(
    { query: searchQuery, limit: 30 },
    { enabled: searchQuery.length >= 2 }
  );

  // Attack path data
  const attackPathQuery = trpc.graph.detectAttackPaths.useQuery(
    { minCvss: 5.0, limit: 20 },
    { enabled: showAttackPaths }
  );

  // Extract paths array from the result
  const attackPaths: AttackPath[] = useMemo(() => {
    if (!attackPathQuery.data) return [];
    const result = attackPathQuery.data as unknown as { paths: AttackPath[]; totalPaths: number; maxScore: number; criticalPaths: number };
    return result.paths ?? [];
  }, [attackPathQuery.data]);

  const graphData = viewMode === "overview" ? overviewQuery.data : endpointQuery.data;
  const isLoading = viewMode === "overview" ? overviewQuery.isLoading : endpointQuery.isLoading;

  // Get the selected attack path
  const selectedPath = useMemo(() => {
    if (!selectedPathId) return null;
    return attackPaths.find((p: AttackPath) => p.id === selectedPathId) ?? null;
  }, [selectedPathId, attackPaths]);

  // Set of node IDs that are on the selected attack path
  const attackPathNodeIds = useMemo(() => {
    if (!selectedPath) return new Set<string>();
    return new Set(selectedPath.hops.map((h: AttackPathHop) => h.nodeId));
  }, [selectedPath]);

  // Filter nodes based on active filters
  const filteredData = useMemo(() => {
    if (!graphData) return { nodes: [], edges: [] };
    const filteredNodes = graphData.nodes.filter((n: GraphNode) => activeFilters.has(n.type));
    const nodeIds = new Set(filteredNodes.map((n: GraphNode) => n.id));
    const filteredEdges = graphData.edges.filter((e: GraphEdge) => {
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
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });

    svg.call(zoom);

    const g = svg.append("g");

    // Defs for attack path glow
    const defs = svg.append("defs");
    const glowFilter = defs.append("filter").attr("id", "attack-path-glow");
    glowFilter.append("feGaussianBlur").attr("stdDeviation", "4").attr("result", "coloredBlur");
    const feMerge = glowFilter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "coloredBlur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    // Animated dash pattern for attack paths
    defs.append("style").text(`
      @keyframes dash-flow {
        to { stroke-dashoffset: -20; }
      }
      .attack-path-edge {
        animation: dash-flow 1s linear infinite;
      }
    `);

    const nodes = filteredData.nodes.map(n => ({ ...n })) as GraphNode[];
    const edges = filteredData.edges.map(e => ({ ...e })) as GraphEdge[];

    const simulation = d3.forceSimulation(nodes)
      .force("link", d3.forceLink<GraphNode, GraphEdge>(edges).id(d => d.id).distance(80))
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(30));

    simulationRef.current = simulation;

    // Draw edges
    const link = g.append("g")
      .selectAll("line")
      .data(edges)
      .join("line")
      .attr("stroke", "rgba(255,255,255,0.08)")
      .attr("stroke-width", 1);

    // Draw edge labels
    const linkLabel = g.append("g")
      .selectAll("text")
      .data(edges)
      .join("text")
      .text(d => d.relationship)
      .attr("font-size", "8px")
      .attr("fill", "rgba(255,255,255,0.2)")
      .attr("font-family", "'JetBrains Mono', monospace")
      .attr("text-anchor", "middle");

    // Attack path overlay edges (drawn on top)
    const attackEdgeGroup = g.append("g").attr("class", "attack-edges");

    // Draw nodes
    const node = g.append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .style("cursor", "pointer")
      .call(d3.drag<any, GraphNode>()
        .on("start", (event: any, d: GraphNode) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on("drag", (event: any, d: GraphNode) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on("end", (event: any, d: GraphNode) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        })
      );

    // Node circles
    node.append("circle")
      .attr("r", d => (NODE_CONFIG[d.type]?.size ?? 16) / 2 + 4)
      .attr("fill", d => `${NODE_CONFIG[d.type]?.color ?? "#888"}15`)
      .attr("stroke", d => `${NODE_CONFIG[d.type]?.color ?? "#888"}60`)
      .attr("stroke-width", 1.5);

    // Attack path glow ring (hidden by default)
    node.append("circle")
      .attr("class", "attack-glow")
      .attr("r", d => (NODE_CONFIG[d.type]?.size ?? 16) / 2 + 8)
      .attr("fill", "none")
      .attr("stroke", "transparent")
      .attr("stroke-width", 0)
      .attr("filter", "url(#attack-path-glow)");

    // Node labels
    node.append("text")
      .text(d => d.label.length > 18 ? d.label.slice(0, 16) + "..." : d.label)
      .attr("dy", d => (NODE_CONFIG[d.type]?.size ?? 16) / 2 + 14)
      .attr("text-anchor", "middle")
      .attr("font-size", "9px")
      .attr("fill", "rgba(255,255,255,0.5)")
      .attr("font-family", "'Inter', sans-serif");

    // Node click handler
    node.on("click", (_event, d) => {
      setSelectedNode(d);
    });

    // Double-click to drill into endpoint
    node.on("dblclick", (_event, d) => {
      if (d.type === "endpoint" && d.properties.agentId) {
        setViewMode("endpoint");
        setSelectedAgent(String(d.properties.agentId));
      }
    });

    // Hover effects
    node.on("mouseenter", function (_event, d) {
      d3.select(this).select("circle:first-child")
        .transition().duration(200)
        .attr("stroke-width", 3)
        .attr("fill", `${NODE_CONFIG[d.type]?.color ?? "#888"}30`);
    });

    node.on("mouseleave", function (_event, d) {
      d3.select(this).select("circle:first-child")
        .transition().duration(200)
        .attr("stroke-width", 1.5)
        .attr("fill", `${NODE_CONFIG[d.type]?.color ?? "#888"}15`);
    });

    // Tick
    simulation.on("tick", () => {
      link
        .attr("x1", d => (d.source as GraphNode).x ?? 0)
        .attr("y1", d => (d.source as GraphNode).y ?? 0)
        .attr("x2", d => (d.target as GraphNode).x ?? 0)
        .attr("y2", d => (d.target as GraphNode).y ?? 0);

      linkLabel
        .attr("x", d => (((d.source as GraphNode).x ?? 0) + ((d.target as GraphNode).x ?? 0)) / 2)
        .attr("y", d => (((d.source as GraphNode).y ?? 0) + ((d.target as GraphNode).y ?? 0)) / 2);

      node.attr("transform", d => `translate(${d.x ?? 0},${d.y ?? 0})`);

      // Update attack path overlay edges
      attackEdgeGroup.selectAll("line").each(function () {
        const el = d3.select(this);
        const sourceId = el.attr("data-source");
        const targetId = el.attr("data-target");
        const sourceNode = nodes.find(n => n.id === sourceId);
        const targetNode = nodes.find(n => n.id === targetId);
        if (sourceNode && targetNode) {
          el.attr("x1", sourceNode.x ?? 0)
            .attr("y1", sourceNode.y ?? 0)
            .attr("x2", targetNode.x ?? 0)
            .attr("y2", targetNode.y ?? 0);
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

    return () => {
      simulation.stop();
    };
  }, [filteredData]);

  // Attack path highlighting overlay
  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    const attackEdgeGroup = svg.select(".attack-edges");

    // Clear previous attack path highlights
    attackEdgeGroup.selectAll("*").remove();
    svg.selectAll(".attack-glow")
      .attr("stroke", "transparent")
      .attr("stroke-width", 0);

    // Dim non-path nodes when a path is selected
    if (selectedPath && attackPathNodeIds.size > 0) {
      // Dim all nodes not on the path
      svg.selectAll("g > g > g").each(function () {
        const el = d3.select(this);
        const datum = el.datum() as GraphNode | undefined;
        if (datum && datum.id) {
          if (attackPathNodeIds.has(datum.id)) {
            el.attr("opacity", 1);
            // Highlight the glow ring
            const severity = selectedPath.hops.find((h: AttackPathHop) => h.nodeId === datum.id)?.severity ?? "medium";
            const glowColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.medium;
            el.select(".attack-glow")
              .transition().duration(400)
              .attr("stroke", glowColor)
              .attr("stroke-width", 3);
          } else {
            el.transition().duration(400).attr("opacity", 0.15);
          }
        }
      });

      // Dim all edges
      svg.selectAll("g > g:first-child line")
        .transition().duration(400)
        .attr("stroke", "rgba(255,255,255,0.03)");

      // Draw attack path edges between consecutive hops
      const hopIds = selectedPath.hops.map((h: AttackPathHop) => h.nodeId);
      for (let i = 0; i < hopIds.length - 1; i++) {
        const severity = selectedPath.hops[i + 1]?.severity ?? "medium";
        const edgeColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.medium;
        attackEdgeGroup.append("line")
          .attr("data-source", hopIds[i])
          .attr("data-target", hopIds[i + 1])
          .attr("stroke", edgeColor)
          .attr("stroke-width", 2.5)
          .attr("stroke-dasharray", "6 4")
          .attr("class", "attack-path-edge")
          .attr("opacity", 0)
          .transition().duration(400)
          .attr("opacity", 0.9);
      }
    } else {
      // Reset all nodes to full opacity
      svg.selectAll("g > g > g")
        .transition().duration(300)
        .attr("opacity", 1);

      // Reset edge colors
      svg.selectAll("g > g:first-child line")
        .transition().duration(300)
        .attr("stroke", "rgba(255,255,255,0.08)");
    }
  }, [selectedPath, attackPathNodeIds]);

  const toggleFilter = useCallback((type: string) => {
    setActiveFilters(prev => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }, []);

  const handleZoomIn = () => {
    if (!svgRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(
      d3.zoom<SVGSVGElement, unknown>().scaleBy as never, 1.3
    );
  };

  const handleZoomOut = () => {
    if (!svgRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(
      d3.zoom<SVGSVGElement, unknown>().scaleBy as never, 0.7
    );
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
                {viewMode === "overview" ? "Infrastructure Overview" : `Agent ${selectedAgent}`}
                {statsQuery.data && ` \u2022 ${Object.values(statsQuery.data).reduce((a: number, b: number) => a + b, 0)} entities`}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <input
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search entities..."
                className="pl-8 pr-3 py-1.5 text-xs bg-white/5 border border-white/10 rounded-lg text-foreground placeholder:text-muted-foreground outline-none focus:border-purple-500/30 w-48"
              />
              {searchResults.data && searchResults.data.length > 0 && searchQuery.length >= 2 && (
                <div className="absolute top-full mt-1 left-0 w-64 glass-panel rounded-lg border border-white/10 shadow-2xl z-30 max-h-60 overflow-y-auto">
                  {searchResults.data.slice(0, 10).map((node: GraphNode) => {
                    const config = NODE_CONFIG[node.type] || NODE_CONFIG.endpoint;
                    return (
                      <button
                        key={node.id}
                        onClick={() => {
                          setSelectedNode(node);
                          setSearchQuery("");
                        }}
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

            {/* Attack Path toggle */}
            <button
              onClick={() => {
                setShowAttackPaths(!showAttackPaths);
                if (showAttackPaths) {
                  setSelectedPathId(null);
                }
              }}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg border transition-colors ${
                showAttackPaths
                  ? "border-red-500/30 bg-red-500/15 text-red-300"
                  : "border-white/10 text-muted-foreground hover:bg-white/5 hover:text-foreground"
              }`}
            >
              <Route className="w-3.5 h-3.5" />
              Attack Paths
              {attackPaths.length > 0 && (
                <span className="ml-1 px-1.5 py-0.5 rounded-full text-[9px] font-mono bg-red-500/20 text-red-300">
                  {attackPaths.length}
                </span>
              )}
            </button>

            {/* View mode toggle */}
            {viewMode === "endpoint" && (
              <button
                onClick={() => { setViewMode("overview"); setSelectedAgent(""); }}
                className="text-xs px-3 py-1.5 rounded-lg border border-white/10 text-muted-foreground hover:bg-white/5 hover:text-foreground transition-colors"
              >
                Back to Overview
              </button>
            )}

            {/* Refresh */}
            <button
              onClick={() => viewMode === "overview" ? overviewQuery.refetch() : endpointQuery.refetch()}
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
              <p className="text-sm text-muted-foreground">Loading graph data...</p>
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
                The Knowledge Graph is empty. Run the ETL pipeline from the Data Pipeline page to sync data from your Wazuh environment.
              </p>
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground mt-2">
                <Info className="w-3.5 h-3.5" />
                <span>Navigate to Intelligence &rarr; Data Pipeline to start syncing</span>
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
                  d3.zoom<SVGSVGElement, unknown>().transform as never,
                  d3.zoomIdentity
                );
              }
            }}
            className="p-1.5 glass-panel rounded-lg border border-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
        </div>

        {/* Stats overlay */}
        {statsQuery.data && !showAttackPaths && (
          <div className="absolute top-4 right-4 glass-panel rounded-xl border border-white/10 px-3 py-2 z-10">
            <p className="text-[10px] text-muted-foreground mb-1 font-medium">Graph Stats</p>
            <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
              {Object.entries(statsQuery.data).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between gap-2">
                  <span className="text-[10px] text-muted-foreground">{key}</span>
                  <span className="text-[10px] font-mono text-foreground">{String(value)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Attack Path Panel */}
        {showAttackPaths && (
          <AttackPathPanel
            paths={attackPaths}
            selectedPathId={selectedPathId}
            onSelectPath={setSelectedPathId}
            isLoading={attackPathQuery.isLoading}
            onClose={() => { setShowAttackPaths(false); setSelectedPathId(null); }}
          />
        )}

        {/* Attack path active indicator */}
        {selectedPath && (
          <div className="absolute bottom-4 right-4 glass-panel rounded-xl border border-red-500/20 px-4 py-3 z-10 max-w-xs">
            <div className="flex items-center gap-2 mb-1">
              <Route className="w-3.5 h-3.5 text-red-400" />
              <p className="text-xs font-medium text-foreground">Active Kill Chain</p>
              <button
                onClick={() => setSelectedPathId(null)}
                className="ml-auto p-0.5 rounded hover:bg-white/10 text-muted-foreground"
              >
                <EyeOff className="w-3 h-3" />
              </button>
            </div>
            <p className="text-[10px] text-muted-foreground">{selectedPath.name}</p>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-[10px] font-mono" style={{ color: SEVERITY_COLORS[selectedPath.riskScore >= 8 ? "critical" : selectedPath.riskScore >= 6 ? "high" : "medium"] }}>
                Risk: {selectedPath.riskScore.toFixed(1)}/10
              </span>
              <span className="text-[10px] text-muted-foreground">{selectedPath.hops.length} hops</span>
            </div>
          </div>
        )}

        {/* Legend */}
        <GraphLegend activeFilters={activeFilters} onToggle={toggleFilter} />

        {/* Node detail panel */}
        {selectedNode && !showAttackPaths && (
          <NodeDetailPanel node={selectedNode} onClose={() => setSelectedNode(null)} />
        )}
      </div>
    </div>
  );
}
