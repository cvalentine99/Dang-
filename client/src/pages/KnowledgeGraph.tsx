import React, { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import * as d3 from "d3";
import {
  Network, Search, Filter, ZoomIn, ZoomOut, Maximize2, RefreshCw,
  Server, Cpu, Globe, Package, UserCheck, ShieldAlert, AlertTriangle,
  X, ChevronRight, Loader2, Database, Info,
} from "lucide-react";

// ── Types ───────────────────────────────────────────────────────────────────

interface GraphNode {
  id: string;
  type: "endpoint" | "process" | "network_port" | "software_package" | "identity" | "vulnerability" | "security_event";
  label: string;
  properties: Record<string, unknown>;
  // D3 simulation fields
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
      {/* Header */}
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

      {/* Properties */}
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

      {/* Raw JSON toggle */}
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

  const graphData = viewMode === "overview" ? overviewQuery.data : endpointQuery.data;
  const isLoading = viewMode === "overview" ? overviewQuery.isLoading : endpointQuery.isLoading;

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

    // Create zoom behavior
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });

    svg.call(zoom);

    const g = svg.append("g");

    // Create simulation
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

    // Node labels
    node.append("text")
      .text(d => d.label.length > 18 ? d.label.slice(0, 16) + "..." : d.label)
      .attr("dy", d => (NODE_CONFIG[d.type]?.size ?? 16) / 2 + 14)
      .attr("text-anchor", "middle")
      .attr("font-size", "9px")
      .attr("fill", "rgba(255,255,255,0.6)")
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
      d3.select(this).select("circle")
        .transition().duration(200)
        .attr("stroke-width", 3)
        .attr("fill", `${NODE_CONFIG[d.type]?.color ?? "#888"}30`);
    });

    node.on("mouseleave", function (_event, d) {
      d3.select(this).select("circle")
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
        .attr("x", d => ((d.source as GraphNode).x ?? 0 + ((d.target as GraphNode).x ?? 0)) / 2)
        .attr("y", d => ((d.source as GraphNode).y ?? 0 + ((d.target as GraphNode).y ?? 0)) / 2);

      node.attr("transform", d => `translate(${d.x ?? 0},${d.y ?? 0})`);
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
        {statsQuery.data && (
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

        {/* Legend */}
        <GraphLegend activeFilters={activeFilters} onToggle={toggleFilter} />

        {/* Node detail panel */}
        {selectedNode && (
          <NodeDetailPanel node={selectedNode} onClose={() => setSelectedNode(null)} />
        )}
      </div>
    </div>
  );
}
