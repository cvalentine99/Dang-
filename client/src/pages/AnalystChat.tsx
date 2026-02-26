import React, { useState, useRef, useEffect, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import {
  Send, Bot, User, ChevronDown, ChevronRight, FileJson, Lightbulb, Loader2,
  AlertTriangle, Database, Search, Sparkles, Copy, Check, Shield, ShieldAlert,
  ShieldOff, Terminal, Zap, Activity, Clock, CheckCircle2, XCircle, Eye,
} from "lucide-react";
import { Streamdown } from "streamdown";

// ── Types ───────────────────────────────────────────────────────────────────

interface AgentStep {
  agent: "orchestrator" | "graph_retriever" | "indexer_retriever" | "synthesizer" | "safety_validator";
  phase: number;
  action: string;
  detail: string;
  status: "running" | "complete" | "error" | "blocked";
  timestamp: number;
  durationMs?: number;
  dataPoints?: number;
}

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  reasoning?: string;
  sources?: Array<{
    type: "graph" | "indexer" | "stats";
    label: string;
    data: unknown;
    relevance: string;
  }>;
  suggestedFollowUps?: string[];
  trustScore?: number;
  confidence?: number;
  safetyStatus?: "clean" | "filtered" | "blocked";
  agentSteps?: AgentStep[];
  provenance?: {
    queryHash: string;
    graphSourceCount: number;
    indexerSourceCount: number;
    totalDataPoints: number;
    blockedEndpoints: string[];
    filteredPatterns: string[];
    retrievalLatencyMs: number;
    synthesisLatencyMs: number;
  };
  timestamp: Date;
}

// ── Agent Config ────────────────────────────────────────────────────────────

const AGENT_CONFIG: Record<string, { label: string; icon: typeof Bot; color: string; bgClass: string }> = {
  orchestrator:       { label: "Orchestrator",      icon: Zap,      color: "#a78bfa", bgClass: "bg-purple-500/15 border-purple-500/30 text-purple-400" },
  graph_retriever:    { label: "Graph Retriever",   icon: Database,  color: "#818cf8", bgClass: "bg-indigo-500/15 border-indigo-500/30 text-indigo-400" },
  indexer_retriever:  { label: "Indexer Retriever",  icon: Search,    color: "#22d3ee", bgClass: "bg-cyan-500/15 border-cyan-500/30 text-cyan-400" },
  synthesizer:        { label: "Synthesizer",        icon: Sparkles,  color: "#fbbf24", bgClass: "bg-amber-500/15 border-amber-500/30 text-amber-400" },
  safety_validator:   { label: "Safety Validator",   icon: Shield,    color: "#34d399", bgClass: "bg-emerald-500/15 border-emerald-500/30 text-emerald-400" },
};

// ── Agent Activity Console ──────────────────────────────────────────────────

function AgentActivityConsole({ steps, isLive }: { steps: AgentStep[]; isLive: boolean }): React.JSX.Element {
  const [expanded, setExpanded] = useState(true);
  const consoleRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (consoleRef.current && isLive) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [steps, isLive]);

  const statusIcon = (status: string) => {
    switch (status) {
      case "running": return <Loader2 className="w-3 h-3 animate-spin text-blue-400" />;
      case "complete": return <CheckCircle2 className="w-3 h-3 text-green-400" />;
      case "error": return <XCircle className="w-3 h-3 text-red-400" />;
      case "blocked": return <ShieldOff className="w-3 h-3 text-red-400" />;
      default: return <Clock className="w-3 h-3 text-muted-foreground" />;
    }
  };

  return (
    <div className="mt-3 border border-white/5 rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2 px-3 py-2 text-xs hover:bg-white/5 transition-colors"
      >
        {expanded ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />}
        <Terminal className="w-3.5 h-3.5 text-green-400" />
        <span className="text-green-400 font-mono text-[11px]">Agent Activity</span>
        {isLive && (
          <span className="flex items-center gap-1 ml-auto">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            <span className="text-[10px] text-green-400 font-mono">LIVE</span>
          </span>
        )}
        {!isLive && steps.length > 0 && (
          <span className="text-[10px] text-muted-foreground font-mono ml-auto">
            {steps.length} step{steps.length !== 1 ? "s" : ""}
          </span>
        )}
      </button>
      {expanded && (
        <div
          ref={consoleRef}
          className="bg-black/60 border-t border-white/5 px-3 py-2 max-h-64 overflow-y-auto font-mono text-[11px] space-y-1"
        >
          {steps.length === 0 && isLive && (
            <div className="flex items-center gap-2 text-muted-foreground">
              <Loader2 className="w-3 h-3 animate-spin" />
              <span>Initializing pipeline...</span>
            </div>
          )}
          {steps.map((step, i) => {
            const config = AGENT_CONFIG[step.agent] || AGENT_CONFIG.orchestrator;
            const AgentIcon = config.icon;
            return (
              <div
                key={i}
                className={`flex items-start gap-2 py-1 transition-all duration-300 ${
                  i === steps.length - 1 && isLive ? "animate-fade-in" : ""
                }`}
              >
                {/* Timestamp */}
                <span className="text-muted-foreground flex-shrink-0 w-16 text-right">
                  {step.durationMs != null ? `${step.durationMs}ms` : "..."}
                </span>

                {/* Status icon */}
                <span className="flex-shrink-0 mt-0.5">{statusIcon(step.status)}</span>

                {/* Agent badge */}
                <span
                  className="flex-shrink-0 flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px]"
                  style={{ borderColor: `${config.color}40`, backgroundColor: `${config.color}10`, color: config.color }}
                >
                  <AgentIcon className="w-2.5 h-2.5" />
                  {config.label}
                </span>

                {/* Action & detail */}
                <div className="flex-1 min-w-0">
                  <span className="text-foreground">{step.action}</span>
                  {step.detail && (
                    <span className="text-muted-foreground ml-1.5">— {step.detail}</span>
                  )}
                  {step.dataPoints != null && step.dataPoints > 0 && (
                    <span className="text-cyan-400 ml-1.5">[{step.dataPoints} pts]</span>
                  )}
                </div>
              </div>
            );
          })}
          {isLive && (
            <div className="flex items-center gap-1 text-green-400/60 pt-1">
              <span className="animate-pulse">▌</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Trust & Safety Badge ────────────────────────────────────────────────────

function TrustBadge({ trustScore, confidence, safetyStatus, provenance }: {
  trustScore: number;
  confidence: number;
  safetyStatus: "clean" | "filtered" | "blocked";
  provenance?: ChatMessage["provenance"];
}): React.JSX.Element {
  const [showDetails, setShowDetails] = useState(false);

  const trustColor = trustScore >= 0.7 ? "text-green-400" : trustScore >= 0.4 ? "text-yellow-400" : "text-red-400";
  const trustBg = trustScore >= 0.7 ? "bg-green-500/10 border-green-500/20" : trustScore >= 0.4 ? "bg-yellow-500/10 border-yellow-500/20" : "bg-red-500/10 border-red-500/20";

  const safetyIcon = safetyStatus === "clean" ? Shield : safetyStatus === "filtered" ? ShieldAlert : ShieldOff;
  const SafetyIcon = safetyIcon;
  const safetyColor = safetyStatus === "clean" ? "text-green-400" : safetyStatus === "filtered" ? "text-yellow-400" : "text-red-400";

  return (
    <div className="mt-2">
      <button
        onClick={() => setShowDetails(!showDetails)}
        className="flex items-center gap-3 text-[11px]"
      >
        {/* Trust score */}
        <span className={`flex items-center gap-1 px-2 py-0.5 rounded-full border ${trustBg}`}>
          <Activity className={`w-3 h-3 ${trustColor}`} />
          <span className={`font-mono ${trustColor}`}>Trust {(trustScore * 100).toFixed(0)}%</span>
        </span>

        {/* Confidence */}
        <span className="flex items-center gap-1 text-muted-foreground">
          <Eye className="w-3 h-3" />
          <span className="font-mono">Conf {(confidence * 100).toFixed(0)}%</span>
        </span>

        {/* Safety */}
        <span className={`flex items-center gap-1 ${safetyColor}`}>
          <SafetyIcon className="w-3 h-3" />
          <span className="font-mono capitalize">{safetyStatus}</span>
        </span>

        <ChevronDown className={`w-3 h-3 text-muted-foreground transition-transform ${showDetails ? "rotate-180" : ""}`} />
      </button>

      {showDetails && provenance && (
        <div className="mt-2 px-3 py-2 rounded-lg bg-black/30 border border-white/5 text-[10px] font-mono text-muted-foreground grid grid-cols-2 gap-x-6 gap-y-1">
          <span>Query Hash: <span className="text-foreground">{provenance.queryHash}</span></span>
          <span>Graph Sources: <span className="text-purple-400">{provenance.graphSourceCount}</span></span>
          <span>Indexer Sources: <span className="text-cyan-400">{provenance.indexerSourceCount}</span></span>
          <span>Data Points: <span className="text-foreground">{provenance.totalDataPoints}</span></span>
          <span>Retrieval: <span className="text-foreground">{provenance.retrievalLatencyMs}ms</span></span>
          <span>Synthesis: <span className="text-foreground">{provenance.synthesisLatencyMs}ms</span></span>
          {provenance.filteredPatterns.length > 0 && (
            <span className="col-span-2 text-yellow-400">
              Filtered: {provenance.filteredPatterns.join(", ")}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ── Source Panel Component ───────────────────────────────────────────────────

function SourcePanel({ sources }: { sources: ChatMessage["sources"] }): React.JSX.Element | null {
  const [expanded, setExpanded] = useState(false);
  const [expandedSources, setExpandedSources] = useState<Set<number>>(new Set());

  if (!sources || sources.length === 0) return null;

  const toggleSource = (idx: number) => {
    const next = new Set(expandedSources);
    if (next.has(idx)) next.delete(idx);
    else next.add(idx);
    setExpandedSources(next);
  };

  const sourceIcon = (type: string) => {
    switch (type) {
      case "graph": return <Database className="w-3.5 h-3.5 text-purple-400" />;
      case "indexer": return <Search className="w-3.5 h-3.5 text-cyan-400" />;
      case "stats": return <Sparkles className="w-3.5 h-3.5 text-amber-400" />;
      default: return <FileJson className="w-3.5 h-3.5 text-gray-400" />;
    }
  };

  return (
    <div className="mt-3 border border-white/5 rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2 px-3 py-2 text-xs text-muted-foreground hover:bg-white/5 transition-colors"
      >
        {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
        <FileJson className="w-3.5 h-3.5" />
        <span>{sources.length} retrieval source{sources.length !== 1 ? "s" : ""}</span>
      </button>
      {expanded && (
        <div className="border-t border-white/5">
          {sources.map((src, idx) => (
            <div key={idx} className="border-b border-white/5 last:border-b-0">
              <button
                onClick={() => toggleSource(idx)}
                className="w-full flex items-center gap-2 px-3 py-1.5 text-xs hover:bg-white/5 transition-colors"
              >
                {expandedSources.has(idx) ? <ChevronDown className="w-3 h-3 text-muted-foreground" /> : <ChevronRight className="w-3 h-3 text-muted-foreground" />}
                {sourceIcon(src.type)}
                <span className="text-muted-foreground truncate flex-1 text-left">{src.label}</span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                  src.relevance === "primary" ? "bg-purple-500/20 text-purple-300" :
                  src.relevance === "error" ? "bg-red-500/20 text-red-300" :
                  "bg-white/5 text-muted-foreground"
                }`}>{src.relevance}</span>
              </button>
              {expandedSources.has(idx) && (
                <div className="px-3 pb-2">
                  <pre className="text-[11px] font-mono text-muted-foreground bg-black/30 rounded p-2 overflow-x-auto max-h-48 overflow-y-auto">
                    {typeof src.data === "string" ? src.data : JSON.stringify(src.data, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Copy Button ─────────────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }): React.JSX.Element {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [text]);

  return (
    <button onClick={handleCopy} className="p-1 rounded hover:bg-white/10 transition-colors text-muted-foreground hover:text-foreground" title="Copy">
      {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

// ── Message Component ───────────────────────────────────────────────────────

function ChatMessageBubble({ message }: { message: ChatMessage }): React.JSX.Element {
  const isUser = message.role === "user";

  return (
    <div className={`flex gap-3 ${isUser ? "flex-row-reverse" : ""}`}>
      {/* Avatar */}
      <div className={`flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center ${
        isUser ? "bg-purple-500/20 border border-purple-500/30" : "bg-cyan-500/10 border border-cyan-500/20"
      }`}>
        {isUser ? <User className="w-4 h-4 text-purple-300" /> : <Bot className="w-4 h-4 text-cyan-300" />}
      </div>

      {/* Content */}
      <div className={`flex-1 min-w-0 ${isUser ? "max-w-[75%] ml-auto" : "max-w-[85%]"}`}>
        <div className={`rounded-xl px-4 py-3 ${
          isUser
            ? "bg-purple-500/15 border border-purple-500/20"
            : "glass-panel"
        }`}>
          {isUser ? (
            <p className="text-sm text-foreground whitespace-pre-wrap">{message.content}</p>
          ) : (
            <div className="text-sm text-foreground prose prose-invert prose-sm max-w-none prose-headings:text-purple-200 prose-strong:text-foreground prose-code:text-cyan-300 prose-code:bg-black/30 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-pre:bg-black/40 prose-pre:border prose-pre:border-white/5">
              <Streamdown>{message.content}</Streamdown>
            </div>
          )}
        </div>

        {/* Trust & Safety Badge */}
        {!isUser && message.trustScore != null && (
          <TrustBadge
            trustScore={message.trustScore}
            confidence={message.confidence ?? 0}
            safetyStatus={message.safetyStatus ?? "clean"}
            provenance={message.provenance}
          />
        )}

        {/* Agent Activity Console */}
        {!isUser && message.agentSteps && message.agentSteps.length > 0 && (
          <AgentActivityConsole steps={message.agentSteps} isLive={false} />
        )}

        {/* Reasoning badge */}
        {message.reasoning && (
          <div className="mt-1.5 flex items-center gap-1.5 text-[11px] text-muted-foreground font-mono">
            <Sparkles className="w-3 h-3" />
            <span>{message.reasoning}</span>
          </div>
        )}

        {/* Sources panel */}
        {!isUser && <SourcePanel sources={message.sources} />}

        {/* Copy button for assistant messages */}
        {!isUser && (
          <div className="mt-1 flex items-center gap-1">
            <CopyButton text={message.content} />
            <span className="text-[10px] text-muted-foreground">
              {message.timestamp.toLocaleTimeString()}
            </span>
          </div>
        )}

        {/* Follow-up suggestions */}
        {!isUser && message.suggestedFollowUps && message.suggestedFollowUps.length > 0 && (
          <div className="mt-3 flex flex-col gap-1.5">
            <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
              <Lightbulb className="w-3 h-3" />
              <span>Suggested follow-ups</span>
            </div>
            {message.suggestedFollowUps.map((q, i) => (
              <SuggestionChip key={i} text={q} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Suggestion Chip ─────────────────────────────────────────────────────────

function SuggestionChip({ text }: { text: string }): React.JSX.Element {
  const handleClick = () => {
    window.dispatchEvent(new CustomEvent("analyst-suggestion", { detail: text }));
  };

  return (
    <button
      onClick={handleClick}
      className="text-left text-xs px-3 py-1.5 rounded-lg border border-purple-500/20 bg-purple-500/5 text-purple-200 hover:bg-purple-500/15 hover:border-purple-500/30 transition-all truncate"
    >
      {text}
    </button>
  );
}

// ── Live Analysis Indicator (replaces old simple spinner) ───────────────────

function LiveAnalysisConsole({ steps }: { steps: AgentStep[] }): React.JSX.Element {
  return (
    <div className="flex gap-3">
      <div className="flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center bg-cyan-500/10 border border-cyan-500/20">
        <Bot className="w-4 h-4 text-cyan-300" />
      </div>
      <div className="flex-1 min-w-0 max-w-[85%]">
        <div className="glass-panel rounded-xl px-4 py-3">
          <div className="flex items-center gap-2 mb-2">
            <Loader2 className="w-4 h-4 text-purple-400 animate-spin" />
            <span className="text-sm text-foreground font-medium">Analyzing...</span>
            <span className="flex items-center gap-1 ml-auto">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
              <span className="text-[10px] text-green-400 font-mono">PIPELINE ACTIVE</span>
            </span>
          </div>

          {/* Live progress bar */}
          <div className="h-1 rounded-full bg-white/5 overflow-hidden mb-3">
            <div
              className="h-full rounded-full bg-gradient-to-r from-purple-500 via-cyan-500 to-amber-500 transition-all duration-1000"
              style={{ width: `${Math.min(100, (steps.length / 6) * 100)}%` }}
            />
          </div>
        </div>

        {/* Live agent activity */}
        <AgentActivityConsole steps={steps} isLive={true} />
      </div>
    </div>
  );
}

// ── Welcome Screen ──────────────────────────────────────────────────────────

function WelcomeScreen(): React.JSX.Element {
  const exampleQueries = [
    "Show me the most critical alerts from the last 24 hours",
    "Which endpoints have the most vulnerabilities?",
    "What MITRE ATT&CK techniques are most prevalent in our environment?",
    "Investigate agent 001 for suspicious activity",
    "What Wazuh API endpoints are available for agent monitoring?",
    "What is the overall security posture of our infrastructure?",
  ];

  return (
    <div className="flex-1 flex flex-col items-center justify-center px-8 py-12">
      <div className="w-16 h-16 rounded-2xl bg-purple-500/15 border border-purple-500/30 flex items-center justify-center mb-6">
        <Sparkles className="w-8 h-8 text-purple-400" />
      </div>
      <h2 className="text-2xl font-display font-bold text-foreground mb-2">Walter</h2>
      <p className="text-muted-foreground text-sm text-center max-w-lg mb-2">
        Policy-Constrained Reasoning Engine with 4-Layer Knowledge Graph
      </p>
      <p className="text-muted-foreground text-xs text-center max-w-lg mb-8 opacity-60">
        Trust scoring · Safety rails · Provenance tracking · Read-only by design
      </p>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-w-2xl w-full">
        {exampleQueries.map((q, i) => (
          <button
            key={i}
            onClick={() => window.dispatchEvent(new CustomEvent("analyst-suggestion", { detail: q }))}
            className="text-left text-xs px-4 py-3 rounded-xl border border-white/5 bg-white/[0.02] text-muted-foreground hover:bg-white/5 hover:border-purple-500/20 hover:text-foreground transition-all"
          >
            {q}
          </button>
        ))}
      </div>

      <div className="mt-8 flex items-center gap-4 text-[11px] text-muted-foreground">
        <div className="flex items-center gap-1.5">
          <Database className="w-3 h-3 text-purple-400" />
          <span>4-Layer KG</span>
        </div>
        <div className="w-1 h-1 rounded-full bg-white/20" />
        <div className="flex items-center gap-1.5">
          <Search className="w-3 h-3 text-cyan-400" />
          <span>Wazuh Indexer</span>
        </div>
        <div className="w-1 h-1 rounded-full bg-white/20" />
        <div className="flex items-center gap-1.5">
          <Shield className="w-3 h-3 text-green-400" />
          <span>Safety Rails</span>
        </div>
        <div className="w-1 h-1 rounded-full bg-white/20" />
        <div className="flex items-center gap-1.5">
          <Activity className="w-3 h-3 text-amber-400" />
          <span>Trust Scoring</span>
        </div>
      </div>
    </div>
  );
}

// ── Main Analyst Chat Page ──────────────────────────────────────────────────

export default function AnalystChat(): React.JSX.Element {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [liveSteps, setLiveSteps] = useState<AgentStep[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const analystMutation = trpc.graph.analystQuery.useMutation();

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isAnalyzing, liveSteps]);

  // Listen for suggestion clicks
  useEffect(() => {
    const handler = (e: Event) => {
      const text = (e as CustomEvent).detail;
      if (typeof text === "string" && !isAnalyzing) {
        handleSend(text);
      }
    };
    window.addEventListener("analyst-suggestion", handler);
    return () => window.removeEventListener("analyst-suggestion", handler);
  }, [isAnalyzing, messages]);

  // Simulate live agent steps while waiting for response
  useEffect(() => {
    if (!isAnalyzing) return;

    const simulatedSteps: AgentStep[] = [
      { agent: "orchestrator", phase: 1, action: "Analyzing query intent", detail: "Classifying query and extracting entities...", status: "running", timestamp: Date.now() },
      { agent: "orchestrator", phase: 1, action: "Intent classified", detail: "Selecting retrieval strategy...", status: "complete", timestamp: Date.now(), durationMs: 800 },
      { agent: "graph_retriever", phase: 2, action: "Querying Knowledge Graph", detail: "Traversing 4-layer API ontology...", status: "running", timestamp: Date.now() },
      { agent: "indexer_retriever", phase: 3, action: "Searching Wazuh Indexer", detail: "Querying wazuh-alerts-* and wazuh-states-vulnerabilities-*...", status: "running", timestamp: Date.now() },
      { agent: "graph_retriever", phase: 2, action: "Graph retrieval complete", detail: "Retrieved data from KG layers...", status: "complete", timestamp: Date.now(), durationMs: 1200 },
      { agent: "indexer_retriever", phase: 3, action: "Indexer search complete", detail: "Retrieved alerts and events...", status: "complete", timestamp: Date.now(), durationMs: 1500 },
      { agent: "synthesizer", phase: 4, action: "Generating analysis", detail: "Synthesizing from retrieved sources...", status: "running", timestamp: Date.now() },
      { agent: "safety_validator", phase: 4, action: "Validating output safety", detail: "Scanning for blocked patterns...", status: "running", timestamp: Date.now() },
    ];

    let stepIndex = 0;
    setLiveSteps([]);

    const interval = setInterval(() => {
      if (stepIndex < simulatedSteps.length) {
        setLiveSteps(prev => [...prev, simulatedSteps[stepIndex]]);
        stepIndex++;
      }
    }, 1200);

    return () => clearInterval(interval);
  }, [isAnalyzing]);

  const handleSend = useCallback(async (overrideText?: string) => {
    const text = overrideText ?? input.trim();
    if (!text || isAnalyzing) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: "user",
      content: text,
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setIsAnalyzing(true);
    setLiveSteps([]);

    const conversationHistory = messages.map(m => ({
      role: m.role as "user" | "assistant",
      content: m.content,
    }));

    try {
      const result = await analystMutation.mutateAsync({
        query: text,
        conversationHistory,
      });

      const assistantMsg: ChatMessage = {
        id: `assistant-${Date.now()}`,
        role: "assistant",
        content: result.answer,
        reasoning: result.reasoning,
        sources: result.sources as ChatMessage["sources"],
        suggestedFollowUps: result.suggestedFollowUps,
        trustScore: result.trustScore,
        confidence: result.confidence,
        safetyStatus: result.safetyStatus,
        agentSteps: result.agentSteps,
        provenance: result.provenance,
        timestamp: new Date(),
      };

      setMessages(prev => [...prev, assistantMsg]);
    } catch (err) {
      const errorMsg: ChatMessage = {
        id: `error-${Date.now()}`,
        role: "assistant",
        content: `**Analysis Error**\n\n${(err as Error).message || "An unexpected error occurred during analysis. Please try again."}\n\nThis may indicate:\n- The LLM service is temporarily unavailable\n- The query exceeded processing limits\n- A network connectivity issue`,
        trustScore: 0,
        confidence: 0,
        safetyStatus: "clean",
        agentSteps: [{
          agent: "orchestrator",
          phase: 0,
          action: "Pipeline error",
          detail: (err as Error).message || "Unknown error",
          status: "error",
          timestamp: Date.now(),
        }],
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, errorMsg]);
    } finally {
      setIsAnalyzing(false);
      setLiveSteps([]);
    }
  }, [input, isAnalyzing, messages, analystMutation]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-3.5rem)]">
      {/* Header */}
      <div className="flex-shrink-0 px-6 py-4 border-b border-white/5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-purple-500/15 border border-purple-500/30 flex items-center justify-center">
              <Sparkles className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <h1 className="text-lg font-display font-bold text-foreground">Walter</h1>
              <p className="text-xs text-muted-foreground">Policy-Constrained Reasoning Engine · 4-Layer KG</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {messages.length > 0 && (
              <button
                onClick={() => setMessages([])}
                className="text-xs px-3 py-1.5 rounded-lg border border-white/10 text-muted-foreground hover:bg-white/5 hover:text-foreground transition-colors"
              >
                New conversation
              </button>
            )}
            {analystMutation.isError && (
              <div className="flex items-center gap-1.5 text-xs text-threat-high">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Pipeline error</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Messages area */}
      <div className="flex-1 overflow-y-auto px-6 py-4">
        {messages.length === 0 ? (
          <WelcomeScreen />
        ) : (
          <div className="max-w-4xl mx-auto space-y-6">
            {messages.map(msg => (
              <ChatMessageBubble key={msg.id} message={msg} />
            ))}
            {isAnalyzing && <LiveAnalysisConsole steps={liveSteps} />}
            <div ref={messagesEndRef} />
          </div>
        )}
      </div>

      {/* Input area */}
      <div className="flex-shrink-0 px-6 py-4 border-t border-white/5">
        <div className="max-w-4xl mx-auto">
          <div className="glass-panel rounded-xl overflow-hidden flex items-end">
            <textarea
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask a security question... (e.g., 'Show me critical vulnerabilities on agent 001')"
              className="flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground px-4 py-3 resize-none outline-none min-h-[44px] max-h-[120px]"
              rows={1}
              disabled={isAnalyzing}
            />
            <button
              onClick={() => handleSend()}
              disabled={!input.trim() || isAnalyzing}
              className="flex-shrink-0 p-3 text-purple-400 hover:text-purple-300 disabled:text-muted-foreground disabled:opacity-50 transition-colors"
            >
              {isAnalyzing ? <Loader2 className="w-5 h-5 animate-spin" /> : <Send className="w-5 h-5" />}
            </button>
          </div>
          <p className="text-[10px] text-muted-foreground mt-1.5 text-center">
            Walter operates read-only with trust scoring and safety rails. Verify critical findings independently.
          </p>
        </div>
      </div>
    </div>
  );
}
