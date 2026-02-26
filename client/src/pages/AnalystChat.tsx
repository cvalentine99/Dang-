import React, { useState, useRef, useEffect, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { Send, Bot, User, ChevronDown, ChevronRight, FileJson, Lightbulb, Loader2, AlertTriangle, Database, Search, Sparkles, Copy, Check } from "lucide-react";
import { Streamdown } from "streamdown";

// ── Types ───────────────────────────────────────────────────────────────────

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
  timestamp: Date;
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

// ── Suggestion Chip (needs access to send handler, so we use context) ───────

function SuggestionChip({ text }: { text: string }): React.JSX.Element {
  // We'll use a custom event to communicate with the parent
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

// ── Loading Indicator ───────────────────────────────────────────────────────

function AnalysisIndicator(): React.JSX.Element {
  const [phase, setPhase] = useState(0);
  const phases = [
    { label: "Analyzing intent...", icon: Sparkles },
    { label: "Querying Knowledge Graph...", icon: Database },
    { label: "Searching Wazuh Indexer...", icon: Search },
    { label: "Synthesizing analysis...", icon: Bot },
  ];

  useEffect(() => {
    const interval = setInterval(() => {
      setPhase(p => (p + 1) % phases.length);
    }, 2500);
    return () => clearInterval(interval);
  }, [phases.length]);

  const CurrentIcon = phases[phase].icon;

  return (
    <div className="flex gap-3">
      <div className="flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center bg-cyan-500/10 border border-cyan-500/20">
        <Bot className="w-4 h-4 text-cyan-300" />
      </div>
      <div className="glass-panel rounded-xl px-4 py-3 flex items-center gap-3">
        <Loader2 className="w-4 h-4 text-purple-400 animate-spin" />
        <div className="flex items-center gap-2">
          <CurrentIcon className="w-3.5 h-3.5 text-purple-300" />
          <span className="text-sm text-muted-foreground">{phases[phase].label}</span>
        </div>
        {/* Phase dots */}
        <div className="flex gap-1 ml-2">
          {phases.map((_, i) => (
            <div key={i} className={`w-1.5 h-1.5 rounded-full transition-colors ${i <= phase ? "bg-purple-400" : "bg-white/10"}`} />
          ))}
        </div>
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
    "Show me all critical CVEs affecting our Linux servers",
    "What is the overall security posture of our infrastructure?",
  ];

  return (
    <div className="flex-1 flex flex-col items-center justify-center px-8 py-12">
      <div className="w-16 h-16 rounded-2xl bg-purple-500/15 border border-purple-500/30 flex items-center justify-center mb-6">
        <Sparkles className="w-8 h-8 text-purple-400" />
      </div>
      <h2 className="text-2xl font-display font-bold text-foreground mb-2">Walter</h2>
      <p className="text-muted-foreground text-sm text-center max-w-lg mb-8">
        AI-powered security analysis using HybridRAG — combining Knowledge Graph traversals with Wazuh Indexer search for evidence-based threat intelligence.
      </p>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-w-2xl w-full">
        {exampleQueries.map((q, i) => (
          <button
            key={i}
            onClick={() => window.dispatchEvent(new CustomEvent("analyst-suggestion", { detail: q }))}
            className="text-left text-xs px-4 py-3 rounded-xl border border-white/5 bg-white/[0.02] text-muted-foreground hover:bg-purple-500/10 hover:border-purple-500/20 hover:text-purple-200 transition-all"
          >
            {q}
          </button>
        ))}
      </div>

      <div className="mt-8 flex items-center gap-4 text-[11px] text-muted-foreground">
        <div className="flex items-center gap-1.5">
          <Database className="w-3 h-3 text-purple-400" />
          <span>Knowledge Graph</span>
        </div>
        <div className="w-1 h-1 rounded-full bg-white/20" />
        <div className="flex items-center gap-1.5">
          <Search className="w-3 h-3 text-cyan-400" />
          <span>Wazuh Indexer</span>
        </div>
        <div className="w-1 h-1 rounded-full bg-white/20" />
        <div className="flex items-center gap-1.5">
          <Sparkles className="w-3 h-3 text-amber-400" />
          <span>LLM Synthesis</span>
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
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const analystMutation = trpc.graph.analystQuery.useMutation();

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isAnalyzing]);

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

    // Build conversation history for context
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
        timestamp: new Date(),
      };

      setMessages(prev => [...prev, assistantMsg]);
    } catch (err) {
      const errorMsg: ChatMessage = {
        id: `error-${Date.now()}`,
        role: "assistant",
        content: `**Analysis Error**\n\n${(err as Error).message || "An unexpected error occurred during analysis. Please try again."}\n\nThis may indicate:\n- The LLM service is temporarily unavailable\n- The query exceeded processing limits\n- A network connectivity issue`,
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, errorMsg]);
    } finally {
      setIsAnalyzing(false);
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
              <p className="text-xs text-muted-foreground">HybridRAG Security Analysis Engine</p>
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
            {isAnalyzing && <AnalysisIndicator />}
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
            Walter grounds analysis in Wazuh telemetry. Verify critical findings independently.
          </p>
        </div>
      </div>
    </div>
  );
}
