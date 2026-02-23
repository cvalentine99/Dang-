import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { GlassPanel } from "@/components/shared/GlassPanel";
import { StatCard } from "@/components/shared/StatCard";
import { ThreatBadge, threatLevelFromNumber } from "@/components/shared/ThreatBadge";
import { PageHeader } from "@/components/shared/PageHeader";
import { RawJsonViewer } from "@/components/shared/RawJsonViewer";
import { WazuhGuard, useWazuhStatus } from "@/components/shared/WazuhGuard";
import {
  MOCK_AGENTS,
  MOCK_RULES,
  MOCK_VULNERABILITIES,
  MOCK_SYSCHECK_FILES,
  MOCK_MANAGER_LOGS,
  MOCK_MITRE_TECHNIQUES,
  useFallback,
} from "@/lib/mockData";
import {
  Search,
  Crosshair,
  Shield,
  FileWarning,
  Bug,
  Network,
  Clock,
  Filter,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Hash,
  Globe,
  User,
  Terminal,
  AlertTriangle,
  Activity,
  Target,
  Layers,
  BarChart3,
  X,
  Bookmark,
  BookmarkPlus,
  Save,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
} from "recharts";

// ── IOC Types ───────────────────────────────────────────────────────────────────
type IOCType = "ip" | "hash" | "cve" | "filename" | "username" | "rule_id" | "mitre_id" | "freetext";

const IOC_TYPES: { value: IOCType; label: string; icon: typeof Globe; placeholder: string }[] = [
  { value: "freetext", label: "Free Text", icon: Search, placeholder: "Search across all fields..." },
  { value: "ip", label: "IP Address", icon: Globe, placeholder: "e.g. 10.0.1.10 or 192.168.1.0/24" },
  { value: "hash", label: "File Hash", icon: Hash, placeholder: "MD5, SHA1, or SHA256 hash" },
  { value: "cve", label: "CVE ID", icon: Bug, placeholder: "e.g. CVE-2024-6387" },
  { value: "filename", label: "File Path", icon: FileWarning, placeholder: "e.g. /etc/shadow or *.sh" },
  { value: "username", label: "Username", icon: User, placeholder: "e.g. root, admin, www-data" },
  { value: "rule_id", label: "Rule ID", icon: Shield, placeholder: "e.g. 5710, 87105" },
  { value: "mitre_id", label: "MITRE ID", icon: Target, placeholder: "e.g. T1110, T1003" },
];

const CHART_COLORS = [
  "oklch(0.72 0.19 295)",
  "oklch(0.637 0.237 25.331)",
  "oklch(0.705 0.191 22.216)",
  "oklch(0.795 0.184 86.047)",
  "oklch(0.765 0.177 163.223)",
  "oklch(0.789 0.154 211.53)",
];

// ── Correlation result type ─────────────────────────────────────────────────────
interface CorrelationHit {
  source: "agents" | "rules" | "vulnerabilities" | "syscheck" | "logs" | "mitre" | "alerts";
  sourceLabel: string;
  matches: Record<string, unknown>[];
  count: number;
}

interface HuntEntry {
  id: string;
  timestamp: string;
  query: string;
  iocType: IOCType;
  totalHits: number;
  sources: string[];
}

export default function ThreatHunting() {
  const { isConnected } = useWazuhStatus();

  // ── Query state ────────────────────────────────────────────────────────────
  const [iocType, setIocType] = useState<IOCType>("freetext");
  const [searchValue, setSearchValue] = useState("");
  const [activeQuery, setActiveQuery] = useState("");
  const [activeIocType, setActiveIocType] = useState<IOCType>("freetext");
  const [huntHistory, setHuntHistory] = useState<HuntEntry[]>([]);
  const [expandedSource, setExpandedSource] = useState<string | null>(null);
  const [selectedHunt, setSelectedHunt] = useState<string | null>(null);

  // ── Saved search state ────────────────────────────────────────────────────
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [saveName, setSaveName] = useState("");
  const [saveDescription, setSaveDescription] = useState("");
  const [showSavedSearches, setShowSavedSearches] = useState(false);

  // ── Saved search queries ──────────────────────────────────────────────────
  const savedSearchesQ = trpc.savedSearches.list.useQuery({ searchType: "hunting" });
  const createSearchMut = trpc.savedSearches.create.useMutation({
    onSuccess: () => {
      savedSearchesQ.refetch();
      setShowSaveDialog(false);
      setSaveName("");
      setSaveDescription("");
      toast.success("Hunt query saved successfully");
    },
    onError: (err) => toast.error(`Failed to save: ${err.message}`),
  });
  const deleteSearchMut = trpc.savedSearches.delete.useMutation({
    onSuccess: () => {
      savedSearchesQ.refetch();
      toast.success("Saved search deleted");
    },
    onError: (err) => toast.error(`Failed to delete: ${err.message}`),
  });

  // ── API queries (always enabled, use fallback when not connected) ──────────
  const agentsQ = trpc.wazuh.agents.useQuery({ limit: 500, offset: 0 }, { retry: 1, staleTime: 60_000 });
  const rulesQ = trpc.wazuh.rules.useQuery({ limit: 500, offset: 0 }, { retry: 1, staleTime: 60_000 });
  const logsQ = trpc.wazuh.managerLogs.useQuery({ limit: 500, offset: 0 }, { retry: 1, staleTime: 30_000 });
  const mitreQ = trpc.wazuh.mitreTechniques.useQuery({ limit: 500, offset: 0 }, { retry: 1, staleTime: 60_000 });

  const agents = useFallback(agentsQ.data, MOCK_AGENTS, isConnected);
  const rules = useFallback(rulesQ.data, MOCK_RULES, isConnected);
  const logs = useFallback(logsQ.data, MOCK_MANAGER_LOGS, isConnected);
  const mitreTechniques = useFallback(mitreQ.data, MOCK_MITRE_TECHNIQUES, isConnected);

  // ── Indexer queries for cross-agent vulnerability + FIM search ─────────
  const indexerStatusQ = trpc.indexer.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const isIndexerConnected = !!(indexerStatusQ.data as Record<string, unknown>)?.configured && !!(indexerStatusQ.data as Record<string, unknown>)?.healthy;

  // Cross-agent vulnerability search via Indexer (no agentId required)
  const vulnSearchQ = trpc.indexer.vulnSearch.useQuery(
    { from: "now-90d", to: "now", size: 200 },
    { retry: false, staleTime: 60_000, enabled: isIndexerConnected }
  );

  // FIM/syscheck events via alerts index (decoder.name contains syscheck)
  const fimSearchQ = trpc.indexer.alertsSearch.useQuery(
    { from: "now-30d", to: "now", size: 200, decoderName: "syscheck" },
    { retry: false, staleTime: 60_000, enabled: isIndexerConnected }
  );

  // Cross-agent alerts search for IOC correlation
  const [iocAlertQuery, setIocAlertQuery] = useState<string | null>(null);
  const iocAlertsQ = trpc.indexer.alertsSearch.useQuery(
    { from: "now-30d", to: "now", size: 100, query: iocAlertQuery ?? "" },
    { retry: false, staleTime: 30_000, enabled: isIndexerConnected && !!iocAlertQuery }
  );

  // Parse Indexer vulnerability results into the same shape as MOCK_VULNERABILITIES
  const vulns = useMemo(() => {
    if (isIndexerConnected && vulnSearchQ.data?.data) {
      const resp = vulnSearchQ.data.data as unknown as Record<string, unknown>;
      const hits = (resp.hits as Record<string, unknown>) ?? {};
      const hitArr = (hits.hits as Array<Record<string, unknown>>) ?? [];
      const total = typeof hits.total === "object"
        ? Number((hits.total as Record<string, unknown>).value ?? 0)
        : Number(hits.total ?? 0);
      const items = hitArr.map((h) => {
        const src = (h._source ?? {}) as Record<string, unknown>;
        const vuln = (src.vulnerability ?? {}) as Record<string, unknown>;
        const pkg = (src.package ?? {}) as Record<string, unknown>;
        const score = (vuln.score ?? {}) as Record<string, unknown>;
        return {
          cve: String(vuln.id ?? ""),
          severity: String(vuln.severity ?? "Medium"),
          cvss3_score: Number(score.base ?? 0),
          cvss2_score: Number(score.version ?? 0),
          name: String(pkg.name ?? ""),
          version: String(pkg.version ?? ""),
          title: String(vuln.description ?? vuln.title ?? ""),
          status: String(vuln.status ?? "Active"),
          published: String(vuln.published ?? ""),
          detection_time: String(vuln.detected_at ?? src.timestamp ?? ""),
        };
      });
      return { data: { affected_items: items, total_affected_items: total, total_failed_items: 0, failed_items: [] } };
    }
    return MOCK_VULNERABILITIES;
  }, [isIndexerConnected, vulnSearchQ.data]);

  // Parse Indexer FIM/syscheck results into the same shape as MOCK_SYSCHECK_FILES
  const syscheck = useMemo(() => {
    if (isIndexerConnected && fimSearchQ.data?.data) {
      const resp = fimSearchQ.data.data as unknown as Record<string, unknown>;
      const hits = (resp.hits as Record<string, unknown>) ?? {};
      const hitArr = (hits.hits as Array<Record<string, unknown>>) ?? [];
      const total = typeof hits.total === "object"
        ? Number((hits.total as Record<string, unknown>).value ?? 0)
        : Number(hits.total ?? 0);
      const items = hitArr.map((h) => {
        const src = (h._source ?? {}) as Record<string, unknown>;
        const sysData = (src.syscheck ?? src.data ?? {}) as Record<string, unknown>;
        return {
          file: String(sysData.path ?? sysData.file ?? (src.data as Record<string, unknown>)?.path ?? ""),
          event: String(sysData.event ?? "modified"),
          md5: String(sysData.md5_after ?? sysData.md5 ?? ""),
          sha256: String(sysData.sha256_after ?? sysData.sha256 ?? ""),
          sha1: String(sysData.sha1_after ?? sysData.sha1 ?? ""),
          uname: String(sysData.uname_after ?? sysData.uname ?? ""),
          date: String(src.timestamp ?? ""),
          size: Number(sysData.size_after ?? sysData.size ?? 0),
        };
      });
      return { data: { affected_items: items, total_affected_items: total, total_failed_items: 0, failed_items: [] } };
    }
    return MOCK_SYSCHECK_FILES;
  }, [isIndexerConnected, fimSearchQ.data]);

  // ── Correlation engine ────────────────────────────────────────────────────
  const correlationResults = useMemo<CorrelationHit[]>(() => {
    if (!activeQuery) return [];

    const q = activeQuery.toLowerCase();
    const results: CorrelationHit[] = [];

    // Search agents
    const agentsData = (agents as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const agentHits = ((agentsData?.affected_items ?? []) as Record<string, unknown>[]).filter((a: Record<string, unknown>) => {
      const str = JSON.stringify(a).toLowerCase();
      if (activeIocType === "ip") return String(a.ip ?? "").includes(q);
      if (activeIocType === "username") return String(a.name ?? "").toLowerCase().includes(q);
      return str.includes(q);
    });
    if (agentHits.length > 0) {
      results.push({ source: "agents", sourceLabel: "Agents", matches: agentHits, count: agentHits.length });
    }

    // Search rules
    const rulesData = (rules as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const ruleHits = ((rulesData?.affected_items ?? []) as Record<string, unknown>[]).filter((r: Record<string, unknown>) => {
      const str = JSON.stringify(r).toLowerCase();
      if (activeIocType === "rule_id") return String(r.id ?? "") === q || String(r.id ?? "").includes(q);
      if (activeIocType === "mitre_id") {
        const mitre = r.mitre as { id?: string[] } | undefined;
        return (mitre?.id ?? []).some((id: string) => id.toLowerCase().includes(q));
      }
      return str.includes(q);
    });
    if (ruleHits.length > 0) {
      results.push({ source: "rules", sourceLabel: "Rules", matches: ruleHits, count: ruleHits.length });
    }

    // Search vulnerabilities
    const vulnsData = (vulns as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const vulnHits = ((vulnsData?.affected_items ?? []) as Record<string, unknown>[]).filter((v: Record<string, unknown>) => {
      const str = JSON.stringify(v).toLowerCase();
      if (activeIocType === "cve") return String(v.cve ?? "").toLowerCase().includes(q);
      return str.includes(q);
    });
    if (vulnHits.length > 0) {
      results.push({ source: "vulnerabilities", sourceLabel: "Vulnerabilities", matches: vulnHits, count: vulnHits.length });
    }

    // Search syscheck
    const fimData = (syscheck as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const fimHits = ((fimData?.affected_items ?? []) as Record<string, unknown>[]).filter((f: Record<string, unknown>) => {
      const str = JSON.stringify(f).toLowerCase();
      if (activeIocType === "hash") return str.includes(q);
      if (activeIocType === "filename") return String(f.file ?? "").toLowerCase().includes(q);
      return str.includes(q);
    });
    if (fimHits.length > 0) {
      results.push({ source: "syscheck", sourceLabel: "File Integrity", matches: fimHits, count: fimHits.length });
    }

    // Search logs
    const logsData = (logs as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const logHits = ((logsData?.affected_items ?? []) as Record<string, unknown>[]).filter((l: Record<string, unknown>) => {
      const str = JSON.stringify(l).toLowerCase();
      return str.includes(q);
    });
    if (logHits.length > 0) {
      results.push({ source: "logs", sourceLabel: "Manager Logs", matches: logHits, count: logHits.length });
    }

    // Search MITRE techniques
    const mitreData = (mitreTechniques as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const mitreHits = ((mitreData?.affected_items ?? []) as Record<string, unknown>[]).filter((t: Record<string, unknown>) => {
      const str = JSON.stringify(t).toLowerCase();
      if (activeIocType === "mitre_id") return String(t.external_id ?? "").toLowerCase().includes(q);
      return str.includes(q);
    });
    if (mitreHits.length > 0) {
      results.push({ source: "mitre", sourceLabel: "MITRE ATT&CK", matches: mitreHits, count: mitreHits.length });
    }

    // Search Indexer alerts (cross-agent, real-time)
    if (isIndexerConnected && iocAlertsQ.data?.data) {
      const resp = iocAlertsQ.data.data as unknown as Record<string, unknown>;
      const hitsObj = (resp.hits as Record<string, unknown>) ?? {};
      const hitArr = (hitsObj.hits as Array<Record<string, unknown>>) ?? [];
      const alertHits = hitArr.map((h) => {
        const src = (h._source ?? {}) as Record<string, unknown>;
        return {
          _id: h._id,
          timestamp: src.timestamp,
          agent: src.agent,
          rule: src.rule,
          decoder: src.decoder,
          data: src.data,
          full_log: src.full_log,
          location: src.location,
        };
      });
      if (alertHits.length > 0) {
        results.push({ source: "alerts", sourceLabel: "Indexer Alerts", matches: alertHits as Record<string, unknown>[], count: alertHits.length });
      }
    }

    return results;
  }, [activeQuery, activeIocType, agents, rules, vulns, syscheck, logs, mitreTechniques, isIndexerConnected, iocAlertsQ.data]);

  const totalHits = correlationResults.reduce((sum, r) => sum + r.count, 0);

  // ── Execute hunt ──────────────────────────────────────────────────────────
  const executeHunt = useCallback(() => {
    if (!searchValue.trim()) return;
    setActiveQuery(searchValue.trim());
    setActiveIocType(iocType);
    setExpandedSource(null);
    setSelectedHunt(null);
    // Trigger Indexer alert search for IOC correlation
    if (isIndexerConnected) {
      setIocAlertQuery(searchValue.trim());
    }

    const entry: HuntEntry = {
      id: `hunt-${Date.now()}`,
      timestamp: new Date().toISOString(),
      query: searchValue.trim(),
      iocType,
      totalHits: 0, // Will be updated after render
      sources: [],
    };
    setHuntHistory((prev) => [entry, ...prev].slice(0, 50));
  }, [searchValue, iocType, isIndexerConnected]);

  // Update last hunt entry with results
  useMemo(() => {
    if (huntHistory.length > 0 && correlationResults.length > 0 && huntHistory[0].query === activeQuery) {
      setHuntHistory((prev) => {
        const updated = [...prev];
        if (updated[0]) {
          updated[0] = {
            ...updated[0],
            totalHits: totalHits,
            sources: correlationResults.map((r) => r.sourceLabel),
          };
        }
        return updated;
      });
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [correlationResults, totalHits]);

  // ── Refresh all queries ───────────────────────────────────────────────────
  const handleRefresh = () => {
    agentsQ.refetch();
    rulesQ.refetch();
    logsQ.refetch();
    mitreQ.refetch();
    if (isIndexerConnected) {
      vulnSearchQ.refetch();
      fimSearchQ.refetch();
      if (iocAlertQuery) iocAlertsQ.refetch();
    }
  };

  const isLoading = agentsQ.isLoading || rulesQ.isLoading || logsQ.isLoading || mitreQ.isLoading
    || (isIndexerConnected && (vulnSearchQ.isLoading || fimSearchQ.isLoading));

  // ── Computed stats ────────────────────────────────────────────────────────
  const agentCount = Number(((agents as Record<string, unknown>)?.data as Record<string, unknown>)?.total_affected_items ?? 0);
  const ruleCount = Number(((rules as Record<string, unknown>)?.data as Record<string, unknown>)?.total_affected_items ?? 0);
  const vulnCount = Number(((vulns as Record<string, unknown>)?.data as Record<string, unknown>)?.total_affected_items ?? 0);
  const fimCount = Number(((syscheck as Record<string, unknown>)?.data as Record<string, unknown>)?.total_affected_items ?? 0);

  // Source distribution for pie chart
  const sourceDistribution = correlationResults.map((r) => ({
    name: r.sourceLabel,
    value: r.count,
  }));

  // Severity distribution from rule hits
  const severityData = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const ruleResult = correlationResults.find((r) => r.source === "rules");
    if (ruleResult) {
      ruleResult.matches.forEach((m) => {
        const level = threatLevelFromNumber(Number((m as Record<string, unknown>).level ?? 0));
        counts[level] = (counts[level] || 0) + 1;
      });
    }
    const logResult = correlationResults.find((r) => r.source === "logs");
    if (logResult) {
      logResult.matches.forEach((m) => {
        const lvl = String((m as Record<string, unknown>).level ?? "info");
        if (lvl === "error") counts.high += 1;
        else if (lvl === "warning") counts.medium += 1;
        else counts.info += 1;
      });
    }
    return Object.entries(counts)
      .filter(([, v]) => v > 0)
      .map(([k, v]) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), value: v, level: k }));
  }, [correlationResults]);

  // MITRE tactic distribution from correlated rules
  const mitreTacticData = useMemo(() => {
    const tacticCounts: Record<string, number> = {};
    const ruleResult = correlationResults.find((r) => r.source === "rules");
    if (ruleResult) {
      ruleResult.matches.forEach((m) => {
        const mitre = (m as Record<string, unknown>).mitre as { tactic?: string[] } | undefined;
        (mitre?.tactic ?? []).forEach((t: string) => {
          tacticCounts[t] = (tacticCounts[t] || 0) + 1;
        });
      });
    }
    return Object.entries(tacticCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8)
      .map(([name, count]) => ({ name: name.length > 18 ? name.slice(0, 16) + "…" : name, fullName: name, count }));
  }, [correlationResults]);

  // ── Quick hunt presets ────────────────────────────────────────────────────
  const quickHunts = [
    { label: "Brute Force", type: "mitre_id" as IOCType, value: "T1110" },
    { label: "Credential Dump", type: "mitre_id" as IOCType, value: "T1003" },
    { label: "Lateral Movement", type: "freetext" as IOCType, value: "lateral movement" },
    { label: "Privilege Escalation", type: "freetext" as IOCType, value: "privilege escalation" },
    { label: "RegreSSHion", type: "cve" as IOCType, value: "CVE-2024-6387" },
    { label: "XZ Backdoor", type: "cve" as IOCType, value: "CVE-2024-3094" },
    { label: "Mimikatz", type: "freetext" as IOCType, value: "mimikatz" },
    { label: "Shellshock", type: "freetext" as IOCType, value: "shellshock" },
    { label: "/etc/shadow", type: "filename" as IOCType, value: "/etc/shadow" },
    { label: "SSH Scan", type: "freetext" as IOCType, value: "ssh scan" },
  ];

  const currentIOC = IOC_TYPES.find((t) => t.value === iocType) ?? IOC_TYPES[0];

  return (
    <WazuhGuard>
      <div className="flex items-center justify-between mb-6">
        <PageHeader
          title="Threat Hunting"
          subtitle="Cross-correlate IOCs across agents, rules, vulnerabilities, FIM, and MITRE ATT&CK"
          onRefresh={handleRefresh}
          isLoading={isLoading}
        />
        <div className="flex items-center gap-2 flex-shrink-0">
          {/* Saved Searches Dropdown */}
          <div className="relative">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowSavedSearches(!showSavedSearches)}
              className="text-xs bg-transparent border-border text-muted-foreground hover:bg-secondary/50"
            >
              <Bookmark className="h-3.5 w-3.5 mr-1" />
              Saved ({savedSearchesQ.data?.searches?.length ?? 0})
            </Button>
            {showSavedSearches && (
              <div className="absolute right-0 top-full mt-1 w-80 bg-[oklch(0.17_0.025_286)] border border-border rounded-lg shadow-xl z-50 max-h-[400px] overflow-y-auto">
                <div className="p-3 border-b border-border">
                  <h4 className="text-xs font-semibold text-primary">Saved Hunt Queries</h4>
                </div>
                {(savedSearchesQ.data?.searches ?? []).length === 0 ? (
                  <div className="p-4 text-center text-xs text-muted-foreground">
                    No saved hunts yet
                  </div>
                ) : (
                  <div className="divide-y divide-border/30">
                    {(savedSearchesQ.data?.searches ?? []).map((s) => (
                      <div
                        key={s.id}
                        className="flex items-center justify-between px-3 py-2.5 hover:bg-secondary/30 cursor-pointer group"
                      >
                        <div
                          className="flex-1 min-w-0"
                          onClick={() => {
                            const filters = s.filters as Record<string, unknown>;
                            if (filters.iocType) setIocType(filters.iocType as IOCType);
                            if (filters.searchValue) {
                              setSearchValue(filters.searchValue as string);
                              setActiveQuery(filters.searchValue as string);
                            }
                            if (filters.iocType) setActiveIocType(filters.iocType as IOCType);
                            setShowSavedSearches(false);
                            toast.success("Hunt query loaded");
                          }}
                        >
                          <p className="text-xs text-foreground truncate font-medium">{s.name}</p>
                          {s.description && (
                            <p className="text-[10px] text-muted-foreground truncate mt-0.5">{s.description}</p>
                          )}
                          <p className="text-[10px] text-muted-foreground/60 mt-0.5">
                            {new Date(s.createdAt).toLocaleDateString()}
                          </p>
                        </div>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            deleteSearchMut.mutate({ id: s.id });
                          }}
                          className="p-1 rounded opacity-0 group-hover:opacity-100 hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-all"
                        >
                          <Trash2 className="h-3 w-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Save Current Hunt */}
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowSaveDialog(true)}
            disabled={!activeQuery}
            className="text-xs bg-transparent border-border text-muted-foreground hover:bg-secondary/50"
          >
            <BookmarkPlus className="h-3.5 w-3.5 mr-1" />
            Save Hunt
          </Button>
        </div>
      </div>

      {/* ── Save Hunt Dialog ──────────────────────────────────────────────── */}
      {showSaveDialog && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center" onClick={() => setShowSaveDialog(false)}>
          <div className="bg-[oklch(0.17_0.025_286)] border border-border rounded-xl p-6 w-full max-w-md shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-sm font-semibold text-primary mb-4 flex items-center gap-2">
              <Save className="h-4 w-4" /> Save Hunt Query
            </h3>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Name *</label>
                <input
                  type="text"
                  value={saveName}
                  onChange={(e) => setSaveName(e.target.value)}
                  placeholder="e.g., Lateral movement via SSH"
                  className="w-full px-3 py-2 bg-secondary/50 border border-border rounded-lg text-sm text-foreground placeholder-muted-foreground/50 focus:outline-none focus:border-primary/50"
                  autoFocus
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Description (optional)</label>
                <input
                  type="text"
                  value={saveDescription}
                  onChange={(e) => setSaveDescription(e.target.value)}
                  placeholder="Brief description of this hunt..."
                  className="w-full px-3 py-2 bg-secondary/50 border border-border rounded-lg text-sm text-foreground placeholder-muted-foreground/50 focus:outline-none focus:border-primary/50"
                />
              </div>
              <div className="bg-secondary/30 rounded-lg p-3 text-xs text-muted-foreground space-y-1">
                <p className="font-semibold text-foreground">Current Query:</p>
                <p>IOC Type: <span className="text-primary">{IOC_TYPES.find((t) => t.value === iocType)?.label}</span></p>
                <p>Query: <span className="font-mono text-primary">{activeQuery || searchValue}</span></p>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-4">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowSaveDialog(false)}
                className="bg-transparent border-border text-muted-foreground"
              >
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={() => {
                  if (!saveName.trim()) {
                    toast.error("Please enter a name");
                    return;
                  }
                  createSearchMut.mutate({
                    name: saveName.trim(),
                    searchType: "hunting",
                    filters: {
                      iocType: activeIocType || iocType,
                      searchValue: activeQuery || searchValue,
                    },
                    description: saveDescription.trim() || undefined,
                  });
                }}
                disabled={createSearchMut.isPending}
                className="bg-primary hover:bg-primary/90 text-primary-foreground"
              >
                {createSearchMut.isPending ? "Saving..." : "Save Hunt"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* ── KPI Row ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-3 mb-6">
        <StatCard label="Searchable Agents" value={agentCount} icon={Activity} colorClass="text-primary" />
        <StatCard label="Detection Rules" value={ruleCount} icon={Shield} colorClass="text-threat-info" />
        <StatCard label="Known CVEs" value={vulnCount} icon={Bug} colorClass="text-threat-high" />
        <StatCard label="FIM Events" value={fimCount} icon={FileWarning} colorClass="text-threat-medium" />
        <StatCard label="Hunt Queries" value={huntHistory.length} icon={Crosshair} colorClass="text-primary" />
        <StatCard
          label="Last Correlation"
          value={totalHits > 0 ? `${totalHits} hits` : "—"}
          icon={Target}
          colorClass={totalHits > 0 ? "text-threat-critical" : "text-muted-foreground"}
        />
      </div>

      {/* ── Query Builder ────────────────────────────────────────────────── */}
      <GlassPanel className="mb-6">
        <div className="flex items-center gap-2 mb-4">
          <Crosshair className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-display font-semibold text-foreground">Hunt Query Builder</h2>
        </div>

        <div className="flex flex-col lg:flex-row gap-3">
          {/* IOC Type Selector */}
          <div className="relative">
            <select
              value={iocType}
              onChange={(e) => setIocType(e.target.value as IOCType)}
              className="h-11 px-4 pr-10 rounded-lg bg-secondary/50 border border-border text-sm text-foreground appearance-none cursor-pointer focus:outline-none focus:ring-2 focus:ring-primary/50 min-w-[160px]"
            >
              {IOC_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
          </div>

          {/* Search Input */}
          <div className="flex-1 relative">
            <currentIOC.icon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && executeHunt()}
              placeholder={currentIOC.placeholder}
              className="w-full h-11 pl-10 pr-10 rounded-lg bg-secondary/50 border border-border text-sm text-foreground font-mono placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50"
            />
            {searchValue && (
              <button
                onClick={() => setSearchValue("")}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>

          {/* Execute Button */}
          <Button
            onClick={executeHunt}
            disabled={!searchValue.trim()}
            className="h-11 px-6 bg-primary hover:bg-primary/90 text-primary-foreground font-medium gap-2"
          >
            <Search className="h-4 w-4" />
            Hunt
          </Button>
        </div>

        {/* Quick Hunt Presets */}
        <div className="flex flex-wrap gap-2 mt-4">
          <span className="text-xs text-muted-foreground self-center mr-1">Quick hunts:</span>
          {quickHunts.map((qh) => (
            <button
              key={qh.label}
              onClick={() => {
                setIocType(qh.type);
                setSearchValue(qh.value);
                setActiveQuery(qh.value);
                setActiveIocType(qh.type);
                setExpandedSource(null);
                if (isIndexerConnected) setIocAlertQuery(qh.value);
                const entry: HuntEntry = {
                  id: `hunt-${Date.now()}`,
                  timestamp: new Date().toISOString(),
                  query: qh.value,
                  iocType: qh.type,
                  totalHits: 0,
                  sources: [],
                };
                setHuntHistory((prev) => [entry, ...prev].slice(0, 50));
              }}
              className="px-3 py-1.5 rounded-full text-xs font-medium bg-primary/10 border border-primary/20 text-primary hover:bg-primary/20 transition-colors"
            >
              {qh.label}
            </button>
          ))}
        </div>
      </GlassPanel>

      {/* ── Results Section ──────────────────────────────────────────────── */}
      {activeQuery && (
        <>
          {/* Results Header */}
          <div className="flex items-center gap-3 mb-4">
            <div className="flex items-center gap-2">
              <Search className="h-4 w-4 text-primary" />
              <span className="text-sm text-muted-foreground">Results for</span>
              <code className="px-2 py-0.5 rounded bg-primary/10 border border-primary/20 text-xs font-mono text-primary">
                {activeQuery}
              </code>
              <span className="text-xs text-muted-foreground">
                ({IOC_TYPES.find((t) => t.value === activeIocType)?.label})
              </span>
            </div>
            <div className="ml-auto flex items-center gap-2">
              <span className="text-sm font-medium text-foreground">
                {totalHits} total hit{totalHits !== 1 ? "s" : ""} across {correlationResults.length} source{correlationResults.length !== 1 ? "s" : ""}
              </span>
              <RawJsonViewer data={correlationResults} title="Correlation Results" />
            </div>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
            {/* Source Distribution Pie */}
            <GlassPanel>
              <h3 className="text-sm font-medium text-foreground mb-3 flex items-center gap-2">
                <Layers className="h-4 w-4 text-primary" />
                Source Distribution
              </h3>
              {sourceDistribution.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={sourceDistribution}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={80}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {sourceDistribution.map((_, i) => (
                        <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ background: "oklch(0.17 0.025 286)", border: "1px solid oklch(0.3 0.04 286 / 40%)", borderRadius: "8px", color: "oklch(0.93 0.005 286)" }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[200px] flex items-center justify-center text-sm text-muted-foreground">No hits</div>
              )}
              <div className="flex flex-wrap gap-2 mt-2">
                {sourceDistribution.map((s, i) => (
                  <span key={s.name} className="text-xs flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full" style={{ background: CHART_COLORS[i % CHART_COLORS.length] }} />
                    {s.name}: {s.value}
                  </span>
                ))}
              </div>
            </GlassPanel>

            {/* Severity Breakdown */}
            <GlassPanel>
              <h3 className="text-sm font-medium text-foreground mb-3 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-threat-high" />
                Severity Breakdown
              </h3>
              {severityData.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={severityData} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
                    <XAxis type="number" tick={{ fill: "oklch(0.7 0.01 286)", fontSize: 11 }} />
                    <YAxis type="category" dataKey="name" tick={{ fill: "oklch(0.7 0.01 286)", fontSize: 11 }} width={70} />
                    <Tooltip
                      contentStyle={{ background: "oklch(0.17 0.025 286)", border: "1px solid oklch(0.3 0.04 286 / 40%)", borderRadius: "8px", color: "oklch(0.93 0.005 286)" }}
                    />
                    <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                      {severityData.map((entry) => (
                        <Cell
                          key={entry.name}
                          fill={
                            entry.level === "critical"
                              ? "oklch(0.637 0.237 25.331)"
                              : entry.level === "high"
                              ? "oklch(0.705 0.191 22.216)"
                              : entry.level === "medium"
                              ? "oklch(0.795 0.184 86.047)"
                              : entry.level === "low"
                              ? "oklch(0.765 0.177 163.223)"
                              : "oklch(0.789 0.154 211.53)"
                          }
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[200px] flex items-center justify-center text-sm text-muted-foreground">No severity data</div>
              )}
            </GlassPanel>

            {/* MITRE Tactic Correlation */}
            <GlassPanel>
              <h3 className="text-sm font-medium text-foreground mb-3 flex items-center gap-2">
                <Target className="h-4 w-4 text-threat-critical" />
                MITRE Tactic Correlation
              </h3>
              {mitreTacticData.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={mitreTacticData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.3 0.04 286 / 20%)" />
                    <XAxis dataKey="name" tick={{ fill: "oklch(0.7 0.01 286)", fontSize: 9 }} angle={-30} textAnchor="end" height={50} />
                    <YAxis tick={{ fill: "oklch(0.7 0.01 286)", fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{ background: "oklch(0.17 0.025 286)", border: "1px solid oklch(0.3 0.04 286 / 40%)", borderRadius: "8px", color: "oklch(0.93 0.005 286)" }}
                      formatter={(value: number, _: string, props: { payload?: { fullName?: string } }) => [value, props.payload?.fullName ?? ""]}
                    />
                    <Bar dataKey="count" fill="oklch(0.72 0.19 295)" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[200px] flex items-center justify-center text-sm text-muted-foreground">No MITRE data</div>
              )}
            </GlassPanel>
          </div>

          {/* ── Correlation Results by Source ─────────────────────────────── */}
          <GlassPanel className="mb-6">
            <h3 className="text-sm font-medium text-foreground mb-4 flex items-center gap-2">
              <Filter className="h-4 w-4 text-primary" />
              Correlated Results by Data Source
            </h3>

            {correlationResults.length === 0 ? (
              <div className="py-12 text-center">
                <Search className="h-10 w-10 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">No matches found for "{activeQuery}"</p>
                <p className="text-xs text-muted-foreground/60 mt-1">Try a different IOC type or search term</p>
              </div>
            ) : (
              <div className="space-y-2">
                {correlationResults.map((result) => {
                  const isExpanded = expandedSource === result.source;
                  const sourceIcon = result.source === "agents" ? Activity
                    : result.source === "rules" ? Shield
                    : result.source === "vulnerabilities" ? Bug
                    : result.source === "syscheck" ? FileWarning
                    : result.source === "logs" ? Terminal
                    : result.source === "alerts" ? AlertTriangle
                    : Target;

                  return (
                    <div key={result.source} className="border border-border/50 rounded-lg overflow-hidden">
                      {/* Source Header */}
                      <button
                        onClick={() => setExpandedSource(isExpanded ? null : result.source)}
                        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-secondary/30 transition-colors text-left"
                      >
                        {isExpanded ? (
                          <ChevronDown className="h-4 w-4 text-muted-foreground shrink-0" />
                        ) : (
                          <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
                        )}
                        {(() => {
                          const Icon = sourceIcon;
                          return <Icon className="h-4 w-4 text-primary shrink-0" />;
                        })()}
                        <span className="text-sm font-medium text-foreground">{result.sourceLabel}</span>
                        <span className="ml-auto flex items-center gap-2">
                          <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-primary/10 border border-primary/20 text-primary">
                            {result.count} hit{result.count !== 1 ? "s" : ""}
                          </span>
                        </span>
                      </button>

                      {/* Expanded Results */}
                      {isExpanded && (
                        <div className="border-t border-border/30">
                          <div className="overflow-x-auto">
                            <table className="w-full text-xs">
                              <thead>
                                <tr className="border-b border-border/30">
                                  <th className="px-4 py-2 text-left text-muted-foreground font-medium">#</th>
                                  {result.source === "agents" && (
                                    <>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">ID</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Name</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">IP</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Status</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">OS</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Groups</th>
                                    </>
                                  )}
                                  {result.source === "rules" && (
                                    <>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Rule ID</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Level</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Description</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">MITRE</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Groups</th>
                                    </>
                                  )}
                                  {result.source === "vulnerabilities" && (
                                    <>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">CVE</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Severity</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">CVSS</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Package</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Title</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Status</th>
                                    </>
                                  )}
                                  {result.source === "syscheck" && (
                                    <>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">File</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Event</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">MD5</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">SHA256</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Owner</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Date</th>
                                    </>
                                  )}
                                  {result.source === "logs" && (
                                    <>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Timestamp</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Level</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Tag</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Description</th>
                                    </>
                                  )}
                                  {result.source === "mitre" && (
                                    <>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">ID</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Name</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Tactics</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Description</th>
                                    </>
                                  )}
                                  {result.source === "alerts" && (
                                    <>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Timestamp</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Agent</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Rule</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Level</th>
                                      <th className="px-4 py-2 text-left text-muted-foreground font-medium">Description</th>
                                    </>
                                  )}
                                  <th className="px-4 py-2 text-left text-muted-foreground font-medium">JSON</th>
                                </tr>
                              </thead>
                              <tbody>
                                {result.matches.slice(0, 25).map((match, idx) => {
                                  const m = match as Record<string, unknown>;
                                  return (
                                    <tr key={idx} className="border-b border-border/20 hover:bg-secondary/20 transition-colors">
                                      <td className="px-4 py-2 text-muted-foreground font-mono">{idx + 1}</td>

                                      {result.source === "agents" && (
                                        <>
                                          <td className="px-4 py-2 font-mono text-primary">{String(m.id ?? "")}</td>
                                          <td className="px-4 py-2 text-foreground">{String(m.name ?? "")}</td>
                                          <td className="px-4 py-2 font-mono">{String(m.ip ?? "")}</td>
                                          <td className="px-4 py-2">
                                            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs ${
                                              m.status === "active" ? "bg-threat-low/20 text-threat-low" : "bg-threat-high/20 text-threat-high"
                                            }`}>
                                              <span className={`h-1.5 w-1.5 rounded-full ${m.status === "active" ? "bg-[oklch(0.765_0.177_163.223)]" : "bg-[oklch(0.705_0.191_22.216)]"}`} />
                                              {String(m.status ?? "")}
                                            </span>
                                          </td>
                                          <td className="px-4 py-2 text-muted-foreground">{String((m.os as Record<string, unknown>)?.name ?? "")}</td>
                                          <td className="px-4 py-2 text-muted-foreground">{(m.group as string[] ?? []).join(", ")}</td>
                                        </>
                                      )}

                                      {result.source === "rules" && (
                                        <>
                                          <td className="px-4 py-2 font-mono text-primary">{String(m.id ?? "")}</td>
                                          <td className="px-4 py-2"><ThreatBadge level={threatLevelFromNumber(Number(m.level ?? 0))} /></td>
                                          <td className="px-4 py-2 text-foreground max-w-[300px] truncate">{String(m.description ?? "")}</td>
                                          <td className="px-4 py-2">
                                            <div className="flex flex-wrap gap-1">
                                              {((m.mitre as Record<string, unknown>)?.id as string[] ?? []).map((id: string) => (
                                                <span key={id} className="px-1.5 py-0.5 rounded bg-threat-critical/10 border border-threat-critical/20 text-threat-critical text-[10px] font-mono">{id}</span>
                                              ))}
                                            </div>
                                          </td>
                                          <td className="px-4 py-2 text-muted-foreground">{(m.groups as string[] ?? []).slice(0, 3).join(", ")}</td>
                                        </>
                                      )}

                                      {result.source === "vulnerabilities" && (
                                        <>
                                          <td className="px-4 py-2">
                                            <a
                                              href={`https://nvd.nist.gov/vuln/detail/${String(m.cve ?? "")}`}
                                              target="_blank"
                                              rel="noopener noreferrer"
                                              className="font-mono text-primary hover:underline inline-flex items-center gap-1"
                                            >
                                              {String(m.cve ?? "")}
                                              <ExternalLink className="h-3 w-3" />
                                            </a>
                                          </td>
                                          <td className="px-4 py-2">
                                            <ThreatBadge level={(String(m.severity ?? "medium")).toLowerCase() as "critical" | "high" | "medium" | "low"} />
                                          </td>
                                          <td className="px-4 py-2 font-mono">{String(m.cvss3_score ?? m.cvss2_score ?? "—")}</td>
                                          <td className="px-4 py-2 font-mono text-muted-foreground">{String(m.name ?? "")}</td>
                                          <td className="px-4 py-2 text-foreground max-w-[250px] truncate">{String(m.title ?? "")}</td>
                                          <td className="px-4 py-2">
                                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${
                                              m.status === "Fixed" ? "bg-threat-low/20 text-threat-low" : "bg-threat-high/20 text-threat-high"
                                            }`}>
                                              {String(m.status ?? "")}
                                            </span>
                                          </td>
                                        </>
                                      )}

                                      {result.source === "syscheck" && (
                                        <>
                                          <td className="px-4 py-2 font-mono text-foreground max-w-[200px] truncate">{String(m.file ?? "")}</td>
                                          <td className="px-4 py-2">
                                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${
                                              m.event === "added" ? "bg-threat-info/20 text-threat-info"
                                              : m.event === "deleted" ? "bg-threat-critical/20 text-threat-critical"
                                              : "bg-threat-medium/20 text-threat-medium"
                                            }`}>
                                              {String(m.event ?? "")}
                                            </span>
                                          </td>
                                          <td className="px-4 py-2 font-mono text-muted-foreground text-[10px]">{String(m.md5 ?? "").slice(0, 12)}…</td>
                                          <td className="px-4 py-2 font-mono text-muted-foreground text-[10px]">{String(m.sha256 ?? "").slice(0, 16)}…</td>
                                          <td className="px-4 py-2">{String(m.uname ?? "")}</td>
                                          <td className="px-4 py-2 text-muted-foreground">{m.date ? new Date(String(m.date)).toLocaleString() : "—"}</td>
                                        </>
                                      )}

                                      {result.source === "logs" && (
                                        <>
                                          <td className="px-4 py-2 font-mono text-muted-foreground">{m.timestamp ? new Date(String(m.timestamp)).toLocaleString() : "—"}</td>
                                          <td className="px-4 py-2">
                                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${
                                              m.level === "error" ? "bg-threat-high/20 text-threat-high"
                                              : m.level === "warning" ? "bg-threat-medium/20 text-threat-medium"
                                              : "bg-threat-info/20 text-threat-info"
                                            }`}>
                                              {String(m.level ?? "")}
                                            </span>
                                          </td>
                                          <td className="px-4 py-2 font-mono text-primary">{String(m.tag ?? "")}</td>
                                          <td className="px-4 py-2 text-foreground max-w-[400px] truncate">{String(m.description ?? "")}</td>
                                        </>
                                      )}

                                      {result.source === "mitre" && (
                                        <>
                                          <td className="px-4 py-2 font-mono text-primary">{String(m.external_id ?? "")}</td>
                                          <td className="px-4 py-2 text-foreground font-medium">{String(m.name ?? "")}</td>
                                          <td className="px-4 py-2">
                                            <div className="flex flex-wrap gap-1">
                                              {(m.tactics as string[] ?? []).map((t: string) => (
                                                <span key={t} className="px-1.5 py-0.5 rounded bg-primary/10 border border-primary/20 text-primary text-[10px]">{t}</span>
                                              ))}
                                            </div>
                                          </td>
                                          <td className="px-4 py-2 text-muted-foreground max-w-[300px] truncate">{String(m.description ?? "")}</td>
                                        </>
                                      )}

                                      {result.source === "alerts" && (() => {
                                        const agent = (m.agent ?? {}) as Record<string, unknown>;
                                        const rule = (m.rule ?? {}) as Record<string, unknown>;
                                        return (
                                          <>
                                            <td className="px-4 py-2 font-mono text-muted-foreground text-[11px]">
                                              {m.timestamp ? new Date(String(m.timestamp)).toLocaleString() : "—"}
                                            </td>
                                            <td className="px-4 py-2">
                                              <span className="text-foreground">{String(agent.name ?? "")}</span>
                                              <span className="text-muted-foreground text-[10px] ml-1">({String(agent.id ?? "")})</span>
                                            </td>
                                            <td className="px-4 py-2 font-mono text-primary">{String(rule.id ?? "")}</td>
                                            <td className="px-4 py-2">
                                              <ThreatBadge level={threatLevelFromNumber(Number(rule.level ?? 0))} />
                                            </td>
                                            <td className="px-4 py-2 text-foreground max-w-[300px] truncate">{String(rule.description ?? "")}</td>
                                          </>
                                        );
                                      })()}

                                      <td className="px-4 py-2">
                                        <RawJsonViewer data={match} title={`${result.sourceLabel} #${idx + 1}`} />
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                          {result.count > 25 && (
                            <div className="px-4 py-2 text-xs text-muted-foreground border-t border-border/30">
                              Showing 25 of {result.count} results
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </GlassPanel>
        </>
      )}

      {/* ── Bottom Row: Hunt History + Data Coverage ─────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        {/* Hunt History */}
        <GlassPanel>
          <h3 className="text-sm font-medium text-foreground mb-3 flex items-center gap-2">
            <Clock className="h-4 w-4 text-primary" />
            Hunt History
            {huntHistory.length > 0 && (
              <span className="text-xs text-muted-foreground ml-auto">{huntHistory.length} queries</span>
            )}
          </h3>
          {huntHistory.length === 0 ? (
            <div className="py-8 text-center">
              <Crosshair className="h-8 w-8 text-muted-foreground/20 mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">No hunts yet. Use the query builder above.</p>
            </div>
          ) : (
            <div className="space-y-1 max-h-[300px] overflow-y-auto">
              {huntHistory.map((entry) => (
                <button
                  key={entry.id}
                  onClick={() => {
                    setSearchValue(entry.query);
                    setIocType(entry.iocType);
                    setActiveQuery(entry.query);
                    setActiveIocType(entry.iocType);
                    setSelectedHunt(entry.id);
                  }}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-colors ${
                    selectedHunt === entry.id ? "bg-primary/10 border border-primary/20" : "hover:bg-secondary/30"
                  }`}
                >
                  <Search className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <code className="text-xs font-mono text-foreground truncate">{entry.query}</code>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-secondary/50 border border-border text-muted-foreground shrink-0">
                        {IOC_TYPES.find((t) => t.value === entry.iocType)?.label}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px] text-muted-foreground">
                        {new Date(entry.timestamp).toLocaleTimeString()}
                      </span>
                      {entry.totalHits > 0 && (
                        <span className="text-[10px] text-primary font-medium">{entry.totalHits} hits</span>
                      )}
                      {entry.sources.length > 0 && (
                        <span className="text-[10px] text-muted-foreground">{entry.sources.join(", ")}</span>
                      )}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </GlassPanel>

        {/* Data Source Coverage */}
        <GlassPanel>
          <h3 className="text-sm font-medium text-foreground mb-3 flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-primary" />
            Data Source Coverage
          </h3>
          <div className="space-y-3">
            {[
              { label: "Agents", count: agentCount, icon: Activity, color: "bg-primary" },
              { label: "Detection Rules", count: ruleCount, icon: Shield, color: "bg-[oklch(0.789_0.154_211.53)]" },
              { label: "Vulnerabilities (CVE)", count: vulnCount, icon: Bug, color: "bg-[oklch(0.705_0.191_22.216)]" },
              { label: "FIM Events", count: fimCount, icon: FileWarning, color: "bg-[oklch(0.795_0.184_86.047)]" },
              { label: "MITRE Techniques", count: Number(((mitreTechniques as Record<string, unknown>)?.data as Record<string, unknown>)?.total_affected_items ?? 0), icon: Target, color: "bg-[oklch(0.637_0.237_25.331)]" },
              { label: "Manager Log Entries", count: Number(((logs as Record<string, unknown>)?.data as Record<string, unknown>)?.total_affected_items ?? 0), icon: Terminal, color: "bg-[oklch(0.765_0.177_163.223)]" },
            ].map((src) => {
              const Icon = src.icon;
              const maxCount = Math.max(agentCount, ruleCount, vulnCount, fimCount, 1);
              const pct = Math.min((src.count / maxCount) * 100, 100);
              return (
                <div key={src.label} className="flex items-center gap-3">
                  <Icon className="h-4 w-4 text-muted-foreground shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-foreground">{src.label}</span>
                      <span className="text-xs font-mono text-muted-foreground">{src.count.toLocaleString()}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-secondary/50 overflow-hidden">
                      <div className={`h-full rounded-full ${src.color} transition-all`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-4 pt-3 border-t border-border/30 space-y-1">
            <p className="text-xs text-muted-foreground">
              {isConnected ? (
                <span className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-[oklch(0.765_0.177_163.223)]" />
                  Wazuh API: Live data
                </span>
              ) : (
                <span className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-[oklch(0.795_0.184_86.047)]" />
                  Wazuh API: Using sample data
                </span>
              )}
            </p>
            <p className="text-xs text-muted-foreground">
              {isIndexerConnected ? (
                <span className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-[oklch(0.765_0.177_163.223)]" />
                  Indexer: Live vulnerability + FIM + alert search
                </span>
              ) : (
                <span className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-[oklch(0.795_0.184_86.047)]" />
                  Indexer: Offline — CVE/FIM use sample data
                </span>
              )}
            </p>
          </div>
        </GlassPanel>
      </div>
    </WazuhGuard>
  );
}
