import { GlassPanel } from "@/components/shared/GlassPanel";
// StatCard expects LucideIcon (component ref), not JSX elements
// PageHeader does not have an icon prop
import { PageHeader } from "@/components/shared/PageHeader";
import { ThreatBadge } from "@/components/shared/ThreatBadge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  Tabs, TabsContent, TabsList, TabsTrigger,
} from "@/components/ui/tabs";
import type { LucideIcon } from "lucide-react";
import {
  Radar, Search, Globe, Shield, FileText, Hash,
  ExternalLink, ChevronLeft, ChevronRight, AlertTriangle,
  Clock, Users, Eye, Tag, Loader2, RefreshCw, Copy,
  CheckCircle, XCircle, Activity, Target,
} from "lucide-react";
import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";

// ── Colors ───────────────────────────────────────────────────────────────────
const COLORS = {
  purple: "oklch(0.541 0.281 293.009)",
  cyan: "oklch(0.789 0.154 211.53)",
  green: "oklch(0.765 0.177 163.223)",
  yellow: "oklch(0.795 0.184 86.047)",
  red: "oklch(0.637 0.237 25.331)",
  orange: "oklch(0.705 0.191 22.216)",
};

// ── Helpers ──────────────────────────────────────────────────────────────────
function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleString();
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text);
  toast.success("Copied to clipboard");
}

// ── IOC Type icon mapping ────────────────────────────────────────────────────
function IocTypeIcon({ type }: { type: string }) {
  switch (type) {
    case "IPv4":
    case "IPv6":
      return <Globe className="w-3.5 h-3.5" />;
    case "domain":
    case "hostname":
      return <Globe className="w-3.5 h-3.5" />;
    case "FileHash-MD5":
    case "FileHash-SHA1":
    case "FileHash-SHA256":
      return <Hash className="w-3.5 h-3.5" />;
    case "URL":
    case "URI":
      return <ExternalLink className="w-3.5 h-3.5" />;
    case "CVE":
      return <Shield className="w-3.5 h-3.5" />;
    case "email":
      return <FileText className="w-3.5 h-3.5" />;
    default:
      return <Tag className="w-3.5 h-3.5" />;
  }
}

// ── Pulse Card ───────────────────────────────────────────────────────────────
function PulseCard({
  pulse,
  onClick,
}: {
  pulse: Record<string, unknown>;
  onClick: () => void;
}) {
  const name = (pulse.name as string) ?? "Untitled Pulse";
  const description = (pulse.description as string) ?? "";
  const created = pulse.created as string;
  const modified = pulse.modified as string;
  const tags = (pulse.tags as string[]) ?? [];
  const tlp = (pulse.tlp as string) ?? "white";
  const adversary = pulse.adversary as string | undefined;
  const indicatorCount = (pulse.indicator_count as number) ?? 0;
  const references = (pulse.references as string[]) ?? [];
  const targetedCountries = (pulse.targeted_countries as string[]) ?? [];
  const malwareFamilies = (pulse.malware_families as Array<Record<string, string>>) ?? [];
  const attackIds = (pulse.attack_ids as Array<Record<string, string>>) ?? [];

  const tlpColor: Record<string, string> = {
    white: COLORS.green,
    green: COLORS.green,
    amber: COLORS.yellow,
    red: COLORS.red,
  };

  return (
    <div
      className="glass-card p-4 cursor-pointer group"
      onClick={onClick}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex-1 min-w-0">
          <h3 className="font-display text-sm font-semibold text-foreground truncate group-hover:text-primary transition-colors">
            {name}
          </h3>
          {adversary && (
            <span className="text-xs text-threat-high font-mono mt-0.5 inline-block">
              {adversary}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Badge
            variant="outline"
            className="text-[10px] px-1.5 py-0 border-glass-border"
            style={{ color: tlpColor[tlp] ?? COLORS.cyan }}
          >
            TLP:{tlp.toUpperCase()}
          </Badge>
          <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-glass-border text-info-cyan">
            {indicatorCount} IOCs
          </Badge>
        </div>
      </div>

      {description && (
        <p className="text-xs text-muted-foreground line-clamp-2 mb-3">
          {description}
        </p>
      )}

      {/* MITRE ATT&CK IDs */}
      {attackIds.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-2">
          {attackIds.slice(0, 5).map((a, i) => (
            <Badge key={i} variant="outline" className="text-[10px] px-1.5 py-0 border-primary/30 text-primary">
              {a.display_name || a.id}
            </Badge>
          ))}
          {attackIds.length > 5 && (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-glass-border text-muted-foreground">
              +{attackIds.length - 5}
            </Badge>
          )}
        </div>
      )}

      {/* Tags */}
      {tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-3">
          {tags.slice(0, 6).map((tag, i) => (
            <span
              key={i}
              className="text-[10px] px-1.5 py-0.5 rounded-sm bg-accent/50 text-accent-foreground"
            >
              {tag}
            </span>
          ))}
          {tags.length > 6 && (
            <span className="text-[10px] px-1.5 py-0.5 text-muted-foreground">
              +{tags.length - 6}
            </span>
          )}
        </div>
      )}

      {/* Malware families */}
      {malwareFamilies.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-3">
          {malwareFamilies.slice(0, 3).map((m, i) => (
            <Badge key={i} variant="outline" className="text-[10px] px-1.5 py-0 border-threat-high/30 text-threat-high">
              {m.display_name || m.id}
            </Badge>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between text-[10px] text-muted-foreground">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            {created ? timeAgo(created) : "Unknown"}
          </span>
          {targetedCountries.length > 0 && (
            <span className="flex items-center gap-1">
              <Globe className="w-3 h-3" />
              {targetedCountries.slice(0, 3).join(", ")}
            </span>
          )}
        </div>
        {references.length > 0 && (
          <span className="flex items-center gap-1">
            <ExternalLink className="w-3 h-3" />
            {references.length} refs
          </span>
        )}
      </div>
    </div>
  );
}

// ── IOC Lookup Result ────────────────────────────────────────────────────────
function MiniStat({ label, value, icon: Icon, colorClass }: { label: string; value: string | number; icon: LucideIcon; colorClass?: string }) {
  return (
    <div className="glass-card p-4 flex items-start gap-3">
      <div className="h-9 w-9 rounded-lg flex items-center justify-center shrink-0 bg-primary/10 border border-primary/20">
        <Icon className={`h-4 w-4 ${colorClass ?? "text-primary"}`} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">{label}</p>
        <p className="text-lg font-display font-bold text-foreground mt-0.5 truncate">
          {typeof value === "number" ? value.toLocaleString() : value}
        </p>
      </div>
    </div>
  );
}

function IocResult({ data, type, value }: { data: Record<string, unknown>; type: string; value: string }) {
  const pulseInfo = data.pulse_info as Record<string, unknown> | undefined;
  const pulseCount = (pulseInfo?.count as number) ?? 0;
  const pulses = (pulseInfo?.pulses as Array<Record<string, unknown>>) ?? [];
  const reputation = data.reputation as number | undefined;
  const country = (data.country_name as string) ?? (data.country_code as string);
  const asn = data.asn as string;
  const sections = data.sections as string[] | undefined;
  const validation = data.validation as Array<Record<string, unknown>> | undefined;

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <MiniStat
          label="Pulse References"
          value={pulseCount}
          icon={Activity}
          colorClass={pulseCount > 10 ? "text-threat-critical" : pulseCount > 0 ? "text-threat-high" : "text-primary"}
        />
        {reputation !== undefined && (
          <MiniStat
            label="Reputation"
            value={reputation}
            icon={Shield}
            colorClass={reputation > 0 ? "text-threat-critical" : "text-primary"}
          />
        )}
        {country && (
          <MiniStat
            label="Country"
            value={String(country)}
            icon={Globe}
          />
        )}
        {asn && (
          <MiniStat
            label="ASN"
            value={String(asn)}
            icon={Target}
          />
        )}
      </div>

      {/* Indicator value */}
      <GlassPanel className="p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Indicator</span>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 px-2 text-xs"
            onClick={() => copyToClipboard(value)}
          >
            <Copy className="w-3 h-3 mr-1" /> Copy
          </Button>
        </div>
        <code className="font-mono text-sm text-info-cyan break-all">{value}</code>
        <div className="flex items-center gap-2 mt-2">
          <Badge variant="outline" className="text-[10px] border-glass-border">{type}</Badge>
          {sections?.map((s: string, i: number) => (
            <Badge key={i} variant="outline" className="text-[10px] border-glass-border text-muted-foreground">
              {s}
            </Badge>
          ))}
        </div>
      </GlassPanel>

      {/* Validation */}
      {validation && validation.length > 0 && (
        <GlassPanel className="p-4">
          <h4 className="text-xs text-muted-foreground uppercase tracking-wider mb-3">Validation</h4>
          <div className="space-y-2">
            {validation.map((v: Record<string, unknown>, i: number) => (
              <div key={i} className="flex items-center gap-2 text-sm">
                {v.source ? <Badge variant="outline" className="text-[10px]">{String(v.source)}</Badge> : null}
                <span className="text-muted-foreground">{String(v.message)}</span>
              </div>
            ))}
          </div>
        </GlassPanel>
      )}

      {/* Related pulses */}
      {pulses.length > 0 && (
        <GlassPanel className="p-4">
          <h4 className="text-xs text-muted-foreground uppercase tracking-wider mb-3">
            Related Pulses ({pulseCount})
          </h4>
          <div className="space-y-2 max-h-[400px] overflow-y-auto">
            {pulses.map((p, i) => (
              <div key={i} className="glass-card p-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">{String(p.name)}</p>
                    <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">
                      {String(p.description ?? "")}
                    </p>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {p.adversary ? (
                      <Badge variant="outline" className="text-[10px] border-threat-high/30 text-threat-high">
                        {String(p.adversary)}
                      </Badge>
                    ) : null}
                    <span className="text-[10px] text-muted-foreground">
                      {p.created ? timeAgo(p.created as string) : ""}
                    </span>
                  </div>
                </div>
                {(p.tags as string[] | undefined)?.length ? (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {(p.tags as string[]).slice(0, 5).map((t, j) => (
                      <span key={j} className="text-[10px] px-1.5 py-0.5 rounded-sm bg-accent/50 text-accent-foreground">
                        {t}
                      </span>
                    ))}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </GlassPanel>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN PAGE
// ═══════════════════════════════════════════════════════════════════════════════
export default function ThreatIntel() {
  // ── Tab state ──────────────────────────────────────────────────────────────
  const [activeTab, setActiveTab] = useState<"feed" | "search" | "lookup">("feed");

  // ── Feed state ─────────────────────────────────────────────────────────────
  const [feedPage, setFeedPage] = useState(1);
  const [selectedPulse, setSelectedPulse] = useState<Record<string, unknown> | null>(null);

  // ── Search state ───────────────────────────────────────────────────────────
  const [searchQuery, setSearchQuery] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [searchPage, setSearchPage] = useState(1);

  // ── IOC Lookup state ───────────────────────────────────────────────────────
  const [iocType, setIocType] = useState<"IPv4" | "IPv6" | "domain" | "hostname" | "file" | "url" | "cve">("IPv4");
  const [iocValue, setIocValue] = useState("");
  const [iocInput, setIocInput] = useState("");
  const [iocSection, setIocSection] = useState<"general" | "reputation" | "geo" | "malware" | "url_list" | "passive_dns">("general");

  // ── OTX Status ─────────────────────────────────────────────────────────────
  const statusQuery = trpc.otx.status.useQuery();

  // ── Feed queries ───────────────────────────────────────────────────────────
  const feedQuery = trpc.otx.subscribedPulses.useQuery(
    { page: feedPage, limit: 12 },
    { enabled: activeTab === "feed" }
  );

  // ── Search queries ─────────────────────────────────────────────────────────
  const searchResultsQuery = trpc.otx.searchPulses.useQuery(
    { query: searchQuery, page: searchPage, limit: 12 },
    { enabled: activeTab === "search" && searchQuery.length > 0 }
  );

  // ── IOC Lookup ─────────────────────────────────────────────────────────────
  const iocQuery = trpc.otx.indicatorLookup.useQuery(
    { type: iocType, value: iocValue, section: iocSection },
    { enabled: activeTab === "lookup" && iocValue.length > 0 }
  );

  // ── Pulse detail ───────────────────────────────────────────────────────────
  const pulseDetailQuery = trpc.otx.pulseDetail.useQuery(
    { pulseId: (selectedPulse?.id as string) ?? "" },
    { enabled: !!selectedPulse?.id }
  );

  const pulseIndicatorsQuery = trpc.otx.pulseIndicators.useQuery(
    { pulseId: (selectedPulse?.id as string) ?? "", limit: 100 },
    { enabled: !!selectedPulse?.id }
  );

  // ── Handlers ───────────────────────────────────────────────────────────────
  const handleSearch = useCallback(() => {
    if (searchInput.trim()) {
      setSearchQuery(searchInput.trim());
      setSearchPage(1);
    }
  }, [searchInput]);

  const handleIocLookup = useCallback(() => {
    if (iocInput.trim()) {
      setIocValue(iocInput.trim());
    }
  }, [iocInput]);

  // ── Derived data ───────────────────────────────────────────────────────────
  const feedPulses = useMemo(() => {
    const data = feedQuery.data?.data as Record<string, unknown> | null;
    return (data?.results as Array<Record<string, unknown>>) ?? [];
  }, [feedQuery.data]);

  const feedCount = useMemo(() => {
    const data = feedQuery.data?.data as Record<string, unknown> | null;
    return (data?.count as number) ?? 0;
  }, [feedQuery.data]);

  const searchPulses = useMemo(() => {
    const data = searchResultsQuery.data?.data as Record<string, unknown> | null;
    return (data?.results as Array<Record<string, unknown>>) ?? [];
  }, [searchResultsQuery.data]);

  const searchCount = useMemo(() => {
    const data = searchResultsQuery.data?.data as Record<string, unknown> | null;
    return (data?.count as number) ?? 0;
  }, [searchResultsQuery.data]);

  const iocData = useMemo(() => {
    return iocQuery.data?.data as Record<string, unknown> | null;
  }, [iocQuery.data]);

  const pulseDetail = useMemo(() => {
    return pulseDetailQuery.data?.data as Record<string, unknown> | null;
  }, [pulseDetailQuery.data]);

  const pulseIocs = useMemo(() => {
    const data = pulseIndicatorsQuery.data?.data as Record<string, unknown> | null;
    return (data?.results as Array<Record<string, unknown>>) ?? [];
  }, [pulseIndicatorsQuery.data]);

  const isConfigured = statusQuery.data?.configured ?? false;
  const otxUser = statusQuery.data?.user as Record<string, unknown> | null;

  // ── Not configured state ───────────────────────────────────────────────────
  if (statusQuery.isLoading) {
    return (
      <div className="p-6 space-y-6">
        <PageHeader
          title="Threat Intelligence"
          subtitle="AlienVault OTX Feed"
        />
        <GlassPanel className="p-12 text-center">
          <Loader2 className="w-8 h-8 animate-spin text-primary mx-auto mb-3" />
          <p className="text-muted-foreground">Connecting to OTX...</p>
        </GlassPanel>
      </div>
    );
  }

  if (!isConfigured) {
    return (
      <div className="p-6 space-y-6">
        <PageHeader
          title="Threat Intelligence"
          subtitle="AlienVault OTX Feed"
        />
        <GlassPanel className="p-12 text-center">
          <XCircle className="w-12 h-12 text-threat-high mx-auto mb-4" />
          <h3 className="font-display text-lg font-semibold mb-2">OTX Not Configured</h3>
          <p className="text-muted-foreground text-sm max-w-md mx-auto">
            Set the <code className="font-mono text-primary">OTX_API_KEY</code> environment variable to enable threat intelligence feeds.
          </p>
        </GlassPanel>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <PageHeader
        title="Threat Intelligence"
        subtitle="AlienVault OTX Feed"
      >
        <div className="flex items-center gap-3">
          {otxUser && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <CheckCircle className="w-3.5 h-3.5 text-threat-safe" />
              <span className="font-mono">{otxUser.username as string}</span>
            </div>
          )}
          <Badge variant="outline" className="text-[10px] border-threat-safe/30 text-threat-safe">
            OTX Connected
          </Badge>
        </div>
      </PageHeader>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as typeof activeTab)}>
        <TabsList className="bg-glass border border-glass-border">
          <TabsTrigger value="feed" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary">
            <Activity className="w-3.5 h-3.5 mr-1.5" />
            Subscribed Feed
          </TabsTrigger>
          <TabsTrigger value="search" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary">
            <Search className="w-3.5 h-3.5 mr-1.5" />
            Search Pulses
          </TabsTrigger>
          <TabsTrigger value="lookup" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary">
            <Shield className="w-3.5 h-3.5 mr-1.5" />
            IOC Lookup
          </TabsTrigger>
        </TabsList>

        {/* ═══════════════════════════════════════════════════════════════════ */}
        {/* SUBSCRIBED FEED TAB */}
        {/* ═══════════════════════════════════════════════════════════════════ */}
        <TabsContent value="feed" className="space-y-4 mt-4">
          {/* Stats row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <MiniStat label="Subscribed Pulses" value={feedCount} icon={FileText} />
            <MiniStat label="Current Page" value={feedPage} icon={Eye} />
            <MiniStat label="Total Pages" value={Math.ceil(feedCount / 12) || 1} icon={Radar} />
            <MiniStat label="Data Source" value="OTX Live" icon={CheckCircle} colorClass="text-threat-safe" />
          </div>

          {/* Loading state */}
          {feedQuery.isLoading && (
            <GlassPanel className="p-12 text-center">
              <Loader2 className="w-8 h-8 animate-spin text-primary mx-auto mb-3" />
              <p className="text-muted-foreground text-sm">Loading subscribed pulses...</p>
            </GlassPanel>
          )}

          {/* Error state */}
          {feedQuery.isError && (
            <GlassPanel className="p-8 text-center">
              <AlertTriangle className="w-8 h-8 text-threat-high mx-auto mb-3" />
              <p className="text-threat-high text-sm mb-2">Failed to load pulses</p>
              <p className="text-muted-foreground text-xs">{feedQuery.error.message}</p>
              <Button
                variant="outline"
                size="sm"
                className="mt-4"
                onClick={() => feedQuery.refetch()}
              >
                <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Retry
              </Button>
            </GlassPanel>
          )}

          {/* Pulse grid */}
          {!feedQuery.isLoading && !feedQuery.isError && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-3">
                {feedPulses.map((pulse, i) => (
                  <PulseCard
                    key={(pulse.id as string) ?? i}
                    pulse={pulse}
                    onClick={() => setSelectedPulse(pulse)}
                  />
                ))}
              </div>

              {feedPulses.length === 0 && (
                <GlassPanel className="p-12 text-center">
                  <Radar className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
                  <p className="text-muted-foreground">No subscribed pulses found.</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Subscribe to pulses on{" "}
                    <a href="https://otx.alienvault.com" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                      otx.alienvault.com
                    </a>
                  </p>
                </GlassPanel>
              )}

              {/* Pagination */}
              {feedCount > 12 && (
                <div className="flex items-center justify-center gap-3">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={feedPage <= 1}
                    onClick={() => setFeedPage((p) => p - 1)}
                    className="border-glass-border"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </Button>
                  <span className="text-xs text-muted-foreground font-mono">
                    Page {feedPage} of {Math.ceil(feedCount / 12)}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={feedPage >= Math.ceil(feedCount / 12)}
                    onClick={() => setFeedPage((p) => p + 1)}
                    className="border-glass-border"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </Button>
                </div>
              )}
            </>
          )}
        </TabsContent>

        {/* ═══════════════════════════════════════════════════════════════════ */}
        {/* SEARCH PULSES TAB */}
        {/* ═══════════════════════════════════════════════════════════════════ */}
        <TabsContent value="search" className="space-y-4 mt-4">
          {/* Search bar */}
          <GlassPanel className="p-4">
            <div className="flex gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search pulses by keyword, malware family, CVE, threat actor..."
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                  className="pl-10 bg-background/50 border-glass-border"
                />
              </div>
              <Button onClick={handleSearch} className="bg-primary/20 hover:bg-primary/30 text-primary border border-primary/30">
                <Search className="w-4 h-4 mr-1.5" /> Search
              </Button>
            </div>
          </GlassPanel>

          {/* Search results */}
          {searchResultsQuery.isLoading && (
            <GlassPanel className="p-12 text-center">
              <Loader2 className="w-8 h-8 animate-spin text-primary mx-auto mb-3" />
              <p className="text-muted-foreground text-sm">Searching OTX...</p>
            </GlassPanel>
          )}

          {searchQuery && !searchResultsQuery.isLoading && (
            <>
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  {searchCount} results for "<span className="text-primary">{searchQuery}</span>"
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-3">
                {searchPulses.map((pulse, i) => (
                  <PulseCard
                    key={(pulse.id as string) ?? i}
                    pulse={pulse}
                    onClick={() => setSelectedPulse(pulse)}
                  />
                ))}
              </div>

              {searchPulses.length === 0 && (
                <GlassPanel className="p-8 text-center">
                  <Search className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
                  <p className="text-muted-foreground">No pulses found for this query.</p>
                </GlassPanel>
              )}

              {/* Search pagination */}
              {searchCount > 12 && (
                <div className="flex items-center justify-center gap-3">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={searchPage <= 1}
                    onClick={() => setSearchPage((p) => p - 1)}
                    className="border-glass-border"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </Button>
                  <span className="text-xs text-muted-foreground font-mono">
                    Page {searchPage} of {Math.ceil(searchCount / 12)}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={searchPage >= Math.ceil(searchCount / 12)}
                    onClick={() => setSearchPage((p) => p + 1)}
                    className="border-glass-border"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </Button>
                </div>
              )}
            </>
          )}

          {!searchQuery && (
            <GlassPanel className="p-12 text-center">
              <Search className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
              <p className="text-muted-foreground">Enter a search query to find threat intelligence pulses.</p>
              <p className="text-xs text-muted-foreground mt-1">
                Try: "ransomware", "APT29", "CVE-2024", "phishing"
              </p>
            </GlassPanel>
          )}
        </TabsContent>

        {/* ═══════════════════════════════════════════════════════════════════ */}
        {/* IOC LOOKUP TAB */}
        {/* ═══════════════════════════════════════════════════════════════════ */}
        <TabsContent value="lookup" className="space-y-4 mt-4">
          {/* Lookup bar */}
          <GlassPanel className="p-4">
            <div className="flex flex-col sm:flex-row gap-3">
              <Select value={iocType} onValueChange={(v) => setIocType(v as typeof iocType)}>
                <SelectTrigger className="w-full sm:w-[140px] bg-background/50 border-glass-border">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="glass-panel border-glass-border">
                  <SelectItem value="IPv4">IPv4</SelectItem>
                  <SelectItem value="IPv6">IPv6</SelectItem>
                  <SelectItem value="domain">Domain</SelectItem>
                  <SelectItem value="hostname">Hostname</SelectItem>
                  <SelectItem value="file">File Hash</SelectItem>
                  <SelectItem value="url">URL</SelectItem>
                  <SelectItem value="cve">CVE</SelectItem>
                </SelectContent>
              </Select>

              <div className="relative flex-1">
                <Shield className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder={
                    iocType === "IPv4" ? "e.g., 8.8.8.8" :
                    iocType === "domain" ? "e.g., malicious-domain.com" :
                    iocType === "file" ? "e.g., 44d88612fea8a8f36de82e1278abb02f" :
                    iocType === "cve" ? "e.g., CVE-2024-1234" :
                    iocType === "url" ? "e.g., http://malicious.com/payload" :
                    "Enter indicator value..."
                  }
                  value={iocInput}
                  onChange={(e) => setIocInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleIocLookup()}
                  className="pl-10 bg-background/50 border-glass-border font-mono text-sm"
                />
              </div>

              <Select value={iocSection} onValueChange={(v) => setIocSection(v as typeof iocSection)}>
                <SelectTrigger className="w-full sm:w-[150px] bg-background/50 border-glass-border">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="glass-panel border-glass-border">
                  <SelectItem value="general">General</SelectItem>
                  <SelectItem value="reputation">Reputation</SelectItem>
                  <SelectItem value="geo">Geo</SelectItem>
                  <SelectItem value="malware">Malware</SelectItem>
                  <SelectItem value="url_list">URL List</SelectItem>
                  <SelectItem value="passive_dns">Passive DNS</SelectItem>
                </SelectContent>
              </Select>

              <Button onClick={handleIocLookup} className="bg-primary/20 hover:bg-primary/30 text-primary border border-primary/30">
                <Search className="w-4 h-4 mr-1.5" /> Lookup
              </Button>
            </div>
          </GlassPanel>

          {/* IOC Results */}
          {iocQuery.isLoading && (
            <GlassPanel className="p-12 text-center">
              <Loader2 className="w-8 h-8 animate-spin text-primary mx-auto mb-3" />
              <p className="text-muted-foreground text-sm">Looking up indicator...</p>
            </GlassPanel>
          )}

          {iocQuery.isError && (
            <GlassPanel className="p-8 text-center">
              <AlertTriangle className="w-8 h-8 text-threat-high mx-auto mb-3" />
              <p className="text-threat-high text-sm mb-2">Lookup failed</p>
              <p className="text-muted-foreground text-xs">{iocQuery.error.message}</p>
            </GlassPanel>
          )}

          {iocData && !iocQuery.isLoading && (
            <IocResult data={iocData} type={iocType} value={iocValue} />
          )}

          {!iocValue && !iocQuery.isLoading && (
            <GlassPanel className="p-12 text-center">
              <Shield className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
              <p className="text-muted-foreground">Enter an indicator of compromise to check its reputation.</p>
              <div className="flex flex-wrap justify-center gap-2 mt-4">
                {[
                  { type: "IPv4", val: "8.8.8.8", label: "Google DNS" },
                  { type: "domain", val: "example.com", label: "Example" },
                  { type: "cve", val: "CVE-2024-3094", label: "XZ Utils" },
                ].map((ex) => (
                  <Button
                    key={ex.val}
                    variant="outline"
                    size="sm"
                    className="text-xs border-glass-border"
                    onClick={() => {
                      setIocType(ex.type as typeof iocType);
                      setIocInput(ex.val);
                      setIocValue(ex.val);
                    }}
                  >
                    <IocTypeIcon type={ex.type} />
                    <span className="ml-1.5 font-mono">{ex.val}</span>
                    <span className="ml-1 text-muted-foreground">({ex.label})</span>
                  </Button>
                ))}
              </div>
            </GlassPanel>
          )}
        </TabsContent>
      </Tabs>

      {/* ═══════════════════════════════════════════════════════════════════════ */}
      {/* PULSE DETAIL DIALOG */}
      {/* ═══════════════════════════════════════════════════════════════════════ */}
      <Dialog open={!!selectedPulse} onOpenChange={(open) => !open && setSelectedPulse(null)}>
        <DialogContent className="glass-panel border-glass-border max-w-4xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="font-display text-lg">
              {(selectedPulse?.name as string) ?? "Pulse Detail"}
            </DialogTitle>
          </DialogHeader>

          {pulseDetailQuery.isLoading ? (
            <div className="p-8 text-center">
              <Loader2 className="w-6 h-6 animate-spin text-primary mx-auto mb-2" />
              <p className="text-muted-foreground text-sm">Loading pulse details...</p>
            </div>
          ) : pulseDetail ? (
            <div className="space-y-4">
              {/* Pulse metadata */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <MiniStat label="IOC Count" value={(pulseDetail.indicator_count as number) ?? 0} icon={Target} />
                <MiniStat label="References" value={((pulseDetail.references as string[]) ?? []).length} icon={ExternalLink} />
                <MiniStat label="Subscribers" value={(pulseDetail.subscriber_count as number) ?? 0} icon={Users} />
                <MiniStat label="TLP" value={((pulseDetail.tlp as string) ?? "white").toUpperCase()} icon={Shield} />
              </div>

              {/* Description */}
              {pulseDetail.description ? (
                <GlassPanel className="p-4">
                  <h4 className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Description</h4>
                  <p className="text-sm text-foreground whitespace-pre-wrap">
                    {String(pulseDetail.description)}
                  </p>
                </GlassPanel>
              ) : null}

              {/* Timestamps */}
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span>Created: {formatDate((pulseDetail.created as string) ?? "")}</span>
                <span>Modified: {formatDate((pulseDetail.modified as string) ?? "")}</span>
                {pulseDetail.author_name ? (
                  <span>Author: <span className="text-primary font-mono">{String(pulseDetail.author_name)}</span></span>
                ) : null}
              </div>

              {/* MITRE ATT&CK */}
              {((pulseDetail.attack_ids as Array<Record<string, string>>) ?? []).length > 0 && (
                <GlassPanel className="p-4">
                  <h4 className="text-xs text-muted-foreground uppercase tracking-wider mb-2">MITRE ATT&CK</h4>
                  <div className="flex flex-wrap gap-1.5">
                    {((pulseDetail.attack_ids as Array<Record<string, string>>) ?? []).map((a, i) => (
                      <Badge key={i} variant="outline" className="text-xs border-primary/30 text-primary">
                        {a.display_name || a.id}
                      </Badge>
                    ))}
                  </div>
                </GlassPanel>
              )}

              {/* References */}
              {((pulseDetail.references as string[]) ?? []).length > 0 && (
                <GlassPanel className="p-4">
                  <h4 className="text-xs text-muted-foreground uppercase tracking-wider mb-2">References</h4>
                  <div className="space-y-1 max-h-[200px] overflow-y-auto">
                    {((pulseDetail.references as string[]) ?? []).map((ref, i) => (
                      <a
                        key={i}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1.5 text-xs text-info-cyan hover:text-primary transition-colors truncate"
                      >
                        <ExternalLink className="w-3 h-3 shrink-0" />
                        <span className="truncate font-mono">{ref}</span>
                      </a>
                    ))}
                  </div>
                </GlassPanel>
              )}

              {/* IOC Table */}
              <GlassPanel className="p-4">
                <h4 className="text-xs text-muted-foreground uppercase tracking-wider mb-3">
                  Indicators of Compromise ({pulseIocs.length})
                </h4>
                {pulseIndicatorsQuery.isLoading ? (
                  <div className="p-4 text-center">
                    <Loader2 className="w-5 h-5 animate-spin text-primary mx-auto" />
                  </div>
                ) : (
                  <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-glass-border text-muted-foreground">
                          <th className="text-left py-2 px-3 font-medium">Type</th>
                          <th className="text-left py-2 px-3 font-medium">Indicator</th>
                          <th className="text-left py-2 px-3 font-medium">Title</th>
                          <th className="text-left py-2 px-3 font-medium">Created</th>
                          <th className="text-right py-2 px-3 font-medium">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pulseIocs.map((ioc, i) => (
                          <tr key={i} className="border-b border-glass-border/50 data-row">
                            <td className="py-2 px-3">
                              <Badge variant="outline" className="text-[10px] border-glass-border">
                                <IocTypeIcon type={ioc.type as string} />
                                <span className="ml-1">{ioc.type as string}</span>
                              </Badge>
                            </td>
                            <td className="py-2 px-3">
                              <code className="font-mono text-info-cyan break-all">
                                {ioc.indicator as string}
                              </code>
                            </td>
                            <td className="py-2 px-3 text-muted-foreground max-w-[200px] truncate">
                              {(ioc.title as string) || "—"}
                            </td>
                            <td className="py-2 px-3 text-muted-foreground whitespace-nowrap">
                              {ioc.created ? timeAgo(ioc.created as string) : "—"}
                            </td>
                            <td className="py-2 px-3 text-right">
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-6 px-2"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  copyToClipboard(ioc.indicator as string);
                                }}
                              >
                                <Copy className="w-3 h-3" />
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {pulseIocs.length === 0 && (
                      <p className="text-center text-muted-foreground py-4">No indicators found.</p>
                    )}
                  </div>
                )}
              </GlassPanel>

              {/* View on OTX link */}
              <div className="flex justify-end">
                <a
                  href={`https://otx.alienvault.com/pulse/${selectedPulse?.id as string}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-primary hover:underline flex items-center gap-1"
                >
                  <ExternalLink className="w-3 h-3" />
                  View on OTX
                </a>
              </div>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
