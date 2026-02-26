import { GlassPanel } from "@/components/shared/GlassPanel";
import { StatCard } from "@/components/shared/StatCard";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  Package,
  Server,
  UserCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  GitCompare,
  ArrowLeftRight,
  Minus,
  Save,
  FolderOpen,
  Trash2,
  Clock,
  Shield,
  Plus,
  MinusCircle,
  ArrowUpDown,
} from "lucide-react";
import { useState, useMemo, useEffect, useCallback } from "react";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { DataLoading, DataEmpty } from "@/components/shared/DataStates";

type DriftStatus = "present" | "absent" | "version_mismatch" | "state_mismatch";

// Extended for baseline comparison
type BaselineDriftStatus = DriftStatus | "new" | "removed" | "changed";

interface DriftItem {
  name: string;
  status: Record<string, DriftStatus>;
  details: Record<string, string>;
  hasDrift: boolean;
}

interface BaselineDriftItem {
  name: string;
  agentId: string;
  agentName: string;
  baselineValue: string;
  currentValue: string;
  changeType: "new" | "removed" | "changed";
  category: "packages" | "services" | "users";
}

// ── Data extraction helper ─────────────────────────────────────────────

function extractItems(data: unknown): Array<Record<string, unknown>> {
  const d = (data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
}

// ── Per-agent data maps ───────────────────────────────────────────────

type PkgEntry = { name: string; version: string };
type SvcEntry = { name: string; state: string };
type UsrEntry = { name: string; shell: string };

interface AgentDataMaps {
  packages: Record<string, PkgEntry[]>;
  services: Record<string, SvcEntry[]>;
  users: Record<string, UsrEntry[]>;
}

// ── Snapshot helpers ────────────────────────────────────────────────────

function collectAgentSnapshot(data: AgentDataMaps, agentIds: string[]) {
  const packages: Record<string, PkgEntry[]> = {};
  const services: Record<string, SvcEntry[]> = {};
  const users: Record<string, UsrEntry[]> = {};

  for (const id of agentIds) {
    packages[id] = data.packages[id] ?? [];
    services[id] = data.services[id] ?? [];
    users[id] = data.users[id] ?? [];
  }

  return { packages, services, users };
}

// ── Drift detection helpers ──────────────────────────────────────────────

function computePackageDrift(
  agentIds: string[],
  pkgData: Record<string, PkgEntry[]>
): DriftItem[] {
  const allPackages = new Map<string, Record<string, { version: string }>>();

  for (const id of agentIds) {
    for (const pkg of (pkgData[id] ?? [])) {
      if (!allPackages.has(pkg.name)) allPackages.set(pkg.name, {});
      allPackages.get(pkg.name)![id] = { version: pkg.version };
    }
  }

  const results: DriftItem[] = [];
  for (const [name, agents] of Array.from(allPackages)) {
    const status: Record<string, DriftStatus> = {};
    const details: Record<string, string> = {};
    const versions = new Set<string>();

    for (const id of agentIds) {
      if (agents[id]) {
        versions.add(agents[id].version);
        details[id] = agents[id].version;
      } else {
        details[id] = "—";
      }
    }

    const presentCount = Object.keys(agents).length;
    const allPresent = presentCount === agentIds.length;

    for (const id of agentIds) {
      if (!agents[id]) {
        status[id] = "absent";
      } else if (!allPresent) {
        status[id] = "present";
      } else if (versions.size > 1) {
        status[id] = "version_mismatch";
      } else {
        status[id] = "present";
      }
    }

    const hasDrift = !allPresent || versions.size > 1;
    results.push({ name, status, details, hasDrift });
  }

  return results.sort((a, b) => {
    if (a.hasDrift !== b.hasDrift) return a.hasDrift ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}

function computeServiceDrift(
  agentIds: string[],
  svcData: Record<string, SvcEntry[]>
): DriftItem[] {
  const allServices = new Map<string, Record<string, { state: string }>>();

  for (const id of agentIds) {
    for (const svc of (svcData[id] ?? [])) {
      if (!allServices.has(svc.name)) allServices.set(svc.name, {});
      allServices.get(svc.name)![id] = { state: svc.state };
    }
  }

  const results: DriftItem[] = [];
  for (const [name, agents] of Array.from(allServices)) {
    const status: Record<string, DriftStatus> = {};
    const details: Record<string, string> = {};
    const states = new Set<string>();

    for (const id of agentIds) {
      if (agents[id]) {
        states.add(agents[id].state);
        details[id] = agents[id].state;
      } else {
        details[id] = "—";
      }
    }

    const presentCount = Object.keys(agents).length;
    const allPresent = presentCount === agentIds.length;

    for (const id of agentIds) {
      if (!agents[id]) {
        status[id] = "absent";
      } else if (!allPresent) {
        status[id] = "present";
      } else if (states.size > 1) {
        status[id] = "state_mismatch";
      } else {
        status[id] = "present";
      }
    }

    const hasDrift = !allPresent || states.size > 1;
    results.push({ name, status, details, hasDrift });
  }

  return results.sort((a, b) => {
    if (a.hasDrift !== b.hasDrift) return a.hasDrift ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}

function computeUserDrift(
  agentIds: string[],
  usrData: Record<string, UsrEntry[]>
): DriftItem[] {
  const allUsers = new Map<string, Record<string, { shell: string }>>();

  for (const id of agentIds) {
    for (const user of (usrData[id] ?? [])) {
      if (!allUsers.has(user.name)) allUsers.set(user.name, {});
      allUsers.get(user.name)![id] = { shell: user.shell };
    }
  }

  const results: DriftItem[] = [];
  for (const [name, agents] of Array.from(allUsers)) {
    const status: Record<string, DriftStatus> = {};
    const details: Record<string, string> = {};

    for (const id of agentIds) {
      if (agents[id]) {
        details[id] = agents[id].shell;
      } else {
        details[id] = "—";
      }
    }

    const presentCount = Object.keys(agents).length;
    const allPresent = presentCount === agentIds.length;

    for (const id of agentIds) {
      if (!agents[id]) {
        status[id] = "absent";
      } else {
        status[id] = "present";
      }
    }

    const hasDrift = !allPresent;
    results.push({ name, status, details, hasDrift });
  }

  return results.sort((a, b) => {
    if (a.hasDrift !== b.hasDrift) return a.hasDrift ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}

// ── Baseline diff engine ────────────────────────────────────────────────

function computeBaselineDrift(
  baselineSnapshot: Record<string, unknown>,
  agentIds: string[],
  agentNameMap: Record<string, string>,
  currentData: AgentDataMaps
): BaselineDriftItem[] {
  const drifts: BaselineDriftItem[] = [];
  const snap = baselineSnapshot as {
    packages?: Record<string, Array<{ name: string; version: string }>>;
    services?: Record<string, Array<{ name: string; state: string }>>;
    users?: Record<string, Array<{ name: string; shell: string }>>;
  };

  for (const agentId of agentIds) {
    const agentName = agentNameMap[agentId] ?? agentId;

    // Packages
    const baselinePkgs = snap.packages?.[agentId] ?? [];
    const currentPkgs = currentData.packages[agentId] ?? [];

    const baselinePkgMap = new Map(baselinePkgs.map((p) => [p.name, p.version]));
    const currentPkgMap = new Map(currentPkgs.map((p: { name: string; version: string }) => [p.name, p.version]));

    for (const [name, ver] of Array.from(currentPkgMap)) {
      if (!baselinePkgMap.has(name)) {
        drifts.push({ name, agentId, agentName, baselineValue: "—", currentValue: ver, changeType: "new", category: "packages" });
      } else if (baselinePkgMap.get(name) !== ver) {
        drifts.push({ name, agentId, agentName, baselineValue: baselinePkgMap.get(name)!, currentValue: ver, changeType: "changed", category: "packages" });
      }
    }
    for (const [name, ver] of Array.from(baselinePkgMap)) {
      if (!currentPkgMap.has(name)) {
        drifts.push({ name, agentId, agentName, baselineValue: ver, currentValue: "—", changeType: "removed", category: "packages" });
      }
    }

    // Services
    const baselineSvcs = snap.services?.[agentId] ?? [];
    const currentSvcs = currentData.services[agentId] ?? [];

    const baselineSvcMap = new Map(baselineSvcs.map((s) => [s.name, s.state]));
    const currentSvcMap = new Map(currentSvcs.map((s: { name: string; state: string }) => [s.name, s.state]));

    for (const [name, state] of Array.from(currentSvcMap)) {
      if (!baselineSvcMap.has(name)) {
        drifts.push({ name, agentId, agentName, baselineValue: "—", currentValue: state, changeType: "new", category: "services" });
      } else if (baselineSvcMap.get(name) !== state) {
        drifts.push({ name, agentId, agentName, baselineValue: baselineSvcMap.get(name)!, currentValue: state, changeType: "changed", category: "services" });
      }
    }
    for (const [name, state] of Array.from(baselineSvcMap)) {
      if (!currentSvcMap.has(name)) {
        drifts.push({ name, agentId, agentName, baselineValue: state, currentValue: "—", changeType: "removed", category: "services" });
      }
    }

    // Users
    const baselineUsrs = snap.users?.[agentId] ?? [];
    const currentUsrs = currentData.users[agentId] ?? [];

    const baselineUsrMap = new Map(baselineUsrs.map((u) => [u.name, u.shell]));
    const currentUsrMap = new Map(currentUsrs.map((u: { name: string; shell: string }) => [u.name, u.shell]));

    for (const [name, shell] of Array.from(currentUsrMap)) {
      if (!baselineUsrMap.has(name)) {
        drifts.push({ name, agentId, agentName, baselineValue: "—", currentValue: shell, changeType: "new", category: "users" });
      } else if (baselineUsrMap.get(name) !== shell) {
        drifts.push({ name, agentId, agentName, baselineValue: baselineUsrMap.get(name)!, currentValue: shell, changeType: "changed", category: "users" });
      }
    }
    for (const [name, shell] of Array.from(baselineUsrMap)) {
      if (!currentUsrMap.has(name)) {
        drifts.push({ name, agentId, agentName, baselineValue: shell, currentValue: "—", changeType: "removed", category: "users" });
      }
    }
  }

  return drifts.sort((a, b) => {
    const order = { removed: 0, new: 1, changed: 2 };
    if (order[a.changeType] !== order[b.changeType]) return order[a.changeType] - order[b.changeType];
    return a.name.localeCompare(b.name);
  });
}

// ── Status cell component ────────────────────────────────────────────────

function DriftCell({ status, detail }: { status: DriftStatus; detail: string }) {
  const config = {
    present: {
      icon: CheckCircle2,
      bg: "bg-[oklch(0.765_0.177_163.223)]/10",
      border: "border-[oklch(0.765_0.177_163.223)]/30",
      text: "text-[oklch(0.765_0.177_163.223)]",
      label: "Present",
    },
    absent: {
      icon: XCircle,
      bg: "bg-[oklch(0.637_0.237_25.331)]/10",
      border: "border-[oklch(0.637_0.237_25.331)]/30",
      text: "text-[oklch(0.637_0.237_25.331)]",
      label: "Absent",
    },
    version_mismatch: {
      icon: ArrowLeftRight,
      bg: "bg-[oklch(0.795_0.184_86.047)]/10",
      border: "border-[oklch(0.795_0.184_86.047)]/30",
      text: "text-[oklch(0.795_0.184_86.047)]",
      label: "Version Drift",
    },
    state_mismatch: {
      icon: ArrowLeftRight,
      bg: "bg-[oklch(0.795_0.184_86.047)]/10",
      border: "border-[oklch(0.795_0.184_86.047)]/30",
      text: "text-[oklch(0.795_0.184_86.047)]",
      label: "State Drift",
    },
  };

  const c = config[status];
  const Icon = c.icon;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div
          className={`flex items-center gap-1.5 px-2 py-1 rounded-md border ${c.bg} ${c.border} cursor-default`}
        >
          <Icon className={`h-3 w-3 ${c.text} shrink-0`} />
          <span className={`text-[10px] font-mono truncate max-w-[120px] ${c.text}`}>
            {detail === "—" ? "—" : detail}
          </span>
        </div>
      </TooltipTrigger>
      <TooltipContent>
        <p className="text-xs">{c.label}: {detail}</p>
      </TooltipContent>
    </Tooltip>
  );
}

// ── Baseline change type badge ──────────────────────────────────────────

function ChangeTypeBadge({ type }: { type: "new" | "removed" | "changed" }) {
  const config = {
    new: {
      icon: Plus,
      bg: "bg-[oklch(0.765_0.177_163.223)]/15",
      border: "border-[oklch(0.765_0.177_163.223)]/40",
      text: "text-[oklch(0.765_0.177_163.223)]",
      label: "New",
    },
    removed: {
      icon: MinusCircle,
      bg: "bg-[oklch(0.637_0.237_25.331)]/15",
      border: "border-[oklch(0.637_0.237_25.331)]/40",
      text: "text-[oklch(0.637_0.237_25.331)]",
      label: "Removed",
    },
    changed: {
      icon: ArrowUpDown,
      bg: "bg-[oklch(0.795_0.184_86.047)]/15",
      border: "border-[oklch(0.795_0.184_86.047)]/40",
      text: "text-[oklch(0.795_0.184_86.047)]",
      label: "Changed",
    },
  };
  const c = config[type];
  const Icon = c.icon;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium border ${c.bg} ${c.border} ${c.text}`}>
      <Icon className="h-3 w-3" />
      {c.label}
    </span>
  );
}

// ── Main component ───────────────────────────────────────────────────────

interface DriftComparisonProps {
  isConnected: boolean;
  agentList?: Array<Record<string, unknown>>;
}

export default function DriftComparison({ isConnected, agentList = [] }: DriftComparisonProps) {
  const [selectedAgents, setSelectedAgents] = useState<string[]>([]);
  const [driftTab, setDriftTab] = useState<"packages" | "services" | "users">("packages");
  const [showDriftOnly, setShowDriftOnly] = useState(false);
  const [agentData, setAgentData] = useState<AgentDataMaps>({ packages: {}, services: {}, users: {} });
  const [dataLoading, setDataLoading] = useState(false);

  // Baseline state
  const [viewMode, setViewMode] = useState<"live" | "baseline">("live");
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [showLoadDialog, setShowLoadDialog] = useState(false);
  const [baselineName, setBaselineName] = useState("");
  const [baselineDescription, setBaselineDescription] = useState("");
  const [activeBaselineId, setActiveBaselineId] = useState<number | null>(null);
  const [baselineCategoryFilter, setBaselineCategoryFilter] = useState<"all" | "packages" | "services" | "users">("all");

  // tRPC queries for baselines
  const baselinesQ = trpc.baselines.list.useQuery(undefined, {
    staleTime: 30_000,
  });
  const baselineDetailQ = trpc.baselines.get.useQuery(
    { id: activeBaselineId! },
    { enabled: activeBaselineId !== null, staleTime: 60_000 }
  );
  const createBaselineMut = trpc.baselines.create.useMutation({
    onSuccess: () => {
      baselinesQ.refetch();
      setShowSaveDialog(false);
      setBaselineName("");
      setBaselineDescription("");
      toast.success("Baseline saved successfully");
    },
    onError: (err) => toast.error(`Failed to save baseline: ${err.message}`),
  });
  const deleteBaselineMut = trpc.baselines.delete.useMutation({
    onSuccess: () => {
      baselinesQ.refetch();
      if (activeBaselineId) {
        setActiveBaselineId(null);
        setViewMode("live");
      }
      toast.success("Baseline deleted");
    },
    onError: (err) => toast.error(`Failed to delete: ${err.message}`),
  });

  const activeAgents = useMemo(() => {
    return agentList.filter(
      (a) => String(a.status ?? "") === "active"
    );
  }, [agentList]);

  // Auto-select first 2 agents when list loads
  useEffect(() => {
    if (activeAgents.length >= 2 && selectedAgents.length === 0) {
      setSelectedAgents([String(activeAgents[0].id), String(activeAgents[1].id)]);
    }
  }, [activeAgents, selectedAgents.length]);

  // Fetch per-agent data when selection changes
  const utils = trpc.useUtils();
  const fetchAgentData = useCallback(async () => {
    if (!isConnected || selectedAgents.length < 2) return;
    setDataLoading(true);
    const pkgs: Record<string, PkgEntry[]> = {};
    const svcs: Record<string, SvcEntry[]> = {};
    const usrs: Record<string, UsrEntry[]> = {};
    for (const id of selectedAgents) {
      try {
        const pkgRes = await utils.wazuh.agentPackages.fetch({ agentId: id, limit: 500, offset: 0 });
        pkgs[id] = extractItems(pkgRes).map((p) => ({
          name: String(p.name ?? ""),
          version: String(p.version ?? "unknown"),
        }));
      } catch { pkgs[id] = []; }
      try {
        const svcRes = await utils.wazuh.agentServices.fetch({ agentId: id, limit: 500, offset: 0 });
        svcs[id] = extractItems(svcRes).map((s) => ({
          name: String(s.name ?? ""),
          state: String(s.state ?? "unknown"),
        }));
      } catch { svcs[id] = []; }
      try {
        const usrRes = await utils.wazuh.agentUsers.fetch({ agentId: id, limit: 500, offset: 0 });
        usrs[id] = extractItems(usrRes).map((u) => ({
          name: String(u.name ?? ""),
          shell: String(u.shell ?? "unknown"),
        }));
      } catch { usrs[id] = []; }
    }
    setAgentData({ packages: pkgs, services: svcs, users: usrs });
    setDataLoading(false);
  }, [isConnected, selectedAgents, utils]);

  useEffect(() => { fetchAgentData(); }, [fetchAgentData]);

  const toggleAgent = (id: string) => {
    setSelectedAgents((prev) => {
      if (prev.includes(id)) {
        if (prev.length <= 2) return prev;
        return prev.filter((a) => a !== id);
      }
      if (prev.length >= 5) return prev;
      return [...prev, id];
    });
  };

  const packageDrift = useMemo(
    () => (selectedAgents.length >= 2 ? computePackageDrift(selectedAgents, agentData.packages) : []),
    [selectedAgents, agentData.packages]
  );
  const serviceDrift = useMemo(
    () => (selectedAgents.length >= 2 ? computeServiceDrift(selectedAgents, agentData.services) : []),
    [selectedAgents, agentData.services]
  );
  const userDrift = useMemo(
    () => (selectedAgents.length >= 2 ? computeUserDrift(selectedAgents, agentData.users) : []),
    [selectedAgents, agentData.users]
  );

  const currentDrift = driftTab === "packages" ? packageDrift : driftTab === "services" ? serviceDrift : userDrift;
  const filteredDrift = showDriftOnly ? currentDrift.filter((d) => d.hasDrift) : currentDrift;

  // Stats
  const pkgDriftCount = packageDrift.filter((d) => d.hasDrift).length;
  const svcDriftCount = serviceDrift.filter((d) => d.hasDrift).length;
  const usrDriftCount = userDrift.filter((d) => d.hasDrift).length;
  const totalDrifts = pkgDriftCount + svcDriftCount + usrDriftCount;

  const agentNameMap = useMemo(() => {
    const m: Record<string, string> = {};
    for (const a of agentList) {
      m[String(a.id ?? "")] = String(a.name ?? "");
    }
    return m;
  }, [agentList]);

  // Baseline drift computation
  const baselineDrifts = useMemo(() => {
    if (!baselineDetailQ.data?.baseline?.snapshotData) return [];
    const baseline = baselineDetailQ.data.baseline;
    const baselineAgentIds = baseline.agentIds as string[];
    return computeBaselineDrift(baseline.snapshotData, baselineAgentIds, agentNameMap, agentData);
  }, [baselineDetailQ.data, agentNameMap, agentData]);

  const filteredBaselineDrifts = useMemo(() => {
    if (baselineCategoryFilter === "all") return baselineDrifts;
    return baselineDrifts.filter((d) => d.category === baselineCategoryFilter);
  }, [baselineDrifts, baselineCategoryFilter]);

  const baselinePkgDrifts = baselineDrifts.filter((d) => d.category === "packages").length;
  const baselineSvcDrifts = baselineDrifts.filter((d) => d.category === "services").length;
  const baselineUsrDrifts = baselineDrifts.filter((d) => d.category === "users").length;

  // Save baseline handler
  const handleSaveBaseline = () => {
    if (!baselineName.trim()) return;
    const snapshot = collectAgentSnapshot(agentData, selectedAgents);
    createBaselineMut.mutate({
      name: baselineName.trim(),
      description: baselineDescription.trim() || undefined,
      agentIds: selectedAgents,
      snapshotData: snapshot,
    });
  };

  // Load baseline handler
  const handleLoadBaseline = (id: number) => {
    setActiveBaselineId(id);
    setViewMode("baseline");
    setShowLoadDialog(false);
  };

  return (
    <div className="space-y-5">
      {/* ── Agent Selector ──────────────────────────────────────────── */}
      <GlassPanel>
        <div className="flex items-center gap-3 mb-3">
          <GitCompare className="h-4 w-4 text-primary" />
          <h3 className="text-sm font-medium text-foreground">
            Select Agents to Compare
          </h3>
          <span className="text-xs text-muted-foreground ml-auto">
            {selectedAgents.length} selected (2–5 agents)
          </span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
          {activeAgents.length === 0 ? (
            <div className="col-span-full">
              <DataEmpty title="No Agents" message="No active agents available for comparison." />
            </div>
          ) : activeAgents.map((agent) => {
            const aid = String(agent.id ?? "");
            const isSelected = selectedAgents.includes(aid);
            const isDisabledAdd = !isSelected && selectedAgents.length >= 5;
            const isDisabledRemove = isSelected && selectedAgents.length <= 2;
            const disabled = isDisabledAdd || isDisabledRemove;

            return (
              <button
                key={aid}
                onClick={() => !disabled && toggleAgent(aid)}
                disabled={disabled}
                className={`glass-card p-3 text-left transition-all duration-200 flex items-center gap-3 ${
                  isSelected
                    ? "ring-1 ring-primary/50 bg-primary/5 border-primary/30"
                    : disabled
                      ? "opacity-40 cursor-not-allowed"
                      : "hover:bg-secondary/30 border-border/30"
                }`}
              >
                <Checkbox
                  checked={isSelected}
                  disabled={disabled}
                  className="pointer-events-none"
                />
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-medium text-foreground truncate">
                    {String(agent.name ?? "")}
                  </p>
                  <p className="text-[10px] text-muted-foreground font-mono">
                    {aid} · {String(agent.ip ?? "")}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
      </GlassPanel>

      {/* ── View Mode Toggle + Baseline Actions ─────────────────────── */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center rounded-lg border border-border/30 bg-secondary/20 p-0.5">
          <button
            onClick={() => setViewMode("live")}
            className={`px-4 py-1.5 rounded-md text-xs font-medium transition-all ${
              viewMode === "live"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <GitCompare className="h-3.5 w-3.5 inline-block mr-1.5 -mt-0.5" />
            Live Comparison
          </button>
          <button
            onClick={() => {
              if (activeBaselineId) {
                setViewMode("baseline");
              } else {
                setShowLoadDialog(true);
              }
            }}
            className={`px-4 py-1.5 rounded-md text-xs font-medium transition-all ${
              viewMode === "baseline"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <Shield className="h-3.5 w-3.5 inline-block mr-1.5 -mt-0.5" />
            Baseline Drift
          </button>
        </div>

        <div className="flex items-center gap-2 ml-auto">
          <Button
            variant="outline"
            size="sm"
            className="text-xs gap-1.5 border-border/40 bg-transparent hover:bg-primary/10 hover:text-primary"
            onClick={() => setShowSaveDialog(true)}
          >
            <Save className="h-3.5 w-3.5" />
            Save as Baseline
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="text-xs gap-1.5 border-border/40 bg-transparent hover:bg-primary/10 hover:text-primary"
            onClick={() => setShowLoadDialog(true)}
          >
            <FolderOpen className="h-3.5 w-3.5" />
            Load Baseline
          </Button>
        </div>
      </div>

      {/* ── LIVE COMPARISON VIEW ─────────────────────────────────────── */}
      {viewMode === "live" && (
        <>
          {/* KPI row */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <StatCard
              label="Total Drifts"
              value={totalDrifts}
              icon={AlertTriangle}
              colorClass={totalDrifts > 0 ? "text-[oklch(0.795_0.184_86.047)]" : "text-[oklch(0.765_0.177_163.223)]"}
            />
            <StatCard
              label="Package Drifts"
              value={pkgDriftCount}
              icon={Package}
              colorClass={pkgDriftCount > 0 ? "text-[oklch(0.637_0.237_25.331)]" : "text-[oklch(0.765_0.177_163.223)]"}
              trend={`of ${packageDrift.length} packages`}
            />
            <StatCard
              label="Service Drifts"
              value={svcDriftCount}
              icon={Server}
              colorClass={svcDriftCount > 0 ? "text-[oklch(0.795_0.184_86.047)]" : "text-[oklch(0.765_0.177_163.223)]"}
              trend={`of ${serviceDrift.length} services`}
            />
            <StatCard
              label="User Drifts"
              value={usrDriftCount}
              icon={UserCheck}
              colorClass={usrDriftCount > 0 ? "text-[oklch(0.705_0.191_22.216)]" : "text-[oklch(0.765_0.177_163.223)]"}
              trend={`of ${userDrift.length} users`}
            />
          </div>

          {/* Drift table */}
          <GlassPanel>
            <Tabs
              value={driftTab}
              onValueChange={(v) => setDriftTab(v as "packages" | "services" | "users")}
            >
              <div className="flex items-center justify-between mb-4">
                <TabsList className="bg-secondary/30 border border-border/30">
                  <TabsTrigger
                    value="packages"
                    className="text-xs gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary"
                  >
                    <Package className="h-3.5 w-3.5" /> Packages
                    {pkgDriftCount > 0 && (
                      <Badge variant="destructive" className="ml-1 h-4 px-1 text-[9px]">
                        {pkgDriftCount}
                      </Badge>
                    )}
                  </TabsTrigger>
                  <TabsTrigger
                    value="services"
                    className="text-xs gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary"
                  >
                    <Server className="h-3.5 w-3.5" /> Services
                    {svcDriftCount > 0 && (
                      <Badge variant="destructive" className="ml-1 h-4 px-1 text-[9px]">
                        {svcDriftCount}
                      </Badge>
                    )}
                  </TabsTrigger>
                  <TabsTrigger
                    value="users"
                    className="text-xs gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary"
                  >
                    <UserCheck className="h-3.5 w-3.5" /> Users
                    {usrDriftCount > 0 && (
                      <Badge variant="destructive" className="ml-1 h-4 px-1 text-[9px]">
                        {usrDriftCount}
                      </Badge>
                    )}
                  </TabsTrigger>
                </TabsList>

                <label className="flex items-center gap-2 cursor-pointer">
                  <Checkbox
                    checked={showDriftOnly}
                    onCheckedChange={(v) => setShowDriftOnly(v === true)}
                  />
                  <span className="text-xs text-muted-foreground">
                    Show drift only
                  </span>
                </label>
              </div>

              {(["packages", "services", "users"] as const).map((tabKey) => (
                <TabsContent key={tabKey} value={tabKey}>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-border/30">
                          <th className="text-left py-2 px-3 text-muted-foreground font-medium w-8">
                            <Minus className="h-3 w-3" />
                          </th>
                          <th className="text-left py-2 px-3 text-muted-foreground font-medium min-w-[140px]">
                            {tabKey === "packages" ? "Package" : tabKey === "services" ? "Service" : "User"}
                          </th>
                          {selectedAgents.map((id) => (
                            <th
                              key={id}
                              className="text-left py-2 px-3 text-muted-foreground font-medium min-w-[160px]"
                            >
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <span className="cursor-default truncate block max-w-[150px]">
                                    {agentNameMap[id] ?? id}
                                  </span>
                                </TooltipTrigger>
                                <TooltipContent>
                                  <p className="text-xs font-mono">{id} — {agentNameMap[id]}</p>
                                </TooltipContent>
                              </Tooltip>
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {filteredDrift.length === 0 ? (
                          <tr>
                            <td
                              colSpan={selectedAgents.length + 2}
                              className="text-center py-8 text-muted-foreground"
                            >
                              {showDriftOnly
                                ? "No drift detected — all items are consistent across selected agents."
                                : "Select at least 2 agents to begin comparison."}
                            </td>
                          </tr>
                        ) : (
                          filteredDrift.map((item) => (
                            <tr
                              key={item.name}
                              className={`border-b border-border/10 transition-colors ${
                                item.hasDrift
                                  ? "bg-[oklch(0.795_0.184_86.047)]/[0.03] hover:bg-[oklch(0.795_0.184_86.047)]/[0.06]"
                                  : "hover:bg-secondary/20"
                              }`}
                            >
                              <td className="py-2 px-3">
                                {item.hasDrift ? (
                                  <AlertTriangle className="h-3.5 w-3.5 text-[oklch(0.795_0.184_86.047)]" />
                                ) : (
                                  <CheckCircle2 className="h-3.5 w-3.5 text-[oklch(0.765_0.177_163.223)]" />
                                )}
                              </td>
                              <td className="py-2 px-3 font-medium text-foreground font-mono">
                                {item.name}
                              </td>
                              {selectedAgents.map((id) => (
                                <td key={id} className="py-2 px-3">
                                  <DriftCell
                                    status={item.status[id]}
                                    detail={item.details[id]}
                                  />
                                </td>
                              ))}
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>

                  <div className="flex items-center gap-4 mt-4 pt-4 border-t border-border/30">
                    <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">
                      Legend:
                    </span>
                    <div className="flex items-center gap-1.5">
                      <CheckCircle2 className="h-3 w-3 text-[oklch(0.765_0.177_163.223)]" />
                      <span className="text-[10px] text-muted-foreground">Present</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <XCircle className="h-3 w-3 text-[oklch(0.637_0.237_25.331)]" />
                      <span className="text-[10px] text-muted-foreground">Absent</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <ArrowLeftRight className="h-3 w-3 text-[oklch(0.795_0.184_86.047)]" />
                      <span className="text-[10px] text-muted-foreground">
                        {tabKey === "packages" ? "Version Drift" : tabKey === "services" ? "State Drift" : "Drift"}
                      </span>
                    </div>
                  </div>
                </TabsContent>
              ))}
            </Tabs>
          </GlassPanel>
        </>
      )}

      {/* ── BASELINE DRIFT VIEW ──────────────────────────────────────── */}
      {viewMode === "baseline" && (
        <>
          {/* Active baseline info */}
          {baselineDetailQ.data?.baseline && (
            <GlassPanel>
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="h-10 w-10 rounded-lg bg-primary/15 border border-primary/30 flex items-center justify-center">
                    <Shield className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-foreground">
                      {baselineDetailQ.data.baseline.name}
                    </h3>
                    {baselineDetailQ.data.baseline.description && (
                      <p className="text-xs text-muted-foreground mt-0.5">
                        {baselineDetailQ.data.baseline.description}
                      </p>
                    )}
                    <div className="flex items-center gap-3 mt-1.5">
                      <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        Saved {new Date(baselineDetailQ.data.baseline.createdAt).toLocaleDateString()} at{" "}
                        {new Date(baselineDetailQ.data.baseline.createdAt).toLocaleTimeString()}
                      </span>
                      <span className="text-[10px] text-muted-foreground">
                        {(baselineDetailQ.data.baseline.agentIds as string[]).length} agents
                      </span>
                      <div className="flex items-center gap-1">
                        {(baselineDetailQ.data.baseline.agentIds as string[]).map((id) => (
                          <Badge
                            key={id}
                            variant="outline"
                            className="text-[9px] px-1.5 py-0 h-4 font-mono border-border/40"
                          >
                            {agentNameMap[id] ?? id}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="text-xs gap-1.5 border-border/40 bg-transparent hover:bg-destructive/10 hover:text-destructive hover:border-destructive/40"
                  onClick={() => {
                    if (activeBaselineId) deleteBaselineMut.mutate({ id: activeBaselineId });
                  }}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  Delete
                </Button>
              </div>
            </GlassPanel>
          )}

          {/* Baseline drift KPIs */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <StatCard
              label="Total Changes"
              value={baselineDrifts.length}
              icon={AlertTriangle}
              colorClass={baselineDrifts.length > 0 ? "text-[oklch(0.795_0.184_86.047)]" : "text-[oklch(0.765_0.177_163.223)]"}
            />
            <StatCard
              label="Package Changes"
              value={baselinePkgDrifts}
              icon={Package}
              colorClass={baselinePkgDrifts > 0 ? "text-[oklch(0.637_0.237_25.331)]" : "text-[oklch(0.765_0.177_163.223)]"}
              trend={`${baselineDrifts.filter((d) => d.category === "packages" && d.changeType === "new").length} new, ${baselineDrifts.filter((d) => d.category === "packages" && d.changeType === "removed").length} removed`}
            />
            <StatCard
              label="Service Changes"
              value={baselineSvcDrifts}
              icon={Server}
              colorClass={baselineSvcDrifts > 0 ? "text-[oklch(0.795_0.184_86.047)]" : "text-[oklch(0.765_0.177_163.223)]"}
              trend={`${baselineDrifts.filter((d) => d.category === "services" && d.changeType === "changed").length} state changes`}
            />
            <StatCard
              label="User Changes"
              value={baselineUsrDrifts}
              icon={UserCheck}
              colorClass={baselineUsrDrifts > 0 ? "text-[oklch(0.705_0.191_22.216)]" : "text-[oklch(0.765_0.177_163.223)]"}
              trend={`${baselineDrifts.filter((d) => d.category === "users" && d.changeType === "new").length} new, ${baselineDrifts.filter((d) => d.category === "users" && d.changeType === "removed").length} removed`}
            />
          </div>

          {/* Baseline drift table */}
          <GlassPanel>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-foreground flex items-center gap-2">
                <ArrowUpDown className="h-4 w-4 text-primary" />
                Changes Since Baseline
              </h3>
              <Select
                value={baselineCategoryFilter}
                onValueChange={(v) => setBaselineCategoryFilter(v as typeof baselineCategoryFilter)}
              >
                <SelectTrigger className="w-[160px] h-8 text-xs bg-secondary/30 border-border/30">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Categories</SelectItem>
                  <SelectItem value="packages">Packages Only</SelectItem>
                  <SelectItem value="services">Services Only</SelectItem>
                  <SelectItem value="users">Users Only</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {!activeBaselineId ? (
              <div className="text-center py-12 text-muted-foreground">
                <Shield className="h-10 w-10 mx-auto mb-3 opacity-30" />
                <p className="text-sm">No baseline loaded</p>
                <p className="text-xs mt-1">Save a baseline from the current state or load a previously saved one.</p>
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-4 text-xs gap-1.5"
                  onClick={() => setShowLoadDialog(true)}
                >
                  <FolderOpen className="h-3.5 w-3.5" />
                  Load Baseline
                </Button>
              </div>
            ) : baselineDetailQ.isLoading ? (
              <div className="text-center py-12 text-muted-foreground text-sm">
                Loading baseline data…
              </div>
            ) : filteredBaselineDrifts.length === 0 ? (
              <div className="text-center py-12">
                <CheckCircle2 className="h-10 w-10 mx-auto mb-3 text-[oklch(0.765_0.177_163.223)] opacity-50" />
                <p className="text-sm text-foreground font-medium">No drift detected</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Current configuration matches the saved baseline.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border/30">
                      <th className="text-left py-2 px-3 text-muted-foreground font-medium w-[100px]">Change</th>
                      <th className="text-left py-2 px-3 text-muted-foreground font-medium w-[100px]">Category</th>
                      <th className="text-left py-2 px-3 text-muted-foreground font-medium">Item</th>
                      <th className="text-left py-2 px-3 text-muted-foreground font-medium">Agent</th>
                      <th className="text-left py-2 px-3 text-muted-foreground font-medium">Baseline Value</th>
                      <th className="text-left py-2 px-3 text-muted-foreground font-medium">Current Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredBaselineDrifts.map((item, i) => (
                      <tr
                        key={`${item.agentId}-${item.category}-${item.name}-${i}`}
                        className={`border-b border-border/10 transition-colors ${
                          item.changeType === "removed"
                            ? "bg-[oklch(0.637_0.237_25.331)]/[0.03] hover:bg-[oklch(0.637_0.237_25.331)]/[0.06]"
                            : item.changeType === "new"
                              ? "bg-[oklch(0.765_0.177_163.223)]/[0.03] hover:bg-[oklch(0.765_0.177_163.223)]/[0.06]"
                              : "bg-[oklch(0.795_0.184_86.047)]/[0.03] hover:bg-[oklch(0.795_0.184_86.047)]/[0.06]"
                        }`}
                      >
                        <td className="py-2 px-3">
                          <ChangeTypeBadge type={item.changeType} />
                        </td>
                        <td className="py-2 px-3">
                          <Badge variant="outline" className="text-[9px] font-mono border-border/40 capitalize">
                            {item.category}
                          </Badge>
                        </td>
                        <td className="py-2 px-3 font-medium text-foreground font-mono">
                          {item.name}
                        </td>
                        <td className="py-2 px-3 text-muted-foreground">
                          <span className="font-mono text-[10px]">{item.agentId}</span>
                          <span className="text-foreground ml-1.5">{item.agentName}</span>
                        </td>
                        <td className="py-2 px-3">
                          <span className={`font-mono text-[10px] ${item.baselineValue === "—" ? "text-muted-foreground" : "text-foreground"}`}>
                            {item.baselineValue}
                          </span>
                        </td>
                        <td className="py-2 px-3">
                          <span className={`font-mono text-[10px] ${item.currentValue === "—" ? "text-muted-foreground" : "text-foreground"}`}>
                            {item.currentValue}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Baseline legend */}
            {filteredBaselineDrifts.length > 0 && (
              <div className="flex items-center gap-4 mt-4 pt-4 border-t border-border/30">
                <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">
                  Legend:
                </span>
                <div className="flex items-center gap-1.5">
                  <Plus className="h-3 w-3 text-[oklch(0.765_0.177_163.223)]" />
                  <span className="text-[10px] text-muted-foreground">New (not in baseline)</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <MinusCircle className="h-3 w-3 text-[oklch(0.637_0.237_25.331)]" />
                  <span className="text-[10px] text-muted-foreground">Removed (was in baseline)</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <ArrowUpDown className="h-3 w-3 text-[oklch(0.795_0.184_86.047)]" />
                  <span className="text-[10px] text-muted-foreground">Changed (value differs)</span>
                </div>
              </div>
            )}
          </GlassPanel>
        </>
      )}

      {/* ── Save Baseline Dialog ─────────────────────────────────────── */}
      <Dialog open={showSaveDialog} onOpenChange={setShowSaveDialog}>
        <DialogContent className="glass-panel border-border/40 sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-foreground">
              <Shield className="h-5 w-5 text-primary" />
              Save Configuration Baseline
            </DialogTitle>
            <DialogDescription className="text-muted-foreground">
              Snapshot the current packages, services, and users for the {selectedAgents.length} selected agents.
              Future scans will be compared against this baseline to detect unauthorized changes.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <label className="text-xs font-medium text-foreground mb-1.5 block">
                Baseline Name
              </label>
              <Input
                value={baselineName}
                onChange={(e) => setBaselineName(e.target.value)}
                placeholder="e.g., Production servers — Feb 2026"
                className="bg-secondary/30 border-border/30 text-sm"
                maxLength={256}
              />
            </div>
            <div>
              <label className="text-xs font-medium text-foreground mb-1.5 block">
                Description (optional)
              </label>
              <Input
                value={baselineDescription}
                onChange={(e) => setBaselineDescription(e.target.value)}
                placeholder="e.g., Post-patching baseline after Q1 maintenance window"
                className="bg-secondary/30 border-border/30 text-sm"
                maxLength={1000}
              />
            </div>
            <div className="rounded-lg bg-secondary/20 border border-border/20 p-3">
              <p className="text-xs text-muted-foreground mb-2">Agents included in this baseline:</p>
              <div className="flex flex-wrap gap-1.5">
                {selectedAgents.map((id) => (
                  <Badge key={id} variant="outline" className="text-[10px] font-mono border-primary/30 text-primary">
                    {agentNameMap[id] ?? id}
                  </Badge>
                ))}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowSaveDialog(false)}
              className="border-border/40 bg-transparent"
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleSaveBaseline}
              disabled={!baselineName.trim() || createBaselineMut.isPending}
              className="bg-primary hover:bg-primary/90 gap-1.5"
            >
              <Save className="h-3.5 w-3.5" />
              {createBaselineMut.isPending ? "Saving…" : "Save Baseline"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Load Baseline Dialog ─────────────────────────────────────── */}
      <Dialog open={showLoadDialog} onOpenChange={setShowLoadDialog}>
        <DialogContent className="glass-panel border-border/40 sm:max-w-[560px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-foreground">
              <FolderOpen className="h-5 w-5 text-primary" />
              Load Configuration Baseline
            </DialogTitle>
            <DialogDescription className="text-muted-foreground">
              Select a previously saved baseline to compare against the current agent configuration.
            </DialogDescription>
          </DialogHeader>
          <div className="py-2 max-h-[400px] overflow-y-auto space-y-2">
            {baselinesQ.isLoading ? (
              <div className="text-center py-8 text-muted-foreground text-sm">
                Loading baselines…
              </div>
            ) : !baselinesQ.data?.baselines?.length ? (
              <div className="text-center py-8">
                <Shield className="h-8 w-8 mx-auto mb-2 text-muted-foreground opacity-30" />
                <p className="text-sm text-muted-foreground">No baselines saved yet</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Save a baseline from the comparison view first.
                </p>
              </div>
            ) : (
              baselinesQ.data.baselines.map((bl) => (
                <div
                  key={bl.id}
                  className={`glass-card p-4 transition-all duration-200 cursor-pointer group ${
                    activeBaselineId === bl.id
                      ? "ring-1 ring-primary/50 bg-primary/5 border-primary/30"
                      : "hover:bg-secondary/30 border-border/30"
                  }`}
                  onClick={() => handleLoadBaseline(bl.id)}
                >
                  <div className="flex items-start justify-between">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-foreground flex items-center gap-2">
                        {bl.name}
                        {activeBaselineId === bl.id && (
                          <Badge className="text-[9px] bg-primary/20 text-primary border-primary/30">
                            Active
                          </Badge>
                        )}
                      </p>
                      {bl.description && (
                        <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">
                          {bl.description}
                        </p>
                      )}
                      <div className="flex items-center gap-3 mt-2">
                        <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {new Date(bl.createdAt).toLocaleDateString()}
                        </span>
                        <span className="text-[10px] text-muted-foreground">
                          {(bl.agentIds as string[]).length} agents
                        </span>
                        <div className="flex items-center gap-1">
                          {(bl.agentIds as string[]).slice(0, 3).map((id) => (
                            <Badge
                              key={id}
                              variant="outline"
                              className="text-[8px] px-1 py-0 h-3.5 font-mono border-border/30"
                            >
                              {agentNameMap[id] ?? id}
                            </Badge>
                          ))}
                          {(bl.agentIds as string[]).length > 3 && (
                            <span className="text-[8px] text-muted-foreground">
                              +{(bl.agentIds as string[]).length - 3}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="opacity-0 group-hover:opacity-100 transition-opacity h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteBaselineMut.mutate({ id: bl.id });
                      }}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              ))
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
