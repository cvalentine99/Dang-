import { GlassPanel } from "@/components/shared/GlassPanel";
import { StatCard } from "@/components/shared/StatCard";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
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
} from "lucide-react";
import { useState, useMemo } from "react";
import {
  MOCK_AGENTS,
  MOCK_AGENT_PACKAGES,
  MOCK_AGENT_SERVICES,
  MOCK_AGENT_USERS,
  MOCK_PACKAGES,
  MOCK_SERVICES,
  MOCK_USERS,
} from "@/lib/mockData";

type DriftStatus = "present" | "absent" | "version_mismatch" | "state_mismatch";

interface DriftItem {
  name: string;
  status: Record<string, DriftStatus>;
  details: Record<string, string>;
  hasDrift: boolean;
}

// ── Drift detection helpers ──────────────────────────────────────────────

function computePackageDrift(
  agentIds: string[],
  _isConnected: boolean
): DriftItem[] {
  const allPackages = new Map<string, Record<string, { version: string }>>();

  for (const id of agentIds) {
    const data = MOCK_AGENT_PACKAGES[id] ?? { data: { affected_items: MOCK_PACKAGES.data.affected_items } };
    for (const pkg of data.data.affected_items) {
      const name = String(pkg.name);
      if (!allPackages.has(name)) allPackages.set(name, {});
      allPackages.get(name)![id] = { version: String(pkg.version ?? "unknown") };
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
  _isConnected: boolean
): DriftItem[] {
  const allServices = new Map<string, Record<string, { state: string }>>();

  for (const id of agentIds) {
    const data = MOCK_AGENT_SERVICES[id] ?? { data: { affected_items: MOCK_SERVICES.data.affected_items } };
    for (const svc of data.data.affected_items) {
      const name = String(svc.name);
      if (!allServices.has(name)) allServices.set(name, {});
      allServices.get(name)![id] = { state: String(svc.state ?? "unknown") };
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
  _isConnected: boolean
): DriftItem[] {
  const allUsers = new Map<string, Record<string, { shell: string }>>();

  for (const id of agentIds) {
    const data = MOCK_AGENT_USERS[id] ?? { data: { affected_items: MOCK_USERS.data.affected_items } };
    for (const user of data.data.affected_items) {
      const name = String(user.name);
      if (!allUsers.has(name)) allUsers.set(name, {});
      allUsers.get(name)![id] = { shell: String(user.shell ?? "unknown") };
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

// ── Main component ───────────────────────────────────────────────────────

interface DriftComparisonProps {
  isConnected: boolean;
}

export default function DriftComparison({ isConnected }: DriftComparisonProps) {
  const [selectedAgents, setSelectedAgents] = useState<string[]>(["001", "002"]);
  const [driftTab, setDriftTab] = useState<"packages" | "services" | "users">("packages");
  const [showDriftOnly, setShowDriftOnly] = useState(false);

  const activeAgents = useMemo(() => {
    return MOCK_AGENTS.data.affected_items.filter(
      (a) => a.status === "active"
    );
  }, []);

  const toggleAgent = (id: string) => {
    setSelectedAgents((prev) => {
      if (prev.includes(id)) {
        if (prev.length <= 2) return prev; // minimum 2
        return prev.filter((a) => a !== id);
      }
      if (prev.length >= 5) return prev; // maximum 5
      return [...prev, id];
    });
  };

  const packageDrift = useMemo(
    () => (selectedAgents.length >= 2 ? computePackageDrift(selectedAgents, isConnected) : []),
    [selectedAgents, isConnected]
  );
  const serviceDrift = useMemo(
    () => (selectedAgents.length >= 2 ? computeServiceDrift(selectedAgents, isConnected) : []),
    [selectedAgents, isConnected]
  );
  const userDrift = useMemo(
    () => (selectedAgents.length >= 2 ? computeUserDrift(selectedAgents, isConnected) : []),
    [selectedAgents, isConnected]
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
    for (const a of MOCK_AGENTS.data.affected_items) {
      m[a.id] = a.name;
    }
    return m;
  }, []);

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
          {activeAgents.map((agent) => {
            const isSelected = selectedAgents.includes(agent.id);
            const isDisabledAdd = !isSelected && selectedAgents.length >= 5;
            const isDisabledRemove = isSelected && selectedAgents.length <= 2;
            const disabled = isDisabledAdd || isDisabledRemove;

            return (
              <button
                key={agent.id}
                onClick={() => !disabled && toggleAgent(agent.id)}
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
                    {agent.name}
                  </p>
                  <p className="text-[10px] text-muted-foreground font-mono">
                    {agent.id} · {agent.ip}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
      </GlassPanel>

      {/* ── Drift Summary KPIs ──────────────────────────────────────── */}
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

      {/* ── Drift Table ─────────────────────────────────────────────── */}
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

          {/* All three tabs share the same table structure */}
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

              {/* Drift legend */}
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
    </div>
  );
}
