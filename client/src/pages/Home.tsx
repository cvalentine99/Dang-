import { GlassPanel, StatCard } from "@/components/shared";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { trpc } from "@/lib/trpc";
import {
  Activity,
  AlertTriangle,
  Bug,
  FileSearch,
  Shield,
  ShieldCheck,
  Target,
  Wifi,
  WifiOff,
} from "lucide-react";
import { useCallback } from "react";
import { useLocation } from "wouter";

export default function Home() {
  const utils = trpc.useUtils();
  const statusQ = trpc.wazuh.status.useQuery(undefined, { staleTime: 30_000, retry: 1 });
  const agentSummary = trpc.wazuh.agentSummaryStatus.useQuery(undefined, {
    staleTime: 30_000,
    retry: 1,
    enabled: statusQ.data?.configured === true,
  });
  const [, setLocation] = useLocation();

  const handleRefresh = useCallback(() => {
    utils.wazuh.status.invalidate();
    utils.wazuh.agentSummaryStatus.invalidate();
  }, [utils]);

  const isLoading = statusQ.isLoading || agentSummary.isLoading;

  // Extract agent counts from Wazuh response
  const agentData = (agentSummary.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const connection = agentData?.connection as Record<string, number> | undefined;
  const activeAgents = connection?.active ?? 0;
  const disconnectedAgents = connection?.disconnected ?? 0;
  const neverConnected = connection?.never_connected ?? 0;
  const totalAgents = activeAgents + disconnectedAgents + neverConnected;

  // Extract manager info
  const managerData = (statusQ.data?.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const affectedItems = (managerData?.affected_items as Array<Record<string, unknown>>) ?? [];
  const managerVersion = (affectedItems[0]?.version as string) ?? "—";

  const navCards = [
    { icon: Activity, label: "Agent Health", path: "/agents", desc: "Monitor agent status and daemon statistics" },
    { icon: AlertTriangle, label: "Alerts Timeline", path: "/alerts", desc: "View and filter security alerts" },
    { icon: Bug, label: "Vulnerabilities", path: "/vulnerabilities", desc: "CVE severity and remediation tracking" },
    { icon: Target, label: "MITRE ATT&CK", path: "/mitre", desc: "Technique and tactic mapping" },
    { icon: ShieldCheck, label: "Compliance", path: "/compliance", desc: "PCI-DSS, GDPR, HIPAA posture" },
    { icon: FileSearch, label: "File Integrity", path: "/fim", desc: "Syscheck events and modified files" },
  ];

  return (
    <div>
      <PageHeader
        title="Security Overview"
        subtitle="Wazuh SIEM telemetry at a glance"
        onRefresh={handleRefresh}
        isLoading={isLoading}
      />

      <WazuhGuard>
        {/* ── Top stat cards ─────────────────────────────── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
          <StatCard
            label="Total Agents"
            value={totalAgents}
            icon={Shield}
            colorClass="text-primary"
          />
          <StatCard
            label="Active"
            value={activeAgents}
            icon={Wifi}
            colorClass="text-threat-low"
          />
          <StatCard
            label="Disconnected"
            value={disconnectedAgents}
            icon={WifiOff}
            colorClass="text-threat-high"
          />
          <StatCard
            label="Wazuh Manager"
            value={managerVersion}
            icon={Shield}
            colorClass="text-info-cyan"
          />
        </div>

        {/* ── Quick navigation cards ─────────────────────── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
          {navCards.map((card) => (
            <button
              key={card.path}
              onClick={() => setLocation(card.path)}
              className="glass-card p-5 text-left group"
            >
              <div className="flex items-start gap-4">
                <div className="h-10 w-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0 group-hover:bg-primary/20 transition-colors">
                  <card.icon className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="font-display font-semibold text-foreground text-sm">
                    {card.label}
                  </h3>
                  <p className="text-xs text-muted-foreground mt-1">{card.desc}</p>
                </div>
              </div>
            </button>
          ))}
        </div>

        {/* ── Manager info panel ─────────────────────────── */}
        {affectedItems.length > 0 && (
          <GlassPanel className="mt-6 p-5">
            <h2 className="font-display font-semibold text-foreground text-sm mb-3">
              Manager Details
            </h2>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
              {Object.entries(affectedItems[0] ?? {}).map(([key, val]) => (
                <div key={key}>
                  <span className="text-muted-foreground uppercase tracking-wider">{key}</span>
                  <p className="text-foreground font-mono mt-0.5 truncate">
                    {String(val ?? "—")}
                  </p>
                </div>
              ))}
            </div>
          </GlassPanel>
        )}
      </WazuhGuard>
    </div>
  );
}
