import { trpc } from "@/lib/trpc";
import { GlassPanel } from "@/components/shared/GlassPanel";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { RawJsonViewer } from "@/components/shared/RawJsonViewer";
import { MOCK_PACKAGES, MOCK_PORTS, MOCK_PROCESSES, MOCK_NETIFACE, MOCK_NETADDR, MOCK_HOTFIXES, MOCK_AGENTS } from "@/lib/mockData";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Tabs, TabsContent, TabsList, TabsTrigger,
} from "@/components/ui/tabs";
import {
  Package, Globe, Cpu, Network, HardDrive, Search,
  ChevronLeft, ChevronRight, Layers,
} from "lucide-react";
import { useState, useMemo, useCallback } from "react";

type TabKey = "packages" | "ports" | "processes" | "network" | "hotfixes";

function extractItems(data: unknown): { items: Array<Record<string, unknown>>; total: number } {
  const d = (data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const items = (d?.affected_items as Array<Record<string, unknown>>) ?? [];
  const total = Number(d?.total_affected_items ?? items.length);
  return { items, total };
}

export default function ITHygiene() {
  const utils = trpc.useUtils();
  const [agentId, setAgentId] = useState("001");
  const [tab, setTab] = useState<TabKey>("packages");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 50;

  const statusQ = trpc.wazuh.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const isConnected = statusQ.data?.configured === true && statusQ.data?.data != null;

  const agentsQ = trpc.wazuh.agents.useQuery({ limit: 100, offset: 0, status: "active" }, { retry: 1, staleTime: 30_000, enabled: isConnected });
  const agentList = useMemo(() => {
    if (isConnected && agentsQ.data) return extractItems(agentsQ.data).items;
    return MOCK_AGENTS.data.affected_items.filter(a => a.status === "active") as unknown as Array<Record<string, unknown>>;
  }, [agentsQ.data, isConnected]);

  const packagesQ = trpc.wazuh.agentPackages.useQuery(
    { agentId, limit: pageSize, offset: page * pageSize, search: search || undefined },
    { retry: 1, staleTime: 30_000, enabled: isConnected && tab === "packages" }
  );
  const portsQ = trpc.wazuh.agentPorts.useQuery(
    { agentId, limit: pageSize, offset: page * pageSize },
    { retry: 1, staleTime: 30_000, enabled: isConnected && tab === "ports" }
  );
  const processesQ = trpc.wazuh.agentProcesses.useQuery(
    { agentId, limit: pageSize, offset: page * pageSize, search: search || undefined },
    { retry: 1, staleTime: 30_000, enabled: isConnected && tab === "processes" }
  );
  const netifaceQ = trpc.wazuh.agentNetiface.useQuery(
    { agentId },
    { retry: 1, staleTime: 60_000, enabled: isConnected && tab === "network" }
  );
  const netaddrQ = trpc.wazuh.agentNetaddr.useQuery(
    { agentId },
    { retry: 1, staleTime: 60_000, enabled: isConnected && tab === "network" }
  );
  const hotfixesQ = trpc.wazuh.agentHotfixes.useQuery(
    { agentId, limit: pageSize, offset: page * pageSize },
    { retry: 1, staleTime: 60_000, enabled: isConnected && tab === "hotfixes" }
  );

  const handleRefresh = useCallback(() => { utils.wazuh.invalidate(); }, [utils]);

  // ── Fallback-aware data extraction ────────────────────────────────────
  const packagesData = useMemo(() => {
    if (isConnected && packagesQ.data) return extractItems(packagesQ.data);
    let items = MOCK_PACKAGES.data.affected_items as unknown as Array<Record<string, unknown>>;
    if (search) { const q = search.toLowerCase(); items = items.filter(p => String(p.name ?? "").toLowerCase().includes(q)); }
    return { items, total: items.length };
  }, [packagesQ.data, isConnected, search]);

  const portsData = useMemo(() => {
    if (isConnected && portsQ.data) return extractItems(portsQ.data);
    return { items: MOCK_PORTS.data.affected_items as unknown as Array<Record<string, unknown>>, total: MOCK_PORTS.data.total_affected_items };
  }, [portsQ.data, isConnected]);

  const processesData = useMemo(() => {
    if (isConnected && processesQ.data) return extractItems(processesQ.data);
    let items = MOCK_PROCESSES.data.affected_items as unknown as Array<Record<string, unknown>>;
    if (search) { const q = search.toLowerCase(); items = items.filter(p => String(p.name ?? "").toLowerCase().includes(q) || String(p.cmd ?? "").toLowerCase().includes(q)); }
    return { items, total: items.length };
  }, [processesQ.data, isConnected, search]);

  const netifaceData = useMemo(() => {
    if (isConnected && netifaceQ.data) return extractItems(netifaceQ.data);
    return { items: MOCK_NETIFACE.data.affected_items as unknown as Array<Record<string, unknown>>, total: MOCK_NETIFACE.data.total_affected_items };
  }, [netifaceQ.data, isConnected]);

  const netaddrData = useMemo(() => {
    if (isConnected && netaddrQ.data) return extractItems(netaddrQ.data);
    return { items: MOCK_NETADDR.data.affected_items as unknown as Array<Record<string, unknown>>, total: MOCK_NETADDR.data.total_affected_items };
  }, [netaddrQ.data, isConnected]);

  const hotfixesData = useMemo(() => {
    if (isConnected && hotfixesQ.data) return extractItems(hotfixesQ.data);
    return { items: MOCK_HOTFIXES.data.affected_items as unknown as Array<Record<string, unknown>>, total: MOCK_HOTFIXES.data.total_affected_items };
  }, [hotfixesQ.data, isConnected]);

  const isLoading = statusQ.isLoading;

  return (
    <WazuhGuard>
      <div className="space-y-6">
        <PageHeader title="IT Hygiene" subtitle="Syscollector inventory — packages, ports, processes, network, and hotfixes" onRefresh={handleRefresh} isLoading={isLoading} />

        <GlassPanel className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-primary" />
            <span className="text-sm font-medium text-muted-foreground">Target Agent:</span>
          </div>
          <Select value={agentId} onValueChange={(v) => { setAgentId(v); setPage(0); }}>
            <SelectTrigger className="w-[280px] h-8 text-xs bg-secondary/50 border-border"><SelectValue placeholder="Select agent" /></SelectTrigger>
            <SelectContent className="bg-popover border-border max-h-60">
              {agentList.map(a => (
                <SelectItem key={String(a.id)} value={String(a.id)}>
                  {String(a.id)} — {String(a.name ?? "Unknown")} ({String(a.ip ?? "")})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <div className="relative ml-auto">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input placeholder="Search..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(0); }} className="h-8 w-48 pl-8 text-xs bg-secondary/50 border-border" />
          </div>
        </GlassPanel>

        <Tabs value={tab} onValueChange={(v) => { setTab(v as TabKey); setPage(0); setSearch(""); }}>
          <TabsList className="bg-secondary/30 border border-border/30">
            <TabsTrigger value="packages" className="text-xs gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary"><Package className="h-3.5 w-3.5" /> Packages</TabsTrigger>
            <TabsTrigger value="ports" className="text-xs gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary"><Globe className="h-3.5 w-3.5" /> Ports</TabsTrigger>
            <TabsTrigger value="processes" className="text-xs gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary"><Cpu className="h-3.5 w-3.5" /> Processes</TabsTrigger>
            <TabsTrigger value="network" className="text-xs gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary"><Network className="h-3.5 w-3.5" /> Network</TabsTrigger>
            <TabsTrigger value="hotfixes" className="text-xs gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary"><HardDrive className="h-3.5 w-3.5" /> Hotfixes</TabsTrigger>
          </TabsList>

          {/* Packages Tab */}
          <TabsContent value="packages">
            <GlassPanel>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs text-muted-foreground">{packagesData.total} packages</span>
                {packagesQ.data ? <RawJsonViewer data={packagesQ.data as Record<string, unknown>} title="Packages JSON" /> : null}
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr className="border-b border-border/30">
                    {["Name", "Version", "Architecture", "Vendor", "Format", "Description"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {packagesData.items.map((p, i) => (
                      <tr key={i} className="border-b border-border/10 hover:bg-secondary/20 transition-colors">
                        <td className="py-2 px-3 text-foreground font-medium">{String(p.name ?? "—")}</td>
                        <td className="py-2 px-3 font-mono text-primary">{String(p.version ?? "—")}</td>
                        <td className="py-2 px-3 text-muted-foreground">{String(p.architecture ?? "—")}</td>
                        <td className="py-2 px-3 text-muted-foreground truncate max-w-[200px]">{String(p.vendor ?? "—")}</td>
                        <td className="py-2 px-3 text-muted-foreground">{String(p.format ?? "—")}</td>
                        <td className="py-2 px-3 text-muted-foreground truncate max-w-[300px]">{String(p.description ?? "—")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {Math.ceil(packagesData.total / pageSize) > 1 && <Pagination page={page} totalPages={Math.ceil(packagesData.total / pageSize)} onPageChange={setPage} total={packagesData.total} />}
            </GlassPanel>
          </TabsContent>

          {/* Ports Tab */}
          <TabsContent value="ports">
            <GlassPanel>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs text-muted-foreground">{portsData.total} open ports</span>
                {portsQ.data ? <RawJsonViewer data={portsQ.data as Record<string, unknown>} title="Ports JSON" /> : null}
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr className="border-b border-border/30">
                    {["Local IP", "Local Port", "Remote IP", "Remote Port", "Protocol", "State", "PID", "Process"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {portsData.items.map((p, i) => {
                      const local = p.local as Record<string, unknown> | undefined;
                      const remote = p.remote as Record<string, unknown> | undefined;
                      return (
                        <tr key={i} className="border-b border-border/10 hover:bg-secondary/20 transition-colors">
                          <td className="py-2 px-3 font-mono text-foreground">{String(local?.ip ?? "—")}</td>
                          <td className="py-2 px-3 font-mono text-primary">{String(local?.port ?? "—")}</td>
                          <td className="py-2 px-3 font-mono text-muted-foreground">{String(remote?.ip ?? "—")}</td>
                          <td className="py-2 px-3 font-mono text-muted-foreground">{String(remote?.port ?? "—")}</td>
                          <td className="py-2 px-3 text-muted-foreground">{String(p.protocol ?? "—")}</td>
                          <td className="py-2 px-3 text-muted-foreground">{String(p.state ?? "—")}</td>
                          <td className="py-2 px-3 font-mono text-muted-foreground">{String(p.pid ?? "—")}</td>
                          <td className="py-2 px-3 text-muted-foreground">{String(p.process ?? "—")}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {Math.ceil(portsData.total / pageSize) > 1 && <Pagination page={page} totalPages={Math.ceil(portsData.total / pageSize)} onPageChange={setPage} total={portsData.total} />}
            </GlassPanel>
          </TabsContent>

          {/* Processes Tab */}
          <TabsContent value="processes">
            <GlassPanel>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs text-muted-foreground">{processesData.total} processes</span>
                {processesQ.data ? <RawJsonViewer data={processesQ.data as Record<string, unknown>} title="Processes JSON" /> : null}
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr className="border-b border-border/30">
                    {["PID", "Name", "State", "User", "PPID", "Priority", "Threads", "CMD"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {processesData.items.map((p, i) => (
                      <tr key={i} className="border-b border-border/10 hover:bg-secondary/20 transition-colors">
                        <td className="py-2 px-3 font-mono text-primary">{String(p.pid ?? "—")}</td>
                        <td className="py-2 px-3 text-foreground font-medium">{String(p.name ?? "—")}</td>
                        <td className="py-2 px-3 text-muted-foreground">{String(p.state ?? "—")}</td>
                        <td className="py-2 px-3 text-muted-foreground">{String(p.euser ?? p.ruser ?? "—")}</td>
                        <td className="py-2 px-3 font-mono text-muted-foreground">{String(p.ppid ?? "—")}</td>
                        <td className="py-2 px-3 text-muted-foreground">{String(p.priority ?? "—")}</td>
                        <td className="py-2 px-3 text-muted-foreground">{String(p.nlwp ?? "—")}</td>
                        <td className="py-2 px-3 font-mono text-muted-foreground truncate max-w-[300px]">{String(p.cmd ?? "—")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {Math.ceil(processesData.total / pageSize) > 1 && <Pagination page={page} totalPages={Math.ceil(processesData.total / pageSize)} onPageChange={setPage} total={processesData.total} />}
            </GlassPanel>
          </TabsContent>

          {/* Network Tab */}
          <TabsContent value="network">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <GlassPanel>
                <h3 className="text-sm font-medium text-muted-foreground mb-3 flex items-center gap-2"><Network className="h-4 w-4 text-primary" /> Network Interfaces</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead><tr className="border-b border-border/30">
                      {["Name", "Type", "State", "MAC", "MTU", "TX Packets", "RX Packets"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
                    </tr></thead>
                    <tbody>
                      {netifaceData.items.map((iface, i) => {
                        const tx = iface.tx as Record<string, unknown> | undefined;
                        const rx = iface.rx as Record<string, unknown> | undefined;
                        return (
                          <tr key={i} className="border-b border-border/10 hover:bg-secondary/20 transition-colors">
                            <td className="py-2 px-3 text-foreground font-medium">{String(iface.name ?? "—")}</td>
                            <td className="py-2 px-3 text-muted-foreground">{String(iface.type ?? "—")}</td>
                            <td className="py-2 px-3 text-muted-foreground">{String(iface.state ?? "—")}</td>
                            <td className="py-2 px-3 font-mono text-muted-foreground">{String(iface.mac ?? "—")}</td>
                            <td className="py-2 px-3 text-muted-foreground">{String(iface.mtu ?? "—")}</td>
                            <td className="py-2 px-3 font-mono text-muted-foreground">{String(tx?.packets ?? "—")}</td>
                            <td className="py-2 px-3 font-mono text-muted-foreground">{String(rx?.packets ?? "—")}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </GlassPanel>

              <GlassPanel>
                <h3 className="text-sm font-medium text-muted-foreground mb-3 flex items-center gap-2"><Globe className="h-4 w-4 text-primary" /> Network Addresses</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead><tr className="border-b border-border/30">
                      {["Interface", "Protocol", "Address", "Netmask", "Broadcast"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
                    </tr></thead>
                    <tbody>
                      {netaddrData.items.map((addr, i) => (
                        <tr key={i} className="border-b border-border/10 hover:bg-secondary/20 transition-colors">
                          <td className="py-2 px-3 text-foreground font-medium">{String(addr.iface ?? "—")}</td>
                          <td className="py-2 px-3 text-muted-foreground">{String(addr.proto ?? "—")}</td>
                          <td className="py-2 px-3 font-mono text-primary">{String(addr.address ?? "—")}</td>
                          <td className="py-2 px-3 font-mono text-muted-foreground">{String(addr.netmask ?? "—")}</td>
                          <td className="py-2 px-3 font-mono text-muted-foreground">{String(addr.broadcast ?? "—")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </GlassPanel>
            </div>
          </TabsContent>

          {/* Hotfixes Tab */}
          <TabsContent value="hotfixes">
            <GlassPanel>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs text-muted-foreground">{hotfixesData.total} hotfixes</span>
                {hotfixesQ.data ? <RawJsonViewer data={hotfixesQ.data as Record<string, unknown>} title="Hotfixes JSON" /> : null}
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr className="border-b border-border/30">
                    {["Hotfix ID", "Scan Time"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {hotfixesData.items.map((h, i) => (
                      <tr key={i} className="border-b border-border/10 hover:bg-secondary/20 transition-colors">
                        <td className="py-2 px-3 font-mono text-primary">{String(h.hotfix ?? "—")}</td>
                        <td className="py-2 px-3 font-mono text-muted-foreground">{String((h.scan as Record<string, unknown>)?.time ?? "—")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {Math.ceil(hotfixesData.total / pageSize) > 1 && <Pagination page={page} totalPages={Math.ceil(hotfixesData.total / pageSize)} onPageChange={setPage} total={hotfixesData.total} />}
            </GlassPanel>
          </TabsContent>
        </Tabs>
      </div>
    </WazuhGuard>
  );
}

function Pagination({ page, totalPages, onPageChange, total }: { page: number; totalPages: number; onPageChange: (p: number) => void; total: number }) {
  return (
    <div className="flex items-center justify-between mt-4 pt-4 border-t border-border/30">
      <p className="text-xs text-muted-foreground">Page {page + 1} of {totalPages} ({total} items)</p>
      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" disabled={page === 0} onClick={() => onPageChange(page - 1)} className="h-7 bg-transparent border-border"><ChevronLeft className="h-3.5 w-3.5" /></Button>
        <Button variant="outline" size="sm" disabled={page >= totalPages - 1} onClick={() => onPageChange(page + 1)} className="h-7 bg-transparent border-border"><ChevronRight className="h-3.5 w-3.5" /></Button>
      </div>
    </div>
  );
}
