import { trpc } from "@/lib/trpc";
import { GlassPanel } from "@/components/shared/GlassPanel";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { RawJsonViewer } from "@/components/shared/RawJsonViewer";
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

export default function ITHygiene() {
  const utils = trpc.useUtils();
  const [agentId, setAgentId] = useState("001");
  const [tab, setTab] = useState<TabKey>("packages");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 50;

  const statusQ = trpc.wazuh.status.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const enabled = statusQ.data?.configured === true;

  // Agent list for selector
  const agentsQ = trpc.wazuh.agents.useQuery({ limit: 100, offset: 0, status: "active" }, { retry: 1, staleTime: 30_000, enabled });
  const agentList = useMemo(() => {
    const d = (agentsQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    return (d?.affected_items as Array<Record<string, unknown>>) ?? [];
  }, [agentsQ.data]);

  // Syscollector queries
  const packagesQ = trpc.wazuh.agentPackages.useQuery(
    { agentId, limit: pageSize, offset: page * pageSize, search: search || undefined },
    { retry: 1, staleTime: 30_000, enabled: enabled && tab === "packages" }
  );
  const portsQ = trpc.wazuh.agentPorts.useQuery(
    { agentId, limit: pageSize, offset: page * pageSize },
    { retry: 1, staleTime: 30_000, enabled: enabled && tab === "ports" }
  );
  const processesQ = trpc.wazuh.agentProcesses.useQuery(
    { agentId, limit: pageSize, offset: page * pageSize, search: search || undefined },
    { retry: 1, staleTime: 30_000, enabled: enabled && tab === "processes" }
  );
  const netifaceQ = trpc.wazuh.agentNetiface.useQuery(
    { agentId },
    { retry: 1, staleTime: 60_000, enabled: enabled && tab === "network" }
  );
  const netaddrQ = trpc.wazuh.agentNetaddr.useQuery(
    { agentId },
    { retry: 1, staleTime: 60_000, enabled: enabled && tab === "network" }
  );
  const hotfixesQ = trpc.wazuh.agentHotfixes.useQuery(
    { agentId, limit: pageSize, offset: page * pageSize },
    { retry: 1, staleTime: 60_000, enabled: enabled && tab === "hotfixes" }
  );

  const handleRefresh = useCallback(() => { utils.wazuh.invalidate(); }, [utils]);

  function extractItems(data: unknown): { items: Array<Record<string, unknown>>; total: number } {
    const d = (data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
    const items = (d?.affected_items as Array<Record<string, unknown>>) ?? [];
    const total = Number(d?.total_affected_items ?? items.length);
    return { items, total };
  }

  const currentQuery = tab === "packages" ? packagesQ : tab === "ports" ? portsQ : tab === "processes" ? processesQ : tab === "hotfixes" ? hotfixesQ : null;
  const isLoading = currentQuery?.isLoading ?? false;

  return (
    <WazuhGuard>
      <div className="space-y-6">
        <PageHeader title="IT Hygiene" subtitle="Syscollector inventory — packages, ports, processes, network, and hotfixes" onRefresh={handleRefresh} isLoading={isLoading} />

        {/* Agent Selector */}
        <GlassPanel className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-primary" />
            <span className="text-sm font-medium text-muted-foreground">Target Agent:</span>
          </div>
          <Select value={agentId} onValueChange={(v) => { setAgentId(v); setPage(0); }}>
            <SelectTrigger className="w-[280px] h-8 text-xs bg-secondary/50 border-border">
              <SelectValue placeholder="Select agent" />
            </SelectTrigger>
            <SelectContent className="bg-popover border-border max-h-60">
              {agentList.map(a => (
                <SelectItem key={String(a.id)} value={String(a.id)}>
                  {String(a.id)} — {String(a.name ?? "Unknown")} ({String(a.ip ?? "")})
                </SelectItem>
              ))}
              {agentList.length === 0 && <SelectItem value="001" disabled>No active agents</SelectItem>}
            </SelectContent>
          </Select>
          <div className="relative ml-auto">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input placeholder="Search..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(0); }} className="h-8 w-48 pl-8 text-xs bg-secondary/50 border-border" />
          </div>
        </GlassPanel>

        {/* Tabs */}
        <Tabs value={tab} onValueChange={(v) => { setTab(v as TabKey); setPage(0); setSearch(""); }}>
          <TabsList className="bg-secondary/30 border border-border/30">
            <TabsTrigger value="packages" className="text-xs gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary">
              <Package className="h-3.5 w-3.5" /> Packages
            </TabsTrigger>
            <TabsTrigger value="ports" className="text-xs gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary">
              <Globe className="h-3.5 w-3.5" /> Ports
            </TabsTrigger>
            <TabsTrigger value="processes" className="text-xs gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary">
              <Cpu className="h-3.5 w-3.5" /> Processes
            </TabsTrigger>
            <TabsTrigger value="network" className="text-xs gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary">
              <Network className="h-3.5 w-3.5" /> Network
            </TabsTrigger>
            <TabsTrigger value="hotfixes" className="text-xs gap-1.5 data-[state=active]:bg-primary/15 data-[state=active]:text-primary">
              <HardDrive className="h-3.5 w-3.5" /> Hotfixes
            </TabsTrigger>
          </TabsList>

          {/* Packages Tab */}
          <TabsContent value="packages">
            <GlassPanel>
              {(() => {
                const { items, total } = extractItems(packagesQ.data);
                const totalPages = Math.ceil(total / pageSize);
                return (
                  <>
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs text-muted-foreground">{total} packages</span>
                      {packagesQ.data ? <RawJsonViewer data={packagesQ.data as Record<string, unknown>} title="Packages JSON" /> : null}
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead><tr className="border-b border-border/30">
                          {["Name", "Version", "Architecture", "Vendor", "Format", "Description"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
                        </tr></thead>
                        <tbody>
                          {items.map((p, i) => (
                            <tr key={i} className="border-b border-border/10 data-row">
                              <td className="py-2 px-3 text-foreground font-medium">{String(p.name ?? "—")}</td>
                              <td className="py-2 px-3 font-mono text-primary">{String(p.version ?? "—")}</td>
                              <td className="py-2 px-3 text-muted-foreground">{String(p.architecture ?? "—")}</td>
                              <td className="py-2 px-3 text-muted-foreground truncate max-w-[200px]">{String(p.vendor ?? "—")}</td>
                              <td className="py-2 px-3 text-muted-foreground">{String(p.format ?? "—")}</td>
                              <td className="py-2 px-3 text-muted-foreground truncate max-w-[300px]">{String(p.description ?? "—")}</td>
                            </tr>
                          ))}
                          {items.length === 0 && <tr><td colSpan={6} className="py-12 text-center text-muted-foreground">{packagesQ.isLoading ? "Loading..." : "No packages"}</td></tr>}
                        </tbody>
                      </table>
                    </div>
                    {totalPages > 1 && <Pagination page={page} totalPages={totalPages} onPageChange={setPage} total={total} />}
                  </>
                );
              })()}
            </GlassPanel>
          </TabsContent>

          {/* Ports Tab */}
          <TabsContent value="ports">
            <GlassPanel>
              {(() => {
                const { items, total } = extractItems(portsQ.data);
                const totalPages = Math.ceil(total / pageSize);
                return (
                  <>
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs text-muted-foreground">{total} open ports</span>
                      {portsQ.data ? <RawJsonViewer data={portsQ.data as Record<string, unknown>} title="Ports JSON" /> : null}
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead><tr className="border-b border-border/30">
                          {["Local IP", "Local Port", "Remote IP", "Remote Port", "Protocol", "State", "PID", "Process"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
                        </tr></thead>
                        <tbody>
                          {items.map((p, i) => {
                            const local = p.local as Record<string, unknown> | undefined;
                            const remote = p.remote as Record<string, unknown> | undefined;
                            return (
                              <tr key={i} className="border-b border-border/10 data-row">
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
                          {items.length === 0 && <tr><td colSpan={8} className="py-12 text-center text-muted-foreground">{portsQ.isLoading ? "Loading..." : "No open ports"}</td></tr>}
                        </tbody>
                      </table>
                    </div>
                    {totalPages > 1 && <Pagination page={page} totalPages={totalPages} onPageChange={setPage} total={total} />}
                  </>
                );
              })()}
            </GlassPanel>
          </TabsContent>

          {/* Processes Tab */}
          <TabsContent value="processes">
            <GlassPanel>
              {(() => {
                const { items, total } = extractItems(processesQ.data);
                const totalPages = Math.ceil(total / pageSize);
                return (
                  <>
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs text-muted-foreground">{total} processes</span>
                      {processesQ.data ? <RawJsonViewer data={processesQ.data as Record<string, unknown>} title="Processes JSON" /> : null}
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead><tr className="border-b border-border/30">
                          {["PID", "Name", "State", "User", "PPID", "Priority", "Threads", "CMD"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
                        </tr></thead>
                        <tbody>
                          {items.map((p, i) => (
                            <tr key={i} className="border-b border-border/10 data-row">
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
                          {items.length === 0 && <tr><td colSpan={8} className="py-12 text-center text-muted-foreground">{processesQ.isLoading ? "Loading..." : "No processes"}</td></tr>}
                        </tbody>
                      </table>
                    </div>
                    {totalPages > 1 && <Pagination page={page} totalPages={totalPages} onPageChange={setPage} total={total} />}
                  </>
                );
              })()}
            </GlassPanel>
          </TabsContent>

          {/* Network Tab */}
          <TabsContent value="network">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <GlassPanel>
                <h3 className="text-sm font-medium text-muted-foreground mb-3 flex items-center gap-2">
                  <Network className="h-4 w-4 text-primary" /> Network Interfaces
                </h3>
                {(() => {
                  const { items } = extractItems(netifaceQ.data);
                  return (
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead><tr className="border-b border-border/30">
                          {["Name", "Type", "State", "MAC", "MTU", "TX Packets", "RX Packets"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
                        </tr></thead>
                        <tbody>
                          {items.map((iface, i) => {
                            const tx = iface.tx as Record<string, unknown> | undefined;
                            const rx = iface.rx as Record<string, unknown> | undefined;
                            return (
                              <tr key={i} className="border-b border-border/10 data-row">
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
                          {items.length === 0 && <tr><td colSpan={7} className="py-8 text-center text-muted-foreground">{netifaceQ.isLoading ? "Loading..." : "No interfaces"}</td></tr>}
                        </tbody>
                      </table>
                    </div>
                  );
                })()}
              </GlassPanel>

              <GlassPanel>
                <h3 className="text-sm font-medium text-muted-foreground mb-3 flex items-center gap-2">
                  <Globe className="h-4 w-4 text-primary" /> Network Addresses
                </h3>
                {(() => {
                  const { items } = extractItems(netaddrQ.data);
                  return (
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead><tr className="border-b border-border/30">
                          {["Interface", "Protocol", "Address", "Netmask", "Broadcast"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
                        </tr></thead>
                        <tbody>
                          {items.map((addr, i) => (
                            <tr key={i} className="border-b border-border/10 data-row">
                              <td className="py-2 px-3 text-foreground font-medium">{String(addr.iface ?? "—")}</td>
                              <td className="py-2 px-3 text-muted-foreground">{String(addr.proto ?? "—")}</td>
                              <td className="py-2 px-3 font-mono text-primary">{String(addr.address ?? "—")}</td>
                              <td className="py-2 px-3 font-mono text-muted-foreground">{String(addr.netmask ?? "—")}</td>
                              <td className="py-2 px-3 font-mono text-muted-foreground">{String(addr.broadcast ?? "—")}</td>
                            </tr>
                          ))}
                          {items.length === 0 && <tr><td colSpan={5} className="py-8 text-center text-muted-foreground">{netaddrQ.isLoading ? "Loading..." : "No addresses"}</td></tr>}
                        </tbody>
                      </table>
                    </div>
                  );
                })()}
              </GlassPanel>
            </div>
          </TabsContent>

          {/* Hotfixes Tab */}
          <TabsContent value="hotfixes">
            <GlassPanel>
              {(() => {
                const { items, total } = extractItems(hotfixesQ.data);
                const totalPages = Math.ceil(total / pageSize);
                return (
                  <>
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs text-muted-foreground">{total} hotfixes</span>
                      {hotfixesQ.data ? <RawJsonViewer data={hotfixesQ.data as Record<string, unknown>} title="Hotfixes JSON" /> : null}
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead><tr className="border-b border-border/30">
                          {["Hotfix ID", "Scan Time"].map(h => <th key={h} className="text-left py-2 px-3 text-muted-foreground font-medium">{h}</th>)}
                        </tr></thead>
                        <tbody>
                          {items.map((h, i) => (
                            <tr key={i} className="border-b border-border/10 data-row">
                              <td className="py-2 px-3 font-mono text-primary">{String(h.hotfix ?? "—")}</td>
                              <td className="py-2 px-3 font-mono text-muted-foreground">{String((h.scan as Record<string, unknown>)?.time ?? "—")}</td>
                            </tr>
                          ))}
                          {items.length === 0 && <tr><td colSpan={2} className="py-12 text-center text-muted-foreground">{hotfixesQ.isLoading ? "Loading..." : "No hotfixes"}</td></tr>}
                        </tbody>
                      </table>
                    </div>
                    {totalPages > 1 && <Pagination page={page} totalPages={totalPages} onPageChange={setPage} total={total} />}
                  </>
                );
              })()}
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
