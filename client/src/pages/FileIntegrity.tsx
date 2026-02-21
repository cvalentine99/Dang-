import { GlassPanel, RawJsonViewer, ThreatBadge } from "@/components/shared";
import { PageHeader } from "@/components/shared/PageHeader";
import { WazuhGuard } from "@/components/shared/WazuhGuard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { trpc } from "@/lib/trpc";
import { FileSearch, Search, Clock, FolderOpen } from "lucide-react";
import { useCallback, useState } from "react";

export default function FileIntegrity() {
  const [agentId, setAgentId] = useState("000");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const utils = trpc.useUtils();

  const syscheckQ = trpc.wazuh.syscheckFiles.useQuery(
    { agentId, limit: 50, offset: page * 50 },
    { staleTime: 30_000 }
  );

  const lastScanQ = trpc.wazuh.syscheckLastScan.useQuery(
    { agentId },
    { staleTime: 60_000 }
  );

  const handleRefresh = useCallback(() => {
    utils.wazuh.syscheckFiles.invalidate();
    utils.wazuh.syscheckLastScan.invalidate();
  }, [utils]);

  const isLoading = syscheckQ.isLoading;

  // Parse syscheck data
  const fimData = (syscheckQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const fimItems = (fimData?.affected_items as Array<Record<string, unknown>>) ?? [];
  const totalItems = (fimData?.total_affected_items as number) ?? 0;

  // Parse last scan
  const scanData = (lastScanQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const scanItems = (scanData?.affected_items as Array<Record<string, unknown>>) ?? [];
  const lastScan = scanItems[0] ?? {};

  // Client-side search filter
  const filteredItems = search
    ? fimItems.filter((item) => {
        const file = (item.file as string) ?? "";
        return file.toLowerCase().includes(search.toLowerCase());
      })
    : fimItems;

  return (
    <div>
      <PageHeader
        title="File Integrity Monitoring"
        subtitle={`Agent ${agentId} — ${totalItems} monitored entries`}
        onRefresh={handleRefresh}
        isLoading={isLoading}
      >
        <Input
          placeholder="Agent ID"
          value={agentId}
          onChange={(e) => { setAgentId(e.target.value); setPage(0); }}
          className="h-8 text-xs w-24 bg-secondary/50 border-border font-mono"
        />
      </PageHeader>

      <WazuhGuard>
        {/* ── Last scan info ──────────────────────────────── */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
          <GlassPanel className="p-4 flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
              <Clock className="h-5 w-5 text-primary" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Last Scan Start</p>
              <p className="text-sm font-mono text-foreground mt-0.5">
                {(lastScan.start as string) ?? "—"}
              </p>
            </div>
          </GlassPanel>
          <GlassPanel className="p-4 flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
              <Clock className="h-5 w-5 text-threat-low" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Last Scan End</p>
              <p className="text-sm font-mono text-foreground mt-0.5">
                {(lastScan.end as string) ?? "—"}
              </p>
            </div>
          </GlassPanel>
          <GlassPanel className="p-4 flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
              <FolderOpen className="h-5 w-5 text-threat-medium" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Total Entries</p>
              <p className="text-sm font-display font-bold text-foreground mt-0.5">
                {totalItems.toLocaleString()}
              </p>
            </div>
          </GlassPanel>
        </div>

        {/* ── FIM table ───────────────────────────────────── */}
        <GlassPanel className="p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
            <h3 className="font-display font-semibold text-foreground text-sm flex items-center gap-2">
              <FileSearch className="h-4 w-4 text-primary" />
              Syscheck Results
            </h3>
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Filter by file path..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-8 h-8 text-xs w-56 bg-secondary/50 border-border"
                />
              </div>
              <RawJsonViewer data={syscheckQ.data} title="Syscheck Raw Data" />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-muted-foreground">
                  <th className="text-left py-2 px-3 font-medium">File</th>
                  <th className="text-left py-2 px-3 font-medium">Type</th>
                  <th className="text-left py-2 px-3 font-medium">Size</th>
                  <th className="text-left py-2 px-3 font-medium">UID</th>
                  <th className="text-left py-2 px-3 font-medium">GID</th>
                  <th className="text-left py-2 px-3 font-medium">Permissions</th>
                  <th className="text-left py-2 px-3 font-medium">MD5</th>
                  <th className="text-left py-2 px-3 font-medium">Modified</th>
                </tr>
              </thead>
              <tbody>
                {filteredItems.map((item, i) => (
                  <tr key={i} className="border-b border-border/50 data-row">
                    <td className="py-2 px-3 font-mono text-primary text-[10px] max-w-xs truncate">
                      {item.file as string}
                    </td>
                    <td className="py-2 px-3 text-muted-foreground">{item.type as string ?? "—"}</td>
                    <td className="py-2 px-3 font-mono text-foreground">{String(item.size ?? "—")}</td>
                    <td className="py-2 px-3 font-mono text-muted-foreground">{item.uid as string ?? "—"}</td>
                    <td className="py-2 px-3 font-mono text-muted-foreground">{item.gid as string ?? "—"}</td>
                    <td className="py-2 px-3 font-mono text-muted-foreground text-[10px]">{item.perm as string ?? "—"}</td>
                    <td className="py-2 px-3 font-mono text-muted-foreground text-[10px] max-w-[120px] truncate">
                      {item.md5 as string ?? "—"}
                    </td>
                    <td className="py-2 px-3 font-mono text-muted-foreground text-[10px]">
                      {item.mtime as string ?? "—"}
                    </td>
                  </tr>
                ))}
                {filteredItems.length === 0 && (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-muted-foreground">
                      {isLoading ? "Loading..." : "No syscheck entries found"}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {totalItems > 50 && (
            <div className="flex items-center justify-between mt-4 pt-3 border-t border-border">
              <span className="text-xs text-muted-foreground">
                Showing {page * 50 + 1}–{Math.min((page + 1) * 50, totalItems)} of {totalItems}
              </span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0} className="h-7 text-xs bg-transparent border-border">Previous</Button>
                <Button variant="outline" size="sm" onClick={() => setPage((p) => p + 1)} disabled={(page + 1) * 50 >= totalItems} className="h-7 text-xs bg-transparent border-border">Next</Button>
              </div>
            </div>
          )}
        </GlassPanel>
      </WazuhGuard>
    </div>
  );
}
