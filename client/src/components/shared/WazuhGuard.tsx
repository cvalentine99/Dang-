import { trpc } from "@/lib/trpc";
import { Shield, AlertTriangle, Settings2, Wifi, WifiOff } from "lucide-react";
import { ReactNode } from "react";
import { useLocation } from "wouter";

interface WazuhGuardProps {
  children: ReactNode;
}

/**
 * No longer blocks content. Shows an inline connection banner at the top
 * and always renders children. Pages handle their own empty states.
 */
export function WazuhGuard({ children }: WazuhGuardProps) {
  const { data, isLoading } = trpc.wazuh.status.useQuery(undefined, {
    retry: 1,
    staleTime: 60_000,
  });
  const [, setLocation] = useLocation();

  const isConnected = data?.configured === true && data?.data != null;

  return (
    <div className="space-y-4">
      {/* Connection status banner */}
      {!isLoading && (
        <div className={`flex items-center gap-3 px-4 py-2.5 rounded-lg border text-xs font-medium ${
          isConnected
            ? "bg-threat-low/5 border-threat-low/20 text-threat-low"
            : "bg-threat-high/5 border-threat-high/20 text-threat-high"
        }`}>
          {isConnected ? (
            <>
              <Wifi className="h-3.5 w-3.5" />
              <span>Wazuh API Connected</span>
              <span className="text-muted-foreground ml-1">— Live data active</span>
            </>
          ) : (
            <>
              <WifiOff className="h-3.5 w-3.5" />
              <span>Wazuh API Not Connected</span>
              <span className="text-muted-foreground ml-1">
                {!data?.configured
                  ? "— Configure connection in"
                  : `— ${(data as Record<string, unknown>)?.error ?? "Connection failed — check credentials in"}`}
              </span>
              <button
                onClick={() => setLocation("/admin/settings")}
                className="inline-flex items-center gap-1 ml-1 underline underline-offset-2 hover:text-foreground transition-colors"
              >
                <Settings2 className="h-3 w-3" />
                Admin Settings
              </button>
              {!data?.configured && (
                <span className="text-muted-foreground ml-1">or set WAZUH_HOST, WAZUH_USER, WAZUH_PASS env vars</span>
              )}
            </>
          )}
        </div>
      )}

      {/* Always render children */}
      {children}
    </div>
  );
}

/**
 * Hook to check Wazuh connection status without blocking.
 */
export function useWazuhStatus() {
  const { data, isLoading } = trpc.wazuh.status.useQuery(undefined, {
    retry: 1,
    staleTime: 60_000,
  });
  return {
    isLoading,
    isConfigured: data?.configured === true,
    isConnected: data?.configured === true && data?.data != null,
    error: (data as Record<string, unknown>)?.error as string | undefined,
  };
}
