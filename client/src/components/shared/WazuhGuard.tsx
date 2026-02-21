import { trpc } from "@/lib/trpc";
import { Shield, AlertTriangle, Loader2 } from "lucide-react";
import { ReactNode } from "react";

interface WazuhGuardProps {
  children: ReactNode;
}

/**
 * Wraps a page and shows a friendly error state when Wazuh is not configured
 * or the connection fails. Passes through when healthy.
 */
export function WazuhGuard({ children }: WazuhGuardProps) {
  const { data, isLoading, error } = trpc.wazuh.status.useQuery(undefined, {
    retry: 1,
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (error || !data?.configured) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="glass-panel p-8 max-w-lg text-center">
          <div className="h-14 w-14 rounded-xl bg-destructive/10 flex items-center justify-center mx-auto mb-4">
            <AlertTriangle className="h-7 w-7 text-destructive" />
          </div>
          <h2 className="text-lg font-display font-semibold text-foreground mb-2">
            Wazuh Not Connected
          </h2>
          <p className="text-sm text-muted-foreground mb-4">
            {!data?.configured
              ? "The Wazuh API credentials have not been configured. Set WAZUH_HOST, WAZUH_USER, and WAZUH_PASS in your environment secrets."
              : data?.error ?? "Unable to connect to the Wazuh manager. Check your configuration."}
          </p>
          <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground">
            <Shield className="h-3.5 w-3.5" />
            <span className="font-mono">
              {data?.configured ? `Host: ${(data as Record<string, unknown>).host ?? "—"}` : "Not configured"}
            </span>
          </div>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
