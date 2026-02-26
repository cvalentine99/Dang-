import { AlertTriangle, WifiOff, Inbox } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";

interface DataLoadingProps {
  rows?: number;
  variant?: "inline" | "page";
  label?: string;
}

export function DataLoading({ rows = 4, variant = "inline", label = "Loading data..." }: DataLoadingProps) {
  if (variant === "page") {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48 rounded-lg" />
        <div className="grid gap-4 md:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-28 rounded-xl" />
          ))}
        </div>
        <Skeleton className="h-64 rounded-xl" />
      </div>
    );
  }
  return (
    <div className="flex flex-col items-center justify-center py-12 text-muted-foreground gap-3">
      <div className="h-8 w-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
      <p className="text-sm">{label}</p>
    </div>
  );
}

interface DataErrorProps {
  title?: string;
  message?: string;
  onRetry?: () => void;
  variant?: "inline" | "banner";
}

export function DataError({
  title = "Connection Error",
  message = "Unable to reach Wazuh API. Check connection settings.",
  onRetry,
  variant = "inline",
}: DataErrorProps) {
  if (variant === "banner") {
    return (
      <div className="flex items-center gap-3 px-4 py-3 rounded-lg border bg-threat-high/5 border-threat-high/20 text-threat-high text-xs">
        <WifiOff className="h-4 w-4 shrink-0" />
        <span className="font-medium">{title}</span>
        <span className="text-muted-foreground">{message}</span>
        {onRetry && (
          <Button variant="outline" size="sm" onClick={onRetry} className="ml-auto h-6 text-[10px]">
            Retry
          </Button>
        )}
      </div>
    );
  }
  return (
    <div className="flex flex-col items-center justify-center py-12 gap-4 text-center">
      <div className="h-12 w-12 rounded-xl bg-threat-high/10 flex items-center justify-center">
        <AlertTriangle className="h-6 w-6 text-threat-high" />
      </div>
      <div>
        <h3 className="text-sm font-medium text-foreground">{title}</h3>
        <p className="text-xs text-muted-foreground mt-1 max-w-sm">{message}</p>
      </div>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry} className="text-xs">
          Try Again
        </Button>
      )}
    </div>
  );
}

interface DataEmptyProps {
  icon?: React.ComponentType<{ className?: string }>;
  title?: string;
  message?: string;
}

export function DataEmpty({
  icon: Icon = Inbox,
  title = "No Data",
  message = "No results found. Data will appear here once available.",
}: DataEmptyProps) {
  return (
    <div className="flex flex-col items-center justify-center py-12 gap-3 text-center">
      <div className="h-12 w-12 rounded-xl bg-secondary/50 flex items-center justify-center">
        <Icon className="h-6 w-6 text-muted-foreground" />
      </div>
      <div>
        <h3 className="text-sm font-medium text-foreground">{title}</h3>
        <p className="text-xs text-muted-foreground mt-1 max-w-sm">{message}</p>
      </div>
    </div>
  );
}
