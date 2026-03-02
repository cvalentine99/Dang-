import { cn } from "@/lib/utils";
import { forwardRef, ReactNode } from "react";

interface GlassPanelProps {
  children: ReactNode;
  className?: string;
  hover?: boolean;
  glow?: boolean;
}

export const GlassPanel = forwardRef<HTMLDivElement, GlassPanelProps>(
  ({ children, className, hover, glow }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          "glass-panel p-4",
          hover && "glass-panel-hover",
          glow && "amethyst-glow",
          className
        )}
      >
        {children}
      </div>
    );
  }
);
GlassPanel.displayName = "GlassPanel";

export function GlassCard({ children, className, hover = true }: GlassPanelProps) {
  return (
    <div className={cn("glass-card p-4", !hover && "pointer-events-none", className)}>
      {children}
    </div>
  );
}
