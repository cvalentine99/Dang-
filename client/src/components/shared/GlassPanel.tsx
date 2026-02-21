import { cn } from "@/lib/utils";
import { ReactNode } from "react";

interface GlassPanelProps {
  children: ReactNode;
  className?: string;
  hover?: boolean;
  glow?: boolean;
}

export function GlassPanel({ children, className, hover, glow }: GlassPanelProps) {
  return (
    <div
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

export function GlassCard({ children, className, hover = true }: GlassPanelProps) {
  return (
    <div className={cn("glass-card p-4", !hover && "pointer-events-none", className)}>
      {children}
    </div>
  );
}
