import { useAuth } from "@/_core/hooks/useAuth";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";
import { getLoginUrl } from "@/const";
import { useIsMobile } from "@/hooks/useMobile";
import { trpc } from "@/lib/trpc";
import {
  Activity,
  AlertTriangle,
  Bot,
  FileSearch,
  LayoutDashboard,
  LogOut,
  PanelLeft,
  Shield,
  ShieldCheck,
  StickyNote,
  Target,
  Bug,
  Server,
  Monitor,
  Crosshair,
  Layers,
  BookOpen,
  Radar,
  HeartPulse,
  UserCog,
  Brain,
  Network,
  FolderSearch,
  Database,
  Settings,
} from "lucide-react";
import { AlertNotificationBell } from "@/components/LiveAlertFeed";
import { CSSProperties, useEffect, useRef, useState } from "react";
import { useLocation } from "wouter";
import { DashboardLayoutSkeleton } from "./DashboardLayoutSkeleton";
import { Button } from "./ui/button";

const menuItems = [
  { icon: LayoutDashboard, label: "SOC Console", path: "/", group: "Operations" },
  { icon: Activity, label: "Fleet Command", path: "/agents", group: "Operations" },
  { icon: Radar, label: "Threat Intel", path: "/threat-intel", group: "Operations" },
  { icon: Layers, label: "SIEM Events", path: "/siem", group: "Detection" },
  { icon: AlertTriangle, label: "Alerts Timeline", path: "/alerts", group: "Detection" },
  { icon: Bug, label: "Vulnerabilities", path: "/vulnerabilities", group: "Detection" },
  { icon: Target, label: "MITRE ATT&CK", path: "/mitre", group: "Detection" },
  { icon: Crosshair, label: "Threat Hunting", path: "/hunting", group: "Detection" },
  { icon: BookOpen, label: "Ruleset Explorer", path: "/rules", group: "Detection" },
  { icon: ShieldCheck, label: "Compliance", path: "/compliance", group: "Posture" },
  { icon: FileSearch, label: "File Integrity", path: "/fim", group: "Posture" },
  { icon: Monitor, label: "IT Hygiene", path: "/hygiene", group: "Posture" },
  { icon: Server, label: "Cluster Health", path: "/cluster", group: "System" },
  { icon: HeartPulse, label: "System Status", path: "/status", group: "System" },
  { icon: Brain, label: "Walter", path: "/analyst", group: "Intelligence" },
  { icon: Network, label: "Knowledge Graph", path: "/graph", group: "Intelligence" },
  { icon: FolderSearch, label: "Investigations", path: "/investigations", group: "Intelligence" },
  { icon: Database, label: "Data Pipeline", path: "/pipeline", group: "Intelligence" },
  { icon: UserCog, label: "User Management", path: "/admin/users", group: "Admin" },
  { icon: Settings, label: "Connection Settings", path: "/admin/settings", group: "Admin" },
  { icon: StickyNote, label: "Analyst Notes", path: "/notes", group: "Tools" },
  { icon: Bot, label: "AI Assistant", path: "/assistant", group: "Tools" },
];

const SIDEBAR_WIDTH_KEY = "sidebar-width";
const DEFAULT_WIDTH = 260;
const MIN_WIDTH = 200;
const MAX_WIDTH = 400;

/**
 * Unauthenticated landing — detects local vs OAuth mode and routes accordingly.
 */
function UnauthenticatedView() {
  const [, navigate] = useLocation();
  const authMode = trpc.localAuth.authMode.useQuery(undefined, {
    retry: false,
  });

  const isLocal = authMode.data?.mode === "local";

  const handleSignIn = () => {
    if (isLocal) {
      navigate("/login");
    } else {
      window.location.href = getLoginUrl();
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="glass-panel p-8 max-w-md w-full flex flex-col items-center gap-6">
        <div className="h-16 w-16 rounded-xl bg-primary/20 flex items-center justify-center amethyst-glow">
          <Shield className="h-8 w-8 text-primary" />
        </div>
        <h1 className="text-2xl font-display font-semibold tracking-tight text-center text-foreground">
          Dang! Security Platform
        </h1>
        <p className="text-sm text-muted-foreground text-center">
          Sign in to access the Wazuh security monitoring dashboard.
        </p>
        <Button
          onClick={handleSignIn}
          size="lg"
          className="w-full bg-primary hover:bg-primary/90 text-primary-foreground shadow-lg"
        >
          Sign in
        </Button>
        {isLocal && authMode.data?.isFirstUser && (
          <p className="text-xs text-muted-foreground text-center">
            No accounts yet?{" "}
            <button
              onClick={() => navigate("/register")}
              className="text-primary hover:underline"
            >
              Create the first admin account
            </button>
          </p>
        )}
      </div>
    </div>
  );
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    const saved = localStorage.getItem(SIDEBAR_WIDTH_KEY);
    return saved ? parseInt(saved, 10) : DEFAULT_WIDTH;
  });
  const { loading, user } = useAuth();

  useEffect(() => {
    localStorage.setItem(SIDEBAR_WIDTH_KEY, sidebarWidth.toString());
  }, [sidebarWidth]);

  if (loading) {
    return <DashboardLayoutSkeleton />;
  }

  if (!user) {
    return <UnauthenticatedView />;
  }

  return (
    <SidebarProvider
      style={
        {
          "--sidebar-width": `${sidebarWidth}px`,
        } as CSSProperties
      }
    >
      <DashboardLayoutContent setSidebarWidth={setSidebarWidth}>
        {children}
      </DashboardLayoutContent>
    </SidebarProvider>
  );
}

type DashboardLayoutContentProps = {
  children: React.ReactNode;
  setSidebarWidth: (width: number) => void;
};

function DashboardLayoutContent({
  children,
  setSidebarWidth,
}: DashboardLayoutContentProps) {
  const { user, logout } = useAuth();
  const [location, setLocation] = useLocation();
  const { state, toggleSidebar } = useSidebar();
  const isCollapsed = state === "collapsed";
  const [isResizing, setIsResizing] = useState(false);
  const sidebarRef = useRef<HTMLDivElement>(null);
  const activeMenuItem = menuItems.find((item) => item.path === location);
  const isMobile = useIsMobile();

  useEffect(() => {
    if (isCollapsed) setIsResizing(false);
  }, [isCollapsed]);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing) return;
      const sidebarLeft =
        sidebarRef.current?.getBoundingClientRect().left ?? 0;
      const newWidth = e.clientX - sidebarLeft;
      if (newWidth >= MIN_WIDTH && newWidth <= MAX_WIDTH) {
        setSidebarWidth(newWidth);
      }
    };
    const handleMouseUp = () => setIsResizing(false);

    if (isResizing) {
      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
    }
    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [isResizing, setSidebarWidth]);

  return (
    <>
      <div className="relative" ref={sidebarRef}>
        <Sidebar
          collapsible="icon"
          className="border-r-0"
          disableTransition={isResizing}
        >
          {/* ── Header with logo ────────────────────────────── */}
          <SidebarHeader className="h-16 justify-center border-b border-sidebar-border/50">
            <div className="flex items-center gap-3 px-2 transition-all w-full">
              <button
                onClick={toggleSidebar}
                className="h-8 w-8 flex items-center justify-center hover:bg-sidebar-accent rounded-lg transition-colors focus:outline-none shrink-0"
                aria-label="Toggle navigation"
              >
                <PanelLeft className="h-4 w-4 text-muted-foreground" />
              </button>
              {!isCollapsed && (
                <div className="flex items-center gap-2 min-w-0 flex-1">
                  <span className="font-display font-bold text-lg tracking-tight text-primary truncate">
                    Dang!
                  </span>
                  <span className="text-xs text-muted-foreground font-mono">
                    SIEM
                  </span>
                </div>
              )}
              <div className="shrink-0">
                <AlertNotificationBell collapsed={isCollapsed} />
              </div>
            </div>
          </SidebarHeader>

          {/* ── Navigation ──────────────────────────────────── */}
          <SidebarContent className="gap-0 pt-2">
            <SidebarMenu className="px-2 py-1 space-y-0.5">
              {(() => {
                let lastGroup = "";
                return menuItems.map((item) => {
                  const isActive = location === item.path;
                  const showGroup = item.group !== lastGroup;
                  if (showGroup) lastGroup = item.group;
                  return (
                    <div key={item.path}>
                      {showGroup && !isCollapsed && (
                        <p className="text-[10px] uppercase tracking-widest text-muted-foreground/60 px-3 pt-4 pb-1 font-medium">{item.group}</p>
                      )}
                      <SidebarMenuItem>
                        <SidebarMenuButton
                          isActive={isActive}
                          onClick={() => setLocation(item.path)}
                          tooltip={item.label}
                          className={`h-10 transition-all font-normal ${
                            isActive
                              ? "bg-primary/15 text-foreground border-l-2 border-primary"
                              : "text-sidebar-foreground hover:bg-sidebar-accent"
                          }`}
                        >
                          <item.icon
                            className={`h-4 w-4 ${
                              isActive ? "text-primary" : "text-muted-foreground"
                            }`}
                          />
                          <span className="text-sm">{item.label}</span>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    </div>
                  );
                });
              })()}
            
            </SidebarMenu>
          </SidebarContent>

          {/* ── Footer with user ────────────────────────────── */}
          <SidebarFooter className="p-3 border-t border-sidebar-border/50">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="flex items-center gap-3 rounded-lg px-1 py-1 hover:bg-sidebar-accent transition-colors w-full text-left group-data-[collapsible=icon]:justify-center focus:outline-none">
                  <Avatar className="h-9 w-9 border border-primary/30 shrink-0">
                    <AvatarFallback className="text-xs font-medium bg-primary/20 text-primary">
                      {user?.name?.charAt(0).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <div className="flex-1 min-w-0 group-data-[collapsible=icon]:hidden">
                    <p className="text-sm font-medium truncate leading-none text-foreground">
                      {user?.name || "Analyst"}
                    </p>
                    <p className="text-xs text-muted-foreground truncate mt-1">
                      {user?.email || "—"}
                    </p>
                  </div>
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="end"
                className="w-48 bg-popover border-border"
              >
                <DropdownMenuItem
                  onClick={logout}
                  className="cursor-pointer text-destructive focus:text-destructive"
                >
                  <LogOut className="mr-2 h-4 w-4" />
                  <span>Sign out</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </SidebarFooter>
        </Sidebar>

        {/* Resize handle */}
        <div
          className={`absolute top-0 right-0 w-1 h-full cursor-col-resize hover:bg-primary/20 transition-colors ${
            isCollapsed ? "hidden" : ""
          }`}
          onMouseDown={() => {
            if (isCollapsed) return;
            setIsResizing(true);
          }}
          style={{ zIndex: 50 }}
        />
      </div>

      <SidebarInset>
        {isMobile && (
          <div className="flex border-b border-border h-14 items-center justify-between bg-background/80 px-2 backdrop-blur sticky top-0 z-40">
            <div className="flex items-center gap-2">
              <SidebarTrigger className="h-9 w-9 rounded-lg" />
              <span className="font-display text-foreground tracking-tight">
                {activeMenuItem?.label ?? "Dang!"}
              </span>
            </div>
          </div>
        )}
        <main className="flex-1 p-4 lg:p-6">{children}</main>
      </SidebarInset>
    </>
  );
}
