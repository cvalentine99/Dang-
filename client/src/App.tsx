import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import DashboardLayout from "./components/DashboardLayout";
import { ThemeProvider } from "./contexts/ThemeContext";
import Home from "./pages/Home";
import AgentHealth from "./pages/AgentHealth";
import AlertsTimeline from "./pages/AlertsTimeline";
import Vulnerabilities from "./pages/Vulnerabilities";
import MitreAttack from "./pages/MitreAttack";
import Compliance from "./pages/Compliance";
import FileIntegrity from "./pages/FileIntegrity";
import AnalystNotes from "./pages/AnalystNotes";
import Assistant from "./pages/Assistant";
import ITHygiene from "./pages/ITHygiene";
import ClusterHealth from "./pages/ClusterHealth";
import ThreatHunting from "./pages/ThreatHunting";
import SiemEvents from "./pages/SiemEvents";
import RulesetExplorer from "./pages/RulesetExplorer";
import ThreatIntel from "./pages/ThreatIntel";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Status from "./pages/Status";

function Router() {
  return (
    <Switch>
      {/* Auth routes — outside DashboardLayout */}
      <Route path="/login" component={Login} />
      <Route path="/register" component={Register} />

      {/* Dashboard routes — inside DashboardLayout */}
      <Route>
        <DashboardLayout>
          <Switch>
            <Route path="/" component={Home} />
            <Route path="/agents" component={AgentHealth} />
            <Route path="/alerts" component={AlertsTimeline} />
            <Route path="/vulnerabilities" component={Vulnerabilities} />
            <Route path="/mitre" component={MitreAttack} />
            <Route path="/compliance" component={Compliance} />
            <Route path="/fim" component={FileIntegrity} />
            <Route path="/hygiene" component={ITHygiene} />
            <Route path="/cluster" component={ClusterHealth} />
            <Route path="/siem" component={SiemEvents} />
            <Route path="/hunting" component={ThreatHunting} />
            <Route path="/rules" component={RulesetExplorer} />
            <Route path="/threat-intel" component={ThreatIntel} />
            <Route path="/notes" component={AnalystNotes} />
            <Route path="/assistant" component={Assistant} />
            <Route path="/status" component={Status} />
            <Route path="/404" component={NotFound} />
            <Route component={NotFound} />
          </Switch>
        </DashboardLayout>
      </Route>
    </Switch>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="dark">
        <TooltipProvider>
          <Toaster
            toastOptions={{
              style: {
                background: "oklch(0.17 0.025 286)",
                border: "1px solid oklch(0.3 0.04 286 / 40%)",
                color: "oklch(0.93 0.005 286)",
              },
            }}
          />
          <Router />
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
