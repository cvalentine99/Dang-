/**
 * Connection Settings — Admin page for managing Wazuh Manager and Indexer connections.
 * Allows admins to update credentials from the UI without restarting Docker.
 * Shows current source (database override vs environment variable vs default).
 */

import { useState, useEffect } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import {
  Server,
  Database,
  TestTube,
  Save,
  RotateCcw,
  Eye,
  EyeOff,
  CheckCircle2,
  XCircle,
  Loader2,
  Info,
  Shield,
  Users,
  FileKey,
  Lock,
} from "lucide-react";

type Category = "wazuh_manager" | "wazuh_indexer";

interface ConnectionPanelProps {
  category: Category;
  title: string;
  description: string;
  icon: React.ReactNode;
  fields: Array<{
    key: string;
    label: string;
    placeholder: string;
    type?: "text" | "password" | "number";
  }>;
}

function SourceBadge({ source }: { source?: "database" | "env" | "default" }) {
  if (!source) return null;
  const styles = {
    database: "bg-primary/20 text-primary border-primary/30",
    env: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    default: "bg-muted text-muted-foreground border-border",
  };
  const labels = {
    database: "DB Override",
    env: "Env Var",
    default: "Default",
  };
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${styles[source]}`}>
      {labels[source]}
    </span>
  );
}

function ConnectionPanel({ category, title, description, icon, fields }: ConnectionPanelProps) {
  // Using sonner toast
  const [formValues, setFormValues] = useState<Record<string, string>>({});
  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({});
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
    latencyMs: number;
  } | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  const settingsQuery = trpc.connectionSettings.getSettings.useQuery(
    { category },
    { staleTime: 30_000 }
  );

  const updateMutation = trpc.connectionSettings.updateSettings.useMutation({
    onSuccess: () => {
      toast.success(`${title} connection settings updated.`);
      settingsQuery.refetch();
      setTestResult(null);
    },
    onError: (err) => {
      toast.error(`Save failed: ${err.message}`);
    },
  });

  const testMutation = trpc.connectionSettings.testConnection.useMutation({
    onSuccess: (result) => {
      setTestResult(result);
      setIsTesting(false);
    },
    onError: (err) => {
      setTestResult({ success: false, message: err.message, latencyMs: 0 });
      setIsTesting(false);
    },
  });

  const resetMutation = trpc.connectionSettings.resetSettings.useMutation({
    onSuccess: () => {
      toast.success(`${title} settings reverted to environment variables.`);
      settingsQuery.refetch();
      setFormValues({});
      setTestResult(null);
    },
    onError: (err) => {
      toast.error(`Reset failed: ${err.message}`);
    },
  });

  // Initialize form values from query data
  useEffect(() => {
    if (settingsQuery.data) {
      const initial: Record<string, string> = {};
      for (const field of fields) {
        initial[field.key] = settingsQuery.data.values[field.key] ?? "";
      }
      setFormValues(initial);
    }
  }, [settingsQuery.data, fields]);

  const handleSave = () => {
    // Only send non-empty values; skip empty password fields (keep existing)
    const toSave: Record<string, string> = {};
    for (const field of fields) {
      const val = formValues[field.key];
      if (field.type === "password" && (!val || val === "")) continue; // Don't overwrite with empty
      if (val !== undefined && val !== "") toSave[field.key] = val;
    }
    updateMutation.mutate({ category, settings: toSave });
  };

  const handleTest = () => {
    setIsTesting(true);
    setTestResult(null);
    // Use current form values for testing
    const testSettings: Record<string, string> = {};
    for (const field of fields) {
      testSettings[field.key] = formValues[field.key] ?? "";
    }
    testMutation.mutate({ category, settings: testSettings });
  };

  const handleReset = () => {
    if (confirm(`Reset ${title} settings to environment variables? This will remove all database overrides.`)) {
      resetMutation.mutate({ category });
    }
  };

  const hasDbOverrides = settingsQuery.data
    ? Object.values(settingsQuery.data.sources).some((s) => s === "database")
    : false;

  return (
    <div className="glass-panel p-6 space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-lg bg-primary/15 flex items-center justify-center">
            {icon}
          </div>
          <div>
            <h3 className="font-display text-lg font-semibold text-foreground">{title}</h3>
            <p className="text-xs text-muted-foreground mt-0.5">{description}</p>
          </div>
        </div>
        {hasDbOverrides && (
          <Button
            variant="outline"
            size="sm"
            onClick={handleReset}
            disabled={resetMutation.isPending}
            className="text-xs border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
          >
            <RotateCcw className="h-3 w-3 mr-1" />
            Reset to Env
          </Button>
        )}
      </div>

      {/* Fields */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {fields.map((field) => (
          <div key={field.key} className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                {field.label}
              </label>
              <SourceBadge source={settingsQuery.data?.sources[field.key]} />
            </div>
            <div className="relative">
              <Input
                type={
                  field.type === "password" && !showPasswords[field.key]
                    ? "password"
                    : "text"
                }
                placeholder={
                  field.type === "password" && settingsQuery.data?.hasPassword?.[field.key]
                    ? "••••••••  (unchanged)"
                    : field.placeholder
                }
                value={formValues[field.key] ?? ""}
                onChange={(e) =>
                  setFormValues((prev) => ({ ...prev, [field.key]: e.target.value }))
                }
                className="bg-background/50 border-border/50 font-mono text-sm h-9 pr-9"
              />
              {field.type === "password" && (
                <button
                  type="button"
                  onClick={() =>
                    setShowPasswords((prev) => ({
                      ...prev,
                      [field.key]: !prev[field.key],
                    }))
                  }
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                >
                  {showPasswords[field.key] ? (
                    <EyeOff className="h-3.5 w-3.5" />
                  ) : (
                    <Eye className="h-3.5 w-3.5" />
                  )}
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Test Result */}
      {testResult && (
        <div
          className={`flex items-center gap-2 p-3 rounded-lg border text-sm font-mono ${
            testResult.success
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
              : "bg-red-500/10 border-red-500/30 text-red-400"
          }`}
        >
          {testResult.success ? (
            <CheckCircle2 className="h-4 w-4 shrink-0" />
          ) : (
            <XCircle className="h-4 w-4 shrink-0" />
          )}
          <span className="flex-1">{testResult.message}</span>
          {testResult.latencyMs > 0 && (
            <span className="text-xs opacity-70">{testResult.latencyMs}ms</span>
          )}
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-3 pt-2 border-t border-border/30">
        <Button
          onClick={handleTest}
          disabled={isTesting}
          variant="outline"
          size="sm"
          className="border-primary/30 text-primary hover:bg-primary/10"
        >
          {isTesting ? (
            <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
          ) : (
            <TestTube className="h-3.5 w-3.5 mr-1.5" />
          )}
          Test Connection
        </Button>
        <Button
          onClick={handleSave}
          disabled={updateMutation.isPending}
          size="sm"
          className="bg-primary hover:bg-primary/90 text-primary-foreground"
        >
          {updateMutation.isPending ? (
            <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
          ) : (
            <Save className="h-3.5 w-3.5 mr-1.5" />
          )}
          Save Settings
        </Button>
      </div>
    </div>
  );
}

function WazuhRbacPanel() {
  const statusQ = trpc.wazuh.status.useQuery(undefined, { retry: 1, staleTime: 30_000 });
  const isConnected = statusQ.data?.configured === true && statusQ.data?.data != null;

  const secRolesQ = trpc.wazuh.securityRoles.useQuery(undefined, { retry: 1, staleTime: 60_000, enabled: isConnected });
  const secPoliciesQ = trpc.wazuh.securityPolicies.useQuery(undefined, { retry: 1, staleTime: 60_000, enabled: isConnected });
  const secUsersQ = trpc.wazuh.securityUsers.useQuery(undefined, { retry: 1, staleTime: 60_000, enabled: isConnected });

  const rolesData = (secRolesQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const roles = ((rolesData?.affected_items ?? []) as Record<string, unknown>[]);

  const policiesData = (secPoliciesQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const policies = ((policiesData?.affected_items ?? []) as Record<string, unknown>[]);

  const usersData = (secUsersQ.data as Record<string, unknown>)?.data as Record<string, unknown> | undefined;
  const users = ((usersData?.affected_items ?? []) as Record<string, unknown>[]);

  const isLoading = secRolesQ.isLoading || secPoliciesQ.isLoading || secUsersQ.isLoading;

  return (
    <div className="glass-panel p-6 space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-lg bg-primary/15 flex items-center justify-center">
            <Lock className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h3 className="font-display text-lg font-semibold text-foreground">Wazuh Manager RBAC</h3>
            <p className="text-xs text-muted-foreground mt-0.5">Read-only view of roles, policies, and users configured on the Wazuh Manager</p>
          </div>
        </div>
        {isConnected && (
          <span className="text-[10px] px-1.5 py-0.5 rounded border font-mono bg-primary/20 text-primary border-primary/30">
            Live
          </span>
        )}
      </div>

      {!isConnected ? (
        <div className="flex items-center gap-3 p-4 rounded-lg border border-border/40 bg-secondary/20">
          <XCircle className="h-4 w-4 text-muted-foreground shrink-0" />
          <div className="text-xs text-muted-foreground">
            <p className="font-medium text-foreground">Not connected</p>
            <p className="mt-0.5">Connect to the Wazuh Manager above to view RBAC configuration.</p>
          </div>
        </div>
      ) : isLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-5 w-5 animate-spin text-primary" />
          <span className="ml-2 text-sm text-muted-foreground">Loading RBAC data...</span>
        </div>
      ) : (
        <div className="space-y-5">
          {/* Roles Table */}
          <div>
            <h4 className="text-sm font-medium text-foreground mb-2 flex items-center gap-2">
              <Shield className="h-3.5 w-3.5 text-[oklch(0.72_0.19_295)]" />
              Roles
              <span className="text-[10px] font-mono text-muted-foreground ml-auto">{roles.length} total</span>
            </h4>
            {roles.length === 0 ? (
              <p className="text-xs text-muted-foreground py-2">No roles found</p>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-border/30">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border/30 bg-secondary/20">
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">Role ID</th>
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">Name</th>
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">Rules</th>
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {roles.map((role, idx) => (
                      <tr key={idx} className="border-b border-border/20 hover:bg-secondary/20 transition-colors">
                        <td className="px-3 py-2 font-mono text-primary">{String(role.id ?? "")}</td>
                        <td className="px-3 py-2 text-foreground">{String(role.name ?? "")}</td>
                        <td className="px-3 py-2 text-muted-foreground">{Array.isArray(role.rules) ? role.rules.length : 0}</td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {role.created_at ? new Date(String(role.created_at)).toLocaleDateString() : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Policies Table */}
          <div>
            <h4 className="text-sm font-medium text-foreground mb-2 flex items-center gap-2">
              <FileKey className="h-3.5 w-3.5 text-[oklch(0.795_0.184_86.047)]" />
              Policies
              <span className="text-[10px] font-mono text-muted-foreground ml-auto">{policies.length} total</span>
            </h4>
            {policies.length === 0 ? (
              <p className="text-xs text-muted-foreground py-2">No policies found</p>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-border/30">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border/30 bg-secondary/20">
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">Policy ID</th>
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">Name</th>
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">Actions</th>
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">Resources</th>
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">Effect</th>
                    </tr>
                  </thead>
                  <tbody>
                    {policies.map((policy, idx) => {
                      const policyObj = policy.policy as Record<string, unknown> | undefined;
                      const actions = (policyObj?.actions ?? []) as string[];
                      const resources = (policyObj?.resources ?? []) as string[];
                      const effect = String(policyObj?.effect ?? "—");
                      return (
                        <tr key={idx} className="border-b border-border/20 hover:bg-secondary/20 transition-colors">
                          <td className="px-3 py-2 font-mono text-primary">{String(policy.id ?? "")}</td>
                          <td className="px-3 py-2 text-foreground">{String(policy.name ?? "")}</td>
                          <td className="px-3 py-2 text-muted-foreground">
                            <div className="flex flex-wrap gap-1">
                              {actions.slice(0, 3).map((a, i) => (
                                <span key={i} className="px-1.5 py-0.5 rounded bg-[oklch(0.789_0.154_211.53)]/10 border border-[oklch(0.789_0.154_211.53)]/20 text-[oklch(0.789_0.154_211.53)] text-[10px] font-mono">
                                  {String(a)}
                                </span>
                              ))}
                              {actions.length > 3 && (
                                <span className="text-[10px] text-muted-foreground">+{actions.length - 3}</span>
                              )}
                            </div>
                          </td>
                          <td className="px-3 py-2 text-muted-foreground">
                            <div className="flex flex-wrap gap-1">
                              {resources.slice(0, 2).map((r, i) => (
                                <span key={i} className="px-1.5 py-0.5 rounded bg-secondary/50 border border-border text-[10px] font-mono text-muted-foreground max-w-[150px] truncate">
                                  {String(r)}
                                </span>
                              ))}
                              {resources.length > 2 && (
                                <span className="text-[10px] text-muted-foreground">+{resources.length - 2}</span>
                              )}
                            </div>
                          </td>
                          <td className="px-3 py-2">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                              effect === "allow"
                                ? "bg-[oklch(0.765_0.177_163.223)]/20 text-[oklch(0.765_0.177_163.223)]"
                                : effect === "deny"
                                ? "bg-[oklch(0.705_0.191_22.216)]/20 text-[oklch(0.705_0.191_22.216)]"
                                : "bg-secondary/50 text-muted-foreground"
                            }`}>
                              {effect}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Users Table */}
          <div>
            <h4 className="text-sm font-medium text-foreground mb-2 flex items-center gap-2">
              <Users className="h-3.5 w-3.5 text-[oklch(0.765_0.177_163.223)]" />
              Users
              <span className="text-[10px] font-mono text-muted-foreground ml-auto">{users.length} total</span>
            </h4>
            {users.length === 0 ? (
              <p className="text-xs text-muted-foreground py-2">No users found</p>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-border/30">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border/30 bg-secondary/20">
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">User ID</th>
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">Username</th>
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">Roles</th>
                      <th className="px-3 py-2 text-left text-muted-foreground font-medium">Allow run_as</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((user, idx) => {
                      const userRoles = (user.roles ?? []) as Record<string, unknown>[];
                      return (
                        <tr key={idx} className="border-b border-border/20 hover:bg-secondary/20 transition-colors">
                          <td className="px-3 py-2 font-mono text-primary">{String(user.id ?? "")}</td>
                          <td className="px-3 py-2 text-foreground font-medium">{String(user.username ?? "")}</td>
                          <td className="px-3 py-2">
                            <div className="flex flex-wrap gap-1">
                              {userRoles.map((r, i) => (
                                <span key={i} className="px-1.5 py-0.5 rounded bg-[oklch(0.72_0.19_295)]/10 border border-[oklch(0.72_0.19_295)]/20 text-[oklch(0.72_0.19_295)] text-[10px] font-mono">
                                  {String(r.name ?? r.id ?? `role-${i}`)}
                                </span>
                              ))}
                              {userRoles.length === 0 && (
                                <span className="text-[10px] text-muted-foreground">No roles</span>
                              )}
                            </div>
                          </td>
                          <td className="px-3 py-2">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                              user.allow_run_as
                                ? "bg-[oklch(0.765_0.177_163.223)]/20 text-[oklch(0.765_0.177_163.223)]"
                                : "bg-secondary/50 text-muted-foreground"
                            }`}>
                              {user.allow_run_as ? "Yes" : "No"}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function AdminSettings() {
  return (
    <div className="space-y-6 max-w-5xl">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-display font-bold tracking-tight text-foreground">
          Connection Settings
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Configure Wazuh Manager and Indexer connections. Settings saved here override environment variables without requiring a Docker restart.
        </p>
      </div>

      {/* Info Banner */}
      <div className="flex items-start gap-3 p-4 rounded-lg border border-primary/20 bg-primary/5">
        <Info className="h-4 w-4 text-primary mt-0.5 shrink-0" />
        <div className="text-xs text-muted-foreground space-y-1">
          <p>
            <strong className="text-foreground">Priority order:</strong> Database overrides take precedence over environment variables, which take precedence over defaults.
          </p>
          <p>
            Passwords are <strong className="text-foreground">AES-256 encrypted</strong> at rest. Use <strong className="text-foreground">Test Connection</strong> to validate credentials before saving.
          </p>
        </div>
      </div>

      {/* Wazuh Manager */}
      <ConnectionPanel
        category="wazuh_manager"
        title="Wazuh Manager"
        description="REST API connection for agent management, alerts, and system data"
        icon={<Shield className="h-5 w-5 text-primary" />}
        fields={[
          { key: "host", label: "Host", placeholder: "192.168.1.100" },
          { key: "port", label: "Port", placeholder: "55000", type: "number" },
          { key: "user", label: "Username", placeholder: "wazuh-wui" },
          { key: "pass", label: "Password", placeholder: "Enter password", type: "password" },
        ]}
      />

      {/* Wazuh Indexer */}
      <ConnectionPanel
        category="wazuh_indexer"
        title="Wazuh Indexer"
        description="OpenSearch/Elasticsearch connection for alert search, aggregations, and analytics"
        icon={<Database className="h-5 w-5 text-primary" />}
        fields={[
          { key: "host", label: "Host", placeholder: "192.168.1.100" },
          { key: "port", label: "Port", placeholder: "9200", type: "number" },
          { key: "user", label: "Username", placeholder: "admin" },
          { key: "pass", label: "Password", placeholder: "Enter password", type: "password" },
          { key: "protocol", label: "Protocol", placeholder: "https" },
        ]}
      />

      {/* Wazuh RBAC (Read-Only) */}
      <WazuhRbacPanel />
    </div>
  );
}
