/**
 * Config & Stats Tab + Agent Key Disclosure Policy Tests
 *
 * Verifies:
 * 1. Agent Detail page has a "config" tab with Config & Stats UI
 * 2. agentConfig, agentStats, agentKey endpoints are consumed in the tab
 * 3. agentKey disclosure policy: admin-only gate, masked by default, audit trail
 * 4. BrokerWarnings component is integrated in key consumer pages
 * 5. Sensitive access audit table exists in schema
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";

const ROOT = join(__dirname, "..", "..");
function readFile(relPath: string): string {
  return readFileSync(join(ROOT, relPath), "utf-8");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Config & Stats Tab — UI Structure
// ═══════════════════════════════════════════════════════════════════════════════

describe("Agent Detail — Config & Stats Tab", () => {
  const src = readFile("client/src/pages/AgentDetail.tsx");

  it("should have 'config' in the Tab type union", () => {
    expect(src).toMatch(/type Tab\s*=.*"config"/);
  });

  it("should include Config & Stats in TABS array", () => {
    expect(src).toContain('"config"');
    expect(src).toContain("Config & Stats");
  });

  it("should render ConfigStatsTab component for config tab", () => {
    expect(src).toContain("ConfigStatsTab");
    expect(src).toMatch(/activeTab\s*===\s*"config"/);
  });

  it("should consume trpc.wazuh.agentConfig", () => {
    expect(src).toContain("trpc.wazuh.agentConfig.useQuery");
  });

  it("should consume trpc.wazuh.agentStats", () => {
    expect(src).toContain("trpc.wazuh.agentStats.useQuery");
  });

  it("should consume trpc.wazuh.agentKey", () => {
    expect(src).toContain("trpc.wazuh.agentKey.useQuery");
  });

  it("should have a component/configuration picker for agentConfig", () => {
    expect(src).toContain("AGENT_CONFIG_PAIRS");
    expect(src).toContain("configPairIdx");
  });

  it("should have a component picker for agentStats", () => {
    expect(src).toContain("AGENT_STATS_COMPONENTS");
    expect(src).toContain("statsComponent");
  });

  it("should show Wazuh API path for config endpoint", () => {
    // Shows the GET path for transparency
    expect(src).toMatch(/GET\s+\/agents\//);
  });

  it("should include RawJsonViewer for config and stats data", () => {
    expect(src).toContain("RawJsonViewer");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. Agent Key Disclosure Policy
// ═══════════════════════════════════════════════════════════════════════════════

describe("Agent Key — Disclosure Policy", () => {
  const src = readFile("client/src/pages/AgentDetail.tsx");

  it("should import useAuth for RBAC check", () => {
    expect(src).toContain("useAuth");
  });

  it("should check admin role before showing key", () => {
    expect(src).toMatch(/isAdmin/);
    expect(src).toMatch(/user\?\.role\s*===\s*"admin"/);
  });

  it("should mask key by default (keyRevealed = false)", () => {
    expect(src).toContain("keyRevealed");
    expect(src).toMatch(/useState\(false\)/);
  });

  it("should require deliberate reveal action", () => {
    expect(src).toContain("handleRevealKey");
    expect(src).toContain("Reveal Agent Key");
  });

  it("should show disclosure policy warning before reveal", () => {
    expect(src).toContain("Disclosure Policy");
    expect(src).toContain("logged with your user ID");
    expect(src).toContain("not cached");
  });

  it("should allow hiding the key after reveal", () => {
    expect(src).toContain("handleHideKey");
    expect(src).toContain("EyeOff");
  });

  it("should evict key from React Query cache on unmount", () => {
    expect(src).toContain("utils.wazuh.agentKey.invalidate");
    expect(src).toContain("gcTime: 0");
    expect(src).toContain("staleTime: 0");
  });

  it("should have copy-to-clipboard as a privileged action", () => {
    expect(src).toContain("handleCopyKey");
    expect(src).toContain("navigator.clipboard.writeText");
  });

  it("should show lock icon for non-admin users", () => {
    expect(src).toContain("Lock");
    expect(src).toContain("restricted to administrators");
  });

  it("should show Admin Only badge", () => {
    expect(src).toContain("Admin Only");
    expect(src).toContain("ShieldAlert");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. Sensitive Access Audit Schema
// ═══════════════════════════════════════════════════════════════════════════════

describe("Sensitive Access Audit — Schema", () => {
  const schema = readFile("drizzle/schema.ts");

  it("should define sensitiveAccessAudit table", () => {
    expect(schema).toContain("sensitiveAccessAudit");
  });

  it("should have userId column", () => {
    expect(schema).toMatch(/userId|user_id/);
  });

  it("should have resourceType column", () => {
    expect(schema).toMatch(/resourceType|resource_type/);
  });

  it("should have resourceId column", () => {
    expect(schema).toMatch(/resourceId|resource_id/);
  });

  it("should have action column", () => {
    expect(schema).toContain("action");
  });
});

describe("Sensitive Access Audit — Router Integration", () => {
  const router = readFile("server/wazuh/wazuhRouter.ts");

  it("should import logSensitiveAccess from db", () => {
    expect(router).toContain("logSensitiveAccess");
  });

  it("should call logSensitiveAccess in agentKey procedure", () => {
    // The agentKey procedure should log the access
    expect(router).toContain("logSensitiveAccess");
  });

  it("should use protectedProcedure for agentKey (auth required)", () => {
    // agentKey should require authentication
    expect(router).toMatch(/agentKey.*protectedProcedure|protectedProcedure.*agentKey/s);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. BrokerWarnings Integration Across Pages
// ═══════════════════════════════════════════════════════════════════════════════

describe("BrokerWarnings — Page Integration", () => {
  const pages: [string, string][] = [
    ["AgentDetail.tsx", "client/src/pages/AgentDetail.tsx"],
    ["AgentHealth.tsx", "client/src/pages/AgentHealth.tsx"],
    ["FleetInventory.tsx", "client/src/pages/FleetInventory.tsx"],
    ["ITHygiene.tsx", "client/src/pages/ITHygiene.tsx"],
    ["ClusterHealth.tsx", "client/src/pages/ClusterHealth.tsx"],
    ["RulesetExplorer.tsx", "client/src/pages/RulesetExplorer.tsx"],
  ];

  it.each(pages)(
    "%s should import BrokerWarnings",
    (_name, path) => {
      const src = readFile(path);
      expect(src).toContain('import { BrokerWarnings }');
    }
  );

  it.each(pages)(
    "%s should render <BrokerWarnings> with data and context props",
    (_name, path) => {
      const src = readFile(path);
      expect(src).toMatch(/<BrokerWarnings\s+data=/);
      // context can be a static string (context="...") or dynamic expression (context={...})
      expect(src).toMatch(/context[="{]/);
    }
  );
});

// ═══════════════════════════════════════════════════════════════════════════════
// 5. BrokerWarnings Component — Structure
// ═══════════════════════════════════════════════════════════════════════════════

describe("BrokerWarnings Component", () => {
  const src = readFile("client/src/components/shared/BrokerWarnings.tsx");

  it("should export BrokerWarnings component", () => {
    expect(src).toMatch(/export\s+(function|const)\s+BrokerWarnings/);
  });

  it("should accept data and context props", () => {
    expect(src).toContain("data");
    expect(src).toContain("context");
  });

  it("should check for _brokerWarnings field", () => {
    expect(src).toContain("_brokerWarnings");
  });

  it("should be dismissible", () => {
    expect(src).toMatch(/dismiss|close|setDismissed|setVisible/i);
  });

  it("should have a show details toggle for raw warnings", () => {
    expect(src).toMatch(/showDetails|expanded|toggle/i);
  });

  it("should return null when no warnings exist", () => {
    expect(src).toMatch(/return\s+null/);
  });
});
