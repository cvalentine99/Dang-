import { describe, expect, it, vi, beforeEach } from "vitest";
import { appRouter } from "../routers";
import type { TrpcContext } from "../_core/context";

// Mock the wazuh client module
vi.mock("./wazuhClient", () => ({
  isWazuhConfigured: vi.fn(() => false),
  getWazuhConfig: vi.fn(() => ({
    host: "https://wazuh.example.com",
    port: 55000,
    user: "wazuh-wui",
    pass: "test-pass",
  })),
  wazuhGet: vi.fn(async (_config: unknown, opts: { path: string }) => {
    // Return different data based on the syscollector path
    if (opts.path.includes("/packages")) {
      return {
        data: {
          affected_items: [
            { name: "openssl", version: "3.0.2", architecture: "amd64" },
            { name: "nginx", version: "1.24.0", architecture: "amd64" },
          ],
          total_affected_items: 2,
        },
      };
    }
    if (opts.path.includes("/services")) {
      return {
        data: {
          affected_items: [
            { name: "sshd", state: "running" },
            { name: "nginx", state: "running" },
          ],
          total_affected_items: 2,
        },
      };
    }
    if (opts.path.includes("/users")) {
      return {
        data: {
          affected_items: [
            { name: "root", shell: "/bin/bash" },
            { name: "www-data", shell: "/usr/sbin/nologin" },
          ],
          total_affected_items: 2,
        },
      };
    }
    return { data: { affected_items: [], total_affected_items: 0 } };
  }),
  getEffectiveWazuhConfig: vi.fn(async () => ({
    host: "https://wazuh.example.com",
    port: 55000,
    user: "wazuh-wui",
    pass: "test-pass",
  })),
  isWazuhEffectivelyConfigured: vi.fn(async () => true),
}));

// Mock the connectionSettingsService to prevent DB access
vi.mock("../admin/connectionSettingsService", () => ({
  getEffectiveWazuhConfig: vi.fn(async () => ({
    host: "https://wazuh.example.com",
    port: 55000,
    user: "wazuh-wui",
    pass: "test-pass",
  })),
  getEffectiveIndexerConfig: vi.fn(async () => null),
  isWazuhEffectivelyConfigured: vi.fn(async () => true),
  isIndexerEffectivelyConfigured: vi.fn(async () => false),
}));

function createTestContext(): TrpcContext {
  return {
    user: {
      id: 1,
      openId: "test-user",
      email: "test@example.com",
      name: "Test User",
      loginMethod: "manus",
      role: "admin",
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    },
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: vi.fn() } as unknown as TrpcContext["res"],
  };
}

describe("multiAgentSyscollector endpoint", () => {
  let caller: ReturnType<typeof appRouter.createCaller>;

  beforeEach(() => {
    caller = appRouter.createCaller(createTestContext());
  });

  it("returns data for multiple agents with all types", async () => {
    const result = await caller.wazuh.multiAgentSyscollector({
      agentIds: ["001", "002"],
      types: ["packages", "services", "users"],
    });

    expect(result).toBeDefined();
    expect(result).toHaveProperty("001");
    expect(result).toHaveProperty("002");

    // Each agent should have packages, services, and users
    expect(result["001"]).toHaveProperty("packages");
    expect(result["001"]).toHaveProperty("services");
    expect(result["001"]).toHaveProperty("users");
    expect(result["002"]).toHaveProperty("packages");
    expect(result["002"]).toHaveProperty("services");
    expect(result["002"]).toHaveProperty("users");
  });

  it("returns only requested types", async () => {
    const result = await caller.wazuh.multiAgentSyscollector({
      agentIds: ["001"],
      types: ["packages"],
    });

    expect(result).toBeDefined();
    expect(result["001"]).toHaveProperty("packages");
    // services and users should not be present since we only requested packages
    expect(result["001"].services).toBeUndefined();
    expect(result["001"].users).toBeUndefined();
  });

  it("returns packages with correct shape", async () => {
    const result = await caller.wazuh.multiAgentSyscollector({
      agentIds: ["001"],
      types: ["packages"],
    });

    const pkgs = result["001"].packages!;
    expect(Array.isArray(pkgs)).toBe(true);
    expect(pkgs.length).toBeGreaterThan(0);
    expect(pkgs[0]).toHaveProperty("name");
    expect(pkgs[0]).toHaveProperty("version");
  });

  it("returns services with correct shape", async () => {
    const result = await caller.wazuh.multiAgentSyscollector({
      agentIds: ["001"],
      types: ["services"],
    });

    const svcs = result["001"].services!;
    expect(Array.isArray(svcs)).toBe(true);
    expect(svcs.length).toBeGreaterThan(0);
    expect(svcs[0]).toHaveProperty("name");
    expect(svcs[0]).toHaveProperty("state");
  });

  it("returns users with correct shape", async () => {
    const result = await caller.wazuh.multiAgentSyscollector({
      agentIds: ["001"],
      types: ["users"],
    });

    const users = result["001"].users!;
    expect(Array.isArray(users)).toBe(true);
    expect(users.length).toBeGreaterThan(0);
    expect(users[0]).toHaveProperty("name");
    expect(users[0]).toHaveProperty("shell");
  });

  it("rejects invalid agent IDs", async () => {
    await expect(
      caller.wazuh.multiAgentSyscollector({
        agentIds: ["abc"],
        types: ["packages"],
      })
    ).rejects.toThrow();
  });

  it("rejects empty agent IDs array", async () => {
    await expect(
      caller.wazuh.multiAgentSyscollector({
        agentIds: [],
        types: ["packages"],
      })
    ).rejects.toThrow();
  });

  it("defaults to all types when types not specified", async () => {
    const result = await caller.wazuh.multiAgentSyscollector({
      agentIds: ["001"],
    });

    expect(result["001"]).toHaveProperty("packages");
    expect(result["001"]).toHaveProperty("services");
    expect(result["001"]).toHaveProperty("users");
  });
});
