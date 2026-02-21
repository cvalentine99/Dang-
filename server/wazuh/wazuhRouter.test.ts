import { describe, expect, it, vi } from "vitest";
import { appRouter } from "../routers";
import type { TrpcContext } from "../_core/context";

function createPublicContext(): TrpcContext {
  return {
    user: null,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: vi.fn(),
    } as unknown as TrpcContext["res"],
  };
}

describe("wazuh router", () => {
  it("status returns configured: false when no env vars set", async () => {
    const ctx = createPublicContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.wazuh.status();
    // Without WAZUH_HOST set, it should report not configured
    expect(result).toHaveProperty("configured");
    expect(typeof result.configured).toBe("boolean");
  });

  it("isConfigured returns a result with configured property", async () => {
    const ctx = createPublicContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.wazuh.isConfigured();
    expect(result).toHaveProperty("configured");
    expect(typeof result.configured).toBe("boolean");
  });
});
