import { describe, expect, it } from "vitest";
import { appRouter } from "../routers";
import type { TrpcContext } from "../_core/context";

// ── Helpers ─────────────────────────────────────────────────────────────────

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAdminContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "admin-user",
    email: "admin@example.com",
    name: "Admin User",
    loginMethod: "local",
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };

  return {
    user,
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: () => {} } as unknown as TrpcContext["res"],
  };
}

function createUserContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 2,
    openId: "analyst-user",
    email: "analyst@example.com",
    name: "Analyst User",
    loginMethod: "local",
    role: "user",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };

  return {
    user,
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: () => {} } as unknown as TrpcContext["res"],
  };
}

function createUnauthContext(): TrpcContext {
  return {
    user: null,
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: () => {} } as unknown as TrpcContext["res"],
  };
}

// ── Tests ───────────────────────────────────────────────────────────────────

describe("graph.graphStats", () => {
  it("returns entity counts for authenticated users", async () => {
    const caller = appRouter.createCaller(createUserContext());
    const stats = await caller.graph.graphStats();
    expect(stats).toBeDefined();
    expect(typeof stats).toBe("object");
    // Should have numeric counts for entity types
    if (stats.endpoints !== undefined) {
      expect(typeof stats.endpoints).toBe("number");
    }
  });

  it("rejects unauthenticated requests", async () => {
    const caller = appRouter.createCaller(createUnauthContext());
    await expect(caller.graph.graphStats()).rejects.toThrow();
  });
});

describe("graph.etlStatus", () => {
  it("returns sync status array for authenticated users", async () => {
    const caller = appRouter.createCaller(createUserContext());
    const status = await caller.graph.etlStatus();
    expect(Array.isArray(status)).toBe(true);
  });

  it("rejects unauthenticated requests", async () => {
    const caller = appRouter.createCaller(createUnauthContext());
    await expect(caller.graph.etlStatus()).rejects.toThrow();
  });
});

describe("graph.overviewGraph", () => {
  it("returns nodes and edges arrays", async () => {
    const caller = appRouter.createCaller(createUserContext());
    const result = await caller.graph.overviewGraph({ limit: 10 });
    expect(result).toHaveProperty("nodes");
    expect(result).toHaveProperty("edges");
    expect(Array.isArray(result.nodes)).toBe(true);
    expect(Array.isArray(result.edges)).toBe(true);
  });

  it("respects the limit parameter", async () => {
    const caller = appRouter.createCaller(createUserContext());
    const result = await caller.graph.overviewGraph({ limit: 5 });
    // Limit controls the number of endpoints fetched; each endpoint may add
    // summary nodes (processes, vulns, events), so total nodes can exceed limit.
    // Verify that the number of endpoint-type nodes respects the limit.
    const endpointNodes = result.nodes.filter((n: { type: string }) => n.type === "endpoint");
    expect(endpointNodes.length).toBeLessThanOrEqual(5);
  });
});

describe("graph.searchGraph", () => {
  it("returns an array for a search query", async () => {
    const caller = appRouter.createCaller(createUserContext());
    const result = await caller.graph.searchGraph({ query: "test", limit: 10 });
    expect(Array.isArray(result)).toBe(true);
  });

  it("rejects empty queries", async () => {
    const caller = appRouter.createCaller(createUserContext());
    await expect(caller.graph.searchGraph({ query: "", limit: 10 })).rejects.toThrow();
  });
});

describe("graph.mitreDistribution", () => {
  it("returns an array of tactic distributions", async () => {
    const caller = appRouter.createCaller(createUserContext());
    const result = await caller.graph.mitreDistribution();
    expect(Array.isArray(result)).toBe(true);
  });
});

describe("graph.vulnSeverityDistribution", () => {
  it("returns an array of severity distributions", async () => {
    const caller = appRouter.createCaller(createUserContext());
    const result = await caller.graph.vulnSeverityDistribution();
    expect(Array.isArray(result)).toBe(true);
  });
});

describe("graph.analystQuery", () => {
  it("rejects unauthenticated requests", async () => {
    const caller = appRouter.createCaller(createUnauthContext());
    await expect(
      caller.graph.analystQuery({ query: "test", conversationHistory: [] })
    ).rejects.toThrow();
  });

  it("validates query length", async () => {
    const caller = appRouter.createCaller(createUserContext());
    await expect(
      caller.graph.analystQuery({ query: "", conversationHistory: [] })
    ).rejects.toThrow();
  });
});

describe("graph.investigations CRUD", () => {
  it("creates an investigation and lists it", async () => {
    const caller = appRouter.createCaller(createAdminContext());

    // Create
    const created = await caller.graph.createInvestigation({
      title: "Test Investigation " + Date.now(),
      description: "Testing investigation CRUD",
      tags: ["test", "vitest"],
    });
    expect(created).toHaveProperty("id");
    expect(typeof created.id).toBe("number");

    // List
    const list = await caller.graph.listInvestigations({ limit: 50 });
    expect(list.sessions.length).toBeGreaterThan(0);
    expect(list.total).toBeGreaterThan(0);

    // Get
    const fetched = await caller.graph.getInvestigation({ id: created.id });
    expect(fetched).toBeDefined();
    expect(fetched!.title).toContain("Test Investigation");
    expect(fetched!.status).toBe("active");
  });

  it("updates investigation status", async () => {
    const caller = appRouter.createCaller(createAdminContext());

    const created = await caller.graph.createInvestigation({
      title: "Status Test " + Date.now(),
    });

    // Close it
    const updated = await caller.graph.updateInvestigation({
      id: created.id,
      status: "closed",
    });
    expect(updated.success).toBe(true);

    const fetched = await caller.graph.getInvestigation({ id: created.id });
    expect(fetched!.status).toBe("closed");
  });

  it("adds and deletes notes", async () => {
    const caller = appRouter.createCaller(createAdminContext());

    const created = await caller.graph.createInvestigation({
      title: "Notes Test " + Date.now(),
    });

    // Add note
    const note = await caller.graph.addInvestigationNote({
      sessionId: created.id,
      content: "This is a test observation",
    });
    expect(note).toHaveProperty("id");

    // Verify note appears in investigation
    const fetched = await caller.graph.getInvestigation({ id: created.id });
    expect(fetched!.notes.length).toBe(1);
    expect(fetched!.notes[0].content).toBe("This is a test observation");

    // Delete note
    const deleted = await caller.graph.deleteInvestigationNote({ noteId: note.id });
    expect(deleted.success).toBe(true);

    // Verify note is gone
    const fetchedAfter = await caller.graph.getInvestigation({ id: created.id });
    expect(fetchedAfter!.notes.length).toBe(0);
  });

  it("filters investigations by status", async () => {
    const caller = appRouter.createCaller(createAdminContext());

    await caller.graph.createInvestigation({
      title: "Active Filter Test " + Date.now(),
    });

    const activeList = await caller.graph.listInvestigations({ status: "active", limit: 50 });
    for (const s of activeList.sessions) {
      expect(s.status).toBe("active");
    }
  });

  it("rejects unauthenticated investigation creation", async () => {
    const caller = appRouter.createCaller(createUnauthContext());
    await expect(
      caller.graph.createInvestigation({ title: "Should fail" })
    ).rejects.toThrow();
  });
});

describe("graph.endpointGraph", () => {
  it("returns nodes and edges for a given agent", async () => {
    const caller = appRouter.createCaller(createUserContext());
    const result = await caller.graph.endpointGraph({ agentId: "000" });
    expect(result).toHaveProperty("nodes");
    expect(result).toHaveProperty("edges");
    expect(Array.isArray(result.nodes)).toBe(true);
    expect(Array.isArray(result.edges)).toBe(true);
  });
});
