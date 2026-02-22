import { describe, expect, it, vi } from "vitest";
import { appRouter } from "../routers";
import type { TrpcContext } from "../_core/context";

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAuthContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-analyst-user",
    email: "analyst@example.com",
    name: "Test Analyst",
    loginMethod: "manus",
    role: "user",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };

  return {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: vi.fn(),
    } as unknown as TrpcContext["res"],
  };
}

describe("notes v2 router", () => {
  it("list returns notes array and total count", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.notes.list({ limit: 10 });
    expect(result).toHaveProperty("notes");
    expect(result).toHaveProperty("total");
    expect(Array.isArray(result.notes)).toBe(true);
    expect(typeof result.total).toBe("number");
  });

  it("entityCounts returns counts per entity type", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.notes.entityCounts();
    expect(result).toHaveProperty("alert");
    expect(result).toHaveProperty("agent");
    expect(result).toHaveProperty("cve");
    expect(result).toHaveProperty("rule");
    expect(result).toHaveProperty("general");
    expect(typeof result.alert).toBe("number");
    expect(typeof result.agent).toBe("number");
  });

  it("full CRUD round-trip: create, read, update, delete", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);

    // Create a general note
    const created = await caller.notes.create({
      entityType: "general",
      entityId: "",
      title: "Vitest General Note",
      content: "This is a test note from vitest",
      severity: "medium",
      tags: ["test", "vitest"],
    });
    expect(created).toHaveProperty("id");
    expect(created.success).toBe(true);

    // Read back by ID
    const note = await caller.notes.getById({ id: created.id });
    expect(note).not.toBeNull();
    expect(note?.title).toBe("Vitest General Note");
    expect(note?.content).toBe("This is a test note from vitest");
    expect(note?.severity).toBe("medium");
    expect(note?.entityType).toBe("general");
    expect(note?.resolved).toBe(0);

    // Update title and resolve
    const updated = await caller.notes.update({
      id: created.id,
      title: "Updated Vitest Note",
      resolved: true,
    });
    expect(updated.success).toBe(true);

    // Verify update
    const updatedNote = await caller.notes.getById({ id: created.id });
    expect(updatedNote?.title).toBe("Updated Vitest Note");
    expect(updatedNote?.resolved).toBe(1);

    // Delete
    const deleted = await caller.notes.delete({ id: created.id });
    expect(deleted.success).toBe(true);

    // Verify deletion
    const gone = await caller.notes.getById({ id: created.id });
    expect(gone).toBeNull();
  });

  it("create and query entity-linked note (alert)", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);

    // Create an alert-linked note
    const created = await caller.notes.create({
      entityType: "alert",
      entityId: "550",
      title: "Alert 550 investigation",
      content: "Suspicious activity detected",
      severity: "high",
      tags: ["incident"],
    });
    expect(created.success).toBe(true);

    // Query by entity
    const byEntity = await caller.notes.byEntity({
      entityType: "alert",
      entityId: "550",
    });
    expect(Array.isArray(byEntity)).toBe(true);
    expect(byEntity.length).toBeGreaterThanOrEqual(1);
    const found = byEntity.find((n) => n.id === created.id);
    expect(found).toBeDefined();
    expect(found?.entityType).toBe("alert");
    expect(found?.entityId).toBe("550");

    // Cleanup
    await caller.notes.delete({ id: created.id });
  });

  it("create and query CVE-linked note", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);

    const created = await caller.notes.create({
      entityType: "cve",
      entityId: "CVE-2024-1234",
      title: "CVE-2024-1234 remediation",
      content: "Patch applied on server-01",
      severity: "critical",
      tags: ["patch", "cve"],
    });
    expect(created.success).toBe(true);

    // Query by entity
    const byEntity = await caller.notes.byEntity({
      entityType: "cve",
      entityId: "CVE-2024-1234",
    });
    expect(byEntity.length).toBeGreaterThanOrEqual(1);
    const found = byEntity.find((n) => n.id === created.id);
    expect(found?.severity).toBe("critical");

    // Cleanup
    await caller.notes.delete({ id: created.id });
  });

  it("list with filters returns filtered results", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);

    // Create two notes with different entity types
    const alertNote = await caller.notes.create({
      entityType: "alert",
      entityId: "999",
      title: "Filter Test Alert",
      severity: "high",
    });
    const agentNote = await caller.notes.create({
      entityType: "agent",
      entityId: "001",
      title: "Filter Test Agent",
      severity: "low",
    });

    // Filter by entity type
    const alertResults = await caller.notes.list({
      entityType: "alert",
      limit: 100,
    });
    const alertIds = alertResults.notes.map((n) => n.id);
    expect(alertIds).toContain(alertNote.id);
    expect(alertIds).not.toContain(agentNote.id);

    // Filter by severity
    const highResults = await caller.notes.list({
      severity: "high",
      limit: 100,
    });
    const highIds = highResults.notes.map((n) => n.id);
    expect(highIds).toContain(alertNote.id);

    // Cleanup
    await caller.notes.delete({ id: alertNote.id });
    await caller.notes.delete({ id: agentNote.id });
  });

  it("search notes by title content", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);

    const created = await caller.notes.create({
      entityType: "general",
      title: "UniqueSearchTermXYZ123 investigation",
      content: "Detailed findings",
      severity: "info",
    });

    const searchResults = await caller.notes.list({
      search: "UniqueSearchTermXYZ123",
      limit: 100,
    });
    expect(searchResults.notes.length).toBeGreaterThanOrEqual(1);
    const found = searchResults.notes.find((n) => n.id === created.id);
    expect(found).toBeDefined();

    // Cleanup
    await caller.notes.delete({ id: created.id });
  });
});
