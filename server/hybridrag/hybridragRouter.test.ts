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

describe("hybridrag router", () => {
  it("modelStatus returns model info", async () => {
    const ctx = createPublicContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.hybridrag.modelStatus();
    expect(result).toHaveProperty("nemotron");
    expect(result).toHaveProperty("fallbackAvailable");
    expect(result).toHaveProperty("activeModel");
    expect(result.fallbackAvailable).toBe(true);
    expect(typeof result.nemotron.available).toBe("boolean");
    expect(typeof result.nemotron.model).toBe("string");
    expect(typeof result.nemotron.endpoint).toBe("string");
  });

  it("notes.list returns notes array", async () => {
    const ctx = createPublicContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.hybridrag.notes.list({ limit: 10 });
    expect(result).toHaveProperty("notes");
    expect(Array.isArray(result.notes)).toBe(true);
  });

  it("notes.create and delete round-trip", async () => {
    const ctx = createPublicContext();
    const caller = appRouter.createCaller(ctx);

    // Create
    const created = await caller.hybridrag.notes.create({
      title: "Test Note from Vitest",
      content: "This is a test note",
      severity: "medium",
      tags: ["test"],
    });
    expect(created).toHaveProperty("id");
    expect(created.success).toBe(true);

    // Read back
    const note = await caller.hybridrag.notes.getById({ id: created.id });
    expect(note).not.toBeNull();
    expect(note?.title).toBe("Test Note from Vitest");
    expect(note?.severity).toBe("medium");

    // Update
    const updated = await caller.hybridrag.notes.update({
      id: created.id,
      resolved: true,
    });
    expect(updated.success).toBe(true);

    // Verify update
    const updatedNote = await caller.hybridrag.notes.getById({ id: created.id });
    expect(updatedNote?.resolved).toBe(1);

    // Delete
    const deleted = await caller.hybridrag.notes.delete({ id: created.id });
    expect(deleted.success).toBe(true);

    // Verify deletion
    const gone = await caller.hybridrag.notes.getById({ id: created.id });
    expect(gone).toBeNull();
  });
});
