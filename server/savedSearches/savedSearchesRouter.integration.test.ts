/**
 * Saved Searches Router — Real-DB Integration Tests
 *
 * Tests the actual tRPC router procedures (create, list, delete) against
 * a real MySQL database. Uses the appRouter.createCaller() pattern with
 * a synthetic authenticated context.
 *
 * Covers the three new search types: alerts, vulnerabilities, fleet.
 *
 * Gated by DATABASE_URL — skips gracefully when no DB is available.
 */
import { describe, it, expect, afterAll, beforeAll, vi } from "vitest";
import { appRouter } from "../routers";
import type { TrpcContext } from "../_core/context";

const HAS_DB = !!process.env.DATABASE_URL;

/** Synthetic user ID — high number to avoid collisions */
const TEST_USER_ID = 888888;
const TEST_OPEN_ID = "__router_integration_test__";
const TEST_PREFIX = "__router_integ__";

/** Track created IDs for cleanup */
const createdIds: number[] = [];

function createTestContext(userId = TEST_USER_ID): TrpcContext {
  return {
    user: {
      id: userId,
      openId: TEST_OPEN_ID,
      email: "router-test@example.com",
      name: "Router Integration Test",
      loginMethod: "local",
      role: "user",
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    },
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: vi.fn() } as unknown as TrpcContext["res"],
  };
}

function createOtherUserContext(): TrpcContext {
  return {
    user: {
      id: TEST_USER_ID + 1,
      openId: "__other_user__",
      email: "other@example.com",
      name: "Other User",
      loginMethod: "local",
      role: "user",
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    },
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: vi.fn() } as unknown as TrpcContext["res"],
  };
}

afterAll(async () => {
  if (!HAS_DB || createdIds.length === 0) return;
  // Clean up via raw SQL to avoid depending on the router for cleanup
  try {
    const mysql = await import("mysql2/promise");
    const parsed = new URL(process.env.DATABASE_URL!);
    const pool = mysql.createPool({
      host: parsed.hostname,
      port: Number(parsed.port),
      user: parsed.username,
      password: parsed.password,
      database: parsed.pathname.slice(1),
      ssl: { rejectUnauthorized: false },
    });
    await pool.query(
      `DELETE FROM saved_searches WHERE id IN (${createdIds.join(",")})`,
    );
    await pool.end();
  } catch (e) {
    console.warn("[cleanup] Failed to clean up test rows:", e);
  }
});

describe.skipIf(!HAS_DB)("savedSearchesRouter — Real DB Integration", () => {
  const caller = appRouter.createCaller(createTestContext());

  describe("create + list roundtrip for new search types", () => {
    const newTypes = ["alerts", "vulnerabilities", "fleet"] as const;

    for (const searchType of newTypes) {
      it(`creates a saved search with searchType='${searchType}'`, async () => {
        const result = await caller.savedSearches.create({
          name: `${TEST_PREFIX}${searchType}_${Date.now()}`,
          searchType,
          filters: { query: `test-${searchType}`, level: 3 },
          description: `Integration test for ${searchType}`,
        });

        expect(result.success).toBe(true);
        expect(result.id).toBeGreaterThan(0);
        createdIds.push(result.id);
      });

      it(`lists saved searches filtered by searchType='${searchType}'`, async () => {
        const result = await caller.savedSearches.list({ searchType });

        expect(result).toHaveProperty("searches");
        expect(Array.isArray(result.searches)).toBe(true);
        // We just created one above, so at least 1 should exist
        expect(result.searches.length).toBeGreaterThanOrEqual(1);

        // Every returned row must have the correct searchType
        for (const row of result.searches) {
          expect(row.searchType).toBe(searchType);
        }
      });
    }

    it("lists all types when no searchType filter is provided", async () => {
      const result = await caller.savedSearches.list({});
      expect(result.searches.length).toBeGreaterThanOrEqual(3);

      // Should contain at least one of each new type
      const types = new Set(result.searches.map((s) => s.searchType));
      expect(types.has("alerts")).toBe(true);
      expect(types.has("vulnerabilities")).toBe(true);
      expect(types.has("fleet")).toBe(true);
    });
  });

  describe("delete with ownership enforcement", () => {
    let deleteTargetId: number;

    beforeAll(async () => {
      // Create a search to delete
      const result = await caller.savedSearches.create({
        name: `${TEST_PREFIX}delete_target_${Date.now()}`,
        searchType: "fleet",
        filters: { deleteTest: true },
      });
      deleteTargetId = result.id;
      createdIds.push(deleteTargetId);
    });

    it("rejects delete from a different user (ownership check)", async () => {
      const otherCaller = appRouter.createCaller(createOtherUserContext());
      await expect(
        otherCaller.savedSearches.delete({ id: deleteTargetId }),
      ).rejects.toThrow("Saved search not found");
    });

    it("deletes an owned saved search", async () => {
      const result = await caller.savedSearches.delete({ id: deleteTargetId });
      expect(result).toEqual({ success: true });

      // Remove from cleanup list since it's already deleted
      const idx = createdIds.indexOf(deleteTargetId);
      if (idx >= 0) createdIds.splice(idx, 1);
    });

    it("rejects delete of already-deleted search", async () => {
      await expect(
        caller.savedSearches.delete({ id: deleteTargetId }),
      ).rejects.toThrow("Saved search not found");
    });
  });

  describe("update with ownership enforcement", () => {
    let updateTargetId: number;

    beforeAll(async () => {
      const result = await caller.savedSearches.create({
        name: `${TEST_PREFIX}update_target_${Date.now()}`,
        searchType: "alerts",
        filters: { original: true },
        description: "Original description",
      });
      updateTargetId = result.id;
      createdIds.push(updateTargetId);
    });

    it("updates name and filters of an owned search", async () => {
      const result = await caller.savedSearches.update({
        id: updateTargetId,
        name: `${TEST_PREFIX}updated_name`,
        filters: { updated: true, level: 5 },
      });
      expect(result).toEqual({ success: true });

      // Verify the update persisted
      const listed = await caller.savedSearches.list({ searchType: "alerts" });
      const updated = listed.searches.find((s) => s.id === updateTargetId);
      expect(updated).toBeDefined();
      expect(updated!.name).toBe(`${TEST_PREFIX}updated_name`);
    });

    it("rejects update from a different user", async () => {
      const otherCaller = appRouter.createCaller(createOtherUserContext());
      await expect(
        otherCaller.savedSearches.update({
          id: updateTargetId,
          name: "Hijacked",
        }),
      ).rejects.toThrow("Saved search not found");
    });
  });

  describe("input validation", () => {
    it("rejects invalid searchType at Zod level", async () => {
      await expect(
        caller.savedSearches.create({
          name: "Bad Type",
          searchType: "nonexistent" as "siem",
          filters: {},
        }),
      ).rejects.toThrow();
    });

    it("rejects empty name", async () => {
      await expect(
        caller.savedSearches.create({
          name: "",
          searchType: "alerts",
          filters: {},
        }),
      ).rejects.toThrow();
    });

    it("rejects name exceeding 256 characters", async () => {
      await expect(
        caller.savedSearches.create({
          name: "x".repeat(257),
          searchType: "vulnerabilities",
          filters: {},
        }),
      ).rejects.toThrow();
    });
  });
});
