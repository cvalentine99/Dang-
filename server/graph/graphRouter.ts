/**
 * Graph Router — tRPC procedures for HybridRAG Knowledge Graph
 *
 * Provides endpoints for:
 * - ETL pipeline management (sync, status)
 * - Graph queries (stats, endpoint graph, overview, search)
 * - Analyst chat (agentic LLM pipeline)
 * - Investigation sessions (CRUD)
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { runFullSync, syncEntityType, getSyncStatus } from "./etlService";
import {
  getGraphStats,
  getEndpointGraph,
  getOverviewGraph,
  searchGraph,
  getVulnerabilityAttackSurface,
  getMitreDistribution,
  getVulnerabilitySeverityDistribution,
} from "./graphQueryService";
import { runAnalystPipeline, type AnalystMessage } from "./agenticPipeline";
import { getDb } from "../db";
import {
  investigationSessions,
  investigationNotes,
} from "../../drizzle/schema";
import { eq, desc, and, sql } from "drizzle-orm";

export const graphRouter = router({
  // ── ETL Pipeline ────────────────────────────────────────────────────────

  /** Run a full ETL sync across all entity types. */
  etlFullSync: protectedProcedure.mutation(async () => {
    return runFullSync();
  }),

  /** Sync a single entity type. */
  etlSyncEntity: protectedProcedure
    .input(z.object({ entityType: z.string() }))
    .mutation(async ({ input }) => {
      return syncEntityType(input.entityType);
    }),

  /** Get current sync status for all entity types. */
  etlStatus: protectedProcedure.query(async () => {
    return getSyncStatus();
  }),

  // ── Graph Queries ───────────────────────────────────────────────────────

  /** Get Knowledge Graph statistics (entity counts). */
  graphStats: protectedProcedure.query(async () => {
    return getGraphStats();
  }),

  /** Get full graph data for a specific endpoint. */
  endpointGraph: protectedProcedure
    .input(z.object({ agentId: z.string() }))
    .query(async ({ input }) => {
      return getEndpointGraph(input.agentId);
    }),

  /** Get overview graph showing all endpoints and high-level connections. */
  overviewGraph: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(100).default(50) }).optional())
    .query(async ({ input }) => {
      return getOverviewGraph(input?.limit ?? 50);
    }),

  /** Search across all graph entities by keyword. */
  searchGraph: protectedProcedure
    .input(z.object({ query: z.string().min(1), limit: z.number().min(1).max(100).default(50) }))
    .query(async ({ input }) => {
      return searchGraph(input.query, input.limit);
    }),

  /** Get vulnerability attack surface for a specific CVE. */
  vulnAttackSurface: protectedProcedure
    .input(z.object({ cveId: z.string() }))
    .query(async ({ input }) => {
      return getVulnerabilityAttackSurface(input.cveId);
    }),

  /** Get MITRE ATT&CK tactic distribution. */
  mitreDistribution: protectedProcedure.query(async () => {
    return getMitreDistribution();
  }),

  /** Get vulnerability severity distribution. */
  vulnSeverityDistribution: protectedProcedure.query(async () => {
    return getVulnerabilitySeverityDistribution();
  }),

  // ── Analyst Chat (Agentic Pipeline) ───────────────────────────────────

  /** Run the agentic analysis pipeline with a natural language query. */
  analystQuery: protectedProcedure
    .input(z.object({
      query: z.string().min(1).max(2000),
      conversationHistory: z.array(z.object({
        role: z.enum(["user", "assistant", "system"]),
        content: z.string(),
      })).default([]),
    }))
    .mutation(async ({ input }) => {
      return runAnalystPipeline(input.query, input.conversationHistory as AnalystMessage[]);
    }),

  // ── Investigation Sessions ────────────────────────────────────────────

  /** List investigation sessions for the current user. */
  listInvestigations: protectedProcedure
    .input(z.object({
      status: z.enum(["active", "closed", "archived"]).optional(),
      limit: z.number().min(1).max(100).default(20),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) return { sessions: [], total: 0 };

      const conditions = [eq(investigationSessions.userId, ctx.user.id)];
      if (input?.status) {
        conditions.push(eq(investigationSessions.status, input.status));
      }

      const where = conditions.length === 1 ? conditions[0] : and(...conditions);

      const [sessions, countResult] = await Promise.all([
        db.select()
          .from(investigationSessions)
          .where(where)
          .orderBy(desc(investigationSessions.updatedAt))
          .limit(input?.limit ?? 20)
          .offset(input?.offset ?? 0),
        db.select({ count: sql<number>`count(*)` })
          .from(investigationSessions)
          .where(where),
      ]);

      return { sessions, total: countResult[0]?.count ?? 0 };
    }),

  /** Create a new investigation session. */
  createInvestigation: protectedProcedure
    .input(z.object({
      title: z.string().min(1).max(512),
      description: z.string().optional(),
      tags: z.array(z.string()).optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) throw new Error("Database unavailable");

      const result = await db.insert(investigationSessions).values({
        userId: ctx.user.id,
        title: input.title,
        description: input.description ?? null,
        tags: input.tags ?? [],
        evidence: [],
        timeline: [],
      });

      return { id: Number(result[0].insertId) };
    }),

  /** Get a specific investigation session. */
  getInvestigation: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) throw new Error("Database unavailable");

      const sessions = await db.select()
        .from(investigationSessions)
        .where(and(eq(investigationSessions.id, input.id), eq(investigationSessions.userId, ctx.user.id)))
        .limit(1);

      if (sessions.length === 0) throw new Error("Investigation not found");

      // Get notes
      const notes = await db.select()
        .from(investigationNotes)
        .where(eq(investigationNotes.sessionId, input.id))
        .orderBy(desc(investigationNotes.createdAt));

      return { ...sessions[0], notes };
    }),

  /** Update investigation session. */
  updateInvestigation: protectedProcedure
    .input(z.object({
      id: z.number(),
      title: z.string().min(1).max(512).optional(),
      description: z.string().optional(),
      status: z.enum(["active", "closed", "archived"]).optional(),
      tags: z.array(z.string()).optional(),
      evidence: z.array(z.object({
        type: z.string(),
        label: z.string(),
        data: z.record(z.string(), z.unknown()),
        addedAt: z.string(),
      })).optional(),
      timeline: z.array(z.object({
        timestamp: z.string(),
        event: z.string(),
        source: z.string(),
        severity: z.string().optional(),
      })).optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) throw new Error("Database unavailable");

      const updates: Record<string, unknown> = {};
      if (input.title !== undefined) updates.title = input.title;
      if (input.description !== undefined) updates.description = input.description;
      if (input.status !== undefined) updates.status = input.status;
      if (input.tags !== undefined) updates.tags = input.tags;
      if (input.evidence !== undefined) updates.evidence = input.evidence;
      if (input.timeline !== undefined) updates.timeline = input.timeline;

      await db.update(investigationSessions)
        .set(updates)
        .where(and(eq(investigationSessions.id, input.id), eq(investigationSessions.userId, ctx.user.id)));

      return { success: true };
    }),

  /** Add a note to an investigation. */
  addInvestigationNote: protectedProcedure
    .input(z.object({
      sessionId: z.number(),
      content: z.string().min(1),
    }))
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) throw new Error("Database unavailable");

      // Verify ownership
      const sessions = await db.select({ id: investigationSessions.id })
        .from(investigationSessions)
        .where(and(eq(investigationSessions.id, input.sessionId), eq(investigationSessions.userId, ctx.user.id)))
        .limit(1);

      if (sessions.length === 0) throw new Error("Investigation not found");

      const result = await db.insert(investigationNotes).values({
        sessionId: input.sessionId,
        userId: ctx.user.id,
        content: input.content,
      });

      return { id: Number(result[0].insertId) };
    }),

  /** Delete an investigation note. */
  deleteInvestigationNote: protectedProcedure
    .input(z.object({ noteId: z.number() }))
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) throw new Error("Database unavailable");

      await db.delete(investigationNotes)
        .where(and(eq(investigationNotes.id, input.noteId), eq(investigationNotes.userId, ctx.user.id)));

      return { success: true };
    }),
});
