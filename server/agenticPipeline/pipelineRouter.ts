/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * Agentic Pipeline tRPC Router
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * Exposes the agentic SOC pipeline stages as tRPC procedures.
 * All mutations require authentication. Queries are protected.
 * ═══════════════════════════════════════════════════════════════════════════════
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  runTriageAgent,
  getTriageById,
  listTriages,
  getTriageStats,
} from "./triageAgent";

export const pipelineRouter = router({
  // ── Triage: Run ────────────────────────────────────────────────────────────

  /** Run the triage agent on a raw Wazuh alert. Returns the canonical TriageObject. */
  triageAlert: protectedProcedure
    .input(z.object({
      rawAlert: z.record(z.string(), z.unknown()),
      alertQueueItemId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const result = await runTriageAgent({
        rawAlert: input.rawAlert,
        userId: ctx.user.id,
        alertQueueItemId: input.alertQueueItemId,
      });

      if (!result.success) {
        return {
          success: false as const,
          error: result.error ?? "Triage failed",
          triageId: result.triageId,
          latencyMs: result.latencyMs,
        };
      }

      return {
        success: true as const,
        triageObject: result.triageObject!,
        triageId: result.triageId!,
        dbId: result.dbId,
        latencyMs: result.latencyMs,
        tokensUsed: result.tokensUsed,
      };
    }),

  // ── Triage: Get by ID ──────────────────────────────────────────────────────

  /** Get a specific triage object by its triageId. */
  getTriageById: protectedProcedure
    .input(z.object({ triageId: z.string() }))
    .query(async ({ input }) => {
      const row = await getTriageById(input.triageId);
      if (!row) return { found: false as const };
      return { found: true as const, triage: row };
    }),

  // ── Triage: List ───────────────────────────────────────────────────────────

  /** List triage objects with optional filters. */
  listTriages: protectedProcedure
    .input(z.object({
      limit: z.number().int().min(1).max(200).default(50),
      offset: z.number().int().min(0).default(0),
      severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
      route: z.enum(["A_DUPLICATE_NOISY", "B_LOW_CONFIDENCE", "C_HIGH_CONFIDENCE", "D_LIKELY_BENIGN"]).optional(),
      status: z.enum(["pending", "processing", "completed", "failed"]).optional(),
      agentId: z.string().optional(),
    }))
    .query(async ({ input }) => {
      return listTriages(input);
    }),

  // ── Triage: Stats ──────────────────────────────────────────────────────────

  /** Get aggregate triage statistics (severity, route, status distributions). */
  triageStats: protectedProcedure
    .query(async () => {
      const stats = await getTriageStats();
      return stats ?? {
        total: 0,
        bySeverity: {},
        byRoute: {},
        byStatus: {},
      };
    }),
});
