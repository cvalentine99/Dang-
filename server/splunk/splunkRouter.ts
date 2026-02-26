/**
 * Splunk Router — tRPC procedures for Splunk ES Mission Control integration.
 *
 * Provides:
 * - testConnection: Test Splunk HEC connectivity
 * - createTicket: Push a Walter triage report as a notable event to Splunk ES
 * - getConfig: Get current Splunk configuration (masked token)
 *
 * Feature-gated: createTicket requires admin role (SECURITY_ADMIN equivalent).
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  testSplunkConnection,
  createSplunkTicket,
  getEffectiveSplunkConfig,
  isSplunkEnabled,
} from "./splunkService";
import { getDb } from "../db";
import { alertQueue } from "../../drizzle/schema";
import { eq } from "drizzle-orm";

export const splunkRouter = router({
  /**
   * Get current Splunk configuration (token masked for security).
   */
  getConfig: protectedProcedure.query(async () => {
    const config = await getEffectiveSplunkConfig();
    return {
      host: config.host,
      port: config.port,
      hecPort: config.hecPort,
      protocol: config.protocol,
      enabled: config.enabled,
      hasToken: !!config.hecToken,
      tokenPreview: config.hecToken
        ? `${config.hecToken.slice(0, 8)}...${config.hecToken.slice(-4)}`
        : "",
    };
  }),

  /**
   * Test Splunk HEC connectivity.
   */
  testConnection: protectedProcedure.mutation(async () => {
    return testSplunkConnection();
  }),

  /**
   * Check if Splunk integration is available.
   */
  isEnabled: protectedProcedure.query(async () => {
    const enabled = await isSplunkEnabled();
    return { enabled };
  }),

  /**
   * Create a Splunk ES ticket from a Walter triage report.
   * Requires admin role (SECURITY_ADMIN equivalent).
   */
  createTicket: protectedProcedure
    .input(
      z.object({
        /** Alert queue item ID */
        queueItemId: z.number().int(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      // Feature gate: require admin role
      if (ctx.user?.role !== "admin") {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: "Creating Splunk tickets requires SECURITY_ADMIN role",
        });
      }

      // Check if Splunk is enabled
      const enabled = await isSplunkEnabled();
      if (!enabled) {
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message: "Splunk integration is not configured or enabled",
        });
      }

      // Get the queue item with triage result
      const db = await getDb();
      if (!db) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });
      }

      const [item] = await db
        .select()
        .from(alertQueue)
        .where(eq(alertQueue.id, input.queueItemId))
        .limit(1);

      if (!item) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Queue item not found" });
      }

      if (item.status !== "completed") {
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message: "Can only create tickets for completed triage reports",
        });
      }

      const triage = item.triageResult as Record<string, unknown> | null;
      if (!triage) {
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message: "No triage result available for this queue item",
        });
      }

      // Extract MITRE data from raw alert JSON
      const rawJson = (item.rawJson as Record<string, unknown>) ?? {};
      const rule = (rawJson.rule as Record<string, unknown>) ?? {};
      const mitre = (rule.mitre as Record<string, unknown>) ?? {};
      const mitreIds = Array.isArray(mitre.id) ? (mitre.id as string[]) : [];
      const mitreTactics = Array.isArray(mitre.tactic) ? (mitre.tactic as string[]) : [];

      // Create the Splunk ticket
      const result = await createSplunkTicket({
        alertId: item.alertId,
        ruleId: item.ruleId,
        ruleDescription: item.ruleDescription ?? "Unknown",
        ruleLevel: item.ruleLevel,
        agentId: item.agentId ?? "Unknown",
        agentName: item.agentName ?? "Unknown",
        alertTimestamp: item.alertTimestamp ?? new Date().toISOString(),
        triageSummary: (triage.answer as string) ?? "No summary available",
        triageReasoning: (triage.reasoning as string) ?? "",
        trustScore: (triage.trustScore as number) ?? 0,
        confidence: (triage.confidence as number) ?? 0,
        safetyStatus: (triage.safetyStatus as string) ?? "unknown",
        mitreIds,
        mitreTactics,
        suggestedFollowUps: (triage.suggestedFollowUps as string[]) ?? [],
        rawAlertJson: rawJson,
        createdBy: ctx.user?.name ?? ctx.user?.email ?? "unknown",
      });

      // If successful, update the queue item with ticket info
      if (result.success && result.ticketId) {
        const existingTriage = (item.triageResult as Record<string, unknown>) ?? {};
        const updatedTriage = {
          ...existingTriage,
          splunkTicketId: result.ticketId,
          splunkTicketCreatedAt: new Date().toISOString(),
          splunkTicketCreatedBy: ctx.user?.name ?? ctx.user?.email,
        } as unknown as typeof item.triageResult;
        await db
          .update(alertQueue)
          .set({ triageResult: updatedTriage })
          .where(eq(alertQueue.id, input.queueItemId));
      }

      return result;
    }),
});
