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
import { eq, and, inArray, isNull, sql } from "drizzle-orm";

/**
 * In-memory batch progress tracker.
 * Tracks the current state of a running batch ticket operation.
 * Auto-expires after 5 minutes of inactivity.
 */
interface BatchProgress {
  batchId: string;
  status: "idle" | "running" | "completed" | "failed";
  total: number;
  completed: number;
  sent: number;
  failed: number;
  currentAlert: string;
  currentIndex: number;
  startedAt: number;
  updatedAt: number;
  results: Array<{ id: number; alertId: string; ticketId?: string; error?: string }>;
}

const BATCH_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes

let currentBatch: BatchProgress = {
  batchId: "",
  status: "idle",
  total: 0,
  completed: 0,
  sent: 0,
  failed: 0,
  currentAlert: "",
  currentIndex: 0,
  startedAt: 0,
  updatedAt: 0,
  results: [],
};

function resetBatch(): void {
  currentBatch = {
    batchId: "",
    status: "idle",
    total: 0,
    completed: 0,
    sent: 0,
    failed: 0,
    currentAlert: "",
    currentIndex: 0,
    startedAt: 0,
    updatedAt: 0,
    results: [],
  };
}

function isBatchExpired(): boolean {
  if (currentBatch.status === "idle") return false;
  return Date.now() - currentBatch.updatedAt > BATCH_EXPIRY_MS;
}

// Exported for testing
export function _getBatchProgressForTest(): BatchProgress {
  return { ...currentBatch };
}

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

  /**
   * Get current batch ticket creation progress.
   * Polled by the frontend during batch operations.
   */
  batchProgress: protectedProcedure.query(async () => {
    // Auto-expire stale batches
    if (isBatchExpired()) {
      resetBatch();
    }
    return {
      batchId: currentBatch.batchId,
      status: currentBatch.status,
      total: currentBatch.total,
      completed: currentBatch.completed,
      sent: currentBatch.sent,
      failed: currentBatch.failed,
      currentAlert: currentBatch.currentAlert,
      currentIndex: currentBatch.currentIndex,
      percentage: currentBatch.total > 0
        ? Math.round((currentBatch.completed / currentBatch.total) * 100)
        : 0,
    };
  }),

  /**
   * Get the Splunk ES base URL for constructing deep links.
   * Returns the URL pattern for Incident Review page.
   */
  getSplunkBaseUrl: protectedProcedure.query(async () => {
    const config = await getEffectiveSplunkConfig();
    if (!config.enabled || !config.host) {
      return { url: null, enabled: false };
    }
    // Splunk Web runs on port 8000 by default (not the management port 8089)
    const webPort = config.port === "8089" ? "8000" : config.port;
    const baseUrl = `${config.protocol}://${config.host}:${webPort}`;
    return {
      url: baseUrl,
      enabled: true,
      // Full deep link pattern: {baseUrl}/en-US/app/SplunkEnterpriseSecuritySuite/incident_review?search=ticket_id%3D{ticketId}
      incidentReviewUrl: `${baseUrl}/en-US/app/SplunkEnterpriseSecuritySuite/incident_review`,
    };
  }),

  /**
   * Batch create Splunk ES tickets for all completed triage reports
   * that don't already have a ticket. Requires admin role.
   * Updates in-memory progress tracker for real-time polling.
   */
  batchCreateTickets: protectedProcedure
    .mutation(async ({ ctx }) => {
      // Feature gate: require admin role
      if (ctx.user?.role !== "admin") {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: "Creating Splunk tickets requires SECURITY_ADMIN role",
        });
      }

      // Prevent concurrent batches
      if (currentBatch.status === "running") {
        throw new TRPCError({
          code: "CONFLICT",
          message: "A batch ticket creation is already in progress",
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

      const db = await getDb();
      if (!db) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });
      }

      // Get all completed items with triage results
      const completedItems = await db
        .select()
        .from(alertQueue)
        .where(eq(alertQueue.status, "completed"));

      // Filter to items that have triage results but no existing Splunk ticket
      const eligibleItems = completedItems.filter((item) => {
        const triage = item.triageResult as Record<string, unknown> | null;
        if (!triage || !triage.answer) return false;
        if (triage.splunkTicketId) return false;
        return true;
      });

      if (eligibleItems.length === 0) {
        return {
          success: true,
          total: 0,
          sent: 0,
          skipped: completedItems.length,
          failed: 0,
          message: "No eligible triage reports found (all already have tickets or no triage data)",
        };
      }

      // Initialize batch progress
      const batchId = `batch-${Date.now()}`;
      currentBatch = {
        batchId,
        status: "running",
        total: eligibleItems.length,
        completed: 0,
        sent: 0,
        failed: 0,
        currentAlert: eligibleItems[0]?.alertId ?? "",
        currentIndex: 0,
        startedAt: Date.now(),
        updatedAt: Date.now(),
        results: [],
      };

      let sent = 0;
      let failed = 0;
      const results: Array<{ id: number; alertId: string; ticketId?: string; error?: string }> = [];

      for (let i = 0; i < eligibleItems.length; i++) {
        const item = eligibleItems[i];

        // Update progress: currently processing this item
        currentBatch.currentIndex = i + 1;
        currentBatch.currentAlert = item.alertId;
        currentBatch.updatedAt = Date.now();

        try {
          const triage = item.triageResult as Record<string, unknown>;
          const rawJson = (item.rawJson as Record<string, unknown>) ?? {};
          const rule = (rawJson.rule as Record<string, unknown>) ?? {};
          const mitre = (rule.mitre as Record<string, unknown>) ?? {};
          const mitreIds = Array.isArray(mitre.id) ? (mitre.id as string[]) : [];
          const mitreTactics = Array.isArray(mitre.tactic) ? (mitre.tactic as string[]) : [];

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

          if (result.success && result.ticketId) {
            const updatedTriage = {
              ...triage,
              splunkTicketId: result.ticketId,
              splunkTicketCreatedAt: new Date().toISOString(),
              splunkTicketCreatedBy: ctx.user?.name ?? ctx.user?.email,
            } as unknown as typeof item.triageResult;
            await db
              .update(alertQueue)
              .set({ triageResult: updatedTriage })
              .where(eq(alertQueue.id, item.id));

            sent++;
            results.push({ id: item.id, alertId: item.alertId, ticketId: result.ticketId });
            currentBatch.sent = sent;
          } else {
            failed++;
            results.push({ id: item.id, alertId: item.alertId, error: result.message });
            currentBatch.failed = failed;
          }
        } catch (err) {
          failed++;
          results.push({
            id: item.id,
            alertId: item.alertId,
            error: err instanceof Error ? err.message : "Unknown error",
          });
          currentBatch.failed = failed;
        }

        // Update progress: item completed
        currentBatch.completed = i + 1;
        currentBatch.results = results;
        currentBatch.updatedAt = Date.now();
      }

      const skipped = completedItems.length - eligibleItems.length;

      // Mark batch as completed
      currentBatch.status = failed === eligibleItems.length ? "failed" : "completed";
      currentBatch.currentAlert = "";
      currentBatch.updatedAt = Date.now();

      return {
        success: failed === 0,
        total: eligibleItems.length,
        sent,
        skipped,
        failed,
        message: `Batch complete: ${sent} tickets created, ${skipped} skipped (already ticketed), ${failed} failed`,
        results,
      };
    }),
});
