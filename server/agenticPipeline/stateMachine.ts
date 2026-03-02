/**
 * Direction 5: Centralized State Machine for Response Actions
 *
 * This module is the SINGLE source of truth for all response action state transitions.
 * Every mutation that changes action state MUST go through this module.
 *
 * Invariants enforced:
 *   1. requiresApproval=true cannot skip proposed→approved→executed
 *   2. Rejected actions are terminal — cannot be executed
 *   3. Executed actions are terminal — cannot be modified
 *   4. Deferred actions require a reason
 *   5. Rejected actions require a reason
 *   6. Every state transition writes an audit row
 *   7. Every action tied to a case must have a valid caseId
 *   8. Only valid transitions are allowed (no arbitrary jumps)
 *
 * State Machine:
 *   proposed → approved → executed
 *   proposed → rejected (terminal)
 *   proposed → deferred → proposed (re-propose)
 *   approved → rejected (revoke approval, terminal)
 *   approved → executed (terminal)
 */

import { eq, sql } from "drizzle-orm";
import { getDb } from "../db";
import {
  responseActions,
  responseActionAudit,
  livingCaseState,
} from "../../drizzle/schema";

// ── Types ───────────────────────────────────────────────────────────────────

export type ActionState = "proposed" | "approved" | "rejected" | "executed" | "deferred";

export const TERMINAL_STATES: readonly ActionState[] = ["rejected", "executed"] as const;

export interface TransitionRequest {
  actionId: string;
  targetState: ActionState;
  performedBy: string;
  reason?: string;
  metadata?: Record<string, unknown>;
}

export interface TransitionResult {
  success: boolean;
  error?: string;
  invariantViolation?: string;
  action?: typeof responseActions.$inferSelect;
  fromState?: string;
  toState?: string;
}

// ── Valid Transitions ───────────────────────────────────────────────────────

export const VALID_TRANSITIONS: Record<ActionState, ActionState[]> = {
  proposed: ["approved", "rejected", "deferred"],
  approved: ["executed", "rejected"],
  deferred: ["proposed"],
  rejected: [],   // terminal
  executed: [],   // terminal
};

export function isValidTransition(from: string, to: string): boolean {
  return (VALID_TRANSITIONS[from as ActionState] ?? []).includes(to as ActionState);
}

export function isTerminalState(state: string): boolean {
  return TERMINAL_STATES.includes(state as ActionState);
}

export function getAllowedTransitions(state: string): ActionState[] {
  return VALID_TRANSITIONS[state as ActionState] ?? [];
}

// ── Invariant Checks ────────────────────────────────────────────────────────

interface InvariantCheckResult {
  valid: boolean;
  violation?: string;
}

/**
 * Checks all Direction 5 invariants before allowing a transition.
 * Returns { valid: true } if all pass, or { valid: false, violation: "..." } if any fail.
 */
export function checkInvariants(
  action: typeof responseActions.$inferSelect,
  targetState: ActionState,
  reason?: string
): InvariantCheckResult {
  // Invariant 1: Terminal states cannot transition
  if (isTerminalState(action.state)) {
    return {
      valid: false,
      violation: `Action is in terminal state "${action.state}" — no further transitions allowed.`,
    };
  }

  // Invariant 2: Valid transition check
  if (!isValidTransition(action.state, targetState)) {
    const allowed = getAllowedTransitions(action.state);
    return {
      valid: false,
      violation: `Invalid transition: ${action.state} → ${targetState}. Allowed: ${allowed.join(", ") || "none (terminal state)"}`,
    };
  }

  // Invariant 3: requiresApproval=true cannot skip proposed→approved→executed
  if (
    targetState === "executed" &&
    action.requiresApproval === 1 &&
    action.state !== "approved"
  ) {
    return {
      valid: false,
      violation: `Action requires approval before execution. Current state: ${action.state}. Must be approved first.`,
    };
  }

  // Invariant 4: Deferred actions require a reason
  if (targetState === "deferred" && (!reason || reason.trim().length === 0)) {
    return {
      valid: false,
      violation: "Deferred actions require a reason. Provide a reason explaining why this action is being deferred.",
    };
  }

  // Invariant 5: Rejected actions require a reason
  if (targetState === "rejected" && (!reason || reason.trim().length === 0)) {
    return {
      valid: false,
      violation: "Rejected actions require a reason. Provide a reason explaining why this action is being rejected.",
    };
  }

  // Invariant 6: Actions with a caseId must reference a valid case
  // (This is enforced at propose-time, not transition-time, but we guard here too)
  // No-op for transitions — caseId is immutable after creation.

  return { valid: true };
}

// ── Audit Logger ────────────────────────────────────────────────────────────

/**
 * Invariant 6: Every state transition writes an audit row. No exceptions.
 */
async function logAudit(
  db: NonNullable<Awaited<ReturnType<typeof getDb>>>,
  opts: {
    actionDbId: number;
    actionIdStr: string;
    fromState: string;
    toState: string;
    performedBy: string;
    reason?: string;
    metadata?: Record<string, unknown>;
  }
): Promise<void> {
  await db.insert(responseActionAudit).values({
    actionId: opts.actionDbId,
    actionIdStr: opts.actionIdStr,
    fromState: opts.fromState,
    toState: opts.toState,
    performedBy: opts.performedBy,
    reason: opts.reason ?? null,
    metadata: opts.metadata ?? null,
  });
}

// ── Central Transition Function ─────────────────────────────────────────────

/**
 * The ONE function that performs state transitions for response actions.
 * All state changes MUST go through this function.
 *
 * Guarantees:
 *   - All invariants are checked before the transition
 *   - An audit row is written for every transition
 *   - The updated action is returned
 */
export async function transitionActionState(
  req: TransitionRequest
): Promise<TransitionResult> {
  const db = await getDb();
  if (!db) return { success: false, error: "Database not available" };

  // 1. Fetch current action
  const [action] = await db
    .select()
    .from(responseActions)
    .where(eq(responseActions.actionId, req.actionId))
    .limit(1);

  if (!action) {
    return { success: false, error: `Action ${req.actionId} not found` };
  }

  // 2. Check all invariants
  const invariantCheck = checkInvariants(action, req.targetState, req.reason);
  if (!invariantCheck.valid) {
    return {
      success: false,
      error: invariantCheck.violation,
      invariantViolation: invariantCheck.violation,
      fromState: action.state,
      toState: req.targetState,
    };
  }

  // 3. Build update payload
  const fromState = action.state;
  const now = new Date();
  const updatePayload: Record<string, unknown> = { state: req.targetState };

  switch (req.targetState) {
    case "approved":
      updatePayload.approvedBy = req.performedBy;
      updatePayload.approvedAt = now;
      updatePayload.decidedBy = req.performedBy;
      updatePayload.decidedAt = now;
      break;
    case "rejected":
      updatePayload.decidedBy = req.performedBy;
      updatePayload.decidedAt = now;
      updatePayload.decisionReason = req.reason ?? null;
      break;
    case "executed":
      updatePayload.executedBy = req.performedBy;
      updatePayload.executedAt = now;
      break;
    case "deferred":
      updatePayload.decidedBy = req.performedBy;
      updatePayload.decidedAt = now;
      updatePayload.decisionReason = req.reason ?? null;
      break;
    case "proposed":
      // Re-propose from deferred — clear previous decision
      updatePayload.decidedBy = null;
      updatePayload.decidedAt = null;
      updatePayload.decisionReason = null;
      break;
  }

  // 4. Apply transition
  await db
    .update(responseActions)
    .set(updatePayload as any)
    .where(eq(responseActions.id, action.id));

  // 5. Invariant 6: Write audit row (ALWAYS)
  await logAudit(db, {
    actionDbId: action.id,
    actionIdStr: action.actionId,
    fromState,
    toState: req.targetState,
    performedBy: req.performedBy,
    reason: req.reason,
    metadata: req.metadata,
  });

  // 6. Recompute case summary counters from response_actions (eliminates counter drift)
  if (action.caseId) {
    await syncCaseSummaryAfterTransition(action.caseId);
  }

  // 7. Return updated action
  const [updated] = await db
    .select()
    .from(responseActions)
    .where(eq(responseActions.id, action.id))
    .limit(1);

  return {
    success: true,
    action: updated,
    fromState,
    toState: req.targetState,
  };
}

// ── Case Summary Recompute ──────────────────────────────────────────────────

/**
 * Recomputes pendingActionCount, approvalRequiredCount, and actionSummary
 * from the response_actions table — the SINGLE source of truth.
 *
 * This function is called after every state transition to keep
 * living_case_state and LivingCaseObject.actionSummary in sync.
 *
 * This eliminates the "denormalized counter drift" problem where
 * snapshot-based counters set at hypothesis time go stale after
 * approve/reject/defer/execute transitions.
 */
export interface CaseSummary {
  total: number;
  proposed: number;
  approved: number;
  rejected: number;
  executed: number;
  deferred: number;
}

export async function recomputeCaseSummary(caseId: number): Promise<CaseSummary | null> {
  const db = await getDb();
  if (!db) return null;

  // Count actions by state for this case — derived from response_actions, not snapshots
  const rows = await db
    .select({
      state: responseActions.state,
      count: sql<number>`COUNT(*)`.as("count"),
    })
    .from(responseActions)
    .where(eq(responseActions.caseId, caseId))
    .groupBy(responseActions.state);

  const summary: CaseSummary = {
    total: 0,
    proposed: 0,
    approved: 0,
    rejected: 0,
    executed: 0,
    deferred: 0,
  };

  for (const row of rows) {
    const count = Number(row.count);
    summary.total += count;
    if (row.state in summary) {
      (summary as any)[row.state] = count;
    }
  }

  return summary;
}

/**
 * Updates living_case_state counters and LivingCaseObject.actionSummary
 * from the response_actions table. Called after every state transition.
 */
export async function syncCaseSummaryAfterTransition(caseId: number): Promise<void> {
  const db = await getDb();
  if (!db || !caseId) return;

  const summary = await recomputeCaseSummary(caseId);
  if (!summary) return;

  // 1. Update the denormalized counters on living_case_state
  const [caseRow] = await db
    .select()
    .from(livingCaseState)
    .where(eq(livingCaseState.id, caseId))
    .limit(1);

  if (!caseRow) return;

  // 2. Update the counters on the table row
  await db
    .update(livingCaseState)
    .set({
      pendingActionCount: summary.proposed,
      approvalRequiredCount: await getApprovalRequiredCount(db, caseId),
    })
    .where(eq(livingCaseState.id, caseId));

  // 3. Update the actionSummary inside the caseData JSON
  const caseData = caseRow.caseData as any;
  if (caseData) {
    caseData.actionSummary = summary;
    await db
      .update(livingCaseState)
      .set({ caseData })
      .where(eq(livingCaseState.id, caseId));
  }
}

/**
 * Count actions that require approval and are still in proposed state.
 * Derived from response_actions, not from snapshot.
 */
async function getApprovalRequiredCount(
  db: NonNullable<Awaited<ReturnType<typeof getDb>>>,
  caseId: number
): Promise<number> {
  const [result] = await db
    .select({
      count: sql<number>`COUNT(*)`.as("count"),
    })
    .from(responseActions)
    .where(
      sql`${responseActions.caseId} = ${caseId} AND ${responseActions.requiresApproval} = 1 AND ${responseActions.state} = 'proposed'`
    );

  return Number(result?.count ?? 0);
}

// ── Convenience Wrappers ────────────────────────────────────────────────────

export async function approveAction(actionId: string, userId: number, reason?: string) {
  return transitionActionState({
    actionId,
    targetState: "approved",
    performedBy: `user:${userId}`,
    reason,
  });
}

export async function rejectAction(actionId: string, userId: number, reason: string) {
  return transitionActionState({
    actionId,
    targetState: "rejected",
    performedBy: `user:${userId}`,
    reason,
  });
}

export async function executeAction(actionId: string, userId: number, metadata?: Record<string, unknown>) {
  return transitionActionState({
    actionId,
    targetState: "executed",
    performedBy: `user:${userId}`,
    metadata,
  });
}

export async function deferAction(actionId: string, userId: number, reason: string) {
  return transitionActionState({
    actionId,
    targetState: "deferred",
    performedBy: `user:${userId}`,
    reason,
  });
}

export async function reproposeAction(actionId: string, userId: number, reason?: string) {
  return transitionActionState({
    actionId,
    targetState: "proposed",
    performedBy: `user:${userId}`,
    reason: reason ?? "Re-proposed from deferred",
  });
}
