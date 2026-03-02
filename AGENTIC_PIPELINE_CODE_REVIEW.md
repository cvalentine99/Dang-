# Agentic SOC Pipeline — Code Review (Read-Only)

**Date:** 2026-03-02
**Scope:** Read-only review of the agentic pipeline code — `server/agenticPipeline/`, `server/graph/agenticPipeline.ts`, `server/llm/llmService.ts`, `server/alertQueue/`, `shared/agenticSchemas.ts`, `drizzle/schema.ts`

---

## Pipeline Flow Map

```
Alert Source
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                    ALERT QUEUE                              │
│  alertQueueRouter.enqueue() — 10-deep, severity FIFO       │
│                                                             │
│   PATH A (Legacy "Walter")          PATH B (Structured)     │
│   alertQueueRouter.process()        pipeline.autoTriage     │
│         │                              QueueItem()          │
│         ▼                              │                    │
│   runAnalystPipeline()                 ▼                    │
│   (graph/agenticPipeline.ts)     ┌──────────────┐          │
│   KG + RAG + LLM synthesis       │ TRIAGE AGENT │          │
│   Returns: unstructured chat      │ (Step 1)     │          │
│                                   └──────┬───────┘          │
│              ╳ DEAD END                  │                  │
│              (not connected)             ▼ [MANUAL CALL]    │
│                                   ┌──────────────────┐      │
│                                   │ CORRELATION AGENT│      │
│                                   │ (Step 2)         │      │
│                                   └──────┬───────────┘      │
│                                          │                  │
│                                          ▼ [MANUAL CALL]    │
│                                   ┌──────────────────┐      │
│                                   │ HYPOTHESIS AGENT │      │
│                                   │ (Step 3)         │      │
│                                   └──────┬───────────┘      │
│                                          │                  │
│                                          ▼                  │
│                                   ┌──────────────────┐      │
│                                   │ LIVING CASE      │      │
│                                   │ + Response Actions│      │
│                                   │ + State Machine   │      │
│                                   └──────┬───────────┘      │
│                                          │                  │
│                                          ▼                  │
│                                   ┌──────────────────┐      │
│                                   │ REPORT SERVICE   │      │
│                                   │ (5 report types) │      │
│                                   └──────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

---

## Critical Findings

### 1. CorrelationBundle Schema Contract vs. LLM Output — Total Mismatch

**Severity: CRITICAL** | Files: `correlationAgent.ts`, `agenticSchemas.ts`, `livingCaseReportService.ts`

The canonical `CorrelationBundle` interface in `agenticSchemas.ts` defines a rich structure, but the `CORRELATION_JSON_SCHEMA` sent to the LLM in `correlationAgent.ts` returns a **completely different shape**:

| Field | Contract (`agenticSchemas.ts`) | LLM Output Schema (`correlationAgent.ts`) |
|---|---|---|
| `relatedAlerts[].linkedBy` | `ExtractedEntity` (object) | **Missing** — has `relationship: string` instead |
| `relatedAlerts[].relevance` | `Confidence` (number) | **Missing** |
| `blastRadius.affectedHosts` | `number` | `string[]` (array of hostnames) |
| `blastRadius.affectedUsers` | `number` | `string[]` (array of usernames) |
| `blastRadius.affectedAgentIds` | `string[]` | **Missing** |
| `blastRadius.confidence` | `Confidence` | **Missing** |
| `vulnerabilityContext` | `Array<{cveId,severity,name,...}>` | **Missing entirely** |
| `fimContext` | `Array<{path,event,...}>` | **Missing entirely** |
| `threatIntelMatches` | `Array<{ioc,iocType,...}>` | **Missing entirely** |
| `priorInvestigations` | `Array<{investigationId,...}>` | **Missing entirely** |
| `synthesis` | `{narrative,supportingEvidence,...,confidence}` | **Missing entirely** |
| `schemaVersion` | `"1.0"` | **Missing** |
| `correlatedAt` | `string` (ISO-8601) | **Missing** |
| `campaignAssessment.campaignLabel` | `string` | LLM returns `campaignName` instead |
| `campaignAssessment.clusteredTechniques` | `MitreMapping[]` | **Missing** |

At `correlationAgent.ts:758`, the code does an **unsafe cast**:
```ts
const bundle: CorrelationBundle = rawBundle; // rawBundle does NOT match CorrelationBundle
```

**Impact:** Every downstream consumer of `CorrelationBundle` — the hypothesis agent, the living case report service, the frontend — accesses fields that don't exist on the actual object. This causes silent `undefined` access or runtime crashes.

---

### 2. Report Service Will Crash on Real Data

**Severity: CRITICAL** | File: `livingCaseReportService.ts:331`

```ts
lines.push(`| ... ${a.linkedBy.type}:${a.linkedBy.value} | ${(a.relevance * 100).toFixed(0)}% |`);
```

Since the LLM-produced correlation bundle has `relationship: string` instead of `linkedBy: ExtractedEntity`, this will throw:
> `TypeError: Cannot read properties of undefined (reading 'type')`

The same file also accesses:
- `correlationBundle.vulnerabilityContext` — not in LLM output
- `correlationBundle.threatIntelMatches` — not in LLM output
- `correlationBundle.fimContext` — not in LLM output
- `correlationBundle.campaignAssessment.campaignLabel` — LLM returns `campaignName` instead

The report generator's template assumes the canonical contract, but receives the LLM's divergent structure.

---

### 3. Correlation Persistence Stores Wrong Values

**Severity: HIGH** | File: `correlationAgent.ts:771-777`

```ts
blastRadiusHosts: bundle.blastRadius?.affectedHosts ?? 0,  // affectedHosts is string[], not number
blastRadiusUsers: bundle.blastRadius?.affectedUsers ?? 0,   // same problem
confidence: bundle.synthesis?.confidence ?? 0,               // synthesis doesn't exist; always 0
```

- `affectedHosts` from the LLM is `string[]`, coerced to `0` by `?? 0` (since an array is truthy but not a number — this stores the array reference, not a count).
- `confidence` always stores 0 because `synthesis` doesn't exist in the LLM output. The actual confidence is at `bundle.confidence`.

---

### 4. No Automatic Pipeline Orchestration

**Severity: HIGH** | File: `pipelineRouter.ts`

The three pipeline stages must each be triggered by separate client-side API calls:
1. `pipeline.triageAlert` — manual
2. `pipeline.correlateFromTriage` — manual
3. `pipeline.generateHypothesis` — manual

There is no `runFullPipeline` endpoint that chains them. The client must poll for completion between stages and manually pass IDs forward. If any stage fails, there's no retry or backoff. Compare to the architecture intent: *"Alert → Triage → Correlation → Hypothesis → Living Case → Report"* — this chain doesn't run automatically.

---

### 5. Two Disconnected Pipeline Paths

**Severity: HIGH** | Files: `alertQueueRouter.ts`, `pipelineRouter.ts`

**Path A** (`alertQueueRouter.process`): Uses `runAnalystPipeline()` from `graph/agenticPipeline.ts` — a general-purpose RAG/chat pipeline that returns unstructured text. No `TriageObject`, no `CorrelationBundle`, no `LivingCaseObject`.

**Path B** (`pipeline.autoTriageQueueItem`): Uses `runTriageAgent()` — the structured 3-stage agentic pipeline with canonical contracts.

These paths are completely independent. Path A's output can't feed into Path B's stages. An analyst who uses the "process" button gets a chat answer; one who uses "auto-triage" gets a structured `TriageObject` — but still needs to manually trigger correlation and hypothesis.

---

### 6. Race Conditions in State Machine

**Severity: HIGH** | File: `stateMachine.ts:185-283`

`transitionActionState()` is not wrapped in a database transaction. The sequence:
1. `SELECT` current action state
2. Check invariants (in-memory)
3. `UPDATE` action state
4. `INSERT` audit row
5. `UPDATE` case summary

Two concurrent requests to approve the same action can both pass invariant checks (step 2) before either applies the update (step 3). Result: both succeed, double audit entries, corrupted case summary.

---

### 7. Custom LLM Silently Downgrades Schema Enforcement

**Severity: HIGH** | File: `llmService.ts:119-138`

When a custom LLM is configured, `json_schema` is downgraded to `json_object`:
```ts
payload.response_format = { type: "json_object" };
```

The schema is only injected as guidance text in the system prompt. There's no post-validation that the response conforms to the schema. A local model can return any valid JSON — missing required fields, wrong types, extra fields — and the pipeline will attempt to process it. Combined with the `as any` casts, malformed responses cause silent corruption or runtime crashes.

---

## Moderate Findings

### 8. Double DB Update in `syncCaseSummaryAfterTransition`

**File: `stateMachine.ts:352-378`**

Two separate `UPDATE` statements against `livingCaseState` — one for counters, one for the caseData JSON. If the first succeeds and the second fails, counters and caseData diverge. Should be a single atomic update.

---

### 9. Sequential OTX Threat Intel Lookups

**File: `correlationAgent.ts:270-330`**

`fetchThreatIntel` makes up to 11 sequential HTTP calls (5 IPs + 3 hashes + 3 domains). Each has a 600s cache TTL. Worst case: 11 serial network round-trips. These should be `Promise.all`'d.

---

### 10. `userId: 0` for System-Created Sessions

**File: `hypothesisAgent.ts:155`**

```ts
userId: 0, // system-created
```

Creates an `investigation_sessions` row with `userId: 0`, which doesn't reference a real user. Any `JOIN` against the `users` table returns no match. The session appears orphaned in the admin UI.

---

### 11. No Stale "processing" Cleanup

**Files: `triageAgent.ts`, `correlationAgent.ts`, `alertQueueRouter.ts`**

If the server crashes mid-pipeline:
- `triageObjects` rows stay `status: "processing"` forever
- `correlationBundles` rows stay `status: "processing"` forever
- `alertQueue` items stay `status: "processing"` forever

No sweeper/reaper exists to mark these as failed after a timeout.

---

### 12. `FIELD()` and `TIMESTAMPDIFF()` — MySQL-Only SQL

**File: `responseActionsRouter.ts:250-251, 378-387`**

```ts
sql`FIELD(${responseActions.state}, 'proposed', 'approved', ...)`
sql`AVG(TIMESTAMPDIFF(SECOND, ...))`
```

These are MySQL-specific functions. The raw SQL fragments make any future database migration (PostgreSQL, SQLite) impossible without rewriting.

---

### 13. Inconsistent Insert ID Retrieval

`triageAgent.ts:301` uses `result[0]?.insertId` (MySQL raw), while `hypothesisAgent.ts:152-156` uses `.$returningId()` (Drizzle ORM). These should be consistent. The `insertId` approach is fragile.

---

### 14. No LLM Response Retry

All three agent stages call `invokeLLMWithFallback` exactly once. If the response is malformed JSON (possible with custom models using `json_object` mode), the stage fails permanently. No parse retry, no schema validation with feedback loop, no exponential backoff.

---

### 15. Unbounded Prompt Construction

`buildCorrelationPrompt` and `buildHypothesisPrompt` truncate individual sections via `.slice()` but don't cap total prompt length. With large evidence packs (20+ related alerts, 20+ vulns, 10+ FIM events, 10+ threat intel hits), the combined prompt can exceed model context limits.

---

## Minor Findings

### 16. Pervasive `as any` Type Coercion

Throughout the pipeline code, `as any` is used to bypass TypeScript's type system:
- `stateMachine.ts:251` — `.set(updatePayload as any)`
- `correlationAgent.ts:758` — unsafe cast to `CorrelationBundle`
- `triageAgent.ts:299` — `triageData: {} as any`
- `responseActionsRouter.ts:77,242,273,275` — enum casts

These hide real type mismatches (particularly the CorrelationBundle issue) and prevent the compiler from catching bugs.

---

### 17. `normCategory` Maps Wrong Enum

**File: `hypothesisAgent.ts:494-497`**

The LLM is instructed to return action categories like `isolate_host`, `disable_account`, etc. But `normCategory` normalizes to `"immediate" | "next" | "optional"`. The LivingCaseObject snapshot stores the display category while the materialized `response_actions` row stores the LLM's raw category. Same action, different categories in two places.

---

### 18. Empty `catch` Blocks Swallow Errors

Multiple places use `catch {}` or `catch { return []; }` with no logging:
- `triageAgent.ts:210-212` — `fetchRecentTriages`
- `correlationAgent.ts:112-114, 158-160, 206-208, 237-239` — all evidence fetch functions
- `correlationAgent.ts:288, 298, 310` — OTX lookups

When evidence retrieval silently fails, the LLM receives empty evidence packs and makes assessments with incomplete data — nothing in the logs explains why.

---

### 19. `runAnalystPipeline` Prompt Truncation

**File: `alertQueueRouter.ts:369`**

```ts
parts.push(JSON.stringify(item.rawJson, null, 2).slice(0, 4000));
```

Raw alert JSON is truncated to 4K characters. For alerts with large `data` payloads (Windows event logs, FIM diffs), critical fields at the end of the JSON are silently dropped.

---

### 20. `result[0]?.insertId` Can Be `undefined`

**File: `triageAgent.ts:301`**

If the Drizzle MySQL driver doesn't return `insertId`, `dbId` is `undefined`. The later `WHERE id = dbId` update at line 451 would match nothing, silently leaving the triage in `processing` status forever.

---

## Summary Table

| Category | Count | Most Critical |
|---|---|---|
| Contract/Schema Mismatch | 3 | CorrelationBundle LLM output vs. TypeScript interface |
| Missing Orchestration | 2 | No auto-chaining, two disconnected paths |
| Concurrency/Data Integrity | 3 | State machine race conditions, double-write |
| Silent Failures | 4 | Empty catches, stale processing, no LLM retry |
| MySQL Lock-in | 2 | `FIELD()`, `TIMESTAMPDIFF()` |
| Type Safety | 3 | `as any` everywhere, unsafe casts |

**The single biggest issue** is the CorrelationBundle contract mismatch (Finding #1). The TypeScript `CorrelationBundle` interface, the JSON schema sent to the LLM, and the fields accessed by downstream consumers (hypothesis agent, report service, frontend) are three different shapes. This means the pipeline's middle stage produces data that neither matches its contract nor works with its consumers, and `as any` casts hide the compile-time errors.
