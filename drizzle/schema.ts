import {
  index,
  int,
  mysqlEnum,
  mysqlTable,
  text,
  timestamp,
  varchar,
  json,
} from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow.
 */
export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  /** Bcrypt hash for local auth (null for OAuth-only users) */
  passwordHash: varchar("passwordHash", { length: 256 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  /** Whether the user account is disabled (blocked from login) */
  isDisabled: int("isDisabled").default(0).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

/**
 * Analyst notes — local-only, never written back to Wazuh.
 * Supports linking notes to agent IDs, rule IDs, CVE IDs, or free-form tags.
 */
export const analystNotes = mysqlTable("analyst_notes", {
  id: int("id").autoincrement().primaryKey(),
  /** Title / headline of the note */
  title: varchar("title", { length: 512 }).notNull(),
  /** Markdown body */
  content: text("content").notNull(),
  /** Severity classification chosen by analyst */
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low", "info"])
    .default("info")
    .notNull(),
  /** Wazuh agent ID this note relates to (optional) */
  agentId: varchar("agentId", { length: 32 }),
  /** Wazuh rule ID this note relates to (optional) */
  ruleId: varchar("ruleId", { length: 32 }),
  /** CVE identifier (optional) */
  cveId: varchar("cveId", { length: 32 }),
  /** Arbitrary JSON tags for flexible categorization */
  tags: json("tags").$type<string[]>(),
  /** Whether the note has been resolved/closed */
  resolved: int("resolved").default(0).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type AnalystNote = typeof analystNotes.$inferSelect;
export type InsertAnalystNote = typeof analystNotes.$inferInsert;

/**
 * HybridRAG chat sessions — stores conversation history for the AI assistant.
 */
export const ragSessions = mysqlTable("rag_sessions", {
  id: int("id").autoincrement().primaryKey(),
  /** Session identifier for grouping messages */
  sessionId: varchar("sessionId", { length: 64 }).notNull(),
  /** Role: user | assistant | system */
  role: mysqlEnum("role", ["user", "assistant", "system"]).notNull(),
  /** Message content */
  content: text("content").notNull(),
  /** Optional context snapshot injected for this message */
  contextSnapshot: json("contextSnapshot").$type<Record<string, unknown>>(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type RagSession = typeof ragSessions.$inferSelect;
export type InsertRagSession = typeof ragSessions.$inferInsert;

/**
 * Saved search queries — persists SIEM and Threat Hunting search filters.
 */
export const savedSearches = mysqlTable("saved_searches", {
  id: int("id").autoincrement().primaryKey(),
  /** User who saved this search */
  userId: int("userId").notNull(),
  /** Human-readable name for the saved search */
  name: varchar("name", { length: 256 }).notNull(),
  /** Type of search: 'siem' or 'hunting' */
  searchType: mysqlEnum("searchType", ["siem", "hunting"]).notNull(),
  /** Serialized filter state (JSON) */
  filters: json("filters").$type<Record<string, unknown>>().notNull(),
  /** Optional description */
  description: text("description"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type SavedSearch = typeof savedSearches.$inferSelect;
export type InsertSavedSearch = typeof savedSearches.$inferInsert;

/**
 * Configuration baselines — "known-good" snapshots of agent packages, services, and users.
 * Used for drift detection over time. Never written back to Wazuh.
 */
export const configBaselines = mysqlTable("config_baselines", {
  id: int("id").autoincrement().primaryKey(),
  /** User who created this baseline */
  userId: int("userId").notNull(),
  /** Human-readable name for the baseline */
  name: varchar("name", { length: 256 }).notNull(),
  /** Optional description */
  description: text("description"),
  /** Comma-separated agent IDs included in this baseline */
  agentIds: json("agentIds").$type<string[]>().notNull(),
  /** Full snapshot: { packages: Record<agentId, pkg[]>, services: Record<agentId, svc[]>, users: Record<agentId, usr[]> } */
  snapshotData: json("snapshotData").$type<Record<string, unknown>>().notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type ConfigBaseline = typeof configBaselines.$inferSelect;
export type InsertConfigBaseline = typeof configBaselines.$inferInsert;

/**
 * Analyst Notes v2 — Enhanced note-taking system with entity linking.
 * Supports annotating alerts, agents, CVEs, rules, and free-form notes.
 * Local-only: never written back to Wazuh.
 */
export const analystNotesV2 = mysqlTable("analyst_notes_v2", {
  id: int("id").autoincrement().primaryKey(),
  /** User who created this note */
  userId: int("userId").notNull(),
  /** Entity type this note is attached to */
  entityType: mysqlEnum("entityType", ["alert", "agent", "cve", "rule", "general"]).notNull(),
  /** Entity identifier (alert ID, agent ID, CVE ID, rule ID, or empty for general) */
  entityId: varchar("entityId", { length: 128 }).default("").notNull(),
  /** Title / headline of the note */
  title: varchar("title", { length: 512 }).notNull(),
  /** Markdown body */
  content: text("content").notNull(),
  /** Severity classification chosen by analyst */
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low", "info"])
    .default("info")
    .notNull(),
  /** Comma-separated tags for flexible categorization */
  tags: json("tags").$type<string[]>(),
  /** Whether the note has been resolved/closed */
  resolved: int("resolved").default(0).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, (table) => ([
  index("notes_v2_userId_idx").on(table.userId),
  index("notes_v2_entityType_idx").on(table.entityType),
  index("notes_v2_entityId_idx").on(table.entityId),
  index("notes_v2_entity_lookup_idx").on(table.entityType, table.entityId),
]));

export type AnalystNoteV2 = typeof analystNotesV2.$inferSelect;
export type InsertAnalystNoteV2 = typeof analystNotesV2.$inferInsert;

// ══════════════════════════════════════════════════════════════════════════════
// Knowledge Graph — 4-Layer Nemotron-3 Nano Architecture
// Layer 1: API Ontology Graph (endpoints, parameters, responses, auth, resources)
// Layer 2: Operational Semantics Graph (use cases, risk classification)
// Layer 3: Schema & Field Lineage Graph (indices, fields, data flow)
// Layer 4: Error & Failure Graph (error patterns, causes, mitigations)
// Plus: Trust scoring, answer provenance, sync status
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Layer 1: API Endpoints — every Wazuh REST endpoint with risk classification.
 */
export const kgEndpoints = mysqlTable("kg_endpoints", {
  id: int("id").autoincrement().primaryKey(),
  endpointId: varchar("endpoint_id", { length: 128 }),
  path: varchar("path", { length: 512 }).notNull(),
  method: varchar("method", { length: 10 }).notNull(),
  summary: text("summary"),
  description: text("description"),
  tags: json("tags").$type<string[]>(),
  operationId: varchar("operation_id", { length: 128 }),
  resource: varchar("resource", { length: 64 }).notNull(),
  operationType: varchar("operation_type", { length: 16 }).notNull(),
  riskLevel: varchar("risk_level", { length: 16 }).notNull(),
  allowedForLlm: int("allowed_for_llm").default(1).notNull(),
  authMethod: varchar("auth_method", { length: 64 }),
  trustScore: varchar("trust_score", { length: 8 }).default("1.0").notNull(),
  deprecated: int("deprecated").default(0).notNull(),
  lastVerifiedAt: timestamp("last_verified_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow().notNull(),
}, (table) => ([
  index("kge_method_idx").on(table.method),
  index("kge_resource_idx").on(table.resource),
  index("kge_risk_level_idx").on(table.riskLevel),
  index("kge_path_idx").on(table.path),
]));

export type KgEndpoint = typeof kgEndpoints.$inferSelect;
export type InsertKgEndpoint = typeof kgEndpoints.$inferInsert;

/**
 * Layer 1: API Parameters — query/path/body parameters for each endpoint.
 */
export const kgParameters = mysqlTable("kg_parameters", {
  id: int("id").autoincrement().primaryKey(),
  endpointId: int("endpoint_id").notNull(),
  name: varchar("name", { length: 128 }).notNull(),
  location: varchar("location", { length: 16 }).notNull(),
  required: int("required").default(0).notNull(),
  paramType: varchar("param_type", { length: 32 }).notNull(),
  description: text("description"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => ([
  index("kgp_endpoint_id_idx").on(table.endpointId),
  index("kgp_name_idx").on(table.name),
]));

export type KgParameter = typeof kgParameters.$inferSelect;

/**
 * Layer 1: API Responses — response codes and schemas for each endpoint.
 */
export const kgResponses = mysqlTable("kg_responses", {
  id: int("id").autoincrement().primaryKey(),
  endpointId: int("endpoint_id").notNull(),
  httpStatus: int("http_status").notNull(),
  description: text("description"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => ([
  index("kgr_endpoint_id_idx").on(table.endpointId),
]));

export type KgResponse = typeof kgResponses.$inferSelect;

/**
 * Layer 1: Auth Methods — authentication mechanisms supported by the API.
 */
export const kgAuthMethods = mysqlTable("kg_auth_methods", {
  id: int("id").autoincrement().primaryKey(),
  authId: varchar("auth_id", { length: 64 }).notNull(),
  authType: varchar("auth_type", { length: 32 }).notNull(),
  description: text("description"),
  ttlSeconds: int("ttl_seconds"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export type KgAuthMethod = typeof kgAuthMethods.$inferSelect;

/**
 * Layer 1: Resources — API resource categories (agents, manager, cluster, etc.).
 */
export const kgResources = mysqlTable("kg_resources", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 64 }).notNull().unique(),
  endpointCount: int("endpoint_count").default(0).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export type KgResource = typeof kgResources.$inferSelect;

/**
 * Layer 2: Use Cases — operational use case patterns that map to endpoint groups.
 */
export const kgUseCases = mysqlTable("kg_use_cases", {
  id: int("id").autoincrement().primaryKey(),
  intent: varchar("intent", { length: 128 }).notNull(),
  semanticType: varchar("semantic_type", { length: 64 }).notNull(),
  domain: varchar("domain", { length: 64 }).notNull(),
  description: text("description"),
  endpointIds: json("endpoint_ids").$type<number[]>(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow().notNull(),
});

export type KgUseCase = typeof kgUseCases.$inferSelect;

/**
 * Layer 3: Index Patterns — Wazuh Indexer index patterns and their schemas.
 */
export const kgIndices = mysqlTable("kg_indices", {
  id: int("id").autoincrement().primaryKey(),
  pattern: varchar("pattern", { length: 256 }).notNull(),
  description: text("description"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export type KgIndex = typeof kgIndices.$inferSelect;

/**
 * Layer 3: Fields — individual fields within index patterns.
 */
export const kgFields = mysqlTable("kg_fields", {
  id: int("id").autoincrement().primaryKey(),
  indexId: int("index_id").notNull(),
  fieldName: varchar("field_name", { length: 256 }).notNull(),
  fieldType: varchar("field_type", { length: 32 }).notNull(),
  description: text("description"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => ([
  index("kgf_index_id_idx").on(table.indexId),
  index("kgf_field_name_idx").on(table.fieldName),
]));

export type KgField = typeof kgFields.$inferSelect;

/**
 * Layer 4: Error Patterns — known error codes, causes, and mitigations.
 */
export const kgErrorPatterns = mysqlTable("kg_error_patterns", {
  id: int("id").autoincrement().primaryKey(),
  httpStatus: int("http_status").notNull(),
  description: text("description"),
  cause: text("cause"),
  mitigation: text("mitigation"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export type KgErrorPattern = typeof kgErrorPatterns.$inferSelect;

/**
 * Trust History — tracks trust score changes for endpoints over time.
 */
export const kgTrustHistory = mysqlTable("kg_trust_history", {
  id: int("id").autoincrement().primaryKey(),
  endpointId: int("endpoint_id").notNull(),
  oldScore: varchar("old_score", { length: 8 }).notNull(),
  newScore: varchar("new_score", { length: 8 }).notNull(),
  reason: text("reason"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => ([
  index("kgth_endpoint_id_idx").on(table.endpointId),
]));

export type KgTrustHistory = typeof kgTrustHistory.$inferSelect;

/**
 * Answer Provenance — tracks which KG nodes were used to generate each LLM answer.
 */
export const kgAnswerProvenance = mysqlTable("kg_answer_provenance", {
  id: int("id").autoincrement().primaryKey(),
  sessionId: varchar("session_id", { length: 64 }).notNull(),
  question: text("question").notNull(),
  answer: text("answer"),
  confidence: varchar("confidence", { length: 8 }),
  endpointIds: json("endpoint_ids").$type<number[]>(),
  parameterIds: json("parameter_ids").$type<number[]>(),
  docChunkIds: json("doc_chunk_ids").$type<number[]>(),
  warnings: json("warnings").$type<string[]>(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => ([
  index("kgap_session_id_idx").on(table.sessionId),
]));

export type KgAnswerProvenance = typeof kgAnswerProvenance.$inferSelect;

/**
 * KG Sync Status — tracks extraction pipeline runs per layer.
 */
export const kgSyncStatus = mysqlTable("kg_sync_status", {
  id: int("id").autoincrement().primaryKey(),
  layer: varchar("layer", { length: 64 }).notNull().unique(),
  entityCount: int("entity_count").default(0).notNull(),
  lastSyncAt: timestamp("last_sync_at"),
  status: mysqlEnum("status", ["idle", "syncing", "completed", "error"]).default("idle").notNull(),
  errorMessage: text("error_message"),
  durationMs: int("duration_ms"),
  specVersion: varchar("spec_version", { length: 32 }),
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow().notNull(),
});

export type KgSyncStatus = typeof kgSyncStatus.$inferSelect;

/**
 * Investigation Sessions — analyst investigation workspaces.
 * Each session groups evidence, notes, and chat history for a specific investigation.
 */
export const investigationSessions = mysqlTable("investigation_sessions", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  title: varchar("title", { length: 512 }).notNull(),
  description: text("description"),
  status: mysqlEnum("status", ["active", "closed", "archived"]).default("active").notNull(),
  /** JSON array of evidence items collected during investigation */
  evidence: json("evidence").$type<Array<{
    type: string;
    label: string;
    data: Record<string, unknown>;
    addedAt: string;
  }>>(),
  /** JSON array of timeline entries */
  timeline: json("timeline").$type<Array<{
    timestamp: string;
    event: string;
    source: string;
    severity?: string;
  }>>(),
  tags: json("tags").$type<string[]>(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, (table) => ([
  index("is_userId_idx").on(table.userId),
  index("is_status_idx").on(table.status),
]));

export type InvestigationSession = typeof investigationSessions.$inferSelect;
export type InsertInvestigationSession = typeof investigationSessions.$inferInsert;

/**
 * Investigation Notes — per-investigation analyst notes.
 */
export const investigationNotes = mysqlTable("investigation_notes", {
  id: int("id").autoincrement().primaryKey(),
  sessionId: int("sessionId").notNull(),
  userId: int("userId").notNull(),
  content: text("content").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, (table) => ([
  index("in_sessionId_idx").on(table.sessionId),
]));

export type InvestigationNote = typeof investigationNotes.$inferSelect;

/**
 * Connection Settings — runtime-configurable connection parameters.
 * Allows admins to update Wazuh Manager and Indexer credentials from the UI
 * without restarting Docker. Values override environment variables.
 * Sensitive values (passwords) are AES-256 encrypted at rest.
 */
export const connectionSettings = mysqlTable("connection_settings", {
  id: int("id").autoincrement().primaryKey(),
  /** Setting category: 'wazuh_manager' | 'wazuh_indexer' */
  category: varchar("category", { length: 64 }).notNull(),
  /** Setting key: 'host', 'port', 'user', 'pass', 'protocol' */
  settingKey: varchar("settingKey", { length: 64 }).notNull(),
  /** Setting value (encrypted for sensitive fields like passwords) */
  settingValue: text("settingValue").notNull(),
  /** Whether this value is encrypted */
  isEncrypted: int("isEncrypted").default(0).notNull(),
  /** Admin who last updated this setting */
  updatedBy: int("updatedBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, (table) => ([
  index("cs_category_key_idx").on(table.category, table.settingKey),
]));

export type ConnectionSetting = typeof connectionSettings.$inferSelect;
export type InsertConnectionSetting = typeof connectionSettings.$inferInsert;

/**
 * LLM Usage Tracking — logs every LLM invocation for monitoring and analytics.
 * Tracks token counts, latency, model used, and whether it was custom or built-in.
 */
export const llmUsage = mysqlTable("llm_usage", {
  id: int("id").autoincrement().primaryKey(),
  /** Model identifier (e.g., 'unsloth/Nemotron-3-Nano-30B-A3B-GGUF' or 'gemini-2.5-flash') */
  model: varchar("model", { length: 256 }).notNull(),
  /** Source of the response: 'custom', 'builtin', or 'fallback' (custom failed, fell back) */
  source: varchar("source", { length: 32 }).notNull(),
  /** Number of tokens in the prompt */
  promptTokens: int("promptTokens").default(0).notNull(),
  /** Number of tokens in the completion */
  completionTokens: int("completionTokens").default(0).notNull(),
  /** Total tokens (prompt + completion) */
  totalTokens: int("totalTokens").default(0).notNull(),
  /** Latency in milliseconds for the LLM call */
  latencyMs: int("latencyMs").default(0).notNull(),
  /** Caller context: which feature triggered this call */
  caller: varchar("caller", { length: 128 }),
  /** Whether the call succeeded */
  success: int("success").default(1).notNull(),
  /** Error message if the call failed */
  errorMessage: text("errorMessage"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, (table) => ([
  index("lu_source_idx").on(table.source),
  index("lu_model_idx").on(table.model),
  index("lu_created_idx").on(table.createdAt),
]));

export type LlmUsage = typeof llmUsage.$inferSelect;
export type InsertLlmUsage = typeof llmUsage.$inferInsert;

/**
 * Alert Queue — 10-deep FIFO queue for alerts awaiting Walter analysis.
 * Analysts queue alerts from the Alerts Timeline, then click to trigger
 * Walter's full agentic pipeline on demand. Max 10 items; oldest evicted.
 */
export const alertQueue = mysqlTable("alert_queue", {
  id: int("id").autoincrement().primaryKey(),
  /** Wazuh alert ID (from _id or id field) */
  alertId: varchar("alertId", { length: 128 }).notNull(),
  /** Rule ID that fired */
  ruleId: varchar("ruleId", { length: 32 }).notNull(),
  /** Rule description */
  ruleDescription: text("ruleDescription"),
  /** Rule severity level (0-15) */
  ruleLevel: int("ruleLevel").default(0).notNull(),
  /** Agent ID */
  agentId: varchar("agentId", { length: 16 }),
  /** Agent name */
  agentName: varchar("agentName", { length: 128 }),
  /** Alert timestamp from Wazuh */
  alertTimestamp: varchar("alertTimestamp", { length: 64 }),
  /** Full raw alert JSON for Walter context */
  rawJson: json("rawJson").$type<Record<string, unknown>>(),
  /** Queue status: queued → processing → completed → failed → dismissed */
  status: mysqlEnum("status", ["queued", "processing", "completed", "failed", "dismissed"]).default("queued").notNull(),
  /** Walter's triage result (stored after analysis completes) */
  triageResult: json("triageResult").$type<{
    answer: string;
    reasoning?: string;
    trustScore?: number;
    confidence?: number;
    safetyStatus?: string;
    agentSteps?: Array<Record<string, unknown>>;
    sources?: Array<Record<string, unknown>>;
    suggestedFollowUps?: string[];
    provenance?: Record<string, unknown>;
  }>(),
  /** User who queued this alert */
  queuedBy: int("queuedBy"),
  /** When the alert was queued */
  queuedAt: timestamp("queuedAt").defaultNow().notNull(),
  /** When Walter started processing */
  processedAt: timestamp("processedAt"),
  /** When Walter completed analysis */
  completedAt: timestamp("completedAt"),
}, (table) => ([
  index("aq_status_idx").on(table.status),
  index("aq_alertId_idx").on(table.alertId),
  index("aq_queuedAt_idx").on(table.queuedAt),
]));

export type AlertQueueItem = typeof alertQueue.$inferSelect;
export type InsertAlertQueueItem = typeof alertQueue.$inferInsert;

/**
 * Auto-queue rules — configurable rules that automatically send matching
 * Wazuh alerts to Walter's queue without manual analyst intervention.
 *
 * Rules are evaluated against incoming alerts from the Wazuh Indexer.
 * When an alert matches a rule, it is automatically enqueued for Walter analysis.
 *
 * Rule types:
 * - severity_threshold: Queue any alert at or above a severity level
 * - rule_id: Queue alerts matching specific Wazuh rule IDs
 * - agent_pattern: Queue alerts from agents matching a name/ID pattern
 * - combined: All conditions must match (AND logic)
 */
export const autoQueueRules = mysqlTable("auto_queue_rules", {
  id: int("id").autoincrement().primaryKey(),
  /** Human-readable name for the rule */
  name: varchar("name", { length: 256 }).notNull(),
  /** Whether this rule is active */
  enabled: int("enabled").default(1).notNull(),
  /** Minimum severity level (0-15) to trigger auto-queue. Null = no severity filter */
  minSeverity: int("minSeverity"),
  /** Comma-separated Wazuh rule IDs to match. Null = no rule ID filter */
  ruleIds: text("ruleIds"),
  /** Agent name/ID pattern (supports * wildcard). Null = no agent filter */
  agentPattern: varchar("agentPattern", { length: 256 }),
  /** MITRE technique IDs to match (comma-separated). Null = no MITRE filter */
  mitreTechniqueIds: text("mitreTechniqueIds"),
  /** Maximum alerts this rule can auto-queue per hour (rate limit) */
  maxPerHour: int("maxPerHour").default(10).notNull(),
  /** Count of alerts auto-queued by this rule in the current hour window */
  currentHourCount: int("currentHourCount").default(0).notNull(),
  /** Timestamp of the current hour window start */
  currentHourStart: timestamp("currentHourStart"),
  /** User who created this rule */
  createdBy: int("createdBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, (table) => ([
  index("aqr_enabled_idx").on(table.enabled),
]));

export type AutoQueueRule = typeof autoQueueRules.$inferSelect;
export type InsertAutoQueueRule = typeof autoQueueRules.$inferInsert;
