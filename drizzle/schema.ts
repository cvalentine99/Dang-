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
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
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
