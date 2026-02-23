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
// Knowledge Graph Tables — HybridRAG Integration
// Models the Labelled Property Graph schema from the HybridRAG specification.
// Nodes: Endpoint, Process, NetworkPort, SoftwarePackage, Identity, Vulnerability, SecurityEvent
// Edges: stored as foreign key relationships between tables.
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Graph Node: Endpoint — represents a Wazuh agent / managed host.
 */
export const graphEndpoints = mysqlTable("graph_endpoints", {
  id: int("id").autoincrement().primaryKey(),
  agentId: varchar("agentId", { length: 32 }).notNull().unique(),
  hostname: varchar("hostname", { length: 256 }),
  ipAddress: varchar("ipAddress", { length: 64 }),
  osName: varchar("osName", { length: 128 }),
  osVersion: varchar("osVersion", { length: 128 }),
  osPlatform: varchar("osPlatform", { length: 64 }),
  architecture: varchar("architecture", { length: 32 }),
  agentVersion: varchar("agentVersion", { length: 64 }),
  agentStatus: varchar("agentStatus", { length: 32 }),
  lastKeepAlive: timestamp("lastKeepAlive"),
  syncedAt: timestamp("syncedAt").defaultNow().notNull(),
}, (table) => ([
  index("ge_agentId_idx").on(table.agentId),
  index("ge_hostname_idx").on(table.hostname),
]));

export type GraphEndpoint = typeof graphEndpoints.$inferSelect;

/**
 * Graph Node: Process — running process on an endpoint.
 * Edge: (:Endpoint)-->(:Process) via endpointId FK
 */
export const graphProcesses = mysqlTable("graph_processes", {
  id: int("id").autoincrement().primaryKey(),
  endpointId: int("endpointId").notNull(),
  processName: varchar("processName", { length: 256 }).notNull(),
  pid: int("pid"),
  ppid: int("ppid"),
  state: varchar("state", { length: 32 }),
  userName: varchar("userName", { length: 128 }),
  cmdLine: text("cmdLine"),
  syncedAt: timestamp("syncedAt").defaultNow().notNull(),
}, (table) => ([
  index("gp_endpointId_idx").on(table.endpointId),
  index("gp_processName_idx").on(table.processName),
]));

export type GraphProcess = typeof graphProcesses.$inferSelect;

/**
 * Graph Node: NetworkPort — listening port on an endpoint.
 * Edge: (:Process)-->(:NetworkPort) via processId FK
 * Edge: (:Endpoint)-->(:NetworkPort) via endpointId FK
 */
export const graphNetworkPorts = mysqlTable("graph_network_ports", {
  id: int("id").autoincrement().primaryKey(),
  endpointId: int("endpointId").notNull(),
  processId: int("processId"),
  localPort: int("localPort").notNull(),
  localIp: varchar("localIp", { length: 64 }),
  remoteIp: varchar("remoteIp", { length: 64 }),
  remotePort: int("remotePort"),
  protocol: varchar("protocol", { length: 16 }),
  state: varchar("state", { length: 32 }),
  syncedAt: timestamp("syncedAt").defaultNow().notNull(),
}, (table) => ([
  index("gnp_endpointId_idx").on(table.endpointId),
  index("gnp_localPort_idx").on(table.localPort),
]));

export type GraphNetworkPort = typeof graphNetworkPorts.$inferSelect;

/**
 * Graph Node: SoftwarePackage — installed package on an endpoint.
 * Edge: (:Endpoint)-->(:SoftwarePackage) via endpointId FK
 */
export const graphSoftwarePackages = mysqlTable("graph_software_packages", {
  id: int("id").autoincrement().primaryKey(),
  endpointId: int("endpointId").notNull(),
  packageName: varchar("packageName", { length: 256 }).notNull(),
  version: varchar("version", { length: 128 }),
  architecture: varchar("architecture", { length: 32 }),
  vendor: varchar("vendor", { length: 256 }),
  format: varchar("format", { length: 32 }),
  description: text("description"),
  syncedAt: timestamp("syncedAt").defaultNow().notNull(),
}, (table) => ([
  index("gsp_endpointId_idx").on(table.endpointId),
  index("gsp_packageName_idx").on(table.packageName),
]));

export type GraphSoftwarePackage = typeof graphSoftwarePackages.$inferSelect;

/**
 * Graph Node: Identity — local user account on an endpoint.
 * Edge: (:Endpoint)-->(:Identity) via endpointId FK
 * Edge: (:Identity)-->(:Process) via identity running processes
 */
export const graphIdentities = mysqlTable("graph_identities", {
  id: int("id").autoincrement().primaryKey(),
  endpointId: int("endpointId").notNull(),
  username: varchar("username", { length: 128 }).notNull(),
  uid: varchar("uid", { length: 32 }),
  gid: varchar("gid", { length: 32 }),
  homeDir: varchar("homeDir", { length: 512 }),
  shell: varchar("shell", { length: 128 }),
  isAdmin: int("isAdmin").default(0).notNull(),
  userType: varchar("userType", { length: 32 }),
  syncedAt: timestamp("syncedAt").defaultNow().notNull(),
}, (table) => ([
  index("gi_endpointId_idx").on(table.endpointId),
  index("gi_username_idx").on(table.username),
]));

export type GraphIdentity = typeof graphIdentities.$inferSelect;

/**
 * Graph Node: Vulnerability — CVE affecting a software package.
 * Edge: (:SoftwarePackage)-->(:Vulnerability) via packageId FK
 * Edge: (:Endpoint)-->(:Vulnerability) via endpointId FK
 */
export const graphVulnerabilities = mysqlTable("graph_vulnerabilities", {
  id: int("id").autoincrement().primaryKey(),
  endpointId: int("endpointId").notNull(),
  packageId: int("packageId"),
  cveId: varchar("cveId", { length: 32 }).notNull(),
  cvssScore: varchar("cvssScore", { length: 8 }),
  severity: varchar("severity", { length: 16 }),
  status: varchar("status", { length: 32 }),
  packageName: varchar("packageName", { length: 256 }),
  packageVersion: varchar("packageVersion", { length: 128 }),
  title: text("title"),
  publishedAt: timestamp("publishedAt"),
  detectedAt: timestamp("detectedAt"),
  syncedAt: timestamp("syncedAt").defaultNow().notNull(),
}, (table) => ([
  index("gv_endpointId_idx").on(table.endpointId),
  index("gv_cveId_idx").on(table.cveId),
  index("gv_severity_idx").on(table.severity),
]));

export type GraphVulnerability = typeof graphVulnerabilities.$inferSelect;

/**
 * Graph Node: SecurityEvent — alert/event from Wazuh.
 * Edge: (:SecurityEvent)-->(:Endpoint) via endpointId FK
 */
export const graphSecurityEvents = mysqlTable("graph_security_events", {
  id: int("id").autoincrement().primaryKey(),
  endpointId: int("endpointId"),
  alertId: varchar("alertId", { length: 64 }),
  ruleId: varchar("ruleId", { length: 32 }).notNull(),
  ruleLevel: int("ruleLevel"),
  ruleDescription: text("ruleDescription"),
  mitreTactic: varchar("mitreTactic", { length: 128 }),
  mitreTechnique: varchar("mitreTechnique", { length: 128 }),
  mitreId: varchar("mitreId", { length: 32 }),
  agentId: varchar("agentId", { length: 32 }),
  agentName: varchar("agentName", { length: 256 }),
  srcIp: varchar("srcIp", { length: 64 }),
  dstIp: varchar("dstIp", { length: 64 }),
  eventTimestamp: timestamp("eventTimestamp"),
  rawData: json("rawData").$type<Record<string, unknown>>(),
  syncedAt: timestamp("syncedAt").defaultNow().notNull(),
}, (table) => ([
  index("gse_endpointId_idx").on(table.endpointId),
  index("gse_ruleId_idx").on(table.ruleId),
  index("gse_mitreTactic_idx").on(table.mitreTactic),
  index("gse_agentId_idx").on(table.agentId),
  index("gse_eventTimestamp_idx").on(table.eventTimestamp),
]));

export type GraphSecurityEvent = typeof graphSecurityEvents.$inferSelect;

/**
 * ETL Sync Status — tracks the last sync time and entity counts per category.
 */
export const graphSyncStatus = mysqlTable("graph_sync_status", {
  id: int("id").autoincrement().primaryKey(),
  entityType: varchar("entityType", { length: 64 }).notNull().unique(),
  lastSyncAt: timestamp("lastSyncAt"),
  entityCount: int("entityCount").default(0).notNull(),
  status: mysqlEnum("status", ["idle", "syncing", "completed", "error"]).default("idle").notNull(),
  errorMessage: text("errorMessage"),
  durationMs: int("durationMs"),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type GraphSyncStatus = typeof graphSyncStatus.$inferSelect;

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
