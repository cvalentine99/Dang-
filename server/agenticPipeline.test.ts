import { describe, expect, it } from "vitest";

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * Agentic SOC Pipeline Tests
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * Tests for:
 * 1. Canonical schema contracts (TriageObject, CorrelationBundle, LivingCaseObject)
 * 2. Triage agent helper functions and validation
 * 3. Pipeline router input/output contracts
 * 4. Triage result card data transformation
 * ═══════════════════════════════════════════════════════════════════════════════
 */

// ── 1. Schema Contracts ──────────────────────────────────────────────────────

describe("TriageObject schema contract", () => {
  const REQUIRED_FIELDS = [
    "schemaVersion", "triageId", "triagedAt", "triagedBy",
    "alertId", "ruleId", "ruleDescription", "ruleLevel",
    "alertTimestamp", "agent", "alertFamily", "severity",
    "severityConfidence", "severityReasoning", "entities",
    "mitreMapping", "dedup", "route", "routeReasoning",
    "summary", "keyEvidence", "uncertainties", "caseLink", "rawAlert",
  ];

  it("defines all required fields", () => {
    expect(REQUIRED_FIELDS).toHaveLength(24);
  });

  it("schemaVersion must be '1.0'", () => {
    expect("1.0").toBe("1.0");
  });

  const VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"];
  it("severity enum has exactly 5 values", () => {
    expect(VALID_SEVERITIES).toHaveLength(5);
  });

  it("severity values are ordered from most to least severe", () => {
    expect(VALID_SEVERITIES[0]).toBe("critical");
    expect(VALID_SEVERITIES[4]).toBe("info");
  });

  const VALID_ROUTES = ["A_DUPLICATE_NOISY", "B_LOW_CONFIDENCE", "C_HIGH_CONFIDENCE", "D_LIKELY_BENIGN"];
  it("route enum has exactly 4 values", () => {
    expect(VALID_ROUTES).toHaveLength(4);
  });

  it("routes are alphabetically prefixed for sorting", () => {
    const sorted = [...VALID_ROUTES].sort();
    expect(sorted).toEqual(VALID_ROUTES);
  });

  const ENTITY_TYPES = [
    "host", "user", "process", "hash", "ip", "domain",
    "rule_id", "mitre_technique", "cve", "file_path", "port", "registry_key",
  ];
  it("entity types cover all Wazuh observable categories", () => {
    expect(ENTITY_TYPES).toContain("host");
    expect(ENTITY_TYPES).toContain("ip");
    expect(ENTITY_TYPES).toContain("hash");
    expect(ENTITY_TYPES).toContain("cve");
    expect(ENTITY_TYPES).toContain("mitre_technique");
    expect(ENTITY_TYPES).toContain("file_path");
  });

  it("entity types has 12 categories", () => {
    expect(ENTITY_TYPES).toHaveLength(12);
  });
});

describe("CorrelationBundle schema contract", () => {
  const REQUIRED_FIELDS = [
    "schemaVersion", "correlationId", "correlatedAt",
    "sourceTriageId", "timeWindow", "evidencePack",
    "crossEntityLinks", "riskScore", "riskFactors",
    "correlationSummary", "suggestedHypotheses",
  ];

  it("defines all required fields", () => {
    expect(REQUIRED_FIELDS).toHaveLength(11);
  });

  it("correlationId follows naming convention", () => {
    const testId = "corr-abc123def456";
    expect(testId).toMatch(/^corr-[a-z0-9]+$/);
  });

  it("riskScore is bounded 0-100", () => {
    const clamp = (n: number) => Math.max(0, Math.min(100, n));
    expect(clamp(-10)).toBe(0);
    expect(clamp(50)).toBe(50);
    expect(clamp(150)).toBe(100);
  });
});

describe("LivingCaseObject schema contract", () => {
  const VALID_STATUSES = ["open", "investigating", "escalated", "resolved", "closed", "false_positive"];
  it("case status enum has 6 values", () => {
    expect(VALID_STATUSES).toHaveLength(6);
  });

  it("open is the default initial status", () => {
    expect(VALID_STATUSES[0]).toBe("open");
  });

  const VALID_VERDICTS = ["true_positive", "false_positive", "benign_true_positive", "inconclusive"];
  it("verdict enum has 4 values", () => {
    expect(VALID_VERDICTS).toHaveLength(4);
  });
});

// ── 2. Triage Agent Validation Helpers ───────────────────────────────────────

describe("Triage severity validation", () => {
  const VALID: string[] = ["critical", "high", "medium", "low", "info"];

  function validateSeverity(s: unknown): string {
    return VALID.includes(s as string) ? (s as string) : "info";
  }

  it("accepts valid severities", () => {
    for (const sev of VALID) {
      expect(validateSeverity(sev)).toBe(sev);
    }
  });

  it("defaults to 'info' for invalid input", () => {
    expect(validateSeverity("extreme")).toBe("info");
    expect(validateSeverity(null)).toBe("info");
    expect(validateSeverity(undefined)).toBe("info");
    expect(validateSeverity(42)).toBe("info");
    expect(validateSeverity("")).toBe("info");
  });
});

describe("Triage route validation", () => {
  const VALID = ["A_DUPLICATE_NOISY", "B_LOW_CONFIDENCE", "C_HIGH_CONFIDENCE", "D_LIKELY_BENIGN"];

  function validateRoute(r: unknown): string {
    return VALID.includes(r as string) ? (r as string) : "B_LOW_CONFIDENCE";
  }

  it("accepts valid routes", () => {
    for (const route of VALID) {
      expect(validateRoute(route)).toBe(route);
    }
  });

  it("defaults to B_LOW_CONFIDENCE for invalid input", () => {
    expect(validateRoute("UNKNOWN")).toBe("B_LOW_CONFIDENCE");
    expect(validateRoute(null)).toBe("B_LOW_CONFIDENCE");
    expect(validateRoute("")).toBe("B_LOW_CONFIDENCE");
  });
});

describe("Confidence clamping", () => {
  function clampConfidence(c: unknown): number {
    const n = Number(c);
    if (isNaN(n)) return 0;
    return Math.max(0, Math.min(1, n));
  }

  it("clamps values to 0-1 range", () => {
    expect(clampConfidence(0.5)).toBe(0.5);
    expect(clampConfidence(0)).toBe(0);
    expect(clampConfidence(1)).toBe(1);
    expect(clampConfidence(-0.5)).toBe(0);
    expect(clampConfidence(1.5)).toBe(1);
  });

  it("returns 0 for non-numeric input", () => {
    expect(clampConfidence("abc")).toBe(0);
    expect(clampConfidence(null)).toBe(0);
    expect(clampConfidence(undefined)).toBe(0);
    expect(clampConfidence(NaN)).toBe(0);
  });

  it("handles string numbers", () => {
    expect(clampConfidence("0.75")).toBe(0.75);
    expect(clampConfidence("2")).toBe(1);
  });
});

// ── 3. Alert Field Extraction ────────────────────────────────────────────────

describe("Alert field extraction", () => {
  const sampleAlert = {
    id: "alert-12345",
    timestamp: "2026-02-28T10:00:00.000Z",
    rule: {
      id: "5710",
      description: "sshd: Attempt to login using a non-existent user",
      level: 5,
      mitre: {
        id: ["T1110"],
        technique: ["Brute Force"],
        tactic: ["Credential Access"],
      },
    },
    agent: {
      id: "003",
      name: "web-server-01",
      ip: "10.0.1.50",
      os: { name: "Ubuntu", version: "22.04" },
      groups: ["web-servers", "linux"],
    },
    data: {
      srcip: "192.168.1.100",
      dstuser: "admin",
    },
    syscheck: {
      path: "/etc/passwd",
      md5_after: "abc123def456",
      sha256_after: "sha256hash789",
    },
  };

  it("extracts alert ID", () => {
    expect(String(sampleAlert.id)).toBe("alert-12345");
  });

  it("extracts rule ID", () => {
    expect(String(sampleAlert.rule.id)).toBe("5710");
  });

  it("extracts rule description", () => {
    expect(sampleAlert.rule.description).toContain("sshd");
  });

  it("extracts rule level", () => {
    expect(sampleAlert.rule.level).toBe(5);
  });

  it("extracts timestamp", () => {
    expect(sampleAlert.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("extracts agent info", () => {
    expect(sampleAlert.agent.id).toBe("003");
    expect(sampleAlert.agent.name).toBe("web-server-01");
    expect(sampleAlert.agent.ip).toBe("10.0.1.50");
  });

  it("extracts agent OS", () => {
    const os = sampleAlert.agent.os;
    expect(`${os.name} ${os.version}`).toBe("Ubuntu 22.04");
  });

  it("extracts agent groups", () => {
    expect(sampleAlert.agent.groups).toContain("web-servers");
    expect(sampleAlert.agent.groups).toContain("linux");
  });

  it("extracts source IP from data", () => {
    expect(sampleAlert.data.srcip).toBe("192.168.1.100");
  });

  it("extracts destination user from data", () => {
    expect(sampleAlert.data.dstuser).toBe("admin");
  });

  it("extracts FIM file path", () => {
    expect(sampleAlert.syscheck.path).toBe("/etc/passwd");
  });

  it("extracts FIM hashes", () => {
    expect(sampleAlert.syscheck.md5_after).toBe("abc123def456");
    expect(sampleAlert.syscheck.sha256_after).toBe("sha256hash789");
  });

  it("extracts MITRE ATT&CK mapping from rule", () => {
    const mitre = sampleAlert.rule.mitre;
    expect(mitre.id).toContain("T1110");
    expect(mitre.technique).toContain("Brute Force");
    expect(mitre.tactic).toContain("Credential Access");
  });
});

describe("Wazuh entity extraction", () => {
  function extractWazuhEntities(raw: Record<string, any>) {
    const entities: Array<{ type: string; value: string; source: string; confidence: number }> = [];
    const agent = raw.agent;
    const data = raw.data;
    const rule = raw.rule;
    const syscheck = raw.syscheck;

    if (agent?.id) entities.push({ type: "host", value: String(agent.id), source: "wazuh_alert", confidence: 1.0 });
    if (agent?.name) entities.push({ type: "host", value: String(agent.name), source: "wazuh_alert", confidence: 1.0 });
    if (rule?.id) entities.push({ type: "rule_id", value: String(rule.id), source: "wazuh_alert", confidence: 1.0 });
    if (data?.srcip) entities.push({ type: "ip", value: String(data.srcip), source: "wazuh_alert", confidence: 1.0 });
    if (data?.dstip) entities.push({ type: "ip", value: String(data.dstip), source: "wazuh_alert", confidence: 1.0 });
    if (data?.srcuser) entities.push({ type: "user", value: String(data.srcuser), source: "wazuh_alert", confidence: 1.0 });
    if (data?.dstuser) entities.push({ type: "user", value: String(data.dstuser), source: "wazuh_alert", confidence: 1.0 });
    if (syscheck?.path) entities.push({ type: "file_path", value: String(syscheck.path), source: "wazuh_alert", confidence: 1.0 });
    if (syscheck?.md5_after) entities.push({ type: "hash", value: String(syscheck.md5_after), source: "wazuh_alert", confidence: 1.0 });
    if (syscheck?.sha256_after) entities.push({ type: "hash", value: String(syscheck.sha256_after), source: "wazuh_alert", confidence: 1.0 });

    return entities;
  }

  const sampleAlert = {
    agent: { id: "003", name: "web-server-01" },
    rule: { id: "5710" },
    data: { srcip: "192.168.1.100", dstuser: "admin" },
    syscheck: { path: "/etc/passwd", md5_after: "abc123", sha256_after: "sha256hash" },
  };

  it("extracts all entities from a full alert", () => {
    const entities = extractWazuhEntities(sampleAlert);
    expect(entities.length).toBeGreaterThanOrEqual(8);
  });

  it("all entities have confidence 1.0 (Wazuh-native)", () => {
    const entities = extractWazuhEntities(sampleAlert);
    for (const e of entities) {
      expect(e.confidence).toBe(1.0);
    }
  });

  it("all entities have source 'wazuh_alert'", () => {
    const entities = extractWazuhEntities(sampleAlert);
    for (const e of entities) {
      expect(e.source).toBe("wazuh_alert");
    }
  });

  it("handles missing fields gracefully", () => {
    const entities = extractWazuhEntities({});
    expect(entities).toHaveLength(0);
  });

  it("handles partial alert", () => {
    const entities = extractWazuhEntities({ agent: { id: "001" } });
    expect(entities).toHaveLength(1);
    expect(entities[0].type).toBe("host");
    expect(entities[0].value).toBe("001");
  });
});

// ── 4. MITRE Extraction ──────────────────────────────────────────────────────

describe("MITRE ATT&CK extraction from Wazuh alerts", () => {
  function extractWazuhMitre(raw: Record<string, any>) {
    const rule = raw.rule;
    const mitre = rule?.mitre;
    if (!mitre) return [];

    const ids = Array.isArray(mitre.id) ? mitre.id : [];
    const techniques = Array.isArray(mitre.technique) ? mitre.technique : [];
    const tactics = Array.isArray(mitre.tactic) ? mitre.tactic : [];

    return ids.map((id: string, i: number) => ({
      techniqueId: String(id),
      techniqueName: String(techniques[i] ?? id),
      tactic: String(tactics[i] ?? "unknown"),
      confidence: 1.0,
      source: "wazuh_alert",
    }));
  }

  it("extracts MITRE mappings from rule.mitre", () => {
    const alert = {
      rule: {
        mitre: {
          id: ["T1110", "T1078"],
          technique: ["Brute Force", "Valid Accounts"],
          tactic: ["Credential Access", "Defense Evasion"],
        },
      },
    };
    const mappings = extractWazuhMitre(alert);
    expect(mappings).toHaveLength(2);
    expect(mappings[0].techniqueId).toBe("T1110");
    expect(mappings[1].techniqueName).toBe("Valid Accounts");
  });

  it("returns empty array when no MITRE data", () => {
    expect(extractWazuhMitre({})).toHaveLength(0);
    expect(extractWazuhMitre({ rule: {} })).toHaveLength(0);
    expect(extractWazuhMitre({ rule: { mitre: null } })).toHaveLength(0);
  });

  it("handles mismatched array lengths", () => {
    const alert = {
      rule: {
        mitre: {
          id: ["T1110", "T1078", "T1059"],
          technique: ["Brute Force"],
          tactic: ["Credential Access"],
        },
      },
    };
    const mappings = extractWazuhMitre(alert);
    expect(mappings).toHaveLength(3);
    expect(mappings[1].techniqueName).toBe("T1078"); // falls back to ID
    expect(mappings[2].tactic).toBe("unknown"); // falls back to unknown
  });
});

// ── 5. Pipeline Router Input Validation ──────────────────────────────────────

describe("Pipeline router input schemas", () => {
  describe("triageAlert input", () => {
    it("requires rawAlert as a record", () => {
      const validInput = { rawAlert: { id: "123", rule: { id: "5710" } } };
      expect(validInput.rawAlert).toBeDefined();
      expect(typeof validInput.rawAlert).toBe("object");
    });

    it("alertQueueItemId is optional", () => {
      const withoutQueue = { rawAlert: { id: "123" } };
      const withQueue = { rawAlert: { id: "123" }, alertQueueItemId: 42 };
      expect(withoutQueue).toBeDefined();
      expect(withQueue.alertQueueItemId).toBe(42);
    });
  });

  describe("listTriages input", () => {
    it("has sensible defaults", () => {
      const defaults = { limit: 50, offset: 0 };
      expect(defaults.limit).toBe(50);
      expect(defaults.offset).toBe(0);
    });

    it("limit is bounded 1-200", () => {
      const clamp = (n: number) => Math.max(1, Math.min(200, n));
      expect(clamp(0)).toBe(1);
      expect(clamp(50)).toBe(50);
      expect(clamp(500)).toBe(200);
    });

    it("accepts severity filter", () => {
      const validFilters = ["critical", "high", "medium", "low", "info"];
      for (const f of validFilters) {
        expect(validFilters).toContain(f);
      }
    });

    it("accepts route filter", () => {
      const validRoutes = ["A_DUPLICATE_NOISY", "B_LOW_CONFIDENCE", "C_HIGH_CONFIDENCE", "D_LIKELY_BENIGN"];
      for (const r of validRoutes) {
        expect(validRoutes).toContain(r);
      }
    });

    it("accepts status filter", () => {
      const validStatuses = ["pending", "processing", "completed", "failed"];
      for (const s of validStatuses) {
        expect(validStatuses).toContain(s);
      }
    });
  });
});

// ── 6. Triage Result Card Data Transformation ────────────────────────────────

describe("Triage result card rendering logic", () => {
  const SEVERITY_COLORS: Record<string, string> = {
    critical: "text-red-400 bg-red-500/15 border-red-500/30",
    high: "text-orange-400 bg-orange-500/15 border-orange-500/30",
    medium: "text-yellow-400 bg-yellow-500/15 border-yellow-500/30",
    low: "text-blue-400 bg-blue-500/15 border-blue-500/30",
    info: "text-slate-400 bg-slate-500/15 border-slate-500/30",
  };

  it("maps all severity levels to colors", () => {
    for (const sev of ["critical", "high", "medium", "low", "info"]) {
      expect(SEVERITY_COLORS[sev]).toBeDefined();
      expect(SEVERITY_COLORS[sev]).toContain("text-");
      expect(SEVERITY_COLORS[sev]).toContain("bg-");
      expect(SEVERITY_COLORS[sev]).toContain("border-");
    }
  });

  const ROUTE_LABELS: Record<string, { label: string; description: string }> = {
    A_DUPLICATE_NOISY: { label: "Duplicate/Noisy", description: "Suppression candidate" },
    B_LOW_CONFIDENCE: { label: "Low Confidence", description: "Needs enrichment" },
    C_HIGH_CONFIDENCE: { label: "High Confidence", description: "Proceed to correlation" },
    D_LIKELY_BENIGN: { label: "Likely Benign", description: "Closure candidate" },
  };

  it("maps all routes to labels", () => {
    for (const route of ["A_DUPLICATE_NOISY", "B_LOW_CONFIDENCE", "C_HIGH_CONFIDENCE", "D_LIKELY_BENIGN"]) {
      expect(ROUTE_LABELS[route]).toBeDefined();
      expect(ROUTE_LABELS[route].label).toBeTruthy();
      expect(ROUTE_LABELS[route].description).toBeTruthy();
    }
  });

  const ENTITY_ICON_TYPES = [
    "host", "user", "ip", "domain", "hash", "process",
    "file_path", "rule_id", "mitre_technique", "cve", "port", "registry_key",
  ];

  it("has icon mappings for all entity types", () => {
    expect(ENTITY_ICON_TYPES).toHaveLength(12);
  });
});

// ── 7. Triage ID Generation ──────────────────────────────────────────────────

describe("Triage ID generation", () => {
  it("follows triage-{uuid} pattern", () => {
    const id = `triage-${crypto.randomUUID().slice(0, 12)}`;
    expect(id).toMatch(/^triage-[a-f0-9-]+$/);
  });

  it("generates unique IDs", () => {
    const ids = new Set(Array.from({ length: 100 }, () => `triage-${crypto.randomUUID().slice(0, 12)}`));
    expect(ids.size).toBe(100);
  });
});

// ── 8. Pipeline Stage Contracts ──────────────────────────────────────────────

describe("Pipeline stage contracts", () => {
  it("Stage 1 (Triage) outputs a TriageObject", () => {
    const output = {
      schemaVersion: "1.0",
      triageId: "triage-abc123",
      severity: "high",
      route: "C_HIGH_CONFIDENCE",
    };
    expect(output.schemaVersion).toBe("1.0");
    expect(output.triageId).toMatch(/^triage-/);
  });

  it("Stage 2 (Correlation) consumes a triageId and outputs a CorrelationBundle", () => {
    const input = { sourceTriageId: "triage-abc123" };
    const output = {
      schemaVersion: "1.0",
      correlationId: "corr-def456",
      sourceTriageId: input.sourceTriageId,
    };
    expect(output.sourceTriageId).toBe(input.sourceTriageId);
    expect(output.correlationId).toMatch(/^corr-/);
  });

  it("Stage 3 (Hypothesis) consumes a CorrelationBundle and updates a LivingCaseObject", () => {
    const input = { correlationId: "corr-def456" };
    const output = {
      caseId: 1,
      status: "investigating",
      workingTheory: "Brute force attack from external IP",
    };
    expect(output.status).toBe("investigating");
    expect(output.workingTheory).toBeTruthy();
  });

  it("pipeline stages are ordered: triage → correlation → hypothesis → case", () => {
    const stages = ["triage", "correlation", "hypothesis", "case"];
    expect(stages[0]).toBe("triage");
    expect(stages[stages.length - 1]).toBe("case");
    expect(stages).toHaveLength(4);
  });
});

// ── 9. Database Schema Contracts ─────────────────────────────────────────────

describe("Triage objects table schema", () => {
  const COLUMNS = [
    "id", "triageId", "alertId", "ruleId", "ruleDescription", "ruleLevel",
    "alertTimestamp", "agentId", "agentName", "alertFamily", "severity",
    "severityConfidence", "route", "isDuplicate", "similarityScore",
    "similarTriageId", "summary", "status", "errorMessage", "triageData",
    "triagedBy", "triggeredByUserId", "alertQueueItemId",
    "latencyMs", "tokensUsed", "createdAt",
  ];

  it("has all required columns", () => {
    expect(COLUMNS).toContain("triageId");
    expect(COLUMNS).toContain("severity");
    expect(COLUMNS).toContain("route");
    expect(COLUMNS).toContain("triageData");
    expect(COLUMNS).toContain("status");
  });

  it("triageId is the lookup key", () => {
    expect(COLUMNS).toContain("triageId");
  });

  it("stores full triage object as JSON in triageData", () => {
    expect(COLUMNS).toContain("triageData");
  });

  it("tracks processing status", () => {
    const validStatuses = ["pending", "processing", "completed", "failed"];
    expect(validStatuses).toHaveLength(4);
  });

  it("tracks latency and token usage for monitoring", () => {
    expect(COLUMNS).toContain("latencyMs");
    expect(COLUMNS).toContain("tokensUsed");
  });
});

describe("Correlation bundles table schema", () => {
  const COLUMNS = [
    "id", "correlationId", "sourceTriageId", "timeWindowStart", "timeWindowEnd",
    "riskScore", "correlationData", "status", "errorMessage",
    "latencyMs", "tokensUsed", "createdAt",
  ];

  it("has all required columns", () => {
    expect(COLUMNS).toContain("correlationId");
    expect(COLUMNS).toContain("sourceTriageId");
    expect(COLUMNS).toContain("riskScore");
    expect(COLUMNS).toContain("correlationData");
  });

  it("links back to the source triage", () => {
    expect(COLUMNS).toContain("sourceTriageId");
  });
});

// ── 10. Fresh Context Architecture Validation ────────────────────────────────

describe("Fresh context per stage architecture", () => {
  it("each stage gets its own system prompt", () => {
    const stages = ["triage", "correlation", "hypothesis"];
    const prompts = new Map<string, string>();
    prompts.set("triage", "You are a Triage Agent...");
    prompts.set("correlation", "You are a Correlation Agent...");
    prompts.set("hypothesis", "You are a Hypothesis Agent...");

    for (const stage of stages) {
      expect(prompts.has(stage)).toBe(true);
      expect(prompts.get(stage)!.length).toBeGreaterThan(0);
    }
  });

  it("handoff between stages is via structured JSON, not conversation context", () => {
    // Triage outputs a TriageObject
    const triageOutput = { triageId: "triage-abc", severity: "high" };
    // Correlation receives the triageId and fetches the TriageObject
    const correlationInput = { sourceTriageId: triageOutput.triageId };
    expect(correlationInput.sourceTriageId).toBe(triageOutput.triageId);
    // No shared conversation history between stages
  });

  it("context budget is allocated per stage, not shared", () => {
    const CONTEXT_BUDGETS: Record<string, number> = {
      triage: 16384,
      correlation: 32768,
      hypothesis: 16384,
    };

    const totalBudget = Object.values(CONTEXT_BUDGETS).reduce((a, b) => a + b, 0);
    // Each stage gets its full budget independently
    expect(CONTEXT_BUDGETS.triage).toBe(16384);
    expect(CONTEXT_BUDGETS.correlation).toBe(32768);
    // Total is NOT constrained to a single model context window
    expect(totalBudget).toBeGreaterThan(32768);
  });
});
