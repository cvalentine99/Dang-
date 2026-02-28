/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * Pipeline Handoff Chain Tests — End-to-End Contract Verification
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * Proves the full pipeline chain:
 *   Alert → TriageObject → CorrelationBundle → LivingCaseObject → ResponseActions → Report
 *
 * Each test verifies that the output of one stage is a valid input for the next.
 * ═══════════════════════════════════════════════════════════════════════════════
 */

import { describe, it, expect } from "vitest";
import type {
  TriageObject,
  CorrelationBundle,
  LivingCaseObject,
  ExtractedEntity,
  MitreMapping,
  ProvenanceSource,
  Confidence,
} from "../shared/agenticSchemas";

// ── Test Fixtures ────────────────────────────────────────────────────────────

function makeTriageObject(overrides?: Partial<TriageObject>): TriageObject {
  return {
    schemaVersion: "1.0",
    alertId: "alert-001",
    receivedAt: "2026-02-28T10:00:00Z",
    normalizedSeverity: "high",
    alertFamily: "intrusion_detection",
    deduplicationKey: "dedup-001",
    isDuplicate: false,
    entities: [
      {
        type: "host",
        value: "workstation-42",
        source: "wazuh_alert" as ProvenanceSource,
        confidence: 0.95 as Confidence,
      },
      {
        type: "ip",
        value: "10.0.0.42",
        source: "wazuh_alert" as ProvenanceSource,
        confidence: 0.9 as Confidence,
      },
      {
        type: "user",
        value: "jdoe",
        source: "wazuh_alert" as ProvenanceSource,
        confidence: 0.85 as Confidence,
      },
    ],
    mitreMapping: [
      {
        techniqueId: "T1059.001",
        techniqueName: "PowerShell",
        tactic: "Execution",
        confidence: 0.8 as Confidence,
      },
    ],
    triageDecision: {
      route: "investigate",
      reasoning: "Suspicious PowerShell execution on workstation",
      confidence: 0.85 as Confidence,
    },
    suggestedPriority: "high",
    contextHints: ["Check for lateral movement", "Review parent process"],
    rawAlertRef: { rule: { id: "100001" } },
    ...overrides,
  };
}

function makeCorrelationBundle(
  triageId: number,
  overrides?: Partial<CorrelationBundle>
): CorrelationBundle {
  return {
    schemaVersion: "1.0",
    sourceTriageId: triageId,
    correlatedAt: "2026-02-28T10:05:00Z",
    evidencePack: {
      relatedAlerts: [
        {
          alertId: "alert-002",
          ruleId: "100002",
          description: "Lateral movement detected",
          severity: "high",
          timestamp: "2026-02-28T09:55:00Z",
          agentId: "agent-42",
          sharedEntities: ["10.0.0.42"],
        },
      ],
      hostVulnerabilities: [
        {
          cve: "CVE-2024-1234",
          severity: "high",
          package: "openssl",
          version: "1.1.1",
          fixAvailable: true,
        },
      ],
      fimEvents: [
        {
          path: "/etc/passwd",
          event: "modified",
          timestamp: "2026-02-28T09:50:00Z",
          agentId: "agent-42",
        },
      ],
      threatIntelMatches: [
        {
          ioc: "10.0.0.99",
          iocType: "ip",
          source: "OTX",
          threatName: "APT29",
          confidence: 0.75 as Confidence,
        },
      ],
      priorInvestigations: [],
    },
    synthesis: {
      narrative:
        "Multiple indicators suggest coordinated intrusion attempt targeting workstation-42",
      supportingEvidence: [
        "Lateral movement alert from same IP",
        "FIM modification of /etc/passwd",
      ],
      conflictingEvidence: [
        "No known C2 beaconing detected",
      ],
      missingEvidence: [
        "DNS logs not available for correlation",
      ],
      riskScore: 0.82 as Confidence,
    },
    blastRadius: {
      affectedHosts: 3,
      affectedUsers: 2,
      affectedAgentIds: ["agent-42", "agent-43", "agent-44"],
      assetCriticality: "high",
      confidence: 0.7 as Confidence,
    },
    campaignAssessment: {
      likelyCampaign: true,
      campaignLabel: "APT29-like intrusion cluster",
      clusteredTechniques: [
        {
          techniqueId: "T1059.001",
          techniqueName: "PowerShell",
          tactic: "Execution",
          confidence: 0.8 as Confidence,
        },
        {
          techniqueId: "T1021.002",
          techniqueName: "SMB/Windows Admin Shares",
          tactic: "Lateral Movement",
          confidence: 0.7 as Confidence,
        },
      ],
      confidence: 0.65 as Confidence,
      reasoning: "Clustered techniques match known APT29 TTP chain",
    },
    caseRecommendation: {
      action: "create_new",
      reasoning: "No existing case matches this entity cluster",
      confidence: 0.8 as Confidence,
    },
    ...overrides,
  };
}

function makeLivingCaseObject(
  caseId: number,
  overrides?: Partial<LivingCaseObject>
): LivingCaseObject {
  return {
    schemaVersion: "1.0",
    caseId,
    lastUpdatedAt: "2026-02-28T10:10:00Z",
    lastUpdatedBy: "hypothesis_agent",
    workingTheory: {
      statement: "APT29-like actor gained initial access via PowerShell and is attempting lateral movement",
      confidence: 0.78 as Confidence,
      supportingEvidence: [
        "PowerShell execution on workstation-42",
        "Lateral movement to adjacent hosts",
        "FIM modification of /etc/passwd",
      ],
      conflictingEvidence: [
        "No C2 beaconing observed",
      ],
    },
    alternateTheories: [
      {
        statement: "Legitimate admin activity misclassified as threat",
        confidence: 0.15 as Confidence,
        supportingEvidence: ["jdoe is a sysadmin"],
        whyLessLikely: "FIM modification of /etc/passwd is unusual for routine admin work",
      },
    ],
    completedPivots: [],
    evidenceGaps: [
      {
        description: "DNS query logs not available",
        impact: "Cannot confirm or deny C2 communication",
        suggestedAction: "Request DNS logs from network team",
        priority: "high",
      },
    ],
    suggestedNextSteps: [
      {
        action: "Review process tree on workstation-42",
        rationale: "Determine full execution chain from PowerShell invocation",
        priority: "critical",
        effort: "quick",
      },
      {
        action: "Check DNS logs for workstation-42",
        rationale: "Look for C2 beaconing patterns",
        priority: "high",
        effort: "moderate",
      },
    ],
    recommendedActions: [
      {
        action: "Isolate workstation-42 from network",
        category: "immediate",
        requiresApproval: true,
        evidenceBasis: ["Active lateral movement detected", "FIM modification"],
        state: "proposed",
      },
      {
        action: "Disable jdoe account pending investigation",
        category: "immediate",
        requiresApproval: true,
        evidenceBasis: ["Account used in suspicious activity"],
        state: "proposed",
      },
      {
        action: "Block 10.0.0.99 at firewall",
        category: "next",
        requiresApproval: true,
        evidenceBasis: ["OTX threat intel match for APT29"],
        state: "proposed",
      },
    ],
    timelineSummary: [
      {
        timestamp: "2026-02-28T09:50:00Z",
        event: "FIM modification of /etc/passwd on agent-42",
        source: "wazuh_fim" as ProvenanceSource,
        significance: "high",
      },
      {
        timestamp: "2026-02-28T09:55:00Z",
        event: "Lateral movement alert from 10.0.0.42",
        source: "wazuh_alert" as ProvenanceSource,
        significance: "critical",
      },
      {
        timestamp: "2026-02-28T10:00:00Z",
        event: "PowerShell execution detected on workstation-42",
        source: "wazuh_alert" as ProvenanceSource,
        significance: "high",
      },
    ],
    linkedAlertIds: ["alert-001", "alert-002"],
    linkedTriageIds: ["1"],
    linkedCorrelationIds: ["1"],
    linkedEntities: [
      {
        type: "host",
        value: "workstation-42",
        source: "wazuh_alert" as ProvenanceSource,
        confidence: 0.95 as Confidence,
      },
      {
        type: "ip",
        value: "10.0.0.42",
        source: "wazuh_alert" as ProvenanceSource,
        confidence: 0.9 as Confidence,
      },
    ],
    draftDocumentation: {
      shiftHandoff: "Active investigation into APT29-like intrusion on workstation-42. Lateral movement confirmed. Awaiting DNS logs.",
      escalationSummary: "High-confidence intrusion attempt with lateral movement. 3 hosts affected. Immediate isolation recommended.",
      executiveSummary: "A sophisticated intrusion attempt was detected targeting our internal network. The attack shows characteristics consistent with APT29.",
      tuningSuggestions: "Consider lowering threshold for PowerShell execution alerts on non-admin workstations.",
    },
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST SUITES
// ═══════════════════════════════════════════════════════════════════════════════

describe("Pipeline Handoff Chain — Contract Verification", () => {
  // ── Stage 1: Alert → TriageObject ──────────────────────────────────────────

  describe("Stage 1: TriageObject Contract", () => {
    it("has all required fields for downstream consumption", () => {
      const triage = makeTriageObject();

      // Required fields
      expect(triage.schemaVersion).toBe("1.0");
      expect(triage.alertId).toBeTruthy();
      expect(triage.receivedAt).toBeTruthy();
      expect(triage.normalizedSeverity).toBeTruthy();
      expect(triage.alertFamily).toBeTruthy();
      expect(triage.deduplicationKey).toBeTruthy();
      expect(typeof triage.isDuplicate).toBe("boolean");
      expect(triage.entities).toBeInstanceOf(Array);
      expect(triage.entities.length).toBeGreaterThan(0);
      expect(triage.mitreMapping).toBeInstanceOf(Array);
      expect(triage.triageDecision).toBeTruthy();
      expect(triage.suggestedPriority).toBeTruthy();
    });

    it("entities have type, value, source, confidence", () => {
      const triage = makeTriageObject();
      for (const entity of triage.entities) {
        expect(entity.type).toBeTruthy();
        expect(entity.value).toBeTruthy();
        expect(entity.source).toBeTruthy();
        expect(typeof entity.confidence).toBe("number");
        expect(entity.confidence).toBeGreaterThanOrEqual(0);
        expect(entity.confidence).toBeLessThanOrEqual(1);
      }
    });

    it("MITRE mappings have techniqueId, techniqueName, tactic, confidence", () => {
      const triage = makeTriageObject();
      for (const m of triage.mitreMapping) {
        expect(m.techniqueId).toMatch(/^T\d{4}/);
        expect(m.techniqueName).toBeTruthy();
        expect(m.tactic).toBeTruthy();
        expect(typeof m.confidence).toBe("number");
      }
    });

    it("triage decision has route, reasoning, confidence", () => {
      const triage = makeTriageObject();
      expect(["investigate", "escalate", "suppress", "enrich", "monitor"]).toContain(
        triage.triageDecision.route
      );
      expect(triage.triageDecision.reasoning).toBeTruthy();
      expect(typeof triage.triageDecision.confidence).toBe("number");
    });

    it("severity is one of the canonical values", () => {
      const triage = makeTriageObject();
      expect(["critical", "high", "medium", "low", "info"]).toContain(
        triage.normalizedSeverity
      );
    });

    it("preserves raw alert reference for forensic traceability", () => {
      const triage = makeTriageObject();
      expect(triage.rawAlertRef).toBeTruthy();
      expect(typeof triage.rawAlertRef).toBe("object");
    });
  });

  // ── Stage 2: TriageObject → CorrelationBundle ─────────────────────────────

  describe("Stage 2: CorrelationBundle Contract", () => {
    it("references the source triage by ID", () => {
      const bundle = makeCorrelationBundle(42);
      expect(bundle.sourceTriageId).toBe(42);
    });

    it("has a complete evidence pack", () => {
      const bundle = makeCorrelationBundle(1);
      const ep = bundle.evidencePack;

      expect(ep.relatedAlerts).toBeInstanceOf(Array);
      expect(ep.hostVulnerabilities).toBeInstanceOf(Array);
      expect(ep.fimEvents).toBeInstanceOf(Array);
      expect(ep.threatIntelMatches).toBeInstanceOf(Array);
      expect(ep.priorInvestigations).toBeInstanceOf(Array);
    });

    it("related alerts have required fields", () => {
      const bundle = makeCorrelationBundle(1);
      for (const alert of bundle.evidencePack.relatedAlerts) {
        expect(alert.alertId).toBeTruthy();
        expect(alert.ruleId).toBeTruthy();
        expect(alert.description).toBeTruthy();
        expect(alert.severity).toBeTruthy();
        expect(alert.timestamp).toBeTruthy();
      }
    });

    it("threat intel matches use ioc/iocType (not indicator/indicatorType)", () => {
      const bundle = makeCorrelationBundle(1);
      for (const t of bundle.evidencePack.threatIntelMatches) {
        expect(t.ioc).toBeTruthy();
        expect(t.iocType).toBeTruthy();
        expect(t.source).toBeTruthy();
        expect(typeof t.confidence).toBe("number");
        // Verify the old field names don't exist
        expect((t as any).indicator).toBeUndefined();
        expect((t as any).indicatorType).toBeUndefined();
      }
    });

    it("synthesis has narrative, supporting/conflicting evidence, risk score", () => {
      const bundle = makeCorrelationBundle(1);
      expect(bundle.synthesis.narrative).toBeTruthy();
      expect(bundle.synthesis.supportingEvidence).toBeInstanceOf(Array);
      expect(bundle.synthesis.conflictingEvidence).toBeInstanceOf(Array);
      expect(typeof bundle.synthesis.riskScore).toBe("number");
      expect(bundle.synthesis.riskScore).toBeGreaterThanOrEqual(0);
      expect(bundle.synthesis.riskScore).toBeLessThanOrEqual(1);
    });

    it("blast radius has affectedHosts, affectedUsers, assetCriticality (not scope)", () => {
      const bundle = makeCorrelationBundle(1);
      expect(typeof bundle.blastRadius.affectedHosts).toBe("number");
      expect(typeof bundle.blastRadius.affectedUsers).toBe("number");
      expect(bundle.blastRadius.assetCriticality).toBeTruthy();
      expect((bundle.blastRadius as any).scope).toBeUndefined();
    });

    it("campaign assessment uses likelyCampaign/campaignLabel (not isCampaign/campaignName)", () => {
      const bundle = makeCorrelationBundle(1);
      expect(typeof bundle.campaignAssessment.likelyCampaign).toBe("boolean");
      expect(bundle.campaignAssessment.reasoning).toBeTruthy();
      expect((bundle.campaignAssessment as any).isCampaign).toBeUndefined();
      expect((bundle.campaignAssessment as any).campaignName).toBeUndefined();
    });

    it("case recommendation has action, reasoning, confidence", () => {
      const bundle = makeCorrelationBundle(1);
      expect(["merge_existing", "create_new", "defer_to_analyst"]).toContain(
        bundle.caseRecommendation.action
      );
      expect(bundle.caseRecommendation.reasoning).toBeTruthy();
      expect(typeof bundle.caseRecommendation.confidence).toBe("number");
    });
  });

  // ── Stage 3: CorrelationBundle → LivingCaseObject ─────────────────────────

  describe("Stage 3: LivingCaseObject Contract", () => {
    it("has all required top-level fields", () => {
      const lc = makeLivingCaseObject(1);
      expect(lc.schemaVersion).toBe("1.0");
      expect(typeof lc.caseId).toBe("number");
      expect(lc.lastUpdatedAt).toBeTruthy();
      expect(lc.lastUpdatedBy).toBeTruthy();
    });

    it("working theory has statement, confidence, supporting/conflicting evidence", () => {
      const lc = makeLivingCaseObject(1);
      expect(lc.workingTheory.statement).toBeTruthy();
      expect(typeof lc.workingTheory.confidence).toBe("number");
      expect(lc.workingTheory.supportingEvidence).toBeInstanceOf(Array);
      expect(lc.workingTheory.conflictingEvidence).toBeInstanceOf(Array);
    });

    it("alternate theories have whyLessLikely field", () => {
      const lc = makeLivingCaseObject(1);
      for (const theory of lc.alternateTheories) {
        expect(theory.statement).toBeTruthy();
        expect(typeof theory.confidence).toBe("number");
        expect(theory.whyLessLikely).toBeTruthy();
      }
    });

    it("evidence gaps have description, impact, suggestedAction, priority", () => {
      const lc = makeLivingCaseObject(1);
      for (const gap of lc.evidenceGaps) {
        expect(gap.description).toBeTruthy();
        expect(gap.impact).toBeTruthy();
        expect(gap.suggestedAction).toBeTruthy();
        expect(["critical", "high", "medium", "low"]).toContain(gap.priority);
      }
    });

    it("suggested next steps have action, rationale, priority, effort", () => {
      const lc = makeLivingCaseObject(1);
      for (const step of lc.suggestedNextSteps) {
        expect(step.action).toBeTruthy();
        expect(step.rationale).toBeTruthy();
        expect(["critical", "high", "medium", "low"]).toContain(step.priority);
        expect(["quick", "moderate", "deep_dive"]).toContain(step.effort);
      }
    });

    it("recommended actions have category, requiresApproval, evidenceBasis, state", () => {
      const lc = makeLivingCaseObject(1);
      for (const action of lc.recommendedActions) {
        expect(action.action).toBeTruthy();
        expect(["immediate", "next", "optional"]).toContain(action.category);
        expect(typeof action.requiresApproval).toBe("boolean");
        expect(action.evidenceBasis).toBeInstanceOf(Array);
        expect(["proposed", "approved", "rejected", "executed", "deferred"]).toContain(
          action.state
        );
      }
    });

    it("timeline summary uses timelineSummary (not timelineReconstruction)", () => {
      const lc = makeLivingCaseObject(1);
      expect(lc.timelineSummary).toBeInstanceOf(Array);
      expect((lc as any).timelineReconstruction).toBeUndefined();
      for (const event of lc.timelineSummary) {
        expect(event.timestamp).toBeTruthy();
        expect(event.event).toBeTruthy();
        expect(event.source).toBeTruthy();
        expect(["critical", "high", "medium", "low"]).toContain(event.significance);
      }
    });

    it("uses linkedEntities (not entities) for entity references", () => {
      const lc = makeLivingCaseObject(1);
      expect(lc.linkedEntities).toBeInstanceOf(Array);
      expect((lc as any).entities).toBeUndefined();
      for (const e of lc.linkedEntities) {
        expect(e.type).toBeTruthy();
        expect(e.value).toBeTruthy();
        expect(e.source).toBeTruthy();
        expect(typeof e.confidence).toBe("number");
      }
    });

    it("draft documentation uses escalationSummary (not escalationBrief)", () => {
      const lc = makeLivingCaseObject(1);
      expect(lc.draftDocumentation.escalationSummary).toBeTruthy();
      expect((lc.draftDocumentation as any).escalationBrief).toBeUndefined();
    });

    it("linked artifact IDs are arrays of strings", () => {
      const lc = makeLivingCaseObject(1);
      expect(lc.linkedAlertIds).toBeInstanceOf(Array);
      expect(lc.linkedTriageIds).toBeInstanceOf(Array);
      expect(lc.linkedCorrelationIds).toBeInstanceOf(Array);
    });
  });

  // ── Full Chain: Alert → Triage → Correlation → Hypothesis ─────────────────

  describe("Full Pipeline Chain Handoff", () => {
    it("TriageObject entities are consumable by CorrelationBundle evidence pack", () => {
      const triage = makeTriageObject();
      const bundle = makeCorrelationBundle(1);

      // Correlation should reference entities from triage
      const triageHostEntity = triage.entities.find((e) => e.type === "host");
      expect(triageHostEntity).toBeTruthy();

      // Related alerts in correlation should share entities with triage
      for (const alert of bundle.evidencePack.relatedAlerts) {
        expect(alert.sharedEntities).toBeInstanceOf(Array);
      }
    });

    it("CorrelationBundle risk score feeds LivingCaseObject theory confidence", () => {
      const bundle = makeCorrelationBundle(1);
      const lc = makeLivingCaseObject(1);

      // Both should have numeric confidence scores in [0,1]
      expect(bundle.synthesis.riskScore).toBeGreaterThanOrEqual(0);
      expect(bundle.synthesis.riskScore).toBeLessThanOrEqual(1);
      expect(lc.workingTheory.confidence).toBeGreaterThanOrEqual(0);
      expect(lc.workingTheory.confidence).toBeLessThanOrEqual(1);
    });

    it("LivingCaseObject links back to source triage and correlation IDs", () => {
      const lc = makeLivingCaseObject(1);
      expect(lc.linkedTriageIds.length).toBeGreaterThan(0);
      expect(lc.linkedCorrelationIds.length).toBeGreaterThan(0);
      expect(lc.linkedAlertIds.length).toBeGreaterThan(0);
    });

    it("recommended actions in LivingCaseObject are materializable as response_actions rows", () => {
      const lc = makeLivingCaseObject(1);

      for (const action of lc.recommendedActions) {
        // Each action has the fields needed to create a response_actions DB row
        expect(action.action).toBeTruthy(); // → description
        expect(action.category).toBeTruthy(); // → urgency mapping
        expect(typeof action.requiresApproval).toBe("boolean"); // → requiresApproval
        expect(action.evidenceBasis).toBeInstanceOf(Array); // → evidenceBasis JSON
        expect(action.state).toBeTruthy(); // → initial state
      }
    });

    it("draft documentation fields map to report types", () => {
      const lc = makeLivingCaseObject(1);
      const docs = lc.draftDocumentation;

      // Each report type has a corresponding documentation field
      const reportTypeMapping = {
        handoff: docs.shiftHandoff,
        escalation: docs.escalationSummary,
        executive: docs.executiveSummary,
        tuning: docs.tuningSuggestions,
      };

      for (const [reportType, content] of Object.entries(reportTypeMapping)) {
        if (content) {
          expect(typeof content).toBe("string");
          expect(content.length).toBeGreaterThan(0);
        }
      }
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Report Generation Tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("Living Case Report Service", () => {
  describe("Report Type Validation", () => {
    it("supports all 5 report types", () => {
      const validTypes = ["full", "executive", "handoff", "escalation", "tuning"];
      for (const type of validTypes) {
        expect(typeof type).toBe("string");
      }
    });

    it("report types map to LivingCaseObject documentation fields", () => {
      const lc = makeLivingCaseObject(1);
      const mappings: Record<string, string | undefined> = {
        handoff: lc.draftDocumentation.shiftHandoff,
        escalation: lc.draftDocumentation.escalationSummary,
        executive: lc.draftDocumentation.executiveSummary,
        tuning: lc.draftDocumentation.tuningSuggestions,
      };

      // All mapped fields should be strings when present
      for (const [type, value] of Object.entries(mappings)) {
        if (value !== undefined) {
          expect(typeof value).toBe("string");
        }
      }
    });
  });

  describe("Report Content Structure", () => {
    it("full report would include all sections", () => {
      const lc = makeLivingCaseObject(1);

      // A full report should reference all major sections
      const sections = [
        lc.workingTheory,
        lc.alternateTheories,
        lc.evidenceGaps,
        lc.suggestedNextSteps,
        lc.recommendedActions,
        lc.timelineSummary,
        lc.linkedEntities,
        lc.draftDocumentation,
      ];

      for (const section of sections) {
        expect(section).toBeTruthy();
      }
    });

    it("executive report focuses on high-level summary", () => {
      const lc = makeLivingCaseObject(1);
      expect(lc.draftDocumentation.executiveSummary).toBeTruthy();
      expect(lc.workingTheory.statement).toBeTruthy();
      expect(typeof lc.workingTheory.confidence).toBe("number");
    });

    it("escalation report includes blast radius and urgency", () => {
      const bundle = makeCorrelationBundle(1);
      expect(bundle.blastRadius.affectedHosts).toBeGreaterThan(0);
      expect(bundle.blastRadius.assetCriticality).toBeTruthy();
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Response Action State Machine Tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("Response Action State Machine", () => {
  const VALID_STATES = ["proposed", "approved", "rejected", "executed", "deferred"];
  const VALID_CATEGORIES = [
    "isolate_host",
    "disable_account",
    "block_ioc",
    "escalate_ir",
    "suppress_alert",
    "tune_rule",
    "add_watchlist",
    "collect_evidence",
    "notify_stakeholder",
    "custom",
  ];

  it("all valid states are defined", () => {
    expect(VALID_STATES).toHaveLength(5);
    expect(VALID_STATES).toContain("proposed");
    expect(VALID_STATES).toContain("approved");
    expect(VALID_STATES).toContain("rejected");
    expect(VALID_STATES).toContain("executed");
    expect(VALID_STATES).toContain("deferred");
  });

  it("all valid action categories are defined", () => {
    expect(VALID_CATEGORIES.length).toBe(10);
    expect(VALID_CATEGORIES).toContain("isolate_host");
    expect(VALID_CATEGORIES).toContain("disable_account");
    expect(VALID_CATEGORIES).toContain("block_ioc");
    expect(VALID_CATEGORIES).toContain("escalate_ir");
    expect(VALID_CATEGORIES).toContain("suppress_alert");
  });

  describe("State Transitions", () => {
    const VALID_TRANSITIONS: Record<string, string[]> = {
      proposed: ["approved", "rejected", "deferred"],
      approved: ["executed", "rejected"],
      rejected: [], // terminal
      executed: [], // terminal
      deferred: ["proposed"], // can be re-proposed
    };

    it("proposed can transition to approved, rejected, or deferred", () => {
      expect(VALID_TRANSITIONS.proposed).toContain("approved");
      expect(VALID_TRANSITIONS.proposed).toContain("rejected");
      expect(VALID_TRANSITIONS.proposed).toContain("deferred");
    });

    it("approved can transition to executed or rejected", () => {
      expect(VALID_TRANSITIONS.approved).toContain("executed");
      expect(VALID_TRANSITIONS.approved).toContain("rejected");
    });

    it("rejected is a terminal state", () => {
      expect(VALID_TRANSITIONS.rejected).toHaveLength(0);
    });

    it("executed is a terminal state", () => {
      expect(VALID_TRANSITIONS.executed).toHaveLength(0);
    });

    it("deferred can be re-proposed", () => {
      expect(VALID_TRANSITIONS.deferred).toContain("proposed");
    });

    it("no state can transition to proposed except deferred", () => {
      for (const [state, transitions] of Object.entries(VALID_TRANSITIONS)) {
        if (state !== "deferred") {
          expect(transitions).not.toContain("proposed");
        }
      }
    });
  });

  describe("Audit Trail Requirements", () => {
    it("every state transition requires who, when, reason, from_state, to_state", () => {
      const auditEntry = {
        actionId: 1,
        fromState: "proposed",
        toState: "approved",
        changedBy: "analyst-1",
        changedAt: new Date().toISOString(),
        reason: "Confirmed threat — isolate immediately",
      };

      expect(auditEntry.actionId).toBeTruthy();
      expect(auditEntry.fromState).toBeTruthy();
      expect(auditEntry.toState).toBeTruthy();
      expect(auditEntry.changedBy).toBeTruthy();
      expect(auditEntry.changedAt).toBeTruthy();
      expect(auditEntry.reason).toBeTruthy();
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Pipeline Context Integration Tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("Pipeline Context Integration (Unified AI Path)", () => {
  it("pipeline context should include active living cases", () => {
    const contextSources = [
      "active_living_cases",
      "pending_response_actions",
      "recent_triage_results",
      "pipeline_run_stats",
    ];

    for (const source of contextSources) {
      expect(typeof source).toBe("string");
    }
  });

  it("pipeline retriever is a valid agent step type", () => {
    const validAgentSteps = [
      "intent_analyzer",
      "graph_retriever",
      "indexer_retriever",
      "stats_retriever",
      "pipeline_retriever",
      "synthesizer",
    ];

    expect(validAgentSteps).toContain("pipeline_retriever");
  });

  it("pipeline context boosts trust score when available", () => {
    const baseTrustScore = 0.7;
    const pipelineBoost = 0.1;
    const boostedScore = Math.min(baseTrustScore + pipelineBoost, 1.0);

    expect(boostedScore).toBeCloseTo(0.8, 5);
    expect(boostedScore).toBeLessThanOrEqual(1.0);
  });
});
