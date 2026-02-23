/**
 * Agentic LLM Pipeline — HybridRAG Security Analysis
 *
 * Implements the 4-phase multi-agent analytics pipeline:
 * Phase 1: Query Intent Analysis & Orchestration
 * Phase 2: Structured Graph Retrieval (MySQL Knowledge Graph)
 * Phase 3: Semantic Search (Wazuh Indexer full-text search)
 * Phase 4: LLM Synthesis with chain-of-thought reasoning
 *
 * Uses the built-in invokeLLM helper (Claude) as the cognitive engine.
 */

import { invokeLLM } from "../_core/llm";
import { searchGraph, getEndpointGraph, getGraphStats, getVulnerabilityAttackSurface, getMitreDistribution } from "./graphQueryService";
import {
  isIndexerConfigured,
  getIndexerConfig,
  getEffectiveIndexerConfig,
  indexerSearch,
  INDEX_PATTERNS,
  boolQuery,
} from "../indexer/indexerClient";

// ── Types ───────────────────────────────────────────────────────────────────

export interface AnalystMessage {
  role: "user" | "assistant" | "system";
  content: string;
}

export interface RetrievalSource {
  type: "graph" | "indexer" | "stats";
  label: string;
  data: unknown;
  relevance: string;
}

export interface AnalystResponse {
  answer: string;
  reasoning: string;
  sources: RetrievalSource[];
  suggestedFollowUps: string[];
}

interface IntentAnalysis {
  intent: "threat_hunt" | "vulnerability_assessment" | "endpoint_investigation" | "compliance_check" | "general_query" | "mitre_mapping";
  entities: {
    agentIds: string[];
    hostnames: string[];
    cveIds: string[];
    ipAddresses: string[];
    ruleIds: string[];
    mitreTactics: string[];
    keywords: string[];
  };
  retrievalStrategy: ("graph" | "indexer" | "both")[];
  timeRange?: string;
}

// ── Phase 1: Intent Analysis ────────────────────────────────────────────────

async function analyzeIntent(query: string, conversationHistory: AnalystMessage[]): Promise<IntentAnalysis> {
  const historyContext = conversationHistory
    .slice(-6)
    .map(m => `${m.role}: ${m.content}`)
    .join("\n");

  const response = await invokeLLM({
    messages: [
      {
        role: "system",
        content: `You are a security query intent classifier for a Wazuh SIEM system.
Analyze the user's query and extract structured intent information.
You must respond with valid JSON matching this schema exactly:
{
  "intent": "threat_hunt" | "vulnerability_assessment" | "endpoint_investigation" | "compliance_check" | "general_query" | "mitre_mapping",
  "entities": {
    "agentIds": ["string array of agent IDs mentioned"],
    "hostnames": ["string array of hostnames mentioned"],
    "cveIds": ["string array of CVE IDs mentioned"],
    "ipAddresses": ["string array of IP addresses mentioned"],
    "ruleIds": ["string array of Wazuh rule IDs mentioned"],
    "mitreTactics": ["string array of MITRE ATT&CK tactics mentioned"],
    "keywords": ["string array of key search terms"]
  },
  "retrievalStrategy": ["graph", "indexer", or "both"],
  "timeRange": "optional time range like 'last 24h', 'last 7d', etc."
}

Context about available data:
- Knowledge Graph: endpoints, processes, network ports, software packages, identities, vulnerabilities, security events
- Wazuh Indexer: wazuh-alerts-*, wazuh-states-vulnerabilities-*
- MITRE ATT&CK mapping from security events`,
      },
      {
        role: "user",
        content: `Conversation history:\n${historyContext}\n\nCurrent query: ${query}`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "intent_analysis",
        strict: true,
        schema: {
          type: "object",
          properties: {
            intent: { type: "string", enum: ["threat_hunt", "vulnerability_assessment", "endpoint_investigation", "compliance_check", "general_query", "mitre_mapping"] },
            entities: {
              type: "object",
              properties: {
                agentIds: { type: "array", items: { type: "string" } },
                hostnames: { type: "array", items: { type: "string" } },
                cveIds: { type: "array", items: { type: "string" } },
                ipAddresses: { type: "array", items: { type: "string" } },
                ruleIds: { type: "array", items: { type: "string" } },
                mitreTactics: { type: "array", items: { type: "string" } },
                keywords: { type: "array", items: { type: "string" } },
              },
              required: ["agentIds", "hostnames", "cveIds", "ipAddresses", "ruleIds", "mitreTactics", "keywords"],
              additionalProperties: false,
            },
            retrievalStrategy: { type: "array", items: { type: "string", enum: ["graph", "indexer", "both"] } },
            timeRange: { type: "string" },
          },
          required: ["intent", "entities", "retrievalStrategy", "timeRange"],
          additionalProperties: false,
        },
      },
    },
  });

  const content = response.choices?.[0]?.message?.content as string | undefined;
  if (!content) {
    return {
      intent: "general_query",
      entities: { agentIds: [], hostnames: [], cveIds: [], ipAddresses: [], ruleIds: [], mitreTactics: [], keywords: [query] },
      retrievalStrategy: ["both"],
    };
  }

  try {
    return JSON.parse(content) as IntentAnalysis;
  } catch {
    return {
      intent: "general_query",
      entities: { agentIds: [], hostnames: [], cveIds: [], ipAddresses: [], ruleIds: [], mitreTactics: [], keywords: [query] },
      retrievalStrategy: ["both"],
    };
  }
}

// ── Phase 2: Graph Retrieval ────────────────────────────────────────────────

async function retrieveFromGraph(intent: IntentAnalysis): Promise<RetrievalSource[]> {
  const sources: RetrievalSource[] = [];

  try {
    // Get overall graph stats
    const stats = await getGraphStats();
    sources.push({ type: "stats", label: "Knowledge Graph Statistics", data: stats, relevance: "context" });

    // Endpoint-specific queries
    for (const agentId of intent.entities.agentIds) {
      const graph = await getEndpointGraph(agentId);
      if (graph.nodes.length > 0) {
        sources.push({ type: "graph", label: `Endpoint graph: Agent ${agentId}`, data: graph, relevance: "primary" });
      }
    }

    // CVE attack surface queries
    for (const cveId of intent.entities.cveIds) {
      const surface = await getVulnerabilityAttackSurface(cveId);
      if (surface.nodes.length > 0) {
        sources.push({ type: "graph", label: `Attack surface: ${cveId}`, data: surface, relevance: "primary" });
      }
    }

    // MITRE distribution if relevant
    if (intent.intent === "mitre_mapping" || intent.intent === "threat_hunt") {
      const mitre = await getMitreDistribution();
      if (mitre.length > 0) {
        sources.push({ type: "graph", label: "MITRE ATT&CK Distribution", data: mitre, relevance: "primary" });
      }
    }

    // Keyword search across graph
    const allKeywords = [
      ...intent.entities.keywords,
      ...intent.entities.hostnames,
      ...intent.entities.ipAddresses,
      ...intent.entities.ruleIds,
    ];

    for (const keyword of allKeywords.slice(0, 3)) {
      const results = await searchGraph(keyword, 20);
      if (results.length > 0) {
        sources.push({ type: "graph", label: `Graph search: "${keyword}"`, data: results, relevance: "supporting" });
      }
    }
  } catch (err) {
    sources.push({ type: "graph", label: "Graph retrieval error", data: { error: (err as Error).message }, relevance: "error" });
  }

  return sources;
}

// ── Phase 3: Indexer Search ─────────────────────────────────────────────────

async function retrieveFromIndexer(intent: IntentAnalysis): Promise<RetrievalSource[]> {
  const sources: RetrievalSource[] = [];

  const config = await getEffectiveIndexerConfig();
  if (!config) {
    sources.push({ type: "indexer", label: "Indexer not configured", data: null, relevance: "error" });
    return sources;
  }

  try {
    // Build search queries based on intent
    const searchTerms = [
      ...intent.entities.keywords,
      ...intent.entities.hostnames,
      ...intent.entities.ipAddresses,
      ...intent.entities.cveIds,
      ...intent.entities.ruleIds,
    ].filter(Boolean);

    if (searchTerms.length > 0) {
      const queryString = searchTerms.join(" ");

      // Search alerts
      try {
        const alertResults = await indexerSearch(
          config,
          INDEX_PATTERNS.ALERTS,
          {
            query: {
              multi_match: {
                query: queryString,
                fields: ["rule.description", "agent.name", "data.srcip", "data.dstip", "rule.mitre.tactic", "rule.mitre.technique"],
                type: "best_fields",
                fuzziness: "AUTO",
              },
            },
            size: 20,
            sort: [{ timestamp: { order: "desc" } }],
          },
          "alerts"
        );

        const alertHits = alertResults.hits?.hits ?? [];
        if (alertHits.length > 0) {
          sources.push({
            type: "indexer",
            label: `Alert search: "${queryString}" (${alertHits.length} results)`,
            data: alertHits.map((h: { _source: unknown }) => h._source),
            relevance: "primary",
          });
        }
      } catch {
        // Alert index may not exist
      }

      // Search vulnerabilities
      if (intent.intent === "vulnerability_assessment" || intent.entities.cveIds.length > 0) {
        try {
          const vulnResults = await indexerSearch(
            config,
            INDEX_PATTERNS.VULNERABILITIES,
            {
              query: {
                multi_match: {
                  query: queryString,
                  fields: ["vulnerability.id", "vulnerability.title", "vulnerability.severity", "package.name", "agent.name"],
                  type: "best_fields",
                },
              },
              size: 20,
            },
            "vulnerabilities"
          );

          const vulnHits = vulnResults.hits?.hits ?? [];
          if (vulnHits.length > 0) {
            sources.push({
              type: "indexer",
              label: `Vulnerability search: "${queryString}" (${vulnHits.length} results)`,
              data: vulnHits.map((h: { _source: unknown }) => h._source),
              relevance: "primary",
            });
          }
        } catch {
          // Vulnerability index may not exist
        }
      }
    }

    // Agent-specific alert search
    for (const agentId of intent.entities.agentIds.slice(0, 3)) {
      try {
        const agentAlerts = await indexerSearch(
          config,
          INDEX_PATTERNS.ALERTS,
          {
            query: boolQuery({
              filter: [{ term: { "agent.id": agentId } }],
            }),
            size: 20,
            sort: [{ timestamp: { order: "desc" } }],
          },
          "alerts"
        );

        const hits = agentAlerts.hits?.hits ?? [];
        if (hits.length > 0) {
          sources.push({
            type: "indexer",
            label: `Agent ${agentId} alerts (${hits.length} results)`,
            data: hits.map((h: { _source: unknown }) => h._source),
            relevance: "primary",
          });
        }
      } catch {
        // Skip if index doesn't exist
      }
    }
  } catch (err) {
    sources.push({ type: "indexer", label: "Indexer search error", data: { error: (err as Error).message }, relevance: "error" });
  }

  return sources;
}

// ── Phase 4: LLM Synthesis ──────────────────────────────────────────────────

async function synthesizeResponse(
  query: string,
  intent: IntentAnalysis,
  sources: RetrievalSource[],
  conversationHistory: AnalystMessage[]
): Promise<AnalystResponse> {
  // Build context from sources
  const sourceContext = sources
    .filter(s => s.relevance !== "error")
    .map((s, i) => {
      const dataStr = typeof s.data === "string" ? s.data : JSON.stringify(s.data, null, 1);
      // Truncate large data to avoid token limits
      const truncated = dataStr.length > 3000 ? dataStr.slice(0, 3000) + "\n... [truncated]" : dataStr;
      return `[Source ${i + 1}: ${s.label}]\n${truncated}`;
    })
    .join("\n\n");

  const historyContext = conversationHistory
    .slice(-8)
    .map(m => `${m.role}: ${m.content}`)
    .join("\n");

  const response = await invokeLLM({
    messages: [
      {
        role: "system",
        content: `You are SecondSight, an expert security analyst AI assistant integrated with a Wazuh SIEM platform.
Your role is to provide actionable, evidence-based security analysis.

CRITICAL RULES:
1. Ground every claim in the retrieved data. Cite specific agent IDs, rule IDs, CVE IDs, timestamps, and IP addresses.
2. If the data is insufficient, say so explicitly. Never fabricate security findings.
3. Use chain-of-thought reasoning: explain your analytical process step by step.
4. Prioritize findings by severity: Critical > High > Medium > Low > Informational.
5. For threat hunting queries, suggest specific next investigation steps.
6. For vulnerability assessments, include CVSS scores and affected asset counts.
7. Format responses in Markdown with clear headings and structured data.
8. When referencing MITRE ATT&CK, use the standard tactic/technique IDs.
9. Treat all data as forensic evidence — preserve exact values, never approximate.
10. If no relevant data is found, provide general security guidance related to the query.

RESPONSE FORMAT:
Provide your analysis in clear, structured Markdown. Include:
- Executive summary (2-3 sentences)
- Detailed findings with evidence
- Risk assessment where applicable
- Recommended actions
- Suggested follow-up queries

The user's detected intent is: ${intent.intent}
Extracted entities: ${JSON.stringify(intent.entities)}`,
      },
      {
        role: "user",
        content: `Conversation history:\n${historyContext}\n\nRetrieved context:\n${sourceContext}\n\nAnalyst query: ${query}`,
      },
    ],
  });

  const answer = (response.choices?.[0]?.message?.content as string | undefined) ?? "Unable to generate analysis. Please try rephrasing your query.";

  // Generate follow-up suggestions
  const followUpResponse = await invokeLLM({
    messages: [
      {
        role: "system",
        content: `Based on a security analysis conversation, suggest 3 follow-up investigation queries.
Return a JSON array of 3 strings. Each should be a specific, actionable security question.
Example: ["What MITRE techniques are associated with agent 001?", "Show me all critical CVEs affecting the web servers", "What lateral movement indicators exist in the last 24 hours?"]`,
      },
      {
        role: "user",
        content: `Original query: ${query}\nIntent: ${intent.intent}\nAnalysis provided: ${answer.slice(0, 500)}`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "follow_ups",
        strict: true,
        schema: {
          type: "object",
          properties: {
            suggestions: { type: "array", items: { type: "string" } },
          },
          required: ["suggestions"],
          additionalProperties: false,
        },
      },
    },
  });

  let suggestedFollowUps: string[] = [];
  try {
    const parsed = JSON.parse((followUpResponse.choices?.[0]?.message?.content as string | undefined) ?? "{}");
    suggestedFollowUps = parsed.suggestions ?? [];
  } catch {
    suggestedFollowUps = [
      "Show me the most critical alerts from the last 24 hours",
      "Which endpoints have the most vulnerabilities?",
      "What MITRE ATT&CK techniques are most prevalent?",
    ];
  }

  return {
    answer,
    reasoning: `Intent: ${intent.intent} | Strategy: ${intent.retrievalStrategy.join(", ")} | Sources: ${sources.length} retrieved`,
    sources,
    suggestedFollowUps: suggestedFollowUps.slice(0, 3),
  };
}

// ── Main Pipeline ───────────────────────────────────────────────────────────

/**
 * Execute the full 4-phase agentic analysis pipeline.
 */
export async function runAnalystPipeline(
  query: string,
  conversationHistory: AnalystMessage[] = []
): Promise<AnalystResponse> {
  // Phase 1: Intent Analysis
  const intent = await analyzeIntent(query, conversationHistory);

  // Phase 2 & 3: Parallel Retrieval
  const retrievalPromises: Promise<RetrievalSource[]>[] = [];

  const strategy = intent.retrievalStrategy;
  const useGraph = strategy.includes("graph") || strategy.includes("both");
  const useIndexer = strategy.includes("indexer") || strategy.includes("both");

  if (useGraph) retrievalPromises.push(retrieveFromGraph(intent));
  if (useIndexer) retrievalPromises.push(retrieveFromIndexer(intent));

  // Always get graph stats for context
  if (!useGraph) {
    retrievalPromises.push(
      getGraphStats().then(stats => [{ type: "stats" as const, label: "Knowledge Graph Statistics", data: stats, relevance: "context" }])
    );
  }

  const allSources = (await Promise.all(retrievalPromises)).flat();

  // Phase 4: LLM Synthesis
  const response = await synthesizeResponse(query, intent, allSources, conversationHistory);

  return response;
}
