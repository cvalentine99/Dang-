/**
 * HybridRAG Router — Agentic AI assistant for Dang!
 *
 * Architecture:
 * - Primary: NVIDIA Nemotron 3 Nano (local Ollama/OpenAI-compatible endpoint)
 * - Fallback: Manus built-in LLM (invokeLLM) if local model unavailable
 * - RAG context: injects live Wazuh telemetry snapshot into system prompt
 * - Analyst notes: full CRUD for local forensic annotations
 *
 * The assistant is read-only — it cannot trigger Wazuh actions.
 */

import { z } from "zod";
import { eq, desc, and } from "drizzle-orm";
import axios from "axios";
import { nanoid } from "nanoid";
import { publicProcedure, protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import { analystNotes, ragSessions } from "../../drizzle/schema";
import { invokeLLM } from "../_core/llm";
import { isWazuhConfigured, wazuhGet, getWazuhConfig, getEffectiveWazuhConfig } from "../wazuh/wazuhClient";

// ── Nemotron 3 Nano config ────────────────────────────────────────────────────
const NEMOTRON_BASE_URL = process.env.NEMOTRON_BASE_URL ?? "http://localhost:11434";
const NEMOTRON_MODEL = process.env.NEMOTRON_MODEL ?? "unsloth/Nemotron-3-Nano-30B-A3B-GGUF";

interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

/**
 * Try the local Nemotron 3 Nano model via Ollama-compatible API.
 * Falls back to Manus LLM if unavailable.
 */
async function callNemotron(messages: ChatMessage[]): Promise<string> {
  try {
    const response = await axios.post(
      `${NEMOTRON_BASE_URL}/v1/chat/completions`,
      {
        model: NEMOTRON_MODEL,
        messages,
        temperature: 0.3,
        max_tokens: 2048,
        stream: false,
      },
      { timeout: 30_000, headers: { "Content-Type": "application/json" } }
    );
    const content = response.data?.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty response from Nemotron");
    return content;
  } catch {
    // Fallback to Manus built-in LLM
    const fallbackMessages = messages.map(m => ({
      role: m.role as "system" | "user" | "assistant",
      content: m.content as string,
    }));
    const result = await invokeLLM({ messages: fallbackMessages });
    const rawContent = result.choices?.[0]?.message?.content;
    return typeof rawContent === 'string' ? rawContent : "Unable to generate response.";
  }
}

/**
 * Check if the local Nemotron model is available.
 */
async function checkNemotronAvailability(): Promise<{ available: boolean; model: string; endpoint: string }> {
  try {
    const response = await axios.get(`${NEMOTRON_BASE_URL}/api/tags`, { timeout: 3_000 });
    const models: Array<{ name: string }> = response.data?.models ?? [];
    const available = models.some(m => m.name.includes("nemotron") || m.name.includes("nano"));
    return { available, model: NEMOTRON_MODEL, endpoint: NEMOTRON_BASE_URL };
  } catch {
    return { available: false, model: NEMOTRON_MODEL, endpoint: NEMOTRON_BASE_URL };
  }
}

/**
 * Build a RAG context snapshot from live Wazuh telemetry.
 * This is injected into the system prompt for grounded responses.
 */
async function buildWazuhContext(): Promise<string> {
  const config = await getEffectiveWazuhConfig();
  if (!config) {
    return "No Wazuh connection configured. Answering from general security knowledge only.";
  }
  const lines: string[] = ["## Live Wazuh Telemetry Context\n"];

  try {
    const summary = await wazuhGet(config, { path: "/agents/summary/status" }) as Record<string, unknown>;
    const data = (summary as { data?: Record<string, unknown> }).data ?? summary;
    lines.push(`### Agent Summary\n${JSON.stringify(data, null, 2)}\n`);
  } catch { lines.push("Agent summary: unavailable\n"); }

  try {
    const analysisd = await wazuhGet(config, { path: "/manager/stats/analysisd" }) as Record<string, unknown>;
    const data = (analysisd as { data?: Record<string, unknown> }).data ?? analysisd;
    lines.push(`### Analysis Engine Stats\n${JSON.stringify(data, null, 2)}\n`);
  } catch { lines.push("Analysisd stats: unavailable\n"); }

  return lines.join("\n");
}

// ── System prompt ─────────────────────────────────────────────────────────────
function buildSystemPrompt(wazuhContext: string): string {
  return `You are Dang! — an expert security analyst AI assistant embedded in a Wazuh SIEM platform.

Your capabilities:
- Analyze Wazuh alerts, agent health, vulnerabilities, and compliance data
- Explain MITRE ATT&CK techniques and map them to observed indicators
- Help analysts triage incidents, prioritize CVEs, and interpret FIM events
- Suggest investigative pivots and remediation steps (advisory only)
- Interpret compliance check failures for PCI-DSS, GDPR, HIPAA, NIST

Your constraints (non-negotiable):
- You are READ-ONLY. Never suggest commands that modify Wazuh configuration.
- Never trigger active responses, delete agents, or modify rules.
- Always cite the specific agent ID, rule ID, or CVE when referencing data.
- If data is unavailable, say so clearly — do not fabricate telemetry.
- Treat all data as forensic evidence. Preserve timestamps and identifiers.

Response format:
- Use structured markdown with clear headings
- Use code blocks for rule IDs, hashes, and JSON
- Use threat level terminology: Critical / High / Medium / Low / Info
- Be concise but thorough — analysts need actionable intelligence

${wazuhContext}

Current date: ${new Date().toISOString()}`;
}

// ── Router ────────────────────────────────────────────────────────────────────
export const hybridragRouter = router({

  // ── Model status ────────────────────────────────────────────────────────────
  modelStatus: publicProcedure.query(async () => {
    const nemotron = await checkNemotronAvailability();
    return {
      nemotron,
      fallbackAvailable: true,
      activeModel: nemotron.available ? NEMOTRON_MODEL : "manus-builtin",
    };
  }),

  // ── Chat ────────────────────────────────────────────────────────────────────
  chat: publicProcedure
    .input(
      z.object({
        sessionId: z.string().default(() => nanoid()),
        message: z.string().min(1).max(4000),
        /** Optional context from the current page (agent IDs, alert data, etc.) */
        pageContext: z.record(z.string(), z.unknown()).optional(),
        /** Whether to inject live Wazuh telemetry into context */
        injectWazuhContext: z.boolean().default(true),
      })
    )
    .mutation(async ({ input }) => {
      const db = await getDb();

      // Load conversation history
      const history = db
        ? await db
            .select()
            .from(ragSessions)
            .where(eq(ragSessions.sessionId, input.sessionId))
            .orderBy(ragSessions.createdAt)
            .limit(20)
        : [];

      // Build context
      const wazuhContext = input.injectWazuhContext
        ? await buildWazuhContext()
        : "Wazuh context injection disabled for this query.";

      const pageContextStr = input.pageContext
        ? `\n## Current Page Context\n\`\`\`json\n${JSON.stringify(input.pageContext, null, 2)}\n\`\`\`\n`
        : "";

      const systemPrompt = buildSystemPrompt(wazuhContext + pageContextStr);

      // Build messages array
      const messages: ChatMessage[] = [
        { role: "system", content: systemPrompt },
        ...history.map(h => ({
          role: h.role as "user" | "assistant",
          content: h.content,
        })),
        { role: "user", content: input.message },
      ];

      // Call model
      const response = await callNemotron(messages);

      // Persist to DB
      if (db) {
        await db.insert(ragSessions).values([
          {
            sessionId: input.sessionId,
            role: "user",
            content: input.message,
            contextSnapshot: input.pageContext,
          },
          {
            sessionId: input.sessionId,
            role: "assistant",
            content: response,
          },
        ]);
      }

      return {
        sessionId: input.sessionId,
        response,
        model: (await checkNemotronAvailability()).available ? NEMOTRON_MODEL : "manus-builtin",
      };
    }),

  // ── Session history ─────────────────────────────────────────────────────────
  sessionHistory: publicProcedure
    .input(z.object({ sessionId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];
      return db
        .select()
        .from(ragSessions)
        .where(eq(ragSessions.sessionId, input.sessionId))
        .orderBy(ragSessions.createdAt);
    }),

  clearSession: publicProcedure
    .input(z.object({ sessionId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) return { success: false };
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        await (db.delete(ragSessions) as any).where(eq(ragSessions.sessionId, input.sessionId));
      return { success: true };
    }),

  // ── Analyst Notes CRUD ──────────────────────────────────────────────────────
  notes: router({
    list: publicProcedure
      .input(
        z.object({
          agentId: z.string().optional(),
          ruleId: z.string().optional(),
          severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
          resolved: z.boolean().optional(),
          limit: z.number().int().min(1).max(200).default(50),
          offset: z.number().int().min(0).default(0),
        })
      )
      .query(async ({ input }) => {
        const db = await getDb();
        if (!db) return { notes: [], total: 0 };

        const conditions = [];
        if (input.agentId) conditions.push(eq(analystNotes.agentId, input.agentId));
        if (input.ruleId) conditions.push(eq(analystNotes.ruleId, input.ruleId));
        if (input.severity) conditions.push(eq(analystNotes.severity, input.severity));
        if (input.resolved !== undefined) {
          conditions.push(eq(analystNotes.resolved, input.resolved ? 1 : 0));
        }

        const query = db
          .select()
          .from(analystNotes)
          .orderBy(desc(analystNotes.createdAt))
          .limit(input.limit)
          .offset(input.offset);

        const notes = conditions.length > 0
          ? await db.select().from(analystNotes).where(and(...conditions)).orderBy(desc(analystNotes.createdAt)).limit(input.limit).offset(input.offset)
          : await query;

        return { notes };
      }),

    create: publicProcedure
      .input(
        z.object({
          title: z.string().min(1).max(512),
          content: z.string().default(""),
          severity: z.enum(["critical", "high", "medium", "low", "info"]).default("info"),
          agentId: z.string().optional(),
          ruleId: z.string().optional(),
          cveId: z.string().optional(),
          tags: z.array(z.string()).default([]),
        })
      )
      .mutation(async ({ input }) => {
        const db = await getDb();
        if (!db) throw new Error("Database unavailable");

        const result = await db.insert(analystNotes).values({
          title: input.title,
          content: input.content,
          severity: input.severity,
          agentId: input.agentId,
          ruleId: input.ruleId,
          cveId: input.cveId,
          tags: input.tags,
          resolved: 0,
        });

        return { id: Number(result[0].insertId), success: true };
      }),

    update: publicProcedure
      .input(
        z.object({
          id: z.number().int(),
          title: z.string().min(1).max(512).optional(),
          content: z.string().optional(),
          severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
          resolved: z.boolean().optional(),
          tags: z.array(z.string()).optional(),
        })
      )
      .mutation(async ({ input }) => {
        const db = await getDb();
        if (!db) throw new Error("Database unavailable");

        const updates: Partial<typeof analystNotes.$inferInsert> = {};
        if (input.title !== undefined) updates.title = input.title;
        if (input.content !== undefined) updates.content = input.content;
        if (input.severity !== undefined) updates.severity = input.severity;
        if (input.resolved !== undefined) updates.resolved = input.resolved ? 1 : 0;
        if (input.tags !== undefined) updates.tags = input.tags;

        await db.update(analystNotes).set(updates).where(eq(analystNotes.id, input.id));
        return { success: true };
      }),

    delete: publicProcedure
      .input(z.object({ id: z.number().int() }))
      .mutation(async ({ input }) => {
        const db = await getDb();
        if (!db) throw new Error("Database unavailable");
        await db.delete(analystNotes).where(eq(analystNotes.id, input.id));
        return { success: true };
      }),

    getById: publicProcedure
      .input(z.object({ id: z.number().int() }))
      .query(async ({ input }) => {
        const db = await getDb();
        if (!db) return null;
        const result = await db.select().from(analystNotes).where(eq(analystNotes.id, input.id)).limit(1);
        return result[0] ?? null;
      }),
  }),
});
