import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router } from "./_core/trpc";
import { wazuhRouter } from "./wazuh/wazuhRouter";
import { hybridragRouter } from "./hybridrag/hybridragRouter";
import { savedSearchesRouter } from "./savedSearches/savedSearchesRouter";
import { baselinesRouter } from "./baselines/baselinesRouter";
import { indexerRouter } from "./indexer/indexerRouter";
import { otxRouter } from "./otx/otxRouter";
import { notesRouter } from "./notes/notesRouter";
import { localAuthRouter } from "./localAuth/localAuthRouter";

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),

  // Wazuh read-only proxy — all GET, no mutations
  wazuh: wazuhRouter,

  // HybridRAG agentic assistant + analyst notes
  hybridrag: hybridragRouter,

  // Saved search queries (SIEM + Threat Hunting)
  savedSearches: savedSearchesRouter,

  // Configuration baselines for drift detection
  baselines: baselinesRouter,

  // Wazuh Indexer (OpenSearch/Elasticsearch) — read-only queries
  indexer: indexerRouter,

  // AlienVault OTX Threat Intelligence — read-only
  otx: otxRouter,

  // Analyst Notes v2 — local-only entity-linked notes
  notes: notesRouter,

  // Local auth for Docker self-hosted mode
  localAuth: localAuthRouter,
});

export type AppRouter = typeof appRouter;
