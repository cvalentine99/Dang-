/**
 * AlienVault OTX tRPC Router — read-only threat intelligence queries.
 *
 * Endpoints:
 * - status: Check OTX connectivity and user info
 * - subscribedPulses: Paginated list of subscribed pulses
 * - pulseDetail: Single pulse with metadata
 * - pulseIndicators: IOCs within a pulse
 * - searchPulses: Full-text pulse search
 * - indicatorLookup: IOC reputation lookup (IPv4, IPv6, domain, hostname, file hash, URL, CVE)
 * - activity: Recent pulse activity feed
 */

import { z } from "zod";
import { publicProcedure, router } from "../_core/trpc";
import { isOtxConfigured, otxGet } from "./otxClient";

export const otxRouter = router({
  // ── Status / connectivity check ────────────────────────────────────────────
  status: publicProcedure.query(async () => {
    if (!isOtxConfigured()) {
      return { configured: false, user: null };
    }
    try {
      const user = await otxGet("/api/v1/users/me", {}, "default", 600);
      return { configured: true, user };
    } catch (err) {
      return { configured: true, user: null, error: (err as Error).message };
    }
  }),

  // ── Subscribed pulses (paginated) ──────────────────────────────────────────
  subscribedPulses: publicProcedure
    .input(
      z.object({
        page: z.number().int().min(1).default(1),
        limit: z.number().int().min(1).max(50).default(10),
        modified_since: z.string().optional(),
      })
    )
    .query(async ({ input }) => {
      if (!isOtxConfigured()) {
        return { configured: false, data: null };
      }
      const data = await otxGet(
        "/api/v1/pulses/subscribed",
        {
          page: input.page,
          limit: input.limit,
          modified_since: input.modified_since,
        },
        "pulses",
        300
      );
      return { configured: true, data };
    }),

  // ── Pulse detail ───────────────────────────────────────────────────────────
  pulseDetail: publicProcedure
    .input(z.object({ pulseId: z.string().min(1) }))
    .query(async ({ input }) => {
      if (!isOtxConfigured()) {
        return { configured: false, data: null };
      }
      const data = await otxGet(
        `/api/v1/pulses/${input.pulseId}`,
        {},
        "pulses",
        300
      );
      return { configured: true, data };
    }),

  // ── Pulse indicators (IOCs in a pulse) ─────────────────────────────────────
  pulseIndicators: publicProcedure
    .input(
      z.object({
        pulseId: z.string().min(1),
        page: z.number().int().min(1).default(1),
        limit: z.number().int().min(1).max(500).default(50),
      })
    )
    .query(async ({ input }) => {
      if (!isOtxConfigured()) {
        return { configured: false, data: null };
      }
      const data = await otxGet(
        `/api/v1/pulses/${input.pulseId}/indicators`,
        { page: input.page, limit: input.limit },
        "pulses",
        300
      );
      return { configured: true, data };
    }),

  // ── Search pulses ──────────────────────────────────────────────────────────
  searchPulses: publicProcedure
    .input(
      z.object({
        query: z.string().min(1),
        page: z.number().int().min(1).default(1),
        limit: z.number().int().min(1).max(50).default(10),
      })
    )
    .query(async ({ input }) => {
      if (!isOtxConfigured()) {
        return { configured: false, data: null };
      }
      const data = await otxGet(
        "/api/v1/search/pulses",
        { q: input.query, page: input.page, limit: input.limit },
        "search",
        300
      );
      return { configured: true, data };
    }),

  // ── IOC Indicator lookup ───────────────────────────────────────────────────
  indicatorLookup: publicProcedure
    .input(
      z.object({
        type: z.enum(["IPv4", "IPv6", "domain", "hostname", "file", "url", "cve"]),
        value: z.string().min(1),
        section: z
          .enum(["general", "reputation", "geo", "malware", "url_list", "passive_dns", "http_scans", "analysis"])
          .default("general"),
      })
    )
    .query(async ({ input }) => {
      if (!isOtxConfigured()) {
        return { configured: false, data: null };
      }

      // URL indicators need encoding
      const encodedValue = input.type === "url"
        ? encodeURIComponent(input.value)
        : input.value;

      const data = await otxGet(
        `/api/v1/indicators/${input.type}/${encodedValue}/${input.section}`,
        {},
        "indicators",
        600 // Cache IOC lookups for 10 minutes
      );
      return { configured: true, data };
    }),

  // ── Recent activity feed ───────────────────────────────────────────────────
  activity: publicProcedure
    .input(
      z.object({
        page: z.number().int().min(1).default(1),
        limit: z.number().int().min(1).max(50).default(20),
      })
    )
    .query(async ({ input }) => {
      if (!isOtxConfigured()) {
        return { configured: false, data: null };
      }
      const data = await otxGet(
        "/api/v1/pulses/activity",
        { page: input.page, limit: input.limit },
        "pulses",
        300
      );
      return { configured: true, data };
    }),
});
