/**
 * AlienVault OTX DirectConnect API Client — server-side only.
 *
 * Responsibilities:
 * - Proxy all OTX requests through the backend
 * - API key stored server-side, never exposed to browser
 * - Rate limiting per endpoint group
 * - Read-only: only GET endpoints
 * - Fail closed on auth/network errors
 */

import axios, { AxiosInstance } from "axios";
import NodeCache from "node-cache";

const OTX_BASE_URL = "https://otx.alienvault.com";

// ── Response cache (5 minute TTL for pulse data) ─────────────────────────────
const responseCache = new NodeCache({ stdTTL: 300, checkperiod: 60 });

// ── Rate-limit state ─────────────────────────────────────────────────────────
const rateLimitState: Record<string, { count: number; resetAt: number }> = {};
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMITS: Record<string, number> = {
  default: 30,
  pulses: 20,
  indicators: 20,
  search: 15,
};

function checkRateLimit(group: string): void {
  const limit = RATE_LIMITS[group] ?? RATE_LIMITS.default;
  const now = Date.now();
  if (!rateLimitState[group] || now > rateLimitState[group].resetAt) {
    rateLimitState[group] = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
  }
  rateLimitState[group].count++;
  if (rateLimitState[group].count > limit) {
    throw new Error(
      `OTX rate limit exceeded for '${group}'. Retry after ${Math.ceil((rateLimitState[group].resetAt - now) / 1000)}s.`
    );
  }
}

// ── Config ───────────────────────────────────────────────────────────────────
export function getOtxApiKey(): string {
  const key = process.env.OTX_API_KEY;
  if (!key) {
    throw new Error("OTX_API_KEY is not configured. Set it in environment variables.");
  }
  return key;
}

export function isOtxConfigured(): boolean {
  return !!process.env.OTX_API_KEY;
}

// ── Axios instance ───────────────────────────────────────────────────────────
function createInstance(): AxiosInstance {
  return axios.create({
    baseURL: OTX_BASE_URL,
    timeout: 15_000,
    headers: {
      "X-OTX-API-KEY": getOtxApiKey(),
      "Content-Type": "application/json",
      Accept: "application/json",
    },
  });
}

// ── Core GET function with caching ───────────────────────────────────────────
export async function otxGet(
  path: string,
  params: Record<string, string | number | undefined> = {},
  rateLimitGroup: string = "default",
  cacheTTL?: number
): Promise<unknown> {
  checkRateLimit(rateLimitGroup);

  // Clean params
  const cleanParams: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) cleanParams[k] = v;
  }

  // Check cache
  const cacheKey = `otx:${path}:${JSON.stringify(cleanParams)}`;
  const cached = responseCache.get(cacheKey);
  if (cached) return cached;

  const instance = createInstance();

  try {
    const response = await instance.get(path, { params: cleanParams });
    const data = response.data;

    // Cache the response
    if (cacheTTL !== undefined) {
      responseCache.set(cacheKey, data, cacheTTL);
    } else {
      responseCache.set(cacheKey, data);
    }

    return data;
  } catch (err: unknown) {
    if (axios.isAxiosError(err)) {
      const status = err.response?.status;
      if (status === 401 || status === 403) {
        throw new Error("OTX authentication failed. Check your API key.");
      }
      if (status === 429) {
        throw new Error("OTX API rate limit exceeded. Please wait before retrying.");
      }
      throw new Error(`OTX API error (${status}): ${err.response?.data?.detail ?? err.message}`);
    }
    throw err;
  }
}
