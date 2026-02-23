/**
 * Wazuh API Client — server-side only.
 *
 * Responsibilities:
 * - Manage JWT token lifecycle (obtain, cache, refresh)
 * - Enforce read-only access (GET only)
 * - Apply per-endpoint rate limiting
 * - Strip sensitive fields before returning data
 * - Never expose tokens to the browser
 * - Fail closed on auth/network errors
 */

import axios, { AxiosInstance } from "axios";
import NodeCache from "node-cache";
import https from "https";

// ── Token cache (TTL slightly under Wazuh's 900s default) ─────────────────────
const tokenCache = new NodeCache({ stdTTL: 840, checkperiod: 60 });
const TOKEN_KEY = "wazuh_jwt";

// ── Rate-limit state (simple token bucket per endpoint group) ─────────────────
const rateLimitState: Record<string, { count: number; resetAt: number }> = {};
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMITS: Record<string, number> = {
  default: 60,
  alerts: 30,
  vulnerabilities: 20,
  syscheck: 20,
};

function checkRateLimit(group: string): void {
  const limit = RATE_LIMITS[group] ?? RATE_LIMITS.default;
  const now = Date.now();
  if (!rateLimitState[group] || now > rateLimitState[group].resetAt) {
    rateLimitState[group] = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
  }
  rateLimitState[group].count++;
  if (rateLimitState[group].count > limit) {
    throw new Error(`Rate limit exceeded for endpoint group '${group}'. Retry after ${Math.ceil((rateLimitState[group].resetAt - now) / 1000)}s.`);
  }
}

// ── Sensitive fields to strip from all responses ──────────────────────────────
const STRIP_FIELDS = new Set([
  "password",
  "token",
  "secret",
  "api_key",
  "key",
  "auth",
  "credential",
]);

function stripSensitiveFields(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(stripSensitiveFields);
  if (obj && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (!STRIP_FIELDS.has(k.toLowerCase())) {
        result[k] = stripSensitiveFields(v);
      }
    }
    return result;
  }
  return obj;
}

// ── Axios instance (skip TLS verification for self-signed certs) ──────────────
function createAxiosInstance(baseURL: string): AxiosInstance {
  return axios.create({
    baseURL,
    timeout: 8_000,
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    headers: { "Content-Type": "application/json" },
  });
}

// ── Token management ──────────────────────────────────────────────────────────
async function getToken(baseURL: string, user: string, pass: string): Promise<string> {
  const cached = tokenCache.get<string>(TOKEN_KEY);
  if (cached) return cached;

  const instance = createAxiosInstance(baseURL);
  const response = await instance.post(
    "/security/user/authenticate",
    {},
    { auth: { username: user, password: pass } }
  );

  const token: string = response.data?.data?.token;
  if (!token) throw new Error("Wazuh authentication failed: no token returned");

  tokenCache.set(TOKEN_KEY, token);
  return token;
}

function invalidateToken(): void {
  tokenCache.del(TOKEN_KEY);
}

// ── Core GET proxy ─────────────────────────────────────────────────────────────
export interface WazuhConfig {
  host: string;
  port: number;
  user: string;
  pass: string;
}

export interface WazuhGetOptions {
  path: string;
  params?: Record<string, string | number | boolean | undefined>;
  rateLimitGroup?: string;
}

export async function wazuhGet(
  config: WazuhConfig,
  options: WazuhGetOptions
): Promise<unknown> {
  const { path, params = {}, rateLimitGroup = "default" } = options;

  checkRateLimit(rateLimitGroup);

  const baseURL = `https://${config.host}:${config.port}`;
  let token: string;

  try {
    token = await getToken(baseURL, config.user, config.pass);
  } catch (err) {
    throw new Error(`Wazuh auth error: ${(err as Error).message}`);
  }

  const instance = createAxiosInstance(baseURL);

  // Filter out undefined params
  const cleanParams: Record<string, string | number | boolean> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) cleanParams[k] = v;
  }

  try {
    const response = await instance.get(path, {
      params: cleanParams,
      headers: { Authorization: `Bearer ${token}` },
    });

    return stripSensitiveFields(response.data);
  } catch (err: unknown) {
    if (axios.isAxiosError(err) && err.response?.status === 401) {
      // Token expired — invalidate and retry once
      invalidateToken();
      const freshToken = await getToken(baseURL, config.user, config.pass);
      const retryResponse = await instance.get(path, {
        params: cleanParams,
        headers: { Authorization: `Bearer ${freshToken}` },
      });
      return stripSensitiveFields(retryResponse.data);
    }
    throw err;
  }
}

// ── Config loader ─────────────────────────────────────────────────────────────
export function getWazuhConfig(): WazuhConfig {
  const host = process.env.WAZUH_HOST;
  const port = parseInt(process.env.WAZUH_PORT ?? "55000", 10);
  const user = process.env.WAZUH_USER;
  const pass = process.env.WAZUH_PASS;

  if (!host || !user || !pass) {
    throw new Error(
      "Wazuh is not configured. Set WAZUH_HOST, WAZUH_USER, and WAZUH_PASS environment variables."
    );
  }

  return { host, port, user, pass };
}

export function isWazuhConfigured(): boolean {
  return !!(process.env.WAZUH_HOST && process.env.WAZUH_USER && process.env.WAZUH_PASS);
}
