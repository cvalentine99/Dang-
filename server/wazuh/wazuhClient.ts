/**
 * Wazuh API Client — server-side only.
 *
 * Authentication protocol (Wazuh 4.x):
 *
 *   Step 1 — Authenticate with Basic Auth (no request body):
 *     POST /security/user/authenticate
 *     Authorization: Basic base64(user:pass)
 *     → Returns { data: { token: "<JWT>", exp: <unix_epoch> } }
 *
 *   Step 2 — Use JWT Bearer token on ALL subsequent API requests:
 *     Authorization: Bearer <JWT>
 *
 *   JWT tokens are NOT refreshable. On expiry or 401, the client
 *   must re-authenticate from scratch and retry the failed request once.
 *
 * Why JWT is required:
 *   Wazuh does NOT support Basic Auth on protected endpoints. Only the
 *   /security/user/authenticate endpoint accepts Basic Auth. Every other
 *   endpoint requires a Bearer JWT obtained from that endpoint.
 *
 * Why /authenticate has no body:
 *   The Wazuh authentication endpoint derives credentials solely from the
 *   Authorization header. Sending any request body (even empty JSON `{}`)
 *   violates the API contract and may cause authentication failures.
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
import https from "https";
import fs from "fs";

// ── Token state ───────────────────────────────────────────────────────────────
// We store the JWT and its expiration from the Wazuh API response.
// A 60-second buffer ensures we re-authenticate before actual expiry.
const TOKEN_EXPIRY_BUFFER_MS = 60_000;

interface CachedToken {
  jwt: string;
  expiresAt: number; // Date.now()-based epoch ms
}

let cachedToken: CachedToken | null = null;
let tokenInflight: Promise<string> | null = null; // mutex for concurrent auth

// ── Rate-limit state (simple token bucket per endpoint group) ─────────────────
const rateLimitState: Record<string, { count: number; resetAt: number }> = {};
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMITS: Record<string, number> = {
  default: 60,
  alerts: 30,
  vulnerabilities: 20,
  syscheck: 20,
  syscollector: 20,
  connection_test: 5,
};

export function checkRateLimit(group: string): void {
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

// ── TLS configuration ─────────────────────────────────────────────────────────
// By default, TLS certificates are verified. For Wazuh deployments with
// self-signed certs, set WAZUH_VERIFY_TLS=false. For custom CA certs,
// set WAZUH_CA_CERT to the path of the CA bundle (PEM format).
function buildHttpsAgent(): https.Agent {
  const verifyTls = (process.env.WAZUH_VERIFY_TLS ?? "true").toLowerCase() !== "false";
  const caCertPath = process.env.WAZUH_CA_CERT;

  const opts: https.AgentOptions = { rejectUnauthorized: verifyTls };

  if (caCertPath) {
    try {
      opts.ca = fs.readFileSync(caCertPath);
      console.log("[Wazuh TLS] Using custom CA cert: %s", caCertPath);
    } catch (err) {
      console.error("[Wazuh TLS] Failed to read CA cert at %s: %s", caCertPath, (err as Error).message);
    }
  }

  if (!verifyTls) {
    console.warn("[Wazuh TLS] Certificate verification DISABLED (WAZUH_VERIFY_TLS=false)");
  }

  return new https.Agent(opts);
}

let _httpsAgent: https.Agent | null = null;
function getHttpsAgent(): https.Agent {
  if (!_httpsAgent) _httpsAgent = buildHttpsAgent();
  return _httpsAgent;
}

// ── Axios instance ────────────────────────────────────────────────────────────
function createAxiosInstance(baseURL: string): AxiosInstance {
  return axios.create({
    baseURL,
    timeout: 8_000,
    httpsAgent: getHttpsAgent(),
    // NOTE: Do NOT set a default Content-Type here. The /security/user/authenticate
    // endpoint must receive NO body and NO Content-Type. GET requests also don't
    // need one. Axios sets Content-Type automatically when a body is present.
  });
}

// ── Token management ──────────────────────────────────────────────────────────

/**
 * Performs the actual authentication call. Called only by getToken().
 */
async function authenticateWazuh(baseURL: string, user: string, pass: string): Promise<string> {
  const wasExpired = cachedToken !== null;
  console.log("[Wazuh Auth] %s — calling POST /security/user/authenticate",
    wasExpired ? "Token expired, re-authenticating" : "Initial authentication");

  const instance = createAxiosInstance(baseURL);

  // CRITICAL: The Wazuh /security/user/authenticate endpoint accepts
  // ONLY Basic Auth in the header. It requires NO request body at all.
  // Sending any body (even empty JSON `{}`) violates the API contract.
  const response = await instance.post(
    "/security/user/authenticate",
    undefined, // No body — Wazuh auth accepts credentials in the header only
    { auth: { username: user, password: pass } }
  );

  const token: string = response.data?.data?.token;
  if (!token) throw new Error("Wazuh authentication failed: no token returned");

  // Parse expiration from the API response. Wazuh returns exp as unix epoch seconds.
  // Fall back to 840 seconds (14 min) if exp is missing, which is under the default 900s.
  const expEpochSeconds: number | undefined = response.data?.data?.exp;
  const expiresAt = expEpochSeconds
    ? expEpochSeconds * 1000 // Convert seconds → ms
    : Date.now() + 840_000; // Fallback: 840s

  cachedToken = { jwt: token, expiresAt };

  console.log("[Wazuh Auth] JWT obtained successfully (expires in %ds)",
    Math.round((expiresAt - Date.now()) / 1000));

  return token;
}

/**
 * Returns a valid JWT, re-authenticating only when the cached token is missing
 * or expired. Uses a promise lock so concurrent callers share a single
 * in-flight auth request instead of firing duplicate POST calls.
 */
async function getToken(baseURL: string, user: string, pass: string): Promise<string> {
  // Return cached token if it hasn't expired (with buffer)
  if (cachedToken && Date.now() < cachedToken.expiresAt - TOKEN_EXPIRY_BUFFER_MS) {
    console.log("[Wazuh Auth] Reusing cached JWT (expires in %ds)",
      Math.round((cachedToken.expiresAt - Date.now()) / 1000));
    return cachedToken.jwt;
  }

  // If another caller is already authenticating, wait for that result
  if (tokenInflight) {
    console.log("[Wazuh Auth] Waiting for in-flight authentication");
    return tokenInflight;
  }

  // First caller — take the lock and authenticate
  tokenInflight = authenticateWazuh(baseURL, user, pass).finally(() => {
    tokenInflight = null;
  });

  return tokenInflight;
}

/** Clear cached token so the next getToken() call re-authenticates. */
function invalidateToken(): void {
  cachedToken = null;
  console.log("[Wazuh Auth] Token invalidated (will re-authenticate on next request)");
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
    // All protected Wazuh endpoints require Bearer JWT — never Basic Auth
    const response = await instance.get(path, {
      params: cleanParams,
      headers: { Authorization: `Bearer ${token}` },
    });

    return stripSensitiveFields(response.data);
  } catch (err: unknown) {
    if (axios.isAxiosError(err) && err.response?.status === 401) {
      // Token expired or revoked — invalidate, re-authenticate, retry once
      console.log("[Wazuh Auth] 401 on %s — re-authenticating and retrying", path);
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

// ── Config loader (env-only, synchronous) ────────────────────────────────────
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

// ── Runtime config loader (DB override → env fallback, async) ────────────────

/**
 * Get Wazuh config checking DB overrides first, then env vars.
 * Use this in request handlers instead of the sync version.
 */
export async function getEffectiveWazuhConfig(): Promise<WazuhConfig | null> {
  try {
    const { getEffectiveWazuhConfig: getFromDb } = await import("../admin/connectionSettingsService");
    return await getFromDb();
  } catch {
    // If DB is not available, fall back to env
    if (isWazuhConfigured()) return getWazuhConfig();
    return null;
  }
}

/**
 * Resolve candidate Wazuh configs in priority order.
 *
 * 1) DB override (Admin > Connection Settings)
 * 2) Environment variables (docker/.env)
 *
 * This allows runtime fallback when stale DB overrides are persisted while
 * environment variables have already been corrected.
 */
export async function getWazuhConfigCandidates(): Promise<WazuhConfig[]> {
  const candidates: WazuhConfig[] = [];

  const dbConfig = await getEffectiveWazuhConfig();
  if (dbConfig) candidates.push(dbConfig);

  if (isWazuhConfigured()) {
    const envConfig = getWazuhConfig();
    const isDuplicate = candidates.some((candidate) =>
      candidate.host === envConfig.host &&
      candidate.port === envConfig.port &&
      candidate.user === envConfig.user &&
      candidate.pass === envConfig.pass
    );
    if (!isDuplicate) candidates.push(envConfig);
  }

  return candidates;
}

/**
 * Check if Wazuh is configured via DB overrides or env vars.
 */
export async function isWazuhEffectivelyConfigured(): Promise<boolean> {
  const config = await getEffectiveWazuhConfig();
  return config !== null;
}
