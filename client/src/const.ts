export { COOKIE_NAME, ONE_YEAR_MS } from "@shared/const";

// Generate login URL at runtime so redirect URI reflects the current origin.
// In self-hosted Docker deployments, Manus OAuth may not be configured —
// return a safe fallback instead of crashing on Invalid URL.
export const getLoginUrl = (returnPath?: string) => {
  const oauthPortalUrl = import.meta.env.VITE_OAUTH_PORTAL_URL;
  const appId = import.meta.env.VITE_APP_ID;

  // Guard: if OAuth is not configured (self-hosted Docker), return root
  if (!oauthPortalUrl || !appId) {
    console.warn("[Auth] VITE_OAUTH_PORTAL_URL or VITE_APP_ID not configured — OAuth login unavailable.");
    return "/";
  }

  const redirectUri = `${window.location.origin}/api/oauth/callback`;
  const state = btoa(JSON.stringify({ redirectUri, returnPath: returnPath || "/" }));

  try {
    const url = new URL(`${oauthPortalUrl}/app-auth`);
    url.searchParams.set("appId", appId);
    url.searchParams.set("redirectUri", redirectUri);
    url.searchParams.set("state", state);
    url.searchParams.set("type", "signIn");
    return url.toString();
  } catch {
    console.warn("[Auth] Failed to construct OAuth URL — returning fallback.");
    return "/";
  }
};
