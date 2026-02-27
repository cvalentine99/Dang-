import { describe, it, expect } from "vitest";

/**
 * Validate that Wazuh connection secrets are properly set.
 * These tests verify the environment variables are configured correctly.
 * Hosts must be a valid hostname or IP — exact value varies between
 * local dev (localhost), CI (127.0.0.1), and Docker (host.docker.internal).
 */
const VALID_HOST_RE = /^(localhost|127\.0\.0\.1|host\.docker\.internal|[\w.\-]+)$/;

describe("Wazuh Connection Secrets", () => {
  it("should have WAZUH_HOST set to a valid host", () => {
    expect(process.env.WAZUH_HOST).toBeDefined();
    expect(process.env.WAZUH_HOST).toMatch(VALID_HOST_RE);
  });

  it("should have WAZUH_PORT set to 55000", () => {
    expect(process.env.WAZUH_PORT).toBe("55000");
  });

  it("should have WAZUH_USER configured", () => {
    expect(process.env.WAZUH_USER).toBeDefined();
    expect(process.env.WAZUH_USER!.length).toBeGreaterThan(0);
  });

  it("should have WAZUH_PASS set (non-empty)", () => {
    expect(process.env.WAZUH_PASS).toBeTruthy();
    expect(process.env.WAZUH_PASS!.length).toBeGreaterThan(0);
  });

  it("should have WAZUH_INDEXER_HOST set to a valid host", () => {
    expect(process.env.WAZUH_INDEXER_HOST).toBeDefined();
    expect(process.env.WAZUH_INDEXER_HOST).toMatch(VALID_HOST_RE);
  });

  it("should have WAZUH_INDEXER_PORT set to 9200", () => {
    expect(process.env.WAZUH_INDEXER_PORT).toBe("9200");
  });

  it("should have WAZUH_INDEXER_USER configured", () => {
    expect(process.env.WAZUH_INDEXER_USER).toBeDefined();
    expect(process.env.WAZUH_INDEXER_USER!.length).toBeGreaterThan(0);
  });

  it("should have WAZUH_INDEXER_PASS set (non-empty)", () => {
    expect(process.env.WAZUH_INDEXER_PASS).toBeTruthy();
    expect(process.env.WAZUH_INDEXER_PASS!.length).toBeGreaterThan(0);
  });
});
