/**
 * Parameter Broker — unit tests
 *
 * Proves the forwarding contract:
 *   - Accepted params are forwarded with correct Wazuh outbound names
 *   - Aliases resolve to the canonical param
 *   - Unsupported params are detected and returned
 *   - Type coercion works for string, number, boolean, csv
 *   - Empty/null/undefined values are omitted (not forwarded as empty strings)
 *
 * Also proves the endpoint-specific configs for all 5 wired endpoints:
 *   /agents, /rules, /groups, /cluster/nodes, /sca/{agent_id}
 */
import { describe, it, expect } from "vitest";
import {
  brokerParams,
  AGENTS_CONFIG,
  RULES_CONFIG,
  GROUPS_CONFIG,
  CLUSTER_NODES_CONFIG,
  SCA_POLICIES_CONFIG,
  SCA_CHECKS_CONFIG,
  UNIVERSAL_PARAMS,
} from "./paramBroker";

// ═══════════════════════════════════════════════════════════════════════════════
// BROKER CORE — unit tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("brokerParams core", () => {
  it("forwards recognized params with correct Wazuh outbound names", () => {
    const result = brokerParams(AGENTS_CONFIG, {
      limit: 50,
      offset: 10,
      status: "active",
    });
    expect(result.forwardedQuery).toEqual({
      limit: "50",
      offset: "10",
      status: "active",
    });
    expect(result.recognizedParams).toContain("limit");
    expect(result.recognizedParams).toContain("offset");
    expect(result.recognizedParams).toContain("status");
    expect(result.unsupportedParams).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });

  it("detects and returns unsupported params", () => {
    const result = brokerParams(AGENTS_CONFIG, {
      limit: 10,
      bogus_param: "hello",
      another_fake: 42,
    });
    expect(result.unsupportedParams).toContain("bogus_param");
    expect(result.unsupportedParams).toContain("another_fake");
    expect(result.recognizedParams).toContain("limit");
    // Unsupported params must NOT appear in forwardedQuery
    expect(result.forwardedQuery).not.toHaveProperty("bogus_param");
    expect(result.forwardedQuery).not.toHaveProperty("another_fake");
  });

  it("omits null, undefined, and empty-string values", () => {
    const result = brokerParams(AGENTS_CONFIG, {
      limit: 10,
      status: null,
      search: undefined,
      sort: "",
    });
    expect(result.forwardedQuery).toEqual({ limit: "10" });
    expect(result.recognizedParams).toEqual(["limit"]);
  });

  it("resolves aliases to canonical Wazuh param names", () => {
    const result = brokerParams(AGENTS_CONFIG, {
      os_platform: "ubuntu",
    });
    // os_platform is an alias for "os.platform" → wazuhName "os.platform"
    expect(result.forwardedQuery).toEqual({ "os.platform": "ubuntu" });
    expect(result.recognizedParams).toContain("os_platform");
    expect(result.unsupportedParams).toHaveLength(0);
  });

  it("coerces number values to strings", () => {
    const result = brokerParams(AGENTS_CONFIG, { limit: 100, offset: 0 });
    expect(result.forwardedQuery.limit).toBe("100");
    expect(result.forwardedQuery.offset).toBe("0");
  });

  it("coerces boolean values to strings", () => {
    const result = brokerParams(AGENTS_CONFIG, { distinct: true });
    expect(result.forwardedQuery.distinct).toBe("true");
  });

  it("coerces csv (array) values to comma-separated strings", () => {
    const result = brokerParams(AGENTS_CONFIG, { select: ["name", "ip", "status"] });
    expect(result.forwardedQuery.select).toBe("name,ip,status");
  });

  it("coerces csv (string) values pass-through", () => {
    const result = brokerParams(AGENTS_CONFIG, { select: "name,ip" });
    expect(result.forwardedQuery.select).toBe("name,ip");
  });

  it("handles NaN number coercion by omitting the param", () => {
    const result = brokerParams(AGENTS_CONFIG, { limit: "not-a-number" });
    expect(result.forwardedQuery).not.toHaveProperty("limit");
  });

  it("returns empty result for empty input", () => {
    const result = brokerParams(AGENTS_CONFIG, {});
    expect(result.forwardedQuery).toEqual({});
    expect(result.recognizedParams).toHaveLength(0);
    expect(result.unsupportedParams).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// FIX A1: os_platform → os.platform
// ═══════════════════════════════════════════════════════════════════════════════

describe("Fix A1: os_platform → os.platform", () => {
  it("maps os_platform alias to outbound os.platform", () => {
    const result = brokerParams(AGENTS_CONFIG, { os_platform: "ubuntu" });
    expect(result.forwardedQuery["os.platform"]).toBe("ubuntu");
    expect(result.forwardedQuery).not.toHaveProperty("os_platform");
    expect(result.recognizedParams).toContain("os_platform");
  });

  it("maps osPlatform alias to outbound os.platform", () => {
    const result = brokerParams(AGENTS_CONFIG, { osPlatform: "windows" });
    expect(result.forwardedQuery["os.platform"]).toBe("windows");
  });

  it("maps platform alias to outbound os.platform", () => {
    const result = brokerParams(AGENTS_CONFIG, { platform: "darwin" });
    expect(result.forwardedQuery["os.platform"]).toBe("darwin");
  });

  it("accepts the canonical os.platform name directly", () => {
    const result = brokerParams(AGENTS_CONFIG, { "os.platform": "centos" });
    expect(result.forwardedQuery["os.platform"]).toBe("centos");
  });

  it("maps os_name alias to outbound os.name", () => {
    const result = brokerParams(AGENTS_CONFIG, { os_name: "Ubuntu" });
    expect(result.forwardedQuery["os.name"]).toBe("Ubuntu");
  });

  it("maps os_version alias to outbound os.version", () => {
    const result = brokerParams(AGENTS_CONFIG, { os_version: "22.04" });
    expect(result.forwardedQuery["os.version"]).toBe("22.04");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// FIX A2: search and q are distinct, not conflated
// ═══════════════════════════════════════════════════════════════════════════════

describe("Fix A2: search and q are distinct", () => {
  it("forwards search as native Wazuh search (not rewritten to q)", () => {
    const result = brokerParams(AGENTS_CONFIG, { search: "webserver" });
    expect(result.forwardedQuery.search).toBe("webserver");
    // Must NOT have q — search is its own parameter
    expect(result.forwardedQuery).not.toHaveProperty("q");
  });

  it("forwards q as its own parameter", () => {
    const result = brokerParams(AGENTS_CONFIG, { q: "status=active" });
    expect(result.forwardedQuery.q).toBe("status=active");
    expect(result.forwardedQuery).not.toHaveProperty("search");
  });

  it("forwards both search and q independently when both provided", () => {
    const result = brokerParams(AGENTS_CONFIG, {
      search: "webserver",
      q: "os.platform=ubuntu",
    });
    expect(result.forwardedQuery.search).toBe("webserver");
    expect(result.forwardedQuery.q).toBe("os.platform=ubuntu");
  });

  it("does NOT rewrite search into q=name~... pattern", () => {
    const result = brokerParams(AGENTS_CONFIG, { search: "myhost" });
    // The old buggy behavior was: q: "name~myhost"
    // The correct behavior is: search: "myhost"
    expect(result.forwardedQuery.search).toBe("myhost");
    if (result.forwardedQuery.q) {
      expect(result.forwardedQuery.q).not.toContain("name~");
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// /agents endpoint config — full parameter coverage
// ═══════════════════════════════════════════════════════════════════════════════

describe("/agents endpoint config", () => {
  it("accepts all spec-defined parameters", () => {
    const fullInput = {
      limit: 100,
      offset: 0,
      sort: "+name",
      search: "test",
      select: "name,ip,status",
      q: "status=active",
      distinct: false,
      status: "active",
      "os.platform": "ubuntu",
      "os.version": "22.04",
      "os.name": "Ubuntu",
      older_than: "7d",
      manager_host: "wazuh-master",
      version: "Wazuh v4.14.3",
      group: "default",
      node_name: "node01",
      name: "agent-001",
      ip: "192.168.1.100",
      registerIP: "192.168.1.100",
      group_config_status: "synced",
    };
    const result = brokerParams(AGENTS_CONFIG, fullInput);
    expect(result.unsupportedParams).toHaveLength(0);
    expect(result.recognizedParams.length).toBe(Object.keys(fullInput).length);
  });

  it("rejects parameters not in the /agents spec", () => {
    const result = brokerParams(AGENTS_CONFIG, {
      limit: 10,
      filename: "rules.xml",      // belongs to /rules, not /agents
      pci_dss: "10.6.1",          // belongs to /rules, not /agents
    });
    expect(result.unsupportedParams).toContain("filename");
    expect(result.unsupportedParams).toContain("pci_dss");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// /rules endpoint config
// ═══════════════════════════════════════════════════════════════════════════════

describe("/rules endpoint config", () => {
  it("accepts all spec-defined parameters", () => {
    const fullInput = {
      limit: 100,
      offset: 0,
      sort: "+level",
      search: "ssh",
      select: "id,level,description",
      q: "level>10",
      distinct: true,
      status: "enabled",
      group: "syslog",
      level: "4-8",
      filename: "0010-rules_config.xml",
      relative_dirname: "ruleset/rules",
      pci_dss: "10.6.1",
      gdpr: "IV_35.7.d",
      gpg13: "7.1",
      hipaa: "164.312.b",
      "nist-800-53": "AU.6",
      tsc: "CC7.2",
      mitre: "T1059",
    };
    const result = brokerParams(RULES_CONFIG, fullInput);
    expect(result.unsupportedParams).toHaveLength(0);
    expect(result.recognizedParams.length).toBe(Object.keys(fullInput).length);
  });

  it("maps nist_800_53 alias to nist-800-53", () => {
    const result = brokerParams(RULES_CONFIG, { nist_800_53: "AU.6" });
    expect(result.forwardedQuery["nist-800-53"]).toBe("AU.6");
    expect(result.recognizedParams).toContain("nist_800_53");
  });

  it("maps relativeDirname alias to relative_dirname", () => {
    const result = brokerParams(RULES_CONFIG, { relativeDirname: "ruleset/rules" });
    expect(result.forwardedQuery.relative_dirname).toBe("ruleset/rules");
  });

  it("rejects parameters not in the /rules spec", () => {
    const result = brokerParams(RULES_CONFIG, {
      limit: 10,
      "os.platform": "ubuntu",  // belongs to /agents, not /rules
      registerIP: "1.2.3.4",    // belongs to /agents, not /rules
    });
    expect(result.unsupportedParams).toContain("os.platform");
    expect(result.unsupportedParams).toContain("registerIP");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// /groups endpoint config
// ═══════════════════════════════════════════════════════════════════════════════

describe("/groups endpoint config", () => {
  it("accepts universal params plus hash", () => {
    const result = brokerParams(GROUPS_CONFIG, {
      limit: 50,
      offset: 0,
      sort: "+name",
      search: "web",
      q: "name=default",
      hash: "md5",
    });
    expect(result.unsupportedParams).toHaveLength(0);
    expect(result.forwardedQuery.hash).toBe("md5");
    expect(result.forwardedQuery.search).toBe("web");
  });

  it("rejects endpoint-specific params from other endpoints", () => {
    const result = brokerParams(GROUPS_CONFIG, {
      limit: 10,
      level: "4",           // belongs to /rules
      "os.platform": "ubuntu", // belongs to /agents
    });
    expect(result.unsupportedParams).toContain("level");
    expect(result.unsupportedParams).toContain("os.platform");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// /cluster/nodes endpoint config
// ═══════════════════════════════════════════════════════════════════════════════

describe("/cluster/nodes endpoint config", () => {
  it("accepts universal params plus type", () => {
    const result = brokerParams(CLUSTER_NODES_CONFIG, {
      limit: 10,
      offset: 0,
      sort: "+name",
      search: "worker",
      type: "worker",
    });
    expect(result.unsupportedParams).toHaveLength(0);
    expect(result.forwardedQuery.type).toBe("worker");
    expect(result.forwardedQuery.search).toBe("worker");
  });

  it("maps node_type alias to type", () => {
    const result = brokerParams(CLUSTER_NODES_CONFIG, { node_type: "master" });
    expect(result.forwardedQuery.type).toBe("master");
    expect(result.recognizedParams).toContain("node_type");
  });

  it("maps nodeType alias to type", () => {
    const result = brokerParams(CLUSTER_NODES_CONFIG, { nodeType: "worker" });
    expect(result.forwardedQuery.type).toBe("worker");
  });

  it("rejects parameters not in the /cluster/nodes spec", () => {
    const result = brokerParams(CLUSTER_NODES_CONFIG, {
      limit: 10,
      status: "active",      // belongs to /agents, not /cluster/nodes
      level: "4",            // belongs to /rules
    });
    expect(result.unsupportedParams).toContain("status");
    expect(result.unsupportedParams).toContain("level");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// /sca/{agent_id} endpoint config
// ═══════════════════════════════════════════════════════════════════════════════

describe("/sca/{agent_id} policies config", () => {
  it("accepts universal params plus name, description, references", () => {
    const result = brokerParams(SCA_POLICIES_CONFIG, {
      limit: 50,
      offset: 0,
      search: "cis",
      name: "CIS Benchmark for Debian 10",
      description: "security",
      references: "https://www.cisecurity.org",
    });
    expect(result.unsupportedParams).toHaveLength(0);
    expect(result.forwardedQuery.name).toBe("CIS Benchmark for Debian 10");
    expect(result.forwardedQuery.description).toBe("security");
    expect(result.forwardedQuery.references).toBe("https://www.cisecurity.org");
  });

  it("maps policyName alias to name", () => {
    const result = brokerParams(SCA_POLICIES_CONFIG, { policyName: "CIS Debian" });
    expect(result.forwardedQuery.name).toBe("CIS Debian");
  });

  it("rejects parameters not in the /sca spec", () => {
    const result = brokerParams(SCA_POLICIES_CONFIG, {
      limit: 10,
      level: "4",           // belongs to /rules
      "os.platform": "ubuntu", // belongs to /agents
    });
    expect(result.unsupportedParams).toContain("level");
    expect(result.unsupportedParams).toContain("os.platform");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// /sca/{agent_id}/checks/{policy_id} endpoint config
// ═══════════════════════════════════════════════════════════════════════════════

describe("/sca/{agent_id}/checks/{policy_id} config", () => {
  it("accepts all spec-defined check parameters", () => {
    const fullInput = {
      limit: 100,
      offset: 0,
      sort: "+title",
      search: "password",
      q: "result=failed",
      title: "Ensure password expiration",
      description: "password policy",
      rationale: "security best practice",
      remediation: "Set PASS_MAX_DAYS",
      command: "grep PASS_MAX_DAYS",
      reason: "not configured",
      file: "/etc/login.defs",
      process: "sshd",
      directory: "/etc/ssh",
      registry: "HKLM\\Software",
      references: "CIS 5.4.1.1",
      result: "failed",
      condition: "all",
    };
    const result = brokerParams(SCA_CHECKS_CONFIG, fullInput);
    expect(result.unsupportedParams).toHaveLength(0);
    expect(result.recognizedParams.length).toBe(Object.keys(fullInput).length);
  });

  it("maps full_path alias to file", () => {
    const result = brokerParams(SCA_CHECKS_CONFIG, { full_path: "/etc/passwd" });
    expect(result.forwardedQuery.file).toBe("/etc/passwd");
  });

  it("rejects parameters not in the /sca checks spec", () => {
    const result = brokerParams(SCA_CHECKS_CONFIG, {
      limit: 10,
      "os.platform": "ubuntu",  // belongs to /agents
      pci_dss: "10.6.1",        // belongs to /rules
    });
    expect(result.unsupportedParams).toContain("os.platform");
    expect(result.unsupportedParams).toContain("pci_dss");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Cross-endpoint isolation — params from one endpoint must not leak to another
// ═══════════════════════════════════════════════════════════════════════════════

describe("cross-endpoint isolation", () => {
  const crossTestCases = [
    { name: "/agents", config: AGENTS_CONFIG, foreign: { level: "4", filename: "rules.xml", hash: "md5" } },
    { name: "/rules", config: RULES_CONFIG, foreign: { "os.platform": "ubuntu", registerIP: "1.2.3.4", hash: "md5" } },
    { name: "/groups", config: GROUPS_CONFIG, foreign: { level: "4", "os.platform": "ubuntu", result: "failed" } },
    { name: "/cluster/nodes", config: CLUSTER_NODES_CONFIG, foreign: { status: "active", level: "4", result: "failed" } },
    { name: "/sca policies", config: SCA_POLICIES_CONFIG, foreign: { level: "4", "os.platform": "ubuntu", filename: "rules.xml" } },
    { name: "/sca checks", config: SCA_CHECKS_CONFIG, foreign: { "os.platform": "ubuntu", level: "4", hash: "md5" } },
  ];

  for (const tc of crossTestCases) {
    it(`${tc.name} rejects foreign params: ${Object.keys(tc.foreign).join(", ")}`, () => {
      const result = brokerParams(tc.config, tc.foreign);
      for (const key of Object.keys(tc.foreign)) {
        expect(result.unsupportedParams).toContain(key);
      }
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// Universal params are present in all endpoint configs
// ═══════════════════════════════════════════════════════════════════════════════

describe("universal params present in all configs", () => {
  const configs = [
    { name: "/agents", config: AGENTS_CONFIG },
    { name: "/rules", config: RULES_CONFIG },
    { name: "/groups", config: GROUPS_CONFIG },
    { name: "/cluster/nodes", config: CLUSTER_NODES_CONFIG },
    { name: "/sca policies", config: SCA_POLICIES_CONFIG },
    { name: "/sca checks", config: SCA_CHECKS_CONFIG },
  ];

  const universalKeys = Object.keys(UNIVERSAL_PARAMS);

  for (const { name, config } of configs) {
    for (const key of universalKeys) {
      it(`${name} includes universal param "${key}"`, () => {
        expect(config.params).toHaveProperty(key);
        expect(config.params[key].wazuhName).toBe(UNIVERSAL_PARAMS[key as keyof typeof UNIVERSAL_PARAMS].wazuhName);
      });
    }
  }
});
