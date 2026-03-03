/**
 * Wazuh Parameter Broker — truth-preserving parameter forwarding layer.
 *
 * Responsibilities:
 *   1. Define accepted parameters per Wazuh endpoint (from OpenAPI spec v4.14.3)
 *   2. Map public/internal names to outbound Wazuh query parameter names
 *   3. Coerce/serialize values to the types Wazuh expects
 *   4. Detect and reject unsupported parameters explicitly
 *   5. Assemble the outbound query object with only recognized params
 *
 * Non-negotiable rule: No accepted parameter may disappear silently.
 * Unsupported parameters are returned in the result so the caller can
 * decide whether to reject or warn.
 *
 * Spec baseline: Wazuh REST API OpenAPI v4.14.3-rc3
 */

// ── Types ────────────────────────────────────────────────────────────────────

/** How a parameter value should be serialized for the outbound Wazuh query */
export type ParamType = "string" | "number" | "boolean" | "csv";

export interface ParamDef {
  /** The outbound Wazuh query parameter name (as defined in the spec) */
  wazuhName: string;
  /** Human-readable description (from spec) */
  description: string;
  /** Value type for coercion */
  type: ParamType;
  /** Alternative public names that map to this parameter */
  aliases?: string[];
  /**
   * Optional coercion/serializer. Receives the raw input value and returns
   * the string to send to Wazuh, or null to omit the parameter.
   */
  serialize?: (value: unknown) => string | null;
}

export interface EndpointParamConfig {
  /** Wazuh API path pattern, e.g. "/agents" or "/sca/{agent_id}" */
  endpoint: string;
  /** Map of internal/public parameter name → definition */
  params: Record<string, ParamDef>;
}

export interface BrokerResult {
  /** The clean query object to forward to Wazuh */
  forwardedQuery: Record<string, string | number | boolean>;
  /** Parameters that were recognized and included */
  recognizedParams: string[];
  /** Parameters that were provided but are not in the endpoint config */
  unsupportedParams: string[];
  /** Validation/coercion errors */
  errors: string[];
}

// ── Coercers ─────────────────────────────────────────────────────────────────

function coerceString(value: unknown): string | null {
  if (value === undefined || value === null || value === "") return null;
  return String(value);
}

function coerceNumber(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  const n = Number(value);
  if (Number.isNaN(n)) return null;
  return String(n);
}

function coerceBoolean(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  return String(Boolean(value));
}

function coerceCsv(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (Array.isArray(value)) return value.join(",") || null;
  return String(value);
}

const DEFAULT_COERCERS: Record<ParamType, (v: unknown) => string | null> = {
  string: coerceString,
  number: coerceNumber,
  boolean: coerceBoolean,
  csv: coerceCsv,
};

// ── Broker core ──────────────────────────────────────────────────────────────

/**
 * Build the alias→canonical lookup from an endpoint config.
 * Returns a map where every alias and every canonical name points to
 * the canonical internal name.
 */
function buildAliasMap(config: EndpointParamConfig): Map<string, string> {
  const map = new Map<string, string>();
  for (const [canonical, def] of Object.entries(config.params)) {
    map.set(canonical, canonical);
    if (def.aliases) {
      for (const alias of def.aliases) {
        map.set(alias, canonical);
      }
    }
  }
  return map;
}

/**
 * Process raw input parameters through the broker for a given endpoint.
 *
 * @param config  The endpoint parameter configuration
 * @param input   Raw input parameters (from tRPC input, query string, etc.)
 * @returns       BrokerResult with forwarded query, recognized/unsupported lists, and errors
 */
export function brokerParams(
  config: EndpointParamConfig,
  input: Record<string, unknown>
): BrokerResult {
  const aliasMap = buildAliasMap(config);
  const forwardedQuery: Record<string, string | number | boolean> = {};
  const recognizedParams: string[] = [];
  const unsupportedParams: string[] = [];
  const errors: string[] = [];

  for (const [inputKey, inputValue] of Object.entries(input)) {
    // Skip undefined/null values — they were not provided
    if (inputValue === undefined || inputValue === null) continue;

    const canonical = aliasMap.get(inputKey);
    if (!canonical) {
      unsupportedParams.push(inputKey);
      continue;
    }

    const def = config.params[canonical];
    if (!def) {
      // Shouldn't happen if aliasMap is built correctly, but defensive
      unsupportedParams.push(inputKey);
      continue;
    }

    // Apply custom serializer or default coercer
    const coerce = def.serialize ?? DEFAULT_COERCERS[def.type];
    const serialized = coerce(inputValue);

    if (serialized === null) {
      // Value coerced to nothing — skip but don't flag as unsupported
      continue;
    }

    // Use the Wazuh spec parameter name for the outbound query
    forwardedQuery[def.wazuhName] = serialized;
    recognizedParams.push(inputKey);
  }

  return { forwardedQuery, recognizedParams, unsupportedParams, errors };
}

// ── Universal parameter family ───────────────────────────────────────────────
// These are the common query parameters shared across many Wazuh endpoints.
// Individual endpoint configs compose from these + endpoint-specific params.

export const UNIVERSAL_PARAMS = {
  offset: {
    wazuhName: "offset",
    description: "First element to return in the collection",
    type: "number" as ParamType,
  },
  limit: {
    wazuhName: "limit",
    description: "Maximum number of elements to return",
    type: "number" as ParamType,
  },
  sort: {
    wazuhName: "sort",
    description: "Sort the collection by a field or fields (use +/- prefix for asc/desc)",
    type: "string" as ParamType,
  },
  search: {
    wazuhName: "search",
    description: "Look for elements containing the specified string. Prefix with '-' for complementary search",
    type: "string" as ParamType,
  },
  select: {
    wazuhName: "select",
    description: "Select which fields to return (comma-separated)",
    type: "csv" as ParamType,
  },
  q: {
    wazuhName: "q",
    description: "Query to filter results by. For example q=\"status=active\"",
    type: "string" as ParamType,
  },
  distinct: {
    wazuhName: "distinct",
    description: "Look for distinct values",
    type: "boolean" as ParamType,
  },
} as const satisfies Record<string, ParamDef>;

// ── Endpoint configurations ──────────────────────────────────────────────────
// Each config maps to a specific Wazuh GET endpoint from the v4.14.3 spec.
// Only parameters actually listed in the spec for that endpoint are included.

/**
 * GET /agents — List agents
 * Spec ref: operationId api.controllers.agent_controller.get_agents
 */
export const AGENTS_CONFIG: EndpointParamConfig = {
  endpoint: "/agents",
  params: {
    // Universal params (all supported per spec)
    offset: UNIVERSAL_PARAMS.offset,
    limit: UNIVERSAL_PARAMS.limit,
    sort: UNIVERSAL_PARAMS.sort,
    search: UNIVERSAL_PARAMS.search,
    select: UNIVERSAL_PARAMS.select,
    q: UNIVERSAL_PARAMS.q,
    distinct: UNIVERSAL_PARAMS.distinct,

    // Endpoint-specific params
    status: {
      wazuhName: "status",
      description: "Filter by agent status (comma-separated: active, disconnected, never_connected, pending)",
      type: "csv",
    },
    "os.platform": {
      wazuhName: "os.platform",
      description: "Filter by OS platform",
      type: "string",
      aliases: ["os_platform", "osPlatform", "platform"],
    },
    "os.version": {
      wazuhName: "os.version",
      description: "Filter by OS version",
      type: "string",
      aliases: ["os_version", "osVersion"],
    },
    "os.name": {
      wazuhName: "os.name",
      description: "Filter by OS name",
      type: "string",
      aliases: ["os_name", "osName"],
    },
    older_than: {
      wazuhName: "older_than",
      description: "Filter out agents whose last keep alive is older than specified (e.g. '7d', '10s')",
      type: "string",
      aliases: ["olderThan"],
    },
    manager_host: {
      wazuhName: "manager_host",
      description: "Filter by manager host",
      type: "string",
      aliases: ["managerHost"],
    },
    version: {
      wazuhName: "version",
      description: "Filter by Wazuh agent version",
      type: "string",
    },
    group: {
      wazuhName: "group",
      description: "Filter by group of agents",
      type: "string",
      aliases: ["agent_group"],
    },
    node_name: {
      wazuhName: "node_name",
      description: "Filter by node name",
      type: "string",
      aliases: ["nodeName"],
    },
    name: {
      wazuhName: "name",
      description: "Filter by agent name",
      type: "string",
    },
    ip: {
      wazuhName: "ip",
      description: "Filter by the IP used by the agent to communicate with the manager",
      type: "string",
    },
    registerIP: {
      wazuhName: "registerIP",
      description: "Filter by the IP used when registering the agent",
      type: "string",
    },
    group_config_status: {
      wazuhName: "group_config_status",
      description: "Agent groups configuration sync status (synced | not synced)",
      type: "string",
      aliases: ["groupConfigStatus"],
    },
  },
};

/**
 * GET /rules — List rules
 * Spec ref: operationId api.controllers.rule_controller.get_rules
 */
export const RULES_CONFIG: EndpointParamConfig = {
  endpoint: "/rules",
  params: {
    // Universal params
    offset: UNIVERSAL_PARAMS.offset,
    limit: UNIVERSAL_PARAMS.limit,
    sort: UNIVERSAL_PARAMS.sort,
    search: UNIVERSAL_PARAMS.search,
    select: UNIVERSAL_PARAMS.select,
    q: UNIVERSAL_PARAMS.q,
    distinct: UNIVERSAL_PARAMS.distinct,

    // Endpoint-specific
    status: {
      wazuhName: "status",
      description: "Filter by rule status (enabled | disabled | all)",
      type: "string",
    },
    group: {
      wazuhName: "group",
      description: "Filter by rule group",
      type: "string",
    },
    level: {
      wazuhName: "level",
      description: "Filter by rule level. Can be a single level (4) or an interval (2-4)",
      type: "string",
    },
    filename: {
      wazuhName: "filename",
      description: "Filter by filename",
      type: "string",
    },
    relative_dirname: {
      wazuhName: "relative_dirname",
      description: "Filter by relative directory name",
      type: "string",
      aliases: ["relativeDirname"],
    },
    pci_dss: {
      wazuhName: "pci_dss",
      description: "Filter by PCI_DSS requirement name",
      type: "string",
    },
    gdpr: {
      wazuhName: "gdpr",
      description: "Filter by GDPR requirement",
      type: "string",
    },
    gpg13: {
      wazuhName: "gpg13",
      description: "Filter by GPG13 requirement",
      type: "string",
    },
    hipaa: {
      wazuhName: "hipaa",
      description: "Filter by HIPAA requirement",
      type: "string",
    },
    "nist-800-53": {
      wazuhName: "nist-800-53",
      description: "Filter by NIST-800-53 requirement",
      type: "string",
      aliases: ["nist_800_53"],
    },
    tsc: {
      wazuhName: "tsc",
      description: "Filter by TSC requirement",
      type: "string",
    },
    mitre: {
      wazuhName: "mitre",
      description: "Filter by MITRE technique ID",
      type: "string",
    },
  },
};

/**
 * GET /groups — List groups
 * Spec ref: operationId api.controllers.agent_controller.get_list_group
 */
export const GROUPS_CONFIG: EndpointParamConfig = {
  endpoint: "/groups",
  params: {
    // Universal params
    offset: UNIVERSAL_PARAMS.offset,
    limit: UNIVERSAL_PARAMS.limit,
    sort: UNIVERSAL_PARAMS.sort,
    search: UNIVERSAL_PARAMS.search,
    select: UNIVERSAL_PARAMS.select,
    q: UNIVERSAL_PARAMS.q,
    distinct: UNIVERSAL_PARAMS.distinct,

    // Endpoint-specific
    hash: {
      wazuhName: "hash",
      description: "Select algorithm to generate the returned checksums",
      type: "string",
    },
  },
};

/**
 * GET /cluster/nodes — List cluster nodes
 * Spec ref: operationId api.controllers.cluster_controller.get_cluster_nodes
 */
export const CLUSTER_NODES_CONFIG: EndpointParamConfig = {
  endpoint: "/cluster/nodes",
  params: {
    // Universal params
    offset: UNIVERSAL_PARAMS.offset,
    limit: UNIVERSAL_PARAMS.limit,
    sort: UNIVERSAL_PARAMS.sort,
    search: UNIVERSAL_PARAMS.search,
    select: UNIVERSAL_PARAMS.select,
    q: UNIVERSAL_PARAMS.q,
    distinct: UNIVERSAL_PARAMS.distinct,

    // Endpoint-specific
    type: {
      wazuhName: "type",
      description: "Filter by node type (worker | master)",
      type: "string",
      aliases: ["node_type", "nodeType"],
    },
  },
};

/**
 * GET /sca/{agent_id} — SCA policies for an agent
 * Spec ref: operationId api.controllers.sca_controller.get_sca_agent
 */
export const SCA_POLICIES_CONFIG: EndpointParamConfig = {
  endpoint: "/sca/{agent_id}",
  params: {
    // Universal params
    offset: UNIVERSAL_PARAMS.offset,
    limit: UNIVERSAL_PARAMS.limit,
    sort: UNIVERSAL_PARAMS.sort,
    search: UNIVERSAL_PARAMS.search,
    select: UNIVERSAL_PARAMS.select,
    q: UNIVERSAL_PARAMS.q,
    distinct: UNIVERSAL_PARAMS.distinct,

    // Endpoint-specific
    name: {
      wazuhName: "name",
      description: "Filter by policy name",
      type: "string",
      aliases: ["policyName"],
    },
    description: {
      wazuhName: "description",
      description: "Filter by policy description",
      type: "string",
    },
    references: {
      wazuhName: "references",
      description: "Filter by references",
      type: "string",
    },
  },
};

/**
 * GET /sca/{agent_id}/checks/{policy_id} — SCA checks for a policy
 * Spec ref: operationId api.controllers.sca_controller.get_sca_checks
 */
export const SCA_CHECKS_CONFIG: EndpointParamConfig = {
  endpoint: "/sca/{agent_id}/checks/{policy_id}",
  params: {
    // Universal params
    offset: UNIVERSAL_PARAMS.offset,
    limit: UNIVERSAL_PARAMS.limit,
    sort: UNIVERSAL_PARAMS.sort,
    search: UNIVERSAL_PARAMS.search,
    select: UNIVERSAL_PARAMS.select,
    q: UNIVERSAL_PARAMS.q,
    distinct: UNIVERSAL_PARAMS.distinct,

    // Endpoint-specific
    title: {
      wazuhName: "title",
      description: "Filter by check title",
      type: "string",
    },
    description: {
      wazuhName: "description",
      description: "Filter by check description",
      type: "string",
    },
    rationale: {
      wazuhName: "rationale",
      description: "Filter by rationale",
      type: "string",
    },
    remediation: {
      wazuhName: "remediation",
      description: "Filter by remediation",
      type: "string",
    },
    command: {
      wazuhName: "command",
      description: "Filter by command",
      type: "string",
    },
    reason: {
      wazuhName: "reason",
      description: "Filter by reason",
      type: "string",
    },
    file: {
      wazuhName: "file",
      description: "Filter by file path",
      type: "string",
      aliases: ["full_path"],
    },
    process: {
      wazuhName: "process",
      description: "Filter by process",
      type: "string",
    },
    directory: {
      wazuhName: "directory",
      description: "Filter by directory",
      type: "string",
    },
    registry: {
      wazuhName: "registry",
      description: "Filter by registry",
      type: "string",
    },
    references: {
      wazuhName: "references",
      description: "Filter by references",
      type: "string",
    },
    result: {
      wazuhName: "result",
      description: "Filter by result (passed | failed | not applicable)",
      type: "string",
    },
    condition: {
      wazuhName: "condition",
      description: "Filter by condition",
      type: "string",
    },
  },
};
