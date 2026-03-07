/**
 * KG ETL Service — Knowledge Graph Extraction Pipeline
 *
 * The KG is populated from the Wazuh OpenAPI specification, not from
 * live agent data. The ETL pipeline re-extracts from the spec and updates
 * the database tables. This is a deterministic, reproducible process.
 *
 * Runtime sync flow:
 *   1. Read the canonical spec YAML from disk
 *   2. Call kgExtractor.extract() to produce a KgExtractionResult
 *   3. Call kgLoader.loadAll() or kgLoader.loadLayer() to truncate-and-reload
 *   4. kgLoader updates kg_sync_status with truthful metadata per layer
 *
 * For live Wazuh data (agents, alerts, vulnerabilities), the app queries
 * the Wazuh REST API directly through the existing tRPC procedures.
 * The KG is about the API itself — its structure, safety, and semantics.
 */

import { readFileSync } from "fs";
import { resolve } from "path";
import yaml from "js-yaml";
import { sql } from "drizzle-orm";
import { getDb } from "../db";
import { kgSyncStatus } from "../../drizzle/schema";
import { extract } from "./kgExtractor";
import { loadAll, loadLayer, getLayerNames } from "./kgLoader";
import type { KgExtractionResult, KgLayerName, KgLoadResult, KgSyncLayerResult } from "./kgTypes";
import type { SqlExecutor } from "./kgLoader";

// ── Canonical spec path ────────────────────────────────────────────────────
// Both seed-kg.mjs and this runtime service use the same spec file.
// In Docker, the Dockerfile copies spec-v4.14.3.yaml to the project root.
// In dev, it lives at the project root.

function getSpecPath(): string {
  // Try project root first (works in both dev and Docker)
  const projectRoot = resolve(__dirname, "../..");
  return resolve(projectRoot, "spec-v4.14.3.yaml");
}

// ── Drizzle → SqlExecutor adapter ──────────────────────────────────────────
// kgLoader expects a SqlExecutor interface: { execute(sql, params?) }
// Drizzle's db.execute() uses tagged template literals, not (sql, params).
// We need a raw mysql2 connection for the loader.

async function getRawExecutor(): Promise<SqlExecutor | null> {
  const db = await getDb();
  if (!db) return null;

  // Access the underlying mysql2 pool from Drizzle
  // Drizzle stores the session/pool in the internal structure
  // We use db.execute with sql`` for raw queries
  return {
    async execute(query: string, params?: any[]): Promise<any> {
      if (params && params.length > 0) {
        // Use Drizzle's raw sql execution with parameter binding
        // Build a tagged template-like call
        const result = await db.execute(sql.raw(`${query.replace(/\?/g, () => {
          const val = params!.shift();
          if (val === null || val === undefined) return "NULL";
          if (typeof val === "number") return String(val);
          // Escape single quotes in strings
          return `'${String(val).replace(/'/g, "''")}'`;
        })}`));
        return result;
      }
      return db.execute(sql.raw(query));
    },
  };
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Get sync status for all KG layers.
 */
export async function getSyncStatus() {
  const db = await getDb();
  if (!db) return [];

  return db.select().from(kgSyncStatus);
}

/**
 * Read and parse the canonical OpenAPI spec.
 * Returns the extraction result or throws on failure.
 */
export function extractFromSpec(specPath?: string): KgExtractionResult {
  const path = specPath ?? getSpecPath();
  const specRaw = readFileSync(path, "utf8");
  const spec = yaml.load(specRaw);
  return extract(spec);
}

/**
 * Run a full re-extraction of the KG from the OpenAPI spec.
 * This is a real rebuild: parse spec → extract → truncate all KG tables → reload.
 *
 * Returns per-layer results with truthful metadata (entity counts, duration, errors).
 */
export async function runFullSync(): Promise<{
  success: boolean;
  message: string;
  result?: KgLoadResult;
}> {
  const db = await getDb();
  if (!db) return { success: false, message: "Database unavailable" };

  try {
    // Step 1: Read and parse spec
    const specPath = getSpecPath();
    const data = extractFromSpec(specPath);

    // Step 2: Get a raw SQL executor for kgLoader
    // kgLoader uses raw SQL with ? placeholders, not Drizzle tagged templates.
    // We need to use the underlying mysql2 pool directly.
    const mysql2Pool = (db as any)._.session?.client;
    if (!mysql2Pool) {
      // Fallback: try to get pool from session
      return { success: false, message: "Cannot access raw database connection for KG loader" };
    }

    const exec: SqlExecutor = {
      async execute(query: string, params?: any[]): Promise<any> {
        if (params && params.length > 0) {
          return mysql2Pool.execute(query, params);
        }
        return mysql2Pool.execute(query);
      },
    };

    // Step 3: Load all layers (truncate + insert)
    const result = await loadAll(exec, data);

    const layerSummary = getLayerNames()
      .map(name => {
        const lr = result.layers[name];
        return `${name}: ${lr.status} (${lr.entityCount} entities, ${lr.durationMs}ms)`;
      })
      .join("; ");

    return {
      success: result.success,
      message: result.success
        ? `KG sync completed. ${result.totalRecords} total records across 4 layers in ${result.durationMs}ms. Spec: ${result.specVersion}. [${layerSummary}]`
        : `KG sync partially failed. ${layerSummary}`,
      result,
    };
  } catch (error: any) {
    return { success: false, message: `Sync failed: ${error.message}` };
  }
}

/**
 * Sync a single KG layer.
 * Re-extracts from spec and reloads only the specified layer.
 */
export async function syncLayer(layerName: string): Promise<{
  success: boolean;
  message: string;
  result?: KgSyncLayerResult;
}> {
  const db = await getDb();
  if (!db) return { success: false, message: "Database unavailable" };

  const validLayers = getLayerNames();
  if (!validLayers.includes(layerName as KgLayerName)) {
    return { success: false, message: `Invalid layer: ${layerName}. Valid: ${validLayers.join(", ")}` };
  }

  try {
    // Step 1: Read and parse spec
    const data = extractFromSpec();

    // Step 2: Get raw SQL executor
    const mysql2Pool = (db as any)._.session?.client;
    if (!mysql2Pool) {
      return { success: false, message: "Cannot access raw database connection for KG loader" };
    }

    const exec: SqlExecutor = {
      async execute(query: string, params?: any[]): Promise<any> {
        if (params && params.length > 0) {
          return mysql2Pool.execute(query, params);
        }
        return mysql2Pool.execute(query);
      },
    };

    // Step 3: Load single layer
    const result = await loadLayer(exec, data, layerName as KgLayerName);

    return {
      success: result.status === "completed",
      message: result.status === "completed"
        ? `Layer "${layerName}" synced: ${result.entityCount} entities in ${result.durationMs}ms.`
        : `Layer "${layerName}" failed: ${result.errorMessage}`,
      result,
    };
  } catch (error: any) {
    return { success: false, message: `Sync failed: ${error.message}` };
  }
}
