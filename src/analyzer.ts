import type { AnalyzedSchema, TableInfo, PolicyInfo, BypassRlsGrant } from './types.js';
import type { ParsedFile, CreatePolicyStmt } from './parser.js';

/**
 * Build an AnalyzedSchema from one or more parsed SQL files.
 *
 * Merges across files:
 * - CREATE TABLE from any file registers a table
 * - ALTER TABLE ... ENABLE/DISABLE RLS from any file applies to the table
 * - CREATE POLICY from any file attaches to the table
 */
export function buildSchema(parsedFiles: ParsedFile[]): AnalyzedSchema {
  const tables = new Map<string, TableInfo>();
  const bypassRlsGrants: BypassRlsGrant[] = [];

  for (const file of parsedFiles) {
    // Process CREATE TABLE statements
    for (const ct of file.createTables) {
      const existing = tables.get(ct.tableName);
      if (existing) {
        // Table already defined — update file/line to latest definition
        existing.file = file.relativePath;
        existing.line = ct.line;
      } else {
        tables.set(ct.tableName, {
          name: ct.tableName,
          rlsEnabled: false,
          policies: [],
          file: file.relativePath,
          line: ct.line,
        });
      }
    }

    // Process ALTER TABLE ... ENABLE/DISABLE ROW LEVEL SECURITY
    for (const ar of file.alterRls) {
      const table = getOrCreateTable(tables, ar.tableName, file.relativePath, ar.line);
      table.rlsEnabled = ar.enable;
    }

    // Process CREATE POLICY statements
    for (const cp of file.createPolicies) {
      const table = getOrCreateTable(tables, cp.tableName, file.relativePath, cp.line);
      const policy: PolicyInfo = {
        name: cp.policyName,
        table: cp.tableName,
        command: cp.command ?? 'ALL', // Default is ALL
        using: cp.usingExpression,
        withCheck: cp.withCheckExpression,
        file: file.relativePath,
        line: cp.line,
      };
      table.policies.push(policy);
    }

    // Process GRANT BYPASS RLS
    for (const bg of file.bypassRlsGrants) {
      bypassRlsGrants.push({
        role: bg.role,
        file: file.relativePath,
        line: bg.line,
      });
    }
  }

  return { tables, bypassRlsGrants };
}

/**
 * Get an existing table by name, or create a placeholder entry.
 * This handles cases where a policy is created on a table that hasn't
 * been seen yet (e.g., table defined in a different migration or earlier file).
 */
function getOrCreateTable(
  tables: Map<string, TableInfo>,
  tableName: string,
  file: string,
  line: number,
): TableInfo {
  const existing = tables.get(tableName);
  if (existing) return existing;

  const newTable: TableInfo = {
    name: tableName,
    rlsEnabled: false,
    policies: [],
    file,
    line,
  };
  tables.set(tableName, newTable);
  return newTable;
}
