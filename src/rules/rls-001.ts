import type { AnalyzedSchema, LintResult } from '../types.js';

/**
 * RLS-001: Missing RLS on table.
 *
 * Flags any table that was created (via CREATE TABLE) but never had
 * ALTER TABLE ... ENABLE ROW LEVEL SECURITY called on it.
 *
 * Severity: critical
 */
export function rls001(schema: AnalyzedSchema): LintResult[] {
  const results: LintResult[] = [];

  for (const table of schema.tables.values()) {
    if (!table.rlsEnabled) {
      results.push({
        ruleId: 'RLS-001',
        severity: 'critical',
        file: table.file,
        line: table.line,
        message: `Missing RLS on table '${table.name}' — no ALTER TABLE ... ENABLE ROW LEVEL SECURITY found`,
      });
    }
  }

  return results;
}
