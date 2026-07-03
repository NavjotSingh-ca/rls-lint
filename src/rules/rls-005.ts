import type { AnalyzedSchema, LintResult } from '../types.js';

/**
 * RLS-005: Policy uses FOR ALL instead of a specific command.
 *
 * Flags any CREATE POLICY that uses FOR ALL (or omits the FOR clause,
 * which defaults to ALL) instead of a specific command like
 * FOR SELECT, FOR INSERT, FOR UPDATE, or FOR DELETE.
 *
 * Using FOR ALL is less secure because it applies the same policy
 * to ALL operations when more restrictive per-operation policies
 * would be more appropriate.
 *
 * Severity: warning
 */
export function rls005(schema: AnalyzedSchema): LintResult[] {
  const results: LintResult[] = [];

  for (const table of schema.tables.values()) {
    for (const policy of table.policies) {
      if (policy.command === 'ALL') {
        results.push({
          ruleId: 'RLS-005',
          severity: 'warning',
          file: policy.file,
          line: policy.line,
          message: `Policy '${policy.name}' on '${policy.table}' uses FOR ALL (prefer FOR SELECT/INSERT/UPDATE/DELETE for least privilege)`,
        });
      }
    }
  }

  return results;
}
