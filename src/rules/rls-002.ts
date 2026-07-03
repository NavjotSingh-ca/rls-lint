import type { AnalyzedSchema, LintResult } from '../types.js';

/**
 * RLS-002: Policy open to all.
 *
 * Flags any CREATE POLICY whose USING or WITH CHECK clause is exactly "true"
 * or contains an expression that evaluates to always-true for all rows.
 *
 * For v1, we check if the trimmed expression is exactly "true".
 * Complex always-true expressions (e.g., "1=1", "true OR false") are not
 * detected — this is a known limitation.
 *
 * Severity: critical
 */
export function rls002(schema: AnalyzedSchema): LintResult[] {
  const results: LintResult[] = [];

  for (const table of schema.tables.values()) {
    for (const policy of table.policies) {
      // Check USING clause
      if (policy.using !== null && isAlwaysTrue(policy.using)) {
        results.push({
          ruleId: 'RLS-002',
          severity: 'critical',
          file: policy.file,
          line: policy.line,
          message: `Policy '${policy.name}' on '${policy.table}' uses USING(true) — open to everyone`,
        });
        continue; // Don't double-flag if both USING and WITH CHECK are true
      }

      // Check WITH CHECK clause
      if (policy.withCheck !== null && isAlwaysTrue(policy.withCheck)) {
        results.push({
          ruleId: 'RLS-002',
          severity: 'critical',
          file: policy.file,
          line: policy.line,
          message: `Policy '${policy.name}' on '${policy.table}' uses WITH CHECK(true) — open to everyone`,
        });
      }
    }
  }

  return results;
}

/**
 * Check if an expression evaluates to always-true for all rows.
 * For v1, matches:
 * - exactly "true" (case-insensitive)
 * - exactly "'t'" or "t" (PostgreSQL shorthand)
 *
 * Does NOT match:
 * - "1=1" (possible but not common in Supabase policy templates)
 * - "true OR false" (rare pattern)
 */
function isAlwaysTrue(expr: string): boolean {
  const trimmed = expr.trim().toLowerCase();
  return trimmed === 'true' || trimmed === "'t'" || trimmed === 't';
}
