import type { AnalyzedSchema, LintResult } from '../types.js';

/**
 * RLS-004: GRANT BYPASS RLS detected.
 *
 * Flags any GRANT statement that grants the BYPASS RLS privilege.
 * This privilege allows a role to bypass all row-level security checks,
 * which is a significant security risk in multi-tenant applications.
 *
 * Severity: critical
 */
export function rls004(schema: AnalyzedSchema): LintResult[] {
  const results: LintResult[] = [];

  for (const grant of schema.bypassRlsGrants) {
    results.push({
      ruleId: 'RLS-004',
      severity: 'critical',
      file: grant.file,
      line: grant.line,
      message: `GRANT BYPASS RLS found on role(s): '${grant.role}' — this bypasses all RLS policies`,
    });
  }

  return results;
}
