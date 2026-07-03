import type { AnalyzedSchema, LintResult } from '../types.js';

/**
 * RLS-003: No tenant-scoping column in policy.
 *
 * Flags any policy where neither the USING clause nor the WITH CHECK clause
 * references a column or function that matches common tenant-scoping patterns.
 *
 * Tenant-scoping patterns (case-insensitive match):
 * - Column: tenant_id, org_id, organization_id, user_id
 * - Function call: auth.uid()
 *
 * This is a heuristic — a policy that uses subqueries or JOINs for tenant
 * scoping (e.g., USING (org_id IN (SELECT org_id FROM user_access WHERE ...)))
 * will NOT be flagged, which is a known false-negative limitation.
 *
 * Severity: warning
 */
export function rls003(schema: AnalyzedSchema): LintResult[] {
  const results: LintResult[] = [];

  for (const table of schema.tables.values()) {
    for (const policy of table.policies) {
      const expressions = [policy.using, policy.withCheck].filter(Boolean) as string[];

      // If both USING and WITH CHECK are null, we can't check scoping
      if (expressions.length === 0) continue;

      const hasTenantScoping = expressions.some((expr) =>
        containsTenantScoping(expr),
      );

      if (!hasTenantScoping) {
        results.push({
          ruleId: 'RLS-003',
          severity: 'warning',
          file: policy.file,
          line: policy.line,
          message: `Policy '${policy.name}' on '${policy.table}' has no tenant-scoping column (expected tenant_id, org_id, organization_id, user_id, or auth.uid())`,
        });
      }
    }
  }

  return results;
}

/** Tenant-scoping patterns to match in policy expressions */
const TENANT_PATTERNS = [
  /\btenant_id\b/i,
  /\borg_id\b/i,
  /\borganization_id\b/i,
  /\buser_id\b/i,
  /auth\.\s*uid\s*\(/i,
];

function containsTenantScoping(expr: string): boolean {
  return TENANT_PATTERNS.some((pattern) => pattern.test(expr));
}
