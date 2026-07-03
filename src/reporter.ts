import chalk from 'chalk';
import type { LintResult, Severity } from './types.js';

/**
 * Print lint results as a colored terminal report.
 * Returns the exit code: 1 if critical findings exist, 0 otherwise.
 */
export function printReport(
  results: LintResult[],
  scanErrors: string[],
): number {
  // Print scan errors first
  for (const err of scanErrors) {
    console.error(chalk.yellow(`⚠ ${err}`));
  }

  if (results.length === 0 && scanErrors.length === 0) {
    console.log(chalk.green.bold('\n  rls-lint report'));
    console.log(chalk.green('  ═══════════════'));
    console.log(chalk.green.bold('\n  ✅ No issues found — all policies look secure.\n'));
    return 0;
  }

  // Sort: critical first, then by file
  const sorted = [...results].sort((a, b) => {
    const severityOrder: Record<Severity, number> = { critical: 0, warning: 1 };
    const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
    if (sevDiff !== 0) return sevDiff;
    return a.file.localeCompare(b.file) || a.line - b.line;
  });

  let criticalCount = 0;
  let warningCount = 0;

  console.log(chalk.bold('\n  rls-lint report'));
  console.log(chalk.bold('  ═══════════════\n'));

  for (const result of sorted) {
    const icon = result.severity === 'critical' ? '🔴' : '🟡';
    const colorFn = result.severity === 'critical' ? chalk.red : chalk.yellow;

    if (result.severity === 'critical') criticalCount++;
    else warningCount++;

    console.log(`  ${icon} ${colorFn.bold(result.ruleId)}  ${result.message}`);
    console.log(`               ${chalk.dim(result.file)}:${result.line}`);
    console.log();
  }

  // Summary line
  const summaryParts: string[] = [];
  if (criticalCount > 0) {
    summaryParts.push(chalk.red(`${criticalCount} critical`));
  }
  if (warningCount > 0) {
    summaryParts.push(chalk.yellow(`${warningCount} warning${warningCount !== 1 ? 's' : ''}`));
  }
  const cleanCount = sorted.filter((r) => r.severity !== 'critical' && r.severity !== 'warning').length;

  console.log(chalk.dim('  ────────────────────────────────────────'));
  console.log(
    `  ${summaryParts.length > 0 ? `✘ ${summaryParts.join(', ')}` : chalk.green('✔ All clear')}` +
    `  |  ${sorted.length} total`,
  );
  console.log();

  return criticalCount > 0 ? 1 : 0;
}
