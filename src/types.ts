/** Severity level for a lint finding */
export type Severity = 'critical' | 'warning';

/** A single lint finding produced by a rule */
export interface LintResult {
  ruleId: string;
  severity: Severity;
  file: string;
  line: number;
  message: string;
}

/** Policy information extracted from a CREATE POLICY statement */
export interface PolicyInfo {
  name: string;
  table: string;
  command: 'ALL' | 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';
  /** Raw SQL text of the USING clause, or null */
  using: string | null;
  /** Raw SQL text of the WITH CHECK clause, or null */
  withCheck: string | null;
  /** Source file path */
  file: string;
  /** Line number in source file */
  line: number;
}

/** Table information extracted from CREATE TABLE and ALTER TABLE statements */
export interface TableInfo {
  name: string;
  rlsEnabled: boolean;
  policies: PolicyInfo[];
  /** Source file where table was created */
  file: string;
  /** Line number in source file */
  line: number;
}

/** A GRANT BYPASS RLS statement */
export interface BypassRlsGrant {
  role: string;
  file: string;
  line: number;
}

/** The complete analyzed schema from all migration files */
export interface AnalyzedSchema {
  tables: Map<string, TableInfo>;
  bypassRlsGrants: BypassRlsGrant[];
}

/** A lint rule function signature */
export type RuleFunction = (schema: AnalyzedSchema) => LintResult[];
