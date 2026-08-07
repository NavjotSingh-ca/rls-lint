import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Raw parsed data from a single SQL file before analysis.
 */
export interface ParsedFile {
  /** Absolute file path */
  filePath: string;
  /** Relative file path (from the search root) */
  relativePath: string;
  /** CREATE TABLE statements found */
  createTables: CreateTableStmt[];
  /** ALTER TABLE ... ENABLE/DISABLE ROW LEVEL SECURITY statements */
  alterRls: AlterRlsStmt[];
  /** CREATE POLICY statements */
  createPolicies: CreatePolicyStmt[];
  /** GRANT ... BYPASS RLS statements */
  bypassRlsGrants: BypassRlsGrantStmt[];
  /** Any lines that could not be parsed */
  errors: ParseError[];
}

export interface CreateTableStmt {
  tableName: string;
  schema: string | null;
  line: number;
}

export interface AlterRlsStmt {
  tableName: string;
  schema: string | null;
  enable: boolean; // true for ENABLE, false for DISABLE
  line: number;
}

export interface CreatePolicyStmt {
  policyName: string;
  tableName: string;
  command: 'ALL' | 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | null;
  usingExpression: string | null;
  withCheckExpression: string | null;
  line: number;
}

export interface BypassRlsGrantStmt {
  role: string;
  line: number;
}

export interface ParseError {
  filePath: string;
  line: number;
  message: string;
  text: string;
}

/**
 * Result of scanning a directory for .sql files.
 */
export interface ScanResult {
  files: string[];
  errors: { filePath: string; message: string }[];
}

/**
 * Recursively find all .sql files in the given directory path.
 * If path is a single file, returns that file.
 */
export function scanSqlFiles(searchPath: string): ScanResult {
  const resolvedPath = path.resolve(searchPath);

  try {
    const stat = fs.statSync(resolvedPath);
    if (stat.isFile()) {
      if (resolvedPath.toLowerCase().endsWith('.sql')) {
        return { files: [resolvedPath], errors: [] };
      }
      return { files: [], errors: [{ filePath: resolvedPath, message: 'Not a .sql file' }] };
    }

    if (stat.isDirectory()) {
      return scanDirectoryRecursive(resolvedPath);
    }

    return { files: [], errors: [{ filePath: resolvedPath, message: 'Path is neither a file nor a directory' }] };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { files: [], errors: [{ filePath: resolvedPath, message }] };
  }
}

function scanDirectoryRecursive(dirPath: string): ScanResult {
  const files: string[] = [];
  const errors: { filePath: string; message: string }[] = [];

  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        // Skip node_modules and hidden directories
        if (entry.name.startsWith('.')) continue;
        if (entry.name === 'node_modules') continue;
        const result = scanDirectoryRecursive(fullPath);
        files.push(...result.files);
        errors.push(...result.errors);
      } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.sql')) {
        files.push(fullPath);
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    errors.push({ filePath: dirPath, message });
  }

  return { files, errors };
}

/**
 * Parse a single SQL file, extracting all relevant DDL statements.
 */
export function parseSqlFile(filePath: string, relativePath: string): ParsedFile {
  const content = fs.readFileSync(filePath, 'utf-8');

  // Step 1: Strip SQL comments
  const cleaned = stripComments(content);

  // Step 2: Split into individual statements by semicolons
  const statements = splitStatements(cleaned);

  const result: ParsedFile = {
    filePath,
    relativePath,
    createTables: [],
    alterRls: [],
    createPolicies: [],
    bypassRlsGrants: [],
    errors: [],
  };

  for (const stmt of statements) {
    const trimmed = stmt.text.trim();
    if (!trimmed) continue;

    const line = stmt.line;

    // Try to match statement types in order of specificity
    if (matchCreatePolicy(trimmed, result, line)) continue;
    if (matchCreateTable(trimmed, result, line)) continue;
    if (matchAlterRls(trimmed, result, line)) continue;
    if (matchBypassRlsGrant(trimmed, result, line)) continue;
    // Other statements are silently ignored
  }

  return result;
}

interface Statement {
  text: string;
  line: number;
}

/**
 * Split SQL content into individual statements, tracking line numbers.
 *
 * Quote-aware: semicolons inside single-quoted strings, double-quoted
 * identifiers, and dollar-quoted bodies ($$ ... $$, $tag$ ... $tag$)
 * do NOT terminate a statement.
 */
function splitStatements(content: string): Statement[] {
  const statements: Statement[] = [];

  // Precompute the 1-indexed line number for every character offset.
  const lineAt: number[] = new Array(content.length + 1).fill(1);
  let line = 1;
  for (let i = 0; i < content.length; i++) {
    lineAt[i] = line;
    if (content[i] === '\n') line++;
  }
  lineAt[content.length] = line;

  // Lexical state carried across the whole file
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let dollarQuoteTag: string | null = null;

  let stmtStart = 0; // offset where the current statement begins
  let stmtStartLine = 1; // line of the first non-blank char of the statement
  let seenContent = false;
  let i = 0;

  while (i < content.length) {
    const ch = content[i];
    const next = content[i + 1] ?? '';

    if (!seenContent && !(ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r')) {
      seenContent = true;
      stmtStartLine = lineAt[i];
    }

    if (dollarQuoteTag !== null) {
      if (content.startsWith(dollarQuoteTag, i)) {
        const closingTag = dollarQuoteTag;
        dollarQuoteTag = null;
        i += closingTag.length;
        continue;
      }
      i++;
      continue;
    }

    if (inSingleQuote) {
      if (ch === "'") {
        if (next === "'") {
          i += 2;
          continue;
        }
        inSingleQuote = false;
      }
      i++;
      continue;
    }

    if (inDoubleQuote) {
      if (ch === '"') {
        if (next === '"') {
          i += 2;
          continue;
        }
        inDoubleQuote = false;
      }
      i++;
      continue;
    }

    if (ch === "'") {
      inSingleQuote = true;
      i++;
      continue;
    }
    if (ch === '"') {
      inDoubleQuote = true;
      i++;
      continue;
    }
    if (ch === '$') {
      const tagMatch = content.slice(i).match(/^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/);
      if (tagMatch) {
        dollarQuoteTag = tagMatch[0];
        i += dollarQuoteTag.length;
        continue;
      }
    }

    // Outside any quote — a semicolon terminates the statement. Multiple
    // statements on one line are handled naturally: the scan continues past
    // the semicolon and the next statement starts right where this one ended.
    if (ch === ';') {
      const text = content.slice(stmtStart, i).trim();
      if (text) {
        statements.push({ text, line: stmtStartLine });
      }
      seenContent = false;
      stmtStart = i + 1;
      i++;
      continue;
    }

    i++;
  }

  // Last statement without a trailing semicolon
  if (seenContent) {
    const lastText = content.slice(stmtStart).trim();
    if (lastText) {
      statements.push({ text: lastText, line: stmtStartLine });
    }
  }

  return statements;
}

/**
 * Strip SQL comments (both single-line -- and multi-line /* *​/)
 *
 * Quote-aware: comment markers inside string literals, quoted identifiers,
 * and dollar-quoted bodies are preserved, not stripped.
 */
function stripComments(sql: string): string {
  let result = '';
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let dollarQuoteTag: string | null = null;

  let i = 0;
  while (i < sql.length) {
    const ch = sql[i];
    const next = sql[i + 1];

    if (dollarQuoteTag !== null) {
      if (sql.startsWith(dollarQuoteTag, i)) {
        const closingTag = dollarQuoteTag;
        result += closingTag;
        dollarQuoteTag = null;
        i += closingTag.length;
        continue;
      }
      result += ch;
      i++;
      continue;
    }

    if (inSingleQuote) {
      result += ch;
      if (ch === "'") {
        // Double-quote escape inside a string literal
        if (next === "'") {
          result += next;
          i += 2;
          continue;
        }
        inSingleQuote = false;
      }
      i++;
      continue;
    }

    if (inDoubleQuote) {
      result += ch;
      if (ch === '"') {
        if (next === '"') {
          result += next;
          i += 2;
          continue;
        }
        inDoubleQuote = false;
      }
      i++;
      continue;
    }

    // Outside all quotes — comments are real comments here
    if (ch === '-' && next === '-') {
      // Single-line comment: consume until end of line
      while (i < sql.length && sql[i] !== '\n') i++;
      result += ' ';
      continue;
    }

    if (ch === '/' && next === '*') {
      // Multi-line comment: consume until closing */
      i += 2;
      // Preserve the exact number of newlines so that reported line numbers
      // match the original file (critical for a linter — findings must point
      // at real lines).
      let newlineCount = 0;
      while (i < sql.length && !(sql[i] === '*' && sql[i + 1] === '/')) {
        if (sql[i] === '\n') newlineCount++;
        i++;
      }
      if (i < sql.length) i += 2; // skip closing */
      result += newlineCount > 0 ? '\n'.repeat(newlineCount) : ' ';
      continue;
    }

    if (ch === "'") {
      inSingleQuote = true;
      result += ch;
      i++;
      continue;
    }
    if (ch === '"') {
      inDoubleQuote = true;
      result += ch;
      i++;
      continue;
    }
    if (ch === '$') {
      const dollarMatch = sql.slice(i).match(/^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/);
      if (dollarMatch) {
        dollarQuoteTag = dollarMatch[0];
        result += dollarQuoteTag;
        i += dollarQuoteTag.length;
        continue;
      }
    }

    result += ch;
    i++;
  }

  return result;
}

// =========================================================================
// Statement matchers
// =========================================================================

/**
 * Helper: match a PostgreSQL identifier that may be double-quoted.
 * Returns the identifier without quotes.
 */
function parseIdentifier(input: string, startPos: number): { value: string; endPos: number } | null {
  // Skip whitespace
  while (startPos < input.length && /\s/.test(input[startPos])) startPos++;
  if (startPos >= input.length) return null;

  if (input[startPos] === '"') {
    // Quoted identifier: find closing quote
    const closeQuote = input.indexOf('"', startPos + 1);
    if (closeQuote === -1) return null;
    return {
      value: input.slice(startPos + 1, closeQuote),
      endPos: closeQuote + 1,
    };
  }

  // Unquoted identifier: match word characters
  const match = input.slice(startPos).match(/^(\w+)/);
  if (!match) return null;
  return {
    value: match[1],
    endPos: startPos + match[1].length,
  };
}

/**
 * Parse a table reference like "schema.table" or schema."table" or "table".
 * Returns { schema, tableName }.
 */
function parseTableRef(input: string, startPos: number): { schema: string | null; tableName: string; endPos: number } | null {
  const first = parseIdentifier(input, startPos);
  if (!first) return null;

  // Check for dot (schema qualifier)
  let pos = first.endPos;
  while (pos < input.length && /\s/.test(input[pos])) pos++;
  if (pos < input.length && input[pos] === '.') {
    // Schema-qualified: schema.tableName
    const second = parseIdentifier(input, pos + 1);
    if (!second) return null;
    return {
      schema: first.value,
      tableName: second.value,
      endPos: second.endPos,
    };
  }

  // Just a table name
  return {
    schema: null,
    tableName: first.value,
    endPos: first.endPos,
  };
}

/**
 * Regex for CREATE TABLE statements.
 * Matches: CREATE TABLE [IF NOT EXISTS] [schema.]table_name (
 */
const CREATE_TABLE_RE = /^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?/i;

function matchCreateTable(stmt: string, result: ParsedFile, line: number): boolean {
  const match = CREATE_TABLE_RE.exec(stmt);
  if (!match) return false;

  // Parse table reference after CREATE TABLE ...
  const tableRef = parseTableRef(stmt, match[0].length);
  if (!tableRef) return false;

  result.createTables.push({
    tableName: tableRef.tableName,
    schema: tableRef.schema,
    line,
  });

  return true;
}

/**
 * Regex for ALTER TABLE ... ENABLE/DISABLE ROW LEVEL SECURITY.
 */
const ALTER_RLS_RE = /^\s*ALTER\s+TABLE\s+(?:ONLY\s+)?/i;

function matchAlterRls(stmt: string, result: ParsedFile, line: number): boolean {
  const match = ALTER_RLS_RE.exec(stmt);
  if (!match) return false;

  // Parse table reference
  const tableRef = parseTableRef(stmt, match[0].length);
  if (!tableRef) return false;

  // Check for ENABLE/DISABLE ROW LEVEL SECURITY
  const rest = stmt.slice(tableRef.endPos).trim();
  const rlsMatch = rest.match(/^(ENABLE|DISABLE)\s+ROW\s+LEVEL\s+SECURITY/i);
  if (!rlsMatch) return false;

  result.alterRls.push({
    tableName: tableRef.tableName,
    schema: tableRef.schema,
    enable: rlsMatch[1].toUpperCase() === 'ENABLE',
    line,
  });

  return true;
}

/**
 * Matches CREATE POLICY statements.
 * Full syntax:
 *   CREATE POLICY name ON table_name
 *     [FOR {ALL|SELECT|INSERT|UPDATE|DELETE}]
 *     [TO role[, ...]]
 *     [USING (expr)]
 *     [WITH CHECK (expr)]
 */
const CREATE_POLICY_RE = /^\s*CREATE\s+POLICY\s+/i;

function matchCreatePolicy(stmt: string, result: ParsedFile, line: number): boolean {
  // Check if this starts with CREATE POLICY
  const match = CREATE_POLICY_RE.exec(stmt);
  if (!match) return false;

  // Parse policy name
  const ident = parseIdentifier(stmt, match[0].length);
  if (!ident) return false;

  const policyName = ident.value;
  let pos = ident.endPos;

  // Skip whitespace and expect ON
  while (pos < stmt.length && /\s/.test(stmt[pos])) pos++;
  if (stmt.slice(pos, pos + 2).toUpperCase() !== 'ON') return false;
  pos += 2;

  // Parse table reference
  const tableRef = parseTableRef(stmt, pos);
  if (!tableRef) return false;
  const tableName = tableRef.tableName;
  pos = tableRef.endPos;

  // Extract FOR clause
  const forClauseRe = /\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b/i;
  const forMatch = forClauseRe.exec(stmt.slice(pos));
  const command = forMatch ? (forMatch[1].toUpperCase() as 'ALL' | 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE') : null;

  // Extract USING expression (handling nested parens)
  const usingMatch = extractExpression(stmt, 'USING');
  // Extract WITH CHECK expression
  const withCheckMatch = extractExpression(stmt, 'WITH CHECK');

  result.createPolicies.push({
    policyName,
    tableName,
    command,
    usingExpression: usingMatch,
    withCheckExpression: withCheckMatch,
    line,
  });

  return true;
}

/**
 * Extract the expression inside parentheses following a keyword (e.g., USING, WITH CHECK).
 * Handles nested parentheses by counting depth.
 * Returns null if keyword not found.
 */
function extractExpression(sql: string, keyword: string): string | null {
  // Build a regex: keyword followed by optional whitespace then '('
  const kwRe = new RegExp(`\\b${keyword}\\s*\\(`, 'i');
  const match = kwRe.exec(sql);
  if (!match) return null;

  const startPos = match.index + match[0].length - 1; // position of the '('
  let depth = 1;
  let pos = startPos + 1;

  while (depth > 0 && pos < sql.length) {
    if (sql[pos] === '(') depth++;
    else if (sql[pos] === ')') depth--;
    if (depth > 0) pos++;
  }

  // Extract the text between ( and matching )
  const expr = sql.slice(startPos + 1, pos).trim();
  return expr || null;
}

/**
 * Regex for GRANT ... BYPASS RLS statements.
 * Matches: GRANT [privileges] TO role [, ...] [WITH GRANT OPTION]
 * But we specifically look for the BYPASS RLS keyword anywhere in the statement.
 */
const BYPASS_RLS_RE = /\bBYPASS\s+RLS\b/i;
const GRANT_RE = /^\s*GRANT\s+/i;

/**
 * Extract role names from a GRANT statement.
 * Pattern: GRANT ... TO role1 [, role2, ...] [WITH GRANT OPTION]
 */
const GRANT_TO_RE = /\bTO\s+(\w+(?:\s*,\s*\w+)*)/i;

function matchBypassRlsGrant(stmt: string, result: ParsedFile, line: number): boolean {
  // Must match both GRANT keyword and BYPASS RLS keyword
  if (!GRANT_RE.test(stmt)) return false;
  if (!BYPASS_RLS_RE.test(stmt)) return false;

  // Extract the role(s) being granted BYPASS RLS
  const toMatch = GRANT_TO_RE.exec(stmt);
  const role = toMatch ? toMatch[1].trim() : 'unknown';

  result.bypassRlsGrants.push({
    role,
    line,
  });

  return true;
}
