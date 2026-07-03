#!/usr/bin/env node

import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanSqlFiles, parseSqlFile } from './parser.js';
import { buildSchema } from './analyzer.js';
import { rules } from './rules/index.js';
import { printReport } from './reporter.js';

// Load package.json for version info
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const pkgPath = join(__dirname, '..', 'package.json');
let pkgVersion = '0.1.0';
try {
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
  pkgVersion = pkg.version;
} catch {
  // Fallback to default version
}

const program = new Command();

program
  .name('rls-lint')
  .description('Static security linter for Supabase Row Level Security policies')
  .version(pkgVersion)
  .argument('[path]', 'Path to SQL migration files or single .sql file', './migrations')
  .action((pathArg: string) => {
    runLint(pathArg);
  });

program.parse();

/**
 * Core lint workflow:
 * 1. Scan for .sql files
 * 2. Parse each file
 * 3. Build the analyzed schema
 * 4. Run all lint rules
 * 5. Print report and exit with appropriate code
 */
function runLint(searchPath: string): void {
  // Step 1: Scan for SQL files
  const scanResult = scanSqlFiles(searchPath);

  if (scanResult.errors.length > 0) {
    for (const err of scanResult.errors) {
      console.error(`Error: ${err.message} (${err.filePath})`);
    }
  }

  if (scanResult.files.length === 0) {
    console.error(`Error: No .sql files found at '${searchPath}'`);
    process.exit(2);
  }

  // Step 2: Parse each SQL file
  // Use the search directory (or parent of a single file) as the root for relative paths
  const resolvedSearchPath = scanResult.files.length === 1
    ? resolve(dirname(scanResult.files[0]))
    : resolve(searchPath);
  const parsedFiles = scanResult.files.map((filePath) => {
    const relativePath = relative(resolvedSearchPath, filePath);
    return parseSqlFile(filePath, relativePath || filePath);
  });

  const parseErrors = parsedFiles.flatMap((pf) => pf.errors);
  for (const pe of parseErrors) {
    console.error(`Parse warning at ${pe.filePath}:${pe.line}: ${pe.message}`);
  }

  // Step 3: Build the analyzed schema
  const schema = buildSchema(parsedFiles);

  // Step 4: Run all rules
  const allResults = rules.flatMap((rule) => rule(schema));

  // Step 5: Print report and exit
  const exitCode = printReport(allResults, scanResult.errors.map((e) => e.message));
  process.exit(exitCode);
}
