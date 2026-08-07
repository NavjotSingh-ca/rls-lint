import { describe, it, expect } from 'vitest';
import { buildSchema } from './analyzer.js';
import type { ParsedFile } from './parser.js';

/** Minimal parsed-file factory for schema tests. */
function makeParsedFile(overrides: Partial<ParsedFile> = {}): ParsedFile {
  return {
    filePath: '/tmp/x.sql',
    relativePath: 'x.sql',
    createTables: [],
    alterRls: [],
    createPolicies: [],
    bypassRlsGrants: [],
    errors: [],
    ...overrides,
  };
}

describe('buildSchema', () => {
  it('merges CREATE TABLE + ALTER RLS across files', () => {
    const schema = buildSchema([
      makeParsedFile({
        relativePath: '001.sql',
        createTables: [{ tableName: 'users', schema: 'public', line: 1 }],
      }),
      makeParsedFile({
        relativePath: '002.sql',
        alterRls: [{ tableName: 'users', schema: 'public', enable: true, line: 2 }],
      }),
    ]);

    const table = schema.tables.get('users');
    expect(table).toBeDefined();
    expect(table?.rlsEnabled).toBe(true);
    // File/line prefer the most recent definition
    expect(table?.file).toBe('001.sql');
  });

  it('attaches policies to their table', () => {
    const schema = buildSchema([
      makeParsedFile({
        createTables: [{ tableName: 'notes', schema: null, line: 1 }],
        createPolicies: [
          {
            policyName: 'tenant_read',
            tableName: 'notes',
            command: 'SELECT',
            usingExpression: 'tenant_id = auth.uid()',
            withCheckExpression: null,
            line: 5,
          },
        ],
      }),
    ]);

    const table = schema.tables.get('notes');
    expect(table?.policies).toHaveLength(1);
    expect(table?.policies[0]?.name).toBe('tenant_read');
  });

  it('registers bypass grants', () => {
    const schema = buildSchema([
      makeParsedFile({
        bypassRlsGrants: [{ role: 'postgres', line: 9 }],
      }),
    ]);
    expect(schema.bypassRlsGrants).toHaveLength(1);
    expect(schema.bypassRlsGrants[0]?.role).toBe('postgres');
  });

  it('creates placeholder tables for policies on unknown tables', () => {
    const schema = buildSchema([
      makeParsedFile({
        createPolicies: [
          {
            policyName: 'p',
            tableName: 'phantom',
            command: 'ALL',
            usingExpression: 'true',
            withCheckExpression: null,
            line: 3,
          },
        ],
      }),
    ]);
    const table = schema.tables.get('phantom');
    expect(table?.policies).toHaveLength(1);
    expect(table?.rlsEnabled).toBe(false);
  });
});