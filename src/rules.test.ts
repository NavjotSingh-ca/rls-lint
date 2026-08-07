import { describe, it, expect, beforeEach } from 'vitest';
import type { AnalyzedSchema, PolicyInfo, TableInfo } from './types.js';
import { rls001 } from './rules/rls-001.js';
import { rls002 } from './rules/rls-002.js';
import { rls003 } from './rules/rls-003.js';
import { rls004 } from './rules/rls-004.js';
import { rls005 } from './rules/rls-005.js';

const emptySchema: AnalyzedSchema = { tables: new Map(), bypassRlsGrants: [] };

function makeTable(name: string, overrides: Partial<TableInfo> = {}): TableInfo {
  return {
    name,
    rlsEnabled: false,
    policies: [],
    file: 'x.sql',
    line: 1,
    ...overrides,
  };
}

function makePolicy(overrides: Partial<PolicyInfo> = {}): PolicyInfo {
  return {
    name: 'p',
    table: 't',
    command: 'ALL',
    using: null,
    withCheck: null,
    file: 'x.sql',
    line: 1,
    ...overrides,
  };
}

function schemaWithTables(tables: TableInfo[]): AnalyzedSchema {
  return { tables: new Map(tables.map((t) => [t.name, t])), bypassRlsGrants: [] };
}

describe('rls001 — missing RLS', () => {
  it('flags tables without RLS enabled', () => {
    const schema = schemaWithTables([makeTable('users')]);
    const results = rls001(schema);
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({ ruleId: 'RLS-001', severity: 'critical' });
  });

  it('does not flag tables with RLS enabled', () => {
    const schema = schemaWithTables([makeTable('users', { rlsEnabled: true })]);
    expect(rls001(schema)).toHaveLength(0);
  });

  it('returns nothing for empty schema', () => {
    expect(rls001(emptySchema)).toHaveLength(0);
  });
});

describe('RLS002 — open-to-everyone policies', () => {
  it('flags USING (true)', () => {
    const table = makeTable('t', {
      policies: [makePolicy({ using: 'true' })],
    });
    const results = rls002(schemaWithTables([table]));
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({ ruleId: 'RLS-002', severity: 'critical' });
    expect(results[0].message).toContain('USING(true)');
  });

  it('flags WITH CHECK (true)', () => {
    const table = makeTable('t', {
      policies: [makePolicy({ withCheck: 'TRUE' })],
    });
    const results = rls002(schemaWithTables([table]));
    expect(results[0].message).toContain('WITH CHECK(true)');
  });

  it('flags PostgreSQL shorthand t and escaped t', () => {
    const table = makeTable('t', {
      policies: [makePolicy({ using: "'t'" })],
    });
    expect(rls002(schemaWithTables([table]))).toHaveLength(1);
  });

  it('does not flag scoped expressions', () => {
    const table = makeTable('t', {
      policies: [makePolicy({ using: 'tenant_id = auth.uid()' })],
    });
    expect(rls002(schemaWithTables([table]))).toHaveLength(0);
  });

  it('does not double-flag USING(true) + WITH CHECK(true) on one policy', () => {
    const table = makeTable('t', {
      policies: [makePolicy({ using: 'true', withCheck: 'true' })],
    });
    expect(rls002(schemaWithTables([table]))).toHaveLength(1);
  });
});

describe('RLS003 — missing tenant scoping', () => {
  it('warns when policy has no tenant-scoping column', () => {
    const table = makeTable('t', {
      policies: [makePolicy({ using: 'status = 1' })],
    });
    const results = rls003(schemaWithTables([table]));
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({ ruleId: 'RLS-003', severity: 'warning' });
  });

  it('does not warn when using auth.uid()', () => {
    const table = makeTable('t', {
      policies: [makePolicy({ using: 'user_id = auth.uid()' })],
    });
    expect(rls003(schemaWithTables([table]))).toHaveLength(0);
  });

  it('does not warn when using tenant_id', () => {
    const table = makeTable('t', {
      policies: [makePolicy({ using: 'tenant_id = current_setting' })],
    });
    expect(rls003(schemaWithTables([table]))).toHaveLength(0);
  });

  it('skips policies with no expressions at all', () => {
    const table = makeTable('t', { policies: [makePolicy({})] });
    expect(rls003(schemaWithTables([table]))).toHaveLength(0);
  });
});

describe('RLS004 — GRANT BYPASS RLS', () => {
  it('flags every bypass grant', () => {
    const schema: AnalyzedSchema = {
      tables: new Map(),
      bypassRlsGrants: [{ role: 'postgres', file: 'x.sql', line: 1 }],
    };
    const results = rls004(schema);
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({ ruleId: 'RLS-004', severity: 'critical' });
  });
});

describe('RLS005 — FOR ALL policies', () => {
  it('warns when command defaults to ALL', () => {
    const table = makeTable('t', {
      policies: [makePolicy({ command: 'ALL' })],
    });
    const results = rls005(schemaWithTables([table]));
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({ ruleId: 'RLS-005', severity: 'warning' });
  });

  it('does not warn for specific commands', () => {
    for (const command of ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] as const) {
      const table = makeTable('t', { policies: [makePolicy({ command })] });
      expect(rls005(schemaWithTables([table]))).toHaveLength(0);
    }
  });
});