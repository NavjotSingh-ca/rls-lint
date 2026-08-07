import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { parseSqlFile, scanSqlFiles } from './parser.js';

const tempDirs: string[] = [];

/** Create a temp SQL file and return its absolute path. */
function writeTempSql(content: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rls-lint-test-'));
  tempDirs.push(dir);
  const file = path.join(dir, 'migration.sql');
  fs.writeFileSync(file, content, 'utf-8');
  return file;
}

afterEach(() => {
  for (const dir of tempDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  tempDirs.length = 0;
});

describe('parseSqlFile', () => {
  it('parses CREATE TABLE with schema qualifier', () => {
    const file = writeTempSql(
      'CREATE TABLE public.products (\n  id UUID PRIMARY KEY,\n  tenant_id UUID NOT NULL\n);',
    );
    const parsed = parseSqlFile(file, 'migration.sql');
    expect(parsed.createTables).toHaveLength(1);
    expect(parsed.createTables[0]).toMatchObject({
      tableName: 'products',
      schema: 'public',
      line: 1,
    });
  });

  it('parses CREATE TABLE IF NOT EXISTS', () => {
    const file = writeTempSql('CREATE TABLE IF NOT EXISTS tenants (id UUID PRIMARY KEY);');
    const parsed = parseSqlFile(file, 'x.sql');
    expect(parsed.createTables[0]?.tableName).toBe('tenants');
  });

  it('parses ALTER TABLE ENABLE / DISABLE ROW LEVEL SECURITY', () => {
    const file = writeTempSql(
      'CREATE TABLE public.foo (id UUID PRIMARY KEY);\n' +
        'ALTER TABLE public.foo ENABLE ROW LEVEL SECURITY;\n' +
        'ALTER TABLE public.foo DISABLE ROW LEVEL SECURITY;',
    );
    const parsed = parseSqlFile(file, 'x.sql');
    expect(parsed.alterRls).toHaveLength(2);
    expect(parsed.alterRls[0]).toMatchObject({ tableName: 'foo', enable: true, line: 2 });
    expect(parsed.alterRls[1]).toMatchObject({ tableName: 'foo', enable: false, line: 3 });
  });

  it('parses CREATE POLICY with USING and WITH CHECK', () => {
    const file = writeTempSql(
      `CREATE POLICY "tenant_read" ON public.notes
       FOR SELECT
       USING (tenant_id = auth.uid())
       WITH CHECK (tenant_id = auth.uid());`,
    );
    const parsed = parseSqlFile(file, 'x.sql');
    expect(parsed.createPolicies).toHaveLength(1);
    const policy = parsed.createPolicies[0];
    expect(policy).toMatchObject({
      policyName: 'tenant_read',
      tableName: 'notes',
      command: 'SELECT',
      line: 1,
    });
    expect(policy.usingExpression).toContain('tenant_id');
    expect(policy.withCheckExpression).toContain('tenant_id');
  });

  it('extracts USING (true) — the open-to-everyone pattern', () => {
    const file = writeTempSql(
      'CREATE POLICY "public_read" ON public.products FOR SELECT\n  USING (true);',
    );
    const parsed = parseSqlFile(file, 'x.sql');
    expect(parsed.createPolicies[0]?.usingExpression?.trim().toLowerCase()).toBe('true');
  });

  it('handles nested parentheses in USING expressions', () => {
    const file = writeTempSql(
      'CREATE POLICY "in_org" ON public.items FOR SELECT\n' +
        '  USING (org_id IN (SELECT org_id FROM memberships WHERE user_id = auth.uid()));',
    );
    const parsed = parseSqlFile(file, 'x.sql');
    const using = parsed.createPolicies[0]?.usingExpression;
    expect(using).toContain('(SELECT org_id FROM memberships');
    expect(using).toContain('user_id = auth.uid()');
  });

  it('handles GRANT ... BYPASS RLS', () => {
    const file = writeTempSql('GRANT BYPASS RLS ON public.foo TO postgres;');
    const parsed = parseSqlFile(file, 'x.sql');
    expect(parsed.bypassRlsGrants).toHaveLength(1);
    expect(parsed.bypassRlsGrants[0]?.role).toBe('postgres');
  });

  it('does not count GRANT SELECT TO as bypass', () => {
    const file = writeTempSql('GRANT SELECT ON public.foo TO anon;');
    const parsed = parseSqlFile(file, 'x.sql');
    expect(parsed.bypassRlsGrants).toHaveLength(0);
  });

  it('splits multiple statements on separate lines', () => {
    const file = writeTempSql(
      'CREATE TABLE a (x int);\n' +
        'CREATE TABLE b (y int);\n' +
        'CREATE TABLE c (z int);',
    );
    const parsed = parseSqlFile(file, 'x.sql');
    expect(parsed.createTables.map((t) => t.tableName)).toEqual(['a', 'b', 'c']);
  });

  it('handles multiple statements on a single line', () => {
    const file = writeTempSql(
      'CREATE TABLE a (x int); CREATE TABLE b (y int); CREATE TABLE c (z int);',
    );
    const parsed = parseSqlFile(file, 'x.sql');
    expect(parsed.createTables.map((t) => t.tableName)).toEqual(['a', 'b', 'c']);
    expect(parsed.createTables[0]?.line).toBe(1);
  });

  it('does not split on semicolons inside single-quoted strings', () => {
    // The ";" inside the string literal must NOT terminate the statement
    const file = writeTempSql(
      `CREATE POLICY "greeting" ON public.notes FOR SELECT
  USING (note = 'hello; world');`,
    );
    const parsed = parseSqlFile(file, 'x.sql');
    expect(parsed.createPolicies).toHaveLength(1);
    expect(parsed.createPolicies[0]?.usingExpression).toContain("'hello; world'");
  });

  it('does not split on semicolons inside dollar-quoted bodies', () => {
    const file = writeTempSql(
      `CREATE FUNCTION public.seed() RETURNS void AS $fn$
BEGIN
  INSERT INTO public.x (a) VALUES (1);
  INSERT INTO public.x (a) VALUES (2);
END;
$fn$ LANGUAGE plpgsql;`,
    );
    const parsed = parseSqlFile(file, 'x.sql');
    // The function body statements are ignored as unparseable, but the
    // INSERT statements inside the dollar-quote must NOT be extracted
    expect(parsed.createTables).toHaveLength(0);
    expect(parsed.errors).toHaveLength(0);
  });

  it('strips single-line comments without treating them as code', () => {
    const file = writeTempSql(
      '-- Create the table\n' +
        'CREATE TABLE public.foo (a int); -- inline comment\n' +
        '-- ALTER TABLE public.foo ENABLE ROW LEVEL SECURITY;\n',
    );
    const parsed = parseSqlFile(file, 'x.sql');
    expect(parsed.createTables).toHaveLength(1);
    // The commented-out ALTER must not register
    expect(parsed.alterRls).toHaveLength(0);
  });

  it('strips multi-line comments', () => {
    const file = writeTempSql(
      '/* block comment\n   spanning lines */\n' +
        'CREATE TABLE public.bar (b int);',
    );
    const parsed = parseSqlFile(file, 'x.sql');
    expect(parsed.createTables).toHaveLength(1);
    expect(parsed.createTables[0]?.line).toBe(3);
  });

  it('does not strip -- inside string literals', () => {
    const file = writeTempSql(
      `CREATE POLICY "literal" ON public.notes FOR SELECT
  USING (note = 'a -- not a comment');`,
    );
    const parsed = parseSqlFile(file, 'x.sql');
    // The full USING expression (including the -- inside the literal) survives
    expect(parsed.createPolicies[0]?.usingExpression).toContain('-');
    expect(parsed.createPolicies[0]?.usingExpression).toContain('not a comment');
  });

  it('handles double-quoted table and policy identifiers', () => {
    const file = writeTempSql(
      'CREATE TABLE "Orders" ("Remote Key" uuid PRIMARY KEY);\n' +
        'CREATE POLICY "All Access" ON "Orders" FOR ALL USING (true);',
    );
    const parsed = parseSqlFile(file, 'x.sql');
    expect(parsed.createTables[0]?.tableName).toBe('Orders');
    expect(parsed.createPolicies[0]?.policyName).toBe('All Access');
    expect(parsed.createPolicies[0]?.tableName).toBe('Orders');
  });
});

describe('scanSqlFiles', () => {
  it('finds .sql files recursively and skips hidden dirs', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rls-lint-scan-'));
    tempDirs.push(dir);
    fs.mkdirSync(path.join(dir, 'supabase', 'migrations'), { recursive: true });
    fs.mkdirSync(path.join(dir, '.hidden'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'supabase', 'migrations', '001.sql'), '-- x');
    fs.writeFileSync(path.join(dir, '.hidden', 'secret.sql'), '-- x');
    fs.writeFileSync(path.join(dir, 'readme.txt'), 'not sql');

    const result = scanSqlFiles(dir);
    expect(result.files).toHaveLength(1);
    expect(result.files[0]).toContain('001.sql');
    expect(result.errors).toHaveLength(0);
  });

  it('returns an error for a missing path', () => {
    const result = scanSqlFiles(path.join(os.tmpdir(), 'does-not-exist-xyz'));
    expect(result.files).toHaveLength(0);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns a single file when given a .sql file', () => {
    const file = writeTempSql('CREATE TABLE x (a int);');
    const result = scanSqlFiles(file);
    expect(result.files).toEqual([file]);
  });
});