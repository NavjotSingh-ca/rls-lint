<p align="center">
  <h1 align="center">rls-lint</h1>
  <p align="center"><strong>Static security linter for Supabase Row Level Security policies.</strong></p>
  <p align="center">
    <a href="https://www.npmjs.com/package/rls-lint"><img src="https://img.shields.io/npm/v/rls-lint" alt="npm version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/npm/l/rls-lint" alt="MIT license"></a>
    <a href="https://nodejs.org/"><img src="https://img.shields.io/node/v/rls-lint" alt="Node version"></a>
  </p>
</p>

---

Catch multi-tenant data leaks **before** you ship. `rls-lint` analyzes your Supabase SQL migration files offline — zero network calls, zero database connections — and flags RLS misconfigurations that could expose data across tenants.

## Why rls-lint?

Row Level Security is Supabase's most powerful security feature — and the easiest to get wrong. The most common data leak vulnerabilities in Supabase apps aren't SQL injection or XSS — they're RLS policies that are missing, too permissive, or scoped to the wrong columns.

These bugs are hard to catch in code review because the SQL looks fine on its own. `rls-lint` catches them automatically, every time, in CI or locally, without touching your database.

```bash
$ npx rls-lint ./supabase/migrations

  🔴 RLS-001  Missing RLS on table 'orders'
               migrations/001_create_orders.sql:3

  🔴 RLS-002  Policy 'all_users' uses USING(true) — open to everyone
               migrations/002_policies.sql:5

  🟡 RLS-003  Policy 'org_admins' has no tenant-scoping column
               migrations/002_policies.sql:12

  ✘ 2 critical, 1 warning  |  3 total
```

## Quickstart

### Try it right now (no install)

```bash
# Clone the repo, then:
cd rls-lint
npm install
npm run build

# Run against the included broken fixtures
node dist/cli.js ./test-fixtures
```

### With test fixtures

The repo includes 6 `.sql` files in `test-fixtures/` — 5 intentionally broken and 1 clean — so you can see exactly what each rule detects:

```bash
node dist/cli.js ./test-fixtures
# → 4 critical, 6 warnings (exit code 1)

node dist/cli.js ./test-fixtures/clean.sql
# → ✅ No issues found (exit code 0)
```

### Against your own migrations

```bash
node dist/cli.js ./supabase/migrations
node dist/cli.js ./my-migration.sql
```

## Rules

| ID | Rule | Severity | Detection Method |
|----|------|----------|-----------------|
| **RLS-001** | Table created without `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` | 🔴 critical | Scans all `CREATE TABLE` statements, flags any table that never has `ENABLE ROW LEVEL SECURITY` called on it |
| **RLS-002** | Policy uses `USING (true)` or `WITH CHECK (true)` | 🔴 critical | Checks each policy's `USING` and `WITH CHECK` expressions for literal `true` |
| **RLS-003** | Policy doesn't reference a tenant-scoping column | 🟡 warning | Verifies `USING`/`WITH CHECK` references at least one of: `tenant_id`, `org_id`, `organization_id`, `user_id`, `auth.uid()` |
| **RLS-004** | `GRANT BYPASS RLS` detected | 🔴 critical | Flags any `GRANT` statement containing `BYPASS RLS` |
| **RLS-005** | Policy uses `FOR ALL` instead of a specific command | 🟡 warning | Flags policies with `FOR ALL` or no `FOR` clause (defaults to `ALL`) |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No critical findings (warnings OK) |
| `1` | Critical findings detected (use in CI to fail builds) |
| `2` | Invalid path or no `.sql` files found |

## Test Fixtures

| File | What it tests |
|------|--------------|
| `clean.sql` | Baseline — all rules pass, verifies zero false positives |
| `missing-rls.sql` | **RLS-001** — table with a policy but no `ENABLE ROW LEVEL SECURITY` |
| `using-true.sql` | **RLS-002** — policy scoped to `USING (true)` |
| `no-tenant-scope.sql` | **RLS-003** — policy scoped by `status = 'published'` instead of a tenant column |
| `bypass-rls.sql` | **RLS-004** — `GRANT BYPASS RLS TO postgres` |
| `for-all.sql` | **RLS-005** — policies using `FOR ALL` and implicit `ALL` (no `FOR` clause) |

## Use in CI (GitHub Actions)

```yaml
name: Lint RLS policies
on: [push, pull_request]

jobs:
  rls-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx rls-lint ./supabase/migrations
```

## Known Limitations

- **PostgreSQL only** — No MySQL, SQLite, or other dialect support
- **RLS-003 is heuristic** — Checks for common column name patterns only. A policy that uses subqueries or JOINs for tenant scoping (e.g., `USING (org_id IN (SELECT ...))`) won't be recognized (false negative)
- **No live DB connection** — Pure static analysis. Cannot detect policies modified outside migration files or verify that policies actually compile
- **Complex PL/pgSQL** may cause parse warnings — individual unparseable statements are skipped with a warning; the rest of the file is still analyzed

## Development

```bash
git clone https://github.com/NavjotSingh-ca/rls-lint.git
cd rls-lint
npm install
npm run build       # compiles TypeScript → dist/
npm test            # runs linter against test-fixtures/
```

## Contributing

Contributions welcome! Areas that need work:
- Additional RLS lint rules
- GitHub Action as a composite action
- SARIF output for GitHub code scanning integration
- Support for quoted identifiers with special characters

## License

MIT
