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

## Quickstart

```bash
# Run against your Supabase migrations
npx rls-lint ./supabase/migrations

# Run against a single file
npx rls-lint ./supabase/migrations/20250101_create_users.sql
```

## Example

```
  rls-lint report
  ═══════════════

  🔴 RLS-001  Missing RLS on table 'customer_notes'
               missing-rls.sql:1

  🔴 RLS-002  Policy 'products_public_read' uses USING(true) — open to everyone
               using-true.sql:11

  🟡 RLS-003  Policy 'articles_published_read' has no tenant-scoping column
               no-tenant-scope.sql:12

  🔴 RLS-004  GRANT BYPASS RLS found on role(s): 'postgres'
               bypass-rls.sql:1

  🟡 RLS-005  Policy 'documents_all_access' uses FOR ALL
               for-all.sql:12

  ────────────────────────────────────────
  ✘ 3 critical, 2 warnings  |  5 total
```

## Rules

| ID | Rule | Severity |
|----|------|----------|
| **RLS-001** | Table created without `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` | 🔴 critical |
| **RLS-002** | Policy uses `USING (true)` or `WITH CHECK (true)` | 🔴 critical |
| **RLS-003** | Policy doesn't reference a tenant-scoping column (`tenant_id`, `org_id`, `user_id`, `auth.uid()`) | 🟡 warning |
| **RLS-004** | `GRANT BYPASS RLS` detected — bypasses all policies | 🔴 critical |
| **RLS-005** | Policy uses `FOR ALL` instead of a specific command (`FOR SELECT`, `FOR INSERT`, etc.) | 🟡 warning |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No critical findings (warnings OK) |
| `1` | Critical findings detected — fail CI builds |
| `2` | Invalid path or no `.sql` files found |

## Try It Right Now

```bash
git clone https://github.com/NavjotSingh-ca/rls-lint.git
cd rls-lint
npm install
npm run build
npm test
```

The repo includes 6 test fixture files in `test-fixtures/` — 5 intentionally broken and 1 clean — so you can see exactly what each rule catches:

```bash
node dist/cli.js ./test-fixtures
# → 4 critical, 6 warnings (exit code 1)

node dist/cli.js ./test-fixtures/clean.sql
# → ✅ No issues found (exit code 0)
```

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

- **PostgreSQL only** — No MySQL, SQLite, or other dialect support.
- **RLS-003 is heuristic** — Checks for common column name patterns only. A policy that uses subqueries or JOINs for tenant scoping (e.g., `USING (org_id IN (SELECT ...))`) won't be recognized (false negative).
- **No live DB connection** — Pure static analysis. Cannot detect policies modified outside migration files or verify that policies actually compile.
- **Complex PL/pgSQL** may cause parse warnings — individual unparseable statements are skipped; the rest of the file is still analyzed.

## Roadmap

- [ ] **GitHub Action composite action** — official `rls-lint-action` for one-line CI setup
- [ ] **SARIF output** — GitHub code scanning integration (`--format sarif`)
- [ ] **JSON output** — machine-readable results for custom CI pipelines (`--format json`)
- [ ] **Auto-fix suggestions** — print the corrected `ALTER TABLE` or `CREATE POLICY` statement
- [ ] **Live DB check mode** — connect to a Supabase project and audit current policies (`--live`)
- [ ] **VS Code extension** — inline diagnostics as you edit migration files

## Contributing

Contributions welcome! See [open issues](https://github.com/NavjotSingh-ca/rls-lint/issues) for what needs work.

## License

MIT
