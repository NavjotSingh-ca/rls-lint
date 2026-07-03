# Roadmap Issues

Copy-paste each section below into a new GitHub Issue on https://github.com/NavjotSingh-ca/rls-lint/issues/new

---

## Issue 1: GitHub Action composite action

**Title:** Official `rls-lint-action` GitHub Action

**Body:**
Create a composite GitHub Action so users can run rls-lint in CI with a single step:

```yaml
- uses: NavjotSingh-ca/rls-lint-action@v1
  with:
    path: ./supabase/migrations
```

This should install the package, run it, and annotate the PR with any findings.

---

## Issue 2: SARIF output for GitHub code scanning

**Title:** `--format sarif` for GitHub code scanning integration

**Body:**
Add a `--format sarif` flag that outputs results in SARIF format. This would let rls-lint integrate with GitHub's code scanning alerts, showing findings inline on the Security tab.

---

## Issue 3: JSON output for custom CI pipelines

**Title:** `--format json` for machine-readable output

**Body:**
Add a `--format json` flag that outputs results as JSON. Useful for teams that want to parse results in custom CI pipelines or feed them into dashboards.

---

## Issue 4: Auto-fix suggestions

**Title:** Suggest fixes for common RLS misconfigurations

**Body:**
For rules RLS-001 and RLS-002, print the corrected SQL statement. For example:

```
🛠  Suggestion: add ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
🛠  Suggestion: replace USING(true) with USING(tenant_id = auth.uid())
```

Could be shown with a `--suggestions` flag.

---

## Issue 5: Live DB check mode

**Title:** `--live` flag to audit policies on a running database

**Body:**
Add a `--live` mode that connects to a Supabase project (via connection string or env vars) and audits the actual policies in the database, not just migration files. This would catch policies that were modified outside of migrations.
