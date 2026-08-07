import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { runLint } from './cli.js';

/**
 * Full-stack test: run the real file scan → parse → analyze → rule pipeline
 * against on-disk fixtures, plus the compiled CLI binary end-to-end.
 */

const fixtureDir = path.resolve('test-fixtures');

describe('runLint (in-process pipeline)', () => {
  it('returns 1 (critical findings) for the broken fixtures directory', () => {
    expect(runLint(fixtureDir)).toBe(1);
  });

  it('returns 0 for the clean fixture file', () => {
    expect(runLint(path.join(fixtureDir, 'clean.sql'))).toBe(0);
  });

  it('returns 2 for a nonexistent path', () => {
    expect(runLint(path.join(os.tmpdir(), 'no-such-dir-xyz'))).toBe(2);
  });
});

describe('CLI binary (dist/cli.js)', () => {
  const cliPath = path.resolve('dist/cli.js');
  const built = fs.existsSync(cliPath);

  // Integration tests need the compiled CLI. On a fresh checkout (no dist/)
  // they are skipped — run `npm run build` first to exercise them.
  beforeAll(() => {
    if (!built) {
      console.warn('dist/cli.js not found — skipping CLI binary tests (run npm run build first)');
    }
  });

  function runCli(args: string[]): { stdout: string; status: number } {
    try {
      const stdout = execFileSync(process.execPath, [cliPath, ...args], {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      return { stdout, status: 0 };
    } catch (err) {
      const e = err as { status?: number; stdout?: string; stderr?: string };
      return {
        stdout: e.stdout || '',
        status: e.status ?? 1,
      };
    }
  }

  it.skipIf(!built)('emits a report with critical findings and exits 1 on broken fixtures', () => {
    const { stdout, status } = runCli([fixtureDir]);
    expect(status).toBe(1);
    expect(stdout).toContain('rls-lint report');
    expect(stdout).toContain('critical');
  });

  it.skipIf(!built)('passes with exit code 0 on clean fixtures', () => {
    const { stdout, status } = runCli([path.join(fixtureDir, 'clean.sql')]);
    expect(status).toBe(0);
    expect(stdout).toContain('No issues found');
  });

  it.skipIf(!built)('exits 2 when no SQL files are found', () => {
    const { status } = runCli([path.join(os.tmpdir(), 'no-such-dir-xyz')]);
    expect(status).toBe(2);
  });
});