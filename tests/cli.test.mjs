import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { runCli, runProcess, makeTempDir } from './helpers.mjs';

function writeJson(t, value, name = 'env.json') {
  const directory = makeTempDir(t);
  const file = path.join(directory, name);
  fs.writeFileSync(file, JSON.stringify(value));
  return file;
}

test('CLI --help exits zero and prints usage', async () => {
  const result = await runCli(['--help']);
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /shellcage audit/);
  assert.match(result.stdout, /audit-env/);
});

test('CLI short help exits zero', async () => {
  const result = await runCli(['-h']);
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /Usage:/);
});

test('CLI --version exits zero and prints version', async () => {
  const result = await runCli(['--version']);
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /^shellcage 1\.0\.0/);
});

test('CLI short version exits zero', async () => {
  const result = await runCli(['-v']);
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /^shellcage 1\.0\.0/);
});

test('CLI with no command exits 2', async () => {
  const result = await runCli([]);
  assert.equal(result.exitCode, 2);
  assert.match(result.stderr, /missing command/);
});

test('CLI unknown command exits 2', async () => {
  const result = await runCli(['wat']);
  assert.equal(result.exitCode, 2);
  assert.match(result.stderr, /unknown command/);
});

test('CLI audit without end-of-options separator exits 2', async () => {
  const result = await runCli(['audit', 'git', '--version']);
  assert.equal(result.exitCode, 2);
  assert.match(result.stderr, /requires --/);
});

test('CLI audit with separator but no command exits 2', async () => {
  const result = await runCli(['audit', '--']);
  assert.equal(result.exitCode, 2);
});

test('CLI audit rejects unexpected token before separator', async () => {
  const result = await runCli(['audit', '--verbose', '--', 'git']);
  assert.equal(result.exitCode, 2);
});

test('CLI audit accepts clean invocation and exits zero', async () => {
  const result = await runCli(['audit', '--', 'node', '--version']);
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /clean/);
});

test('CLI audit does not execute the audited command', async () => {
  const result = await runCli(['audit', '--', 'definitely-not-a-real-shellcage-test-command']);
  assert.equal(result.exitCode, 0);
  assert.equal(result.timedOut, false);
});

test('CLI audit detects dangerous git flag and exits 1', async () => {
  const result = await runCli(['audit', '--', 'git', 'clone', '--upload-pack=x', 'repo']);
  assert.equal(result.exitCode, 1);
  assert.match(result.stdout, /SHELLCAGE_DANGEROUS_FLAG/);
});

test('CLI audit detects shell binary and exits 1', async () => {
  const result = await runCli(['audit', '--', 'sh', '-c', 'true']);
  assert.equal(result.exitCode, 1);
  assert.match(result.stdout, /SHELLCAGE_SHELL_BINARY/);
});

test('CLI audit detects batch extension and exits 1', async () => {
  const result = await runCli(['audit', '--', 'job.bat']);
  assert.equal(result.exitCode, 1);
  assert.match(result.stdout, /SHELLCAGE_BATCH_EXTENSION/);
});

test('CLI audit JSON output is parseable and structured', async () => {
  const result = await runCli(['audit', '--json', '--', 'git', 'clone', '--upload-pack=x']);
  assert.equal(result.exitCode, 1);
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.mode, 'audit');
  assert.equal(payload.ok, false);
  assert.equal(payload.findings[0].code, 'SHELLCAGE_DANGEROUS_FLAG');
});

test('CLI audit JSON clean output exits zero', async () => {
  const result = await runCli(['audit', '--json', '--', 'git', '--version']);
  assert.equal(result.exitCode, 0);
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.ok, true);
  assert.deepEqual(payload.findings, []);
});

test('CLI audit does not echo dangerous argument values in text output', async () => {
  const secretLike = 'ext::sh -c secret-material';
  const result = await runCli(['audit', '--', 'git', 'clone', secretLike]);
  assert.equal(result.exitCode, 1);
  assert.equal(result.stdout.includes('secret-material'), false);
});

test('CLI audit does not echo dangerous argument values in JSON output', async () => {
  const secretLike = 'ext::sh -c secret-material';
  const result = await runCli(['audit', '--json', '--', 'git', 'clone', secretLike]);
  assert.equal(result.exitCode, 1);
  assert.equal(result.stdout.includes('secret-material'), false);
});

test('CLI audit preserves inner end-of-options marker as an argument', async () => {
  const result = await runCli(['audit', '--json', '--', 'git', 'clone', '--', '--upload-pack=x']);
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.ok, true);
});

test('CLI audit-env accepts a clean JSON fixture', async (t) => {
  const file = writeJson(t, { PATH: '/bin', HOME: '/home/example' });
  const result = await runCli(['audit-env', '--env-json', file]);
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /clean/);
});

test('CLI audit-env detects dangerous variable and exits 1', async (t) => {
  const file = writeJson(t, { NODE_OPTIONS: '--require x' });
  const result = await runCli(['audit-env', '--env-json', file]);
  assert.equal(result.exitCode, 1);
  assert.match(result.stdout, /SHELLCAGE_ENV_INJECTION/);
  assert.match(result.stdout, /NODE_OPTIONS/);
});

test('CLI audit-env JSON output is parseable and structured', async (t) => {
  const file = writeJson(t, { LD_PRELOAD: 'payload' });
  const result = await runCli(['audit-env', '--json', '--env-json', file]);
  assert.equal(result.exitCode, 1);
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.mode, 'audit-env');
  assert.equal(payload.ok, false);
  assert.equal(payload.findings[0].code, 'SHELLCAGE_ENV_INJECTION');
});

test('CLI audit-env does not print secret values in text output', async (t) => {
  const secret = 'super-secret-value-never-print';
  const file = writeJson(t, { NODE_OPTIONS: secret });
  const result = await runCli(['audit-env', '--env-json', file]);
  assert.equal(result.exitCode, 1);
  assert.equal(result.stdout.includes(secret), false);
  assert.equal(result.stderr.includes(secret), false);
});

test('CLI audit-env does not print secret values in JSON output', async (t) => {
  const secret = 'super-secret-value-never-print';
  const file = writeJson(t, { NODE_OPTIONS: secret });
  const result = await runCli(['audit-env', '--json', '--env-json', file]);
  assert.equal(result.exitCode, 1);
  assert.equal(result.stdout.includes(secret), false);
});

test('CLI audit-env reports non-string value without printing it', async (t) => {
  const file = writeJson(t, { PATH: { nested: 'secret-shape' } });
  const result = await runCli(['audit-env', '--json', '--env-json', file]);
  assert.equal(result.exitCode, 1);
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.findings.some((item) => item.code === 'SHELLCAGE_ENV_VALUE_TYPE'), true);
  assert.equal(result.stdout.includes('secret-shape'), false);
});

test('CLI audit-env rejects malformed JSON input', async (t) => {
  const directory = makeTempDir(t);
  const file = path.join(directory, 'bad.json');
  fs.writeFileSync(file, '{not-json');
  const result = await runCli(['audit-env', '--env-json', file]);
  assert.equal(result.exitCode, 2);
});

test('CLI audit-env rejects non-object JSON input', async (t) => {
  const file = writeJson(t, ['PATH']);
  const result = await runCli(['audit-env', '--env-json', file]);
  assert.equal(result.exitCode, 2);
});

test('CLI audit-env rejects missing JSON file', async (t) => {
  const directory = makeTempDir(t);
  const result = await runCli(['audit-env', '--env-json', path.join(directory, 'missing.json')]);
  assert.equal(result.exitCode, 2);
});

test('CLI audit-env rejects oversized JSON file', async (t) => {
  const directory = makeTempDir(t);
  const file = path.join(directory, 'large.json');
  fs.writeFileSync(file, '{"PATH":"' + 'x'.repeat(1024 * 1024) + '"}');
  const result = await runCli(['audit-env', '--env-json', file]);
  assert.equal(result.exitCode, 2);
});

test('CLI audit-env rejects duplicate json flag', async () => {
  const result = await runCli(['audit-env', '--json', '--json']);
  assert.equal(result.exitCode, 2);
});

test('CLI audit-env rejects missing env-json value', async () => {
  const result = await runCli(['audit-env', '--env-json']);
  assert.equal(result.exitCode, 2);
});

test('CLI audit-env rejects unknown option', async () => {
  const result = await runCli(['audit-env', '--surprise']);
  assert.equal(result.exitCode, 2);
});

test('CLI audit-env empty object fixture is clean', async (t) => {
  const file = writeJson(t, {});
  const result = await runCli(['audit-env', '--env-json', file]);
  assert.equal(result.exitCode, 0);
});

test('CLI audit-env dangerous key case is insensitive', async (t) => {
  const file = writeJson(t, { node_options: '--require x' });
  const result = await runCli(['audit-env', '--env-json', file]);
  assert.equal(result.exitCode, 1);
});

test('CLI audit-env invalid key does not echo control characters', async (t) => {
  const file = writeJson(t, { 'BAD\nKEY': 'x' });
  const result = await runCli(['audit-env', '--json', '--env-json', file]);
  assert.equal(result.exitCode, 1);
  assert.equal(result.stdout.includes('BAD\nKEY'), false);
});

test('CLI audit neutralizes bidirectional controls in command output', async () => {
  const result = await runCli(['audit', '--', 'bad\u202ename']);
  assert.equal(result.exitCode, 1);
  assert.equal(result.stdout.includes('bad\u202ename'), false);
  assert.ok(result.stdout.includes('\\u202e'));
});

test('CLI audit JSON neutralizes bidirectional controls in finding metadata', async () => {
  const result = await runCli(['audit', '--json', '--', 'pwsh', ['-', '-c', 'x'].join('')]);
  assert.equal(result.exitCode, 1);
  assert.equal(result.stdout.includes('\u202e'), false);
});

test('CLI audit-env rejects a FIFO input', async (t) => {
  if (process.platform === 'win32') t.skip('FIFOs are unavailable on Windows');
  const directory = makeTempDir(t);
  const fifo = path.join(directory, 'env-fifo');
  const mkfifo = await runProcess('mkfifo', [fifo]);
  assert.equal(mkfifo.exitCode, 0);
  const result = await runCli(['audit-env', '--env-json', fifo]);
  assert.equal(result.exitCode, 2);
});
