import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { once } from 'node:events';
import {
  safeExecFile,
  safeSpawn,
  createShellCage,
  ShellCageError,
  CODES
} from '../src/index.mjs';
import { makeTempDir, nodeExecOptions } from './helpers.mjs';

function assertCode(fn, code) {
  assert.throws(fn, (error) => error instanceof ShellCageError && error.code === code);
}

async function rejectCode(promise, code) {
  await assert.rejects(promise, (error) => error instanceof ShellCageError && error.code === code);
}

const evalOptions = nodeExecOptions();

test('safeExecFile captures stdout and exit code', async () => {
  const result = await safeExecFile(process.execPath, ['-e', 'process.stdout.write("ok")'], evalOptions);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, 'ok');
  assert.equal(result.stderr, '');
  assert.equal(result.timedOut, false);
  assert.equal(result.truncatedStdout, false);
  assert.equal(result.truncatedStderr, false);
});

test('safeExecFile captures stderr and nonzero exit without throwing', async () => {
  const result = await safeExecFile(process.execPath, ['-e', 'process.stderr.write("bad");process.exit(7)'], evalOptions);
  assert.equal(result.exitCode, 7);
  assert.equal(result.stderr, 'bad');
});

test('safeExecFile result object is frozen and has the documented shape', async () => {
  const result = await safeExecFile(process.execPath, ['-e', ''], evalOptions);
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(Object.keys(result), [
    'command', 'exitCode', 'signal', 'stdout', 'stderr',
    'timedOut', 'truncatedStdout', 'truncatedStderr', 'durationMs'
  ]);
  assert.equal(result.command, process.execPath);
  assert.equal(typeof result.durationMs, 'number');
});

test('safeExecFile passes stdin string to child', async () => {
  const script = 'let s="";process.stdin.on("data",c=>s+=c);process.stdin.on("end",()=>process.stdout.write(s))';
  const result = await safeExecFile(process.execPath, ['-e', script], { ...evalOptions, stdin: 'input-text' });
  assert.equal(result.stdout, 'input-text');
});

test('safeExecFile passes stdin Buffer to child', async () => {
  const script = 'let b=[];process.stdin.on("data",c=>b.push(c));process.stdin.on("end",()=>process.stdout.write(Buffer.concat(b)))';
  const result = await safeExecFile(process.execPath, ['-e', script], { ...evalOptions, stdin: Buffer.from('buffer-input') });
  assert.equal(result.stdout, 'buffer-input');
});

test('safeExecFile rejects oversized stdin before spawning', () => {
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, stdin: 'abc', maxStdinBytes: 2 }), CODES.STDIN_TOO_LARGE);
});

test('safeExecFile accepts stdin at exact byte boundary', async () => {
  const result = await safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, stdin: 'abc', maxStdinBytes: 3 });
  assert.equal(result.exitCode, 0);
});

test('safeExecFile rejects non-string non-Buffer stdin', () => {
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, stdin: 42 }), CODES.STDIN_INVALID);
});

test('safeExecFile enforces timeout for a child that never exits', async () => {
  const result = await safeExecFile(process.execPath, ['-e', 'setTimeout(()=>{},10000)'], { ...evalOptions, timeoutMs: 150 });
  assert.equal(result.timedOut, true);
  assert.ok(result.durationMs < 5000);
});

test('safeExecFile timeout validation rejects zero', () => {
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, timeoutMs: 0 }), CODES.TIMEOUT_INVALID);
});

test('safeExecFile timeout validation rejects values above hard maximum', () => {
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, timeoutMs: 120001 }), CODES.TIMEOUT_INVALID);
});

test('safeExecFile truncates stdout at a streaming byte cap', async () => {
  const script = 'process.stdout.write("x".repeat(5000));setTimeout(()=>{},10000)';
  const result = await safeExecFile(process.execPath, ['-e', script], { ...evalOptions, maxStdoutBytes: 100, timeoutMs: 5000 });
  assert.equal(result.truncatedStdout, true);
  assert.equal(result.stdout.length, 100);
});

test('safeExecFile truncates stderr at a streaming byte cap', async () => {
  const script = 'process.stderr.write("e".repeat(5000));setTimeout(()=>{},10000)';
  const result = await safeExecFile(process.execPath, ['-e', script], { ...evalOptions, maxStderrBytes: 80, timeoutMs: 5000 });
  assert.equal(result.truncatedStderr, true);
  assert.equal(result.stderr.length, 80);
});

test('safeExecFile exact stdout byte boundary is not truncation', async () => {
  const result = await safeExecFile(process.execPath, ['-e', 'process.stdout.write("x".repeat(100))'], { ...evalOptions, maxStdoutBytes: 100 });
  assert.equal(result.truncatedStdout, false);
  assert.equal(result.stdout.length, 100);
});

test('safeExecFile output limit validation rejects zero stdout cap', () => {
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, maxStdoutBytes: 0 }), CODES.OUTPUT_LIMIT_INVALID);
});

test('safeExecFile output limit validation rejects excessive stdout cap', () => {
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, maxStdoutBytes: 64 * 1024 * 1024 + 1 }), CODES.OUTPUT_LIMIT_INVALID);
});

test('safeExecFile output limit validation rejects zero stderr cap', () => {
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, maxStderrBytes: 0 }), CODES.OUTPUT_LIMIT_INVALID);
});

test('safeExecFile environment scrubbing strips unallowlisted custom variables', async () => {
  const script = 'process.stdout.write(JSON.stringify({foo:process.env.FOO,bar:process.env.BAR}))';
  const result = await safeExecFile(process.execPath, ['-e', script], {
    ...evalOptions,
    env: { FOO: 'yes', BAR: 'no' },
    allowEnv: ['FOO']
  });
  assert.deepEqual(JSON.parse(result.stdout), { foo: 'yes' });
});

test('safeExecFile hard-denies NODE_OPTIONS even when explicitly allowlisted', async () => {
  const script = 'process.stdout.write(JSON.stringify({nodeOptions:process.env.NODE_OPTIONS,path:typeof process.env.PATH}))';
  const result = await safeExecFile(process.execPath, ['-e', script], {
    ...evalOptions,
    env: { NODE_OPTIONS: '--require ./definitely-missing', PATH: process.env.PATH || '' },
    allowEnv: ['NODE_OPTIONS', 'PATH']
  });
  assert.equal(result.exitCode, 0);
  assert.equal(JSON.parse(result.stdout).nodeOptions, undefined);
});

test('safeExecFile uses a null-prototype scrubbed environment successfully', async () => {
  const result = await safeExecFile(process.execPath, ['-e', 'process.stdout.write(String(typeof process.env))'], evalOptions);
  assert.equal(result.stdout, 'object');
});

test('safeExecFile blocks eval flags unless dangerous flags are explicitly allowed', () => {
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], {
    allowExecutables: [process.execPath]
  }), CODES.DANGEROUS_FLAG);
});

test('safeExecFile rejects shell true', () => {
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, shell: true }), CODES.SHELL_OPTION_FORBIDDEN);
});

test('safeExecFile rejects windowsVerbatimArguments true', () => {
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, windowsVerbatimArguments: true }), CODES.SHELL_OPTION_FORBIDDEN);
});

test('safeExecFile rejects missing executable allowlist', () => {
  assertCode(() => safeExecFile(process.execPath, ['--version'], {}), CODES.EXECUTABLE_ALLOWLIST_REQUIRED);
});

test('safeExecFile rejects shell interpreters by default before execution', () => {
  assertCode(() => safeExecFile('sh', ['-c', 'true'], { allowExecutables: ['sh'] }), CODES.SHELL_BINARY);
});

test('safeExecFile rejects batch extensions by default before execution', () => {
  assertCode(() => safeExecFile('job.bat', [], { allowExecutables: ['job.bat'] }), CODES.BATCH_EXTENSION);
});

test('safeExecFile rejects unknown option', () => {
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, surprise: true }), CODES.CONFIG_OPTION_UNKNOWN);
});

test('safeExecFile rejects invalid killSignal', () => {
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, killSignal: 'SIGDOESNOTEXIST' }), CODES.CONFIG_INVALID);
});

test('safeExecFile accepts an explicit valid killSignal', async () => {
  const result = await safeExecFile(process.execPath, ['-e', 'setTimeout(()=>{},10000)'], { ...evalOptions, timeoutMs: 100, killSignal: 'SIGKILL' });
  assert.equal(result.timedOut, true);
});

test('safeExecFile reports spawn failure without echoing environment values', async (t) => {
  const directory = makeTempDir(t);
  const missing = path.join(directory, 'missing-tool');
  const secret = 'secret-env-value-never-echo';
  await rejectCode(safeExecFile(missing, [], {
    allowExecutables: [missing],
    env: { PATH: secret },
    allowEnv: ['PATH']
  }), CODES.SPAWN_FAILED);
  try {
    await safeExecFile(missing, [], { allowExecutables: [missing], env: { PATH: secret }, allowEnv: ['PATH'] });
  } catch (error) {
    assert.equal(JSON.stringify(error).includes(secret), false);
  }
});

test('safeExecFile accepts cwd inside an allowed root', async (t) => {
  const root = fs.realpathSync(makeTempDir(t));
  const work = path.join(root, 'work');
  fs.mkdirSync(work);
  const result = await safeExecFile(process.execPath, ['-e', 'process.stdout.write(process.cwd())'], {
    ...evalOptions,
    cwd: work,
    allowedCwdRoots: [root]
  });
  assert.equal(fs.realpathSync(result.stdout), fs.realpathSync(work));
});

test('safeExecFile rejects cwd outside allowed root', async (t) => {
  const root = fs.realpathSync(makeTempDir(t));
  const outside = fs.realpathSync(makeTempDir(t));
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], {
    ...evalOptions,
    cwd: outside,
    allowedCwdRoots: [root]
  }), CODES.CWD_OUTSIDE_ROOT);
});

test('safeExecFile rejects cwd sibling prefix that merely shares a string prefix', async (t) => {
  const base = fs.realpathSync(makeTempDir(t));
  const root = path.join(base, 'work');
  const sibling = path.join(base, 'work-other');
  fs.mkdirSync(root);
  fs.mkdirSync(sibling);
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], {
    ...evalOptions,
    cwd: sibling,
    allowedCwdRoots: [root]
  }), CODES.CWD_OUTSIDE_ROOT);
});

test('safeExecFile rejects symlink cwd escape outside allowed root', async (t) => {
  const root = fs.realpathSync(makeTempDir(t));
  const outside = fs.realpathSync(makeTempDir(t));
  const link = path.join(root, 'escape-link');
  fs.symlinkSync(outside, link, process.platform === 'win32' ? 'junction' : 'dir');
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], {
    ...evalOptions,
    cwd: link,
    allowedCwdRoots: [root]
  }), CODES.CWD_OUTSIDE_ROOT);
});

test('safeExecFile accepts symlink cwd that stays inside allowed root', async (t) => {
  const root = fs.realpathSync(makeTempDir(t));
  const real = path.join(root, 'real');
  fs.mkdirSync(real);
  const link = path.join(root, 'inside-link');
  fs.symlinkSync(real, link, process.platform === 'win32' ? 'junction' : 'dir');
  const result = await safeExecFile(process.execPath, ['-e', 'process.stdout.write(process.cwd())'], {
    ...evalOptions,
    cwd: link,
    allowedCwdRoots: [root]
  });
  assert.equal(fs.realpathSync(result.stdout), fs.realpathSync(real));
});

test('safeExecFile rejects relative cwd', () => {
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, cwd: 'relative/path' }), CODES.CWD_NOT_ABSOLUTE);
});

test('safeExecFile rejects nonexistent cwd', (t) => {
  const directory = makeTempDir(t);
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, cwd: path.join(directory, 'missing') }), CODES.CWD_NOT_FOUND);
});

test('safeExecFile rejects cwd that is a file', (t) => {
  const directory = makeTempDir(t);
  const file = path.join(directory, 'file.txt');
  fs.writeFileSync(file, 'x');
  assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, cwd: file }), CODES.CWD_NOT_DIRECTORY);
});

for (const [label, roots] of [
  ['empty array', []],
  ['relative root', ['relative']],
  ['nonexistent root', ['/definitely-missing-shellcage-root']],
  ['too many roots', Array.from({ length: 65 }, (_, index) => '/root' + index)]
]) {
  test('safeExecFile rejects invalid allowedCwdRoots: ' + label, () => {
    assertCode(() => safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, allowedCwdRoots: roots }), CODES.CWD_ROOT_INVALID);
  });
}

test('safeSpawn executes a valid command and exposes streams', async () => {
  const child = safeSpawn(process.execPath, ['-e', 'process.stdout.write("spawn-ok")'], evalOptions);
  let stdout = '';
  child.stdout.on('data', (chunk) => {
    stdout += chunk.toString('utf8');
  });
  const [exitCode] = await once(child, 'close');
  assert.equal(exitCode, 0);
  assert.equal(stdout, 'spawn-ok');
});

test('safeSpawn rejects invalid invocation before returning a child', () => {
  assertCode(() => safeSpawn('sh', ['-c', 'true'], { allowExecutables: ['sh'] }), CODES.SHELL_BINARY);
});

test('safeSpawn enforces optional timeout', async () => {
  const child = safeSpawn(process.execPath, ['-e', 'setTimeout(()=>{},10000)'], { ...evalOptions, timeoutMs: 100 });
  const start = Date.now();
  await once(child, 'close');
  assert.ok(Date.now() - start < 5000);
});

test('safeSpawn enforces stdin byte cap', () => {
  assertCode(() => safeSpawn(process.execPath, ['-e', ''], { ...evalOptions, stdin: 'abc', maxStdinBytes: 2 }), CODES.STDIN_TOO_LARGE);
});

test('createShellCage requires an executable allowlist', () => {
  assertCode(() => createShellCage({}), CODES.EXECUTABLE_ALLOWLIST_REQUIRED);
});

test('createShellCage bound safeExecFile uses base policy', async () => {
  const cage = createShellCage({
    allowExecutables: [process.execPath],
    allowDangerousFlags: true,
    timeoutMs: 5000
  });
  const result = await cage.safeExecFile(process.execPath, ['-e', 'process.stdout.write("cage")']);
  assert.equal(result.stdout, 'cage');
});

test('createShellCage overrides replace rather than concatenate allowEnv', async () => {
  const cage = createShellCage({
    allowExecutables: [process.execPath],
    allowDangerousFlags: true,
    env: { FOO: 'yes', BAR: 'no' },
    allowEnv: ['FOO']
  });
  const script = 'process.stdout.write(JSON.stringify({foo:process.env.FOO,bar:process.env.BAR}))';
  const result = await cage.safeExecFile(process.execPath, ['-e', script], { allowEnv: ['BAR'] });
  assert.deepEqual(JSON.parse(result.stdout), { bar: 'no' });
});

test('createShellCage validateInvocation uses base allowlist', () => {
  const cage = createShellCage({ allowExecutables: ['git'] });
  assert.equal(cage.validateInvocation('git', ['--version']).ok, true);
  assert.equal(cage.validateInvocation('curl', ['--version']).ok, false);
});

test('createShellCage object is frozen', () => {
  const cage = createShellCage({ allowExecutables: ['git'] });
  assert.equal(Object.isFrozen(cage), true);
});

test('createShellCage does not freeze caller-owned arrays or env objects', () => {
  const allowExecutables = ['git'];
  const allowEnv = ['PATH'];
  const env = { PATH: '/bin' };
  createShellCage({ allowExecutables, allowEnv, env });
  assert.equal(Object.isFrozen(allowExecutables), false);
  assert.equal(Object.isFrozen(allowEnv), false);
  assert.equal(Object.isFrozen(env), false);
});

test('validation error details do not echo dangerous argument values', () => {
  const secretLike = 'ext::sh -c secret-material';
  try {
    safeExecFile('git', ['clone', secretLike], { allowExecutables: ['git'] });
    assert.fail('expected validation failure');
  } catch (error) {
    assert.ok(error instanceof ShellCageError);
    assert.equal(JSON.stringify(error).includes('secret-material'), false);
  }
});

test('windowsHide false is accepted', async () => {
  const result = await safeExecFile(process.execPath, ['-e', ''], { ...evalOptions, windowsHide: false });
  assert.equal(result.exitCode, 0);
});

test('safeSpawn rejects stdout cap options it cannot enforce', () => {
  assertCode(() => safeSpawn(process.execPath, ['-e', ''], { ...evalOptions, maxStdoutBytes: 10 }), CODES.CONFIG_INVALID);
});

test('safeSpawn rejects stderr cap options it cannot enforce', () => {
  assertCode(() => safeSpawn(process.execPath, ['-e', ''], { ...evalOptions, maxStderrBytes: 10 }), CODES.CONFIG_INVALID);
});

test('createShellCage environment overrides reject execution-only options', () => {
  const cage = createShellCage({ allowExecutables: [process.execPath] });
  assertCode(() => cage.sanitizeEnv({ PATH: '/bin' }, { timeoutMs: 5 }), CODES.CONFIG_OPTION_UNKNOWN);
});

test('createShellCage auditEnv supports includeUnlisted override', () => {
  const cage = createShellCage({ allowExecutables: [process.execPath], allowEnv: ['PATH'] });
  const findings = cage.auditEnv({ CUSTOM: 'x' }, { includeUnlisted: true });
  assert.equal(findings.some((finding) => finding.code === CODES.ENV_NOT_ALLOWLISTED), true);
});

test('createShellCage copies fixed Buffer stdin without freezing the caller buffer', async () => {
  const input = Buffer.from('fixed-input');
  const cage = createShellCage({
    allowExecutables: [process.execPath],
    allowDangerousFlags: true,
    stdin: input
  });
  input.write('mutated-input');
  const script = 'let s="";process.stdin.on("data",c=>s+=c);process.stdin.on("end",()=>process.stdout.write(s))';
  const result = await cage.safeExecFile(process.execPath, ['-e', script]);
  assert.equal(result.stdout, 'fixed-input');
});

test('validateInvocation reports Buffer argv input instead of crashing while freezing report', () => {
  const cage = createShellCage({ allowExecutables: [process.execPath] });
  const report = cage.validateInvocation(process.execPath, [Buffer.from('x')]);
  assert.equal(report.ok, false);
  assert.equal(report.findings.some((finding) => finding.code === CODES.ARG_TYPE), true);
});

test('safeSpawn timeout escalates when the child ignores the initial signal', async () => {
  const child = safeSpawn(process.execPath, ['-e', 'process.on("SIGTERM",()=>{});setTimeout(()=>{},10000)'], {
    ...evalOptions,
    timeoutMs: 80,
    killSignal: 'SIGTERM'
  });
  const start = Date.now();
  await once(child, 'close');
  assert.ok(Date.now() - start < 3000);
});

test('safeExecFile truncation does not emit a partial UTF-8 character', async () => {
  const script = 'process.stdout.write("x".repeat(99)+"é");setTimeout(()=>{},10000)';
  const result = await safeExecFile(process.execPath, ['-e', script], {
    ...evalOptions,
    timeoutMs: 5000,
    maxStdoutBytes: 100
  });
  assert.equal(result.truncatedStdout, true);
  assert.equal(result.stdout, 'x'.repeat(99));
  assert.equal(Buffer.byteLength(result.stdout, 'utf8'), 99);
  assert.equal(result.stdout.includes('\ufffd'), false);
});

test('safeExecFile joins multibyte UTF-8 split across chunks without corruption', async () => {
  const script = 'const b=Buffer.from("é","utf8");process.stdout.write(b.subarray(0,1));setImmediate(()=>process.stdout.write(b.subarray(1)))';
  const result = await safeExecFile(process.execPath, ['-e', script], evalOptions);
  assert.equal(result.stdout, 'é');
});
