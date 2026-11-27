import test from 'node:test';
import assert from 'node:assert/strict';
import { validateInvocation, auditArgv, CODES } from '../src/index.mjs';
import { toolPath, codesFromReport, codesFromFindings, hasCode } from './helpers.mjs';

function validate(command, args = [], options = {}) {
  return validateInvocation(command, args, { allowExecutables: ['git', 'tool', 'node', process.execPath, toolPath('tool')], ...options });
}

test('validateInvocation accepts a basename present in the explicit allowlist', () => {
  const report = validate('git', ['--version']);
  assert.equal(report.ok, true);
  assert.deepEqual(report.findings, []);
  assert.equal(report.command, 'git');
  assert.deepEqual(report.args, ['--version']);
});

test('validateInvocation accepts an absolute executable present in the explicit allowlist', () => {
  const report = validate(toolPath('tool'), ['--version'], { allowExecutables: [toolPath('tool')] });
  assert.equal(report.ok, true);
});

test('validateInvocation accepts an absolute executable matched by basename entry', () => {
  const report = validate(toolPath('git'), ['--version']);
  assert.equal(report.ok, true);
});

test('validateInvocation rejects a basename missing from the allowlist', () => {
  const report = validate('curl', ['--version']);
  assert.equal(report.ok, false);
  assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_NOT_ALLOWLISTED));
});

test('validateInvocation rejects an absolute path missing from the allowlist', () => {
  const report = validate(toolPath('missing'), []);
  assert.equal(report.ok, false);
  assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_NOT_ALLOWLISTED));
});

test('validateInvocation requires an executable allowlist', () => {
  const report = validateInvocation('git', ['--version']);
  assert.equal(report.ok, false);
  assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_ALLOWLIST_REQUIRED));
});

for (const [label, value] of [
  ['undefined', undefined],
  ['null', null],
  ['number', 1],
  ['object', {}],
  ['array', []],
  ['boolean', false]
]) {
  test('validateInvocation rejects a non-string executable: ' + label, () => {
    const report = validate(value, []);
    assert.equal(report.ok, false);
    assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_TYPE));
  });
}

for (const [label, command] of [
  ['empty string', ''],
  ['root slash only', '/'],
  ['root backslash only', '\\']
]) {
  test('validateInvocation rejects an empty executable: ' + label, () => {
    const report = validate(command, []);
    assert.equal(report.ok, false);
    assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_EMPTY));
  });
}

test('validateInvocation rejects NUL in executable', () => {
  const report = validate('git\0x', []);
  assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_NUL_BYTE));
});

for (const [label, character] of [
  ['tab in basename', 'git\t'],
  ['newline in basename', 'git\n'],
  ['carriage return in basename', 'git\r'],
  ['bell in basename', 'git\x07'],
  ['C1 control in basename', 'git\x85']
]) {
  test('validateInvocation rejects control whitespace executable: ' + label, () => {
    const report = validate(commandValue(character), []);
    assert.equal(report.ok, false);
    assert.ok(
      codesFromReport(report).includes(CODES.EXECUTABLE_CONTROL_CHAR) ||
      codesFromReport(report).includes(CODES.EXECUTABLE_WHITESPACE)
    );
  });
}

function commandValue(value) {
  return value;
}

for (const character of [' ', '\t', '\n', '\r']) {
  test('validateInvocation rejects whitespace in executable basename for code point ' + character.charCodeAt(0), () => {
    const report = validate('bad' + character + 'name', []);
    assert.equal(report.ok, false);
    assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_WHITESPACE));
  });
}

test('validateInvocation allows whitespace in directories outside the executable basename', () => {
  const command = process.platform === 'win32' ? 'C:\\Program Files\\tools\\git' : '/opt/my tools/git';
  const report = validateInvocation(command, ['--version'], { allowExecutables: [command] });
  assert.equal(report.ok, true);
});

for (const [label, name] of [
  ['latin accented', 'gít'],
  ['cyrillic lookalike', 'gт'],
  ['greek lookalike', 'gτ'],
  ['CJK executable', '工具'],
  ['emoji executable', 'git🙂']
]) {
  test('validateInvocation rejects non-ASCII executable basename: ' + label, () => {
    const report = validate(name, []);
    assert.equal(report.ok, false);
    assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_NON_ASCII));
  });
}

test('validateInvocation rejects executable paths above the byte limit', () => {
  const report = validate('a'.repeat(1025), []);
  assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_TOO_LONG));
});

test('validateInvocation accepts an executable basename at the byte limit', () => {
  const name = 'a'.repeat(1024);
  const report = validateInvocation(name, [], { allowExecutables: [name] });
  assert.equal(report.ok, true);
});

for (const command of ['../git', 'foo/../git', '..\\git', 'foo\\..\\git', '/opt/../git']) {
  test('validateInvocation rejects executable traversal ' + JSON.stringify(command), () => {
    const report = validate(command, []);
    assert.equal(report.ok, false);
    assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_TRAVERSAL));
  });
}

for (const command of ['./git', 'bin/git', 'bin\\git', 'foo/./git']) {
  test('validateInvocation rejects relative executable path ' + JSON.stringify(command), () => {
    const report = validate(command, []);
    assert.equal(report.ok, false);
    assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_RELATIVE_PATH));
  });
}

test('validateInvocation rejects a pasted command line as one executable string', () => {
  const report = validate('git clone example', []);
  assert.equal(report.ok, false);
  assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_WHITESPACE));
});

const shellNames = [
  'sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'fish',
  'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe',
  'wscript', 'cscript', 'mshta', 'SH', 'BASH', 'CMD.EXE'
];

for (const name of shellNames) {
  test('shell interpreter is blocked by default: ' + name, () => {
    const report = validateInvocation(name, [], { allowExecutables: [name] });
    assert.equal(report.ok, false);
    assert.ok(codesFromReport(report).includes(CODES.SHELL_BINARY));
  });
}

for (const name of ['sh', 'bash', 'cmd.exe', 'powershell', 'pwsh']) {
  test('shell interpreter can be explicitly opted in: ' + name, () => {
    const report = validateInvocation(name, [], { allowExecutables: [name], allowShellBinary: true });
    assert.equal(report.ok, true);
  });
}

const batchNames = [
  'job.bat', 'job.cmd', 'job.btm', 'job.vbs', 'job.vbe', 'job.js', 'job.jse',
  'job.wsf', 'job.wsh', 'job.ps1', 'job.com', 'JOB.BAT', 'JOB.PS1'
];

for (const name of batchNames) {
  test('Windows batch or script extension is blocked by default: ' + name, () => {
    const report = validateInvocation(name, [], { allowExecutables: [name] });
    assert.equal(report.ok, false);
    assert.ok(codesFromReport(report).includes(CODES.BATCH_EXTENSION));
  });
}

for (const name of batchNames.slice(0, 6)) {
  test('Windows batch extension can be explicitly opted in: ' + name, () => {
    const report = validateInvocation(name, [], { allowExecutables: [name], allowBatchExtensions: true });
    assert.equal(report.ok, true);
  });
}

test('shell binary and batch extension defenses are independent', () => {
  const report = validateInvocation('cmd.exe', [], {
    allowExecutables: ['cmd.exe'],
    allowShellBinary: true,
    allowBatchExtensions: false
  });
  assert.equal(report.ok, true, 'cmd.exe itself has no batch extension even though it is a shell binary');
});

test('batch extension remains blocked when shell binaries are opted in', () => {
  const report = validateInvocation('job.bat', [], {
    allowExecutables: ['job.bat'],
    allowShellBinary: true
  });
  assert.ok(codesFromReport(report).includes(CODES.BATCH_EXTENSION));
});

test('shell binary remains blocked when batch extensions are opted in', () => {
  const report = validateInvocation('bash', [], {
    allowExecutables: ['bash'],
    allowBatchExtensions: true
  });
  assert.ok(codesFromReport(report).includes(CODES.SHELL_BINARY));
});

test('shell true is rejected even when other options are valid', () => {
  const report = validate('git', ['--version'], { shell: true });
  assert.equal(report.ok, false);
  assert.ok(codesFromReport(report).includes(CODES.SHELL_OPTION_FORBIDDEN));
});

test('windowsVerbatimArguments true is rejected', () => {
  const report = validate('git', ['--version'], { windowsVerbatimArguments: true });
  assert.equal(report.ok, false);
  assert.ok(codesFromReport(report).includes(CODES.SHELL_OPTION_FORBIDDEN));
});

test('shell false is accepted as an explicit no-op', () => {
  const report = validate('git', ['--version'], { shell: false });
  assert.equal(report.ok, true);
});

test('windowsVerbatimArguments false is accepted as an explicit no-op', () => {
  const report = validate('git', ['--version'], { windowsVerbatimArguments: false });
  assert.equal(report.ok, true);
});

test('string argv is rejected as a hidden command line', () => {
  const report = validate('git', 'clone example');
  assert.equal(report.ok, false);
  assert.ok(codesFromReport(report).includes(CODES.ARGS_NOT_ARRAY));
});

for (const value of ['x', 1, null, {}]) {
  test('allowlist shape is validated: ' + String(value), () => {
    const report = validateInvocation('git', [], { allowExecutables: value });
    assert.equal(report.ok, false);
    const codes = codesFromReport(report);
    assert.ok(codes.includes(CODES.EXECUTABLE_ALLOWLIST_REQUIRED) || codes.includes(CODES.EXECUTABLE_ALLOWLIST_INVALID));
  });
}

test('a valid but nonmatching allowlist produces not-allowlisted rather than invalid', () => {
  const report = validateInvocation('git', [], { allowExecutables: ['ok'] });
  assert.equal(report.ok, false);
  const codes = codesFromReport(report);
  assert.ok(codes.includes(CODES.EXECUTABLE_NOT_ALLOWLISTED));
  assert.equal(codes.includes(CODES.EXECUTABLE_ALLOWLIST_INVALID), false);
});

for (const [label, entry] of [
  ['empty', ''],
  ['relative path', 'bin/git'],
  ['traversal', '../git'],
  ['whitespace basename', 'bad name'],
  ['nonascii basename', 'gít'],
  ['NUL', 'git\0']
]) {
  test('invalid allowlist entry is rejected: ' + label, () => {
    const report = validateInvocation('git', [], { allowExecutables: [entry] });
    assert.equal(report.ok, false);
    assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_ALLOWLIST_INVALID));
  });
}

test('relative allowlist path does not accidentally authorize the same relative command', () => {
  const report = validateInvocation('bin/git', [], { allowExecutables: ['bin/git'] });
  assert.equal(report.ok, false);
  assert.ok(codesFromReport(report).includes(CODES.EXECUTABLE_ALLOWLIST_INVALID));
});

test('unknown invocation option becomes a finding', () => {
  const report = validate('git', [], { unknownOption: true });
  assert.equal(report.ok, false);
  assert.ok(codesFromReport(report).includes(CODES.CONFIG_OPTION_UNKNOWN));
});

test('non-plain invocation options become a finding', () => {
  const report = validateInvocation('git', [], null);
  assert.equal(report.ok, false);
  assert.ok(codesFromReport(report).includes(CODES.CONFIG_INVALID));
});

test('report is frozen deeply', () => {
  const report = validate('git', ['--version']);
  assert.equal(Object.isFrozen(report), true);
  assert.equal(Object.isFrozen(report.args), true);
  assert.equal(Object.isFrozen(report.findings), true);
});

test('validation aggregates executable and argv findings', () => {
  const report = validate('bash', ['x\0']);
  const codes = codesFromReport(report);
  assert.ok(codes.includes(CODES.SHELL_BINARY));
  assert.ok(codes.includes(CODES.ARG_NUL_BYTE));
  assert.ok(codes.length >= 2);
});

test('auditArgv does not require an allowlist', () => {
  const findings = auditArgv('git', ['--version']);
  assert.deepEqual(findings, []);
});

test('auditArgv still validates executable syntax without an allowlist', () => {
  const findings = auditArgv('bad name', []);
  assert.ok(hasCode(findings, CODES.EXECUTABLE_WHITESPACE));
});

test('auditArgv reports allowlist mismatch when an allowlist is supplied', () => {
  const findings = auditArgv('git', [], { allowExecutables: ['other'] });
  assert.ok(hasCode(findings, CODES.EXECUTABLE_NOT_ALLOWLISTED));
});

test('auditArgv findings are frozen', () => {
  const findings = auditArgv('bash', []);
  assert.equal(Object.isFrozen(findings), true);
  assert.equal(Object.isFrozen(findings[0]), true);
});

for (const count of [1, 2, 511, 512]) {
  test('argument count within default limit is accepted: ' + count, () => {
    const report = validateInvocation('git', Array.from({ length: count }, () => 'x'), { allowExecutables: ['git'], allowDangerousFlags: true });
    assert.equal(report.ok, true);
  });
}

test('argument count above default limit is rejected', () => {
  const report = validateInvocation('git', Array.from({ length: 513 }, () => 'x'), { allowExecutables: ['git'], allowDangerousFlags: true });
  assert.ok(codesFromReport(report).includes(CODES.ARGV_TOO_MANY));
});

test('custom argument count limit is enforced', () => {
  const report = validateInvocation('git', ['a', 'b'], { allowExecutables: ['git'], maxArgs: 1 });
  assert.ok(codesFromReport(report).includes(CODES.ARGV_TOO_MANY));
});

test('combined argv byte limit is enforced', () => {
  const report = validateInvocation('git', ['aaaa', 'bbbb'], { allowExecutables: ['git'], maxArgvBytes: 4 });
  assert.ok(codesFromReport(report).includes(CODES.ARGV_TOO_LONG));
});

test('combined argv byte limit accepts exact boundary', () => {
  const report = validateInvocation('git', ['aaaa', 'bbbb'], { allowExecutables: ['git'], maxArgvBytes: 8 });
  assert.equal(report.ok, true);
});

test('auditArgv does not invent an allowlist failure for a shell binary', () => {
  const codes = codesFromFindings(auditArgv('sh', []));
  assert.ok(codes.includes(CODES.SHELL_BINARY));
  assert.equal(codes.includes(CODES.EXECUTABLE_NOT_ALLOWLISTED), false);
});
