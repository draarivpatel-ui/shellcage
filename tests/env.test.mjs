import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeEnv, auditEnv, CODES, ShellCageError, DEFAULT_ALLOWED_ENV } from '../src/index.mjs';
import { hasCode } from './helpers.mjs';

function assertCode(fn, code) {
  assert.throws(fn, (error) => error instanceof ShellCageError && error.code === code);
}

function objectWithKey(key, value = 'x') {
  const object = Object.create(null);
  object[key] = value;
  return object;
}

test('DEFAULT_ALLOWED_ENV is the documented minimal list', () => {
  assert.deepEqual(DEFAULT_ALLOWED_ENV, ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR']);
  assert.equal(Object.isFrozen(DEFAULT_ALLOWED_ENV), true);
});

test('sanitizeEnv keeps only default allowlisted variables', () => {
  const env = sanitizeEnv({
    PATH: '/bin',
    HOME: '/home/example',
    LANG: 'C',
    LC_ALL: 'C',
    TMPDIR: '/tmp',
    USER: 'not-copied',
    CUSTOM: 'not-copied'
  });
  assert.deepEqual({ ...env }, {
    PATH: '/bin',
    HOME: '/home/example',
    LANG: 'C',
    LC_ALL: 'C',
    TMPDIR: '/tmp'
  });
});

test('sanitizeEnv returns a frozen null-prototype object', () => {
  const env = sanitizeEnv({ PATH: '/bin' });
  assert.equal(Object.getPrototypeOf(env), null);
  assert.equal(Object.isFrozen(env), true);
});

test('sanitizeEnv supports a custom explicit allowlist', () => {
  const env = sanitizeEnv({ FOO: 'yes', PATH: '/bin' }, { allowEnv: ['FOO'] });
  assert.deepEqual({ ...env }, { FOO: 'yes' });
});

test('sanitizeEnv treats custom allowlist as a replacement rather than additive list', () => {
  const env = sanitizeEnv({ FOO: 'yes', PATH: '/bin' }, { allowEnv: ['FOO'] });
  assert.equal(env.PATH, undefined);
});

test('sanitizeEnv supports an empty allowlist', () => {
  const env = sanitizeEnv({ PATH: '/bin', FOO: 'yes' }, { allowEnv: [] });
  assert.deepEqual({ ...env }, {});
});

test('sanitizeEnv matches keys case-insensitively for policy', () => {
  const env = sanitizeEnv({ path: '/bin' }, { allowEnv: ['PATH'] });
  assert.equal(env.PATH, '/bin');
});

test('sanitizeEnv emits the allowlist spelling as the canonical key', () => {
  const env = sanitizeEnv({ Path: '/bin' }, { allowEnv: ['PATH'] });
  assert.equal(Object.prototype.hasOwnProperty.call(env, 'PATH'), true);
  assert.equal(Object.prototype.hasOwnProperty.call(env, 'Path'), false);
});

test('sanitizeEnv uses the first value when case variants collide', () => {
  const env = sanitizeEnv({ Path: '/first', PATH: '/second' }, { allowEnv: ['PATH'] });
  assert.equal(env.PATH, '/first');
});

test('sanitizeEnv rejects constructor or prototype keys in explicit allowlist configuration', () => {
  assertCode(() => sanitizeEnv({}, { allowEnv: ['__proto__'] }), CODES.CONFIG_INVALID);
  assertCode(() => sanitizeEnv({}, { allowEnv: ['constructor'] }), CODES.CONFIG_INVALID);
  assertCode(() => sanitizeEnv({}, { allowEnv: ['prototype'] }), CODES.CONFIG_INVALID);
});

const dangerousNames = [
  'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'LD_DEBUG',
  'DYLD_INSERT_LIBRARIES', 'DYLD_PRINT_LIBRARIES',
  'NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'NODE_PATH',
  'PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONHOME', 'PYTHONINSPECT', 'PYTHONEXECUTABLE',
  'RUBYOPT', 'RUBYLIB', 'PERL5OPT', 'PERL5LIB',
  'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
  'BASH_ENV', 'ENV', 'CDPATH', 'IFS', 'SHELLOPTS', 'PS4', 'PROMPT_COMMAND', 'ZDOTDIR',
  'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_EXEC_PATH', 'GIT_CONFIG_PARAMETERS',
  'GIT_CONFIG_COUNT', 'GIT_EXT_TRANSPORT', 'GIT_EXTERNAL_DIFF', 'GIT_PAGER',
  'EDITOR', 'VISUAL', 'PAGER', 'COMSPEC', 'PATHEXT',
  'INPUTRC', 'TERMINFO', 'TERMINFO_DIRS', 'LESSOPEN', 'LESSCLOSE', 'SYSTEMD_PAGER'
];

for (const name of dangerousNames) {
  test('hard denylist blocks ' + name + ' even when explicitly allowlisted', () => {
    const env = sanitizeEnv({ [name]: 'payload' }, { allowEnv: [name] });
    assert.equal(Object.prototype.hasOwnProperty.call(env, name), false);
  });
  test('auditEnv reports ' + name + ' as environment injection', () => {
    const findings = auditEnv({ [name]: 'payload' });
    const finding = findings.find((item) => item.code === CODES.ENV_INJECTION && item.key === name);
    assert.ok(finding);
    assert.equal(finding.severity, 'critical');
  });
}

for (const name of ['ld_preload', 'Node_Options', 'git_ssh_command', 'editor', 'comspec']) {
  test('denylist matching is case-insensitive for ' + name, () => {
    const env = sanitizeEnv({ [name]: 'payload' }, { allowEnv: [name.toUpperCase()] });
    assert.deepEqual({ ...env }, {});
    assert.ok(hasCode(auditEnv({ [name]: 'payload' }), CODES.ENV_INJECTION));
  });
}

for (const name of ['LD_ANYTHING', 'ld_custom', 'DYLD_CUSTOM', 'dyld_other', 'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1', 'git_config_key_999', 'BASH_FUNC_x%%']) {
  test('denylist prefix matching blocks ' + name, () => {
    const env = sanitizeEnv({ [name]: 'payload' }, { allowEnv: [name] });
    assert.deepEqual({ ...env }, {});
    assert.ok(hasCode(auditEnv({ [name]: 'payload' }), CODES.ENV_INJECTION));
  });
}

for (const name of ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'CUSTOM_VALUE', 'ProgramFiles(x86)']) {
  test('safe-looking key shape is accepted for ' + name, () => {
    const env = sanitizeEnv({ [name]: 'value' }, { allowEnv: [name] });
    assert.equal(env[name], 'value');
  });
}

for (const [label, key] of [
  ['empty key', ''],
  ['space key', 'BAD KEY'],
  ['tab key', 'BAD\tKEY'],
  ['newline key', 'BAD\nKEY'],
  ['equals key', 'BAD=KEY'],
  ['NUL key', 'BAD\0KEY'],
  ['unicode key', 'BÄD'],
  ['control key', 'BAD\x07KEY']
]) {
  test('auditEnv reports invalid key shape: ' + label, () => {
    const findings = auditEnv(objectWithKey(key));
    assert.ok(hasCode(findings, CODES.ENV_KEY_INVALID));
  });
  test('sanitizeEnv rejects invalid key shape in allowlist: ' + label, () => {
    assertCode(() => sanitizeEnv(objectWithKey(key), { allowEnv: [key] }), CODES.CONFIG_INVALID);
  });
}

for (const key of ['__proto__', 'constructor', 'prototype', 'CONSTRUCTOR', 'Prototype']) {
  test('auditEnv reports prototype pollution key ' + key, () => {
    const findings = auditEnv(objectWithKey(key));
    assert.ok(hasCode(findings, CODES.ENV_KEY_PROTOTYPE));
  });
}

test('auditEnv masks invalid key text rather than echoing control characters', () => {
  const key = 'BAD\nKEY';
  const findings = auditEnv(objectWithKey(key));
  const finding = findings.find((item) => item.code === CODES.ENV_KEY_INVALID);
  assert.equal(finding.key, '[invalid key]');
  assert.equal(JSON.stringify(findings).includes(key), false);
});

for (const [label, value] of [
  ['number', 1],
  ['boolean', true],
  ['null', null],
  ['object', {}],
  ['array', []],
  ['undefined', undefined]
]) {
  test('auditEnv reports non-string value: ' + label, () => {
    const findings = auditEnv({ PATH: value });
    assert.ok(hasCode(findings, CODES.ENV_VALUE_TYPE));
  });
  test('sanitizeEnv omits non-string value: ' + label, () => {
    const env = sanitizeEnv({ PATH: value });
    assert.deepEqual({ ...env }, {});
  });
}

test('auditEnv reports NUL byte value', () => {
  const findings = auditEnv({ PATH: 'a\0b' });
  assert.ok(hasCode(findings, CODES.ENV_VALUE_NUL_BYTE));
});

test('sanitizeEnv omits NUL byte value', () => {
  assert.deepEqual({ ...sanitizeEnv({ PATH: 'a\0b' }) }, {});
});

test('environment value at default byte limit is accepted', () => {
  const value = 'x'.repeat(32768);
  const env = sanitizeEnv({ PATH: value });
  assert.equal(env.PATH.length, 32768);
});

test('environment value above default byte limit is omitted', () => {
  const value = 'x'.repeat(32769);
  assert.deepEqual({ ...sanitizeEnv({ PATH: value }) }, {});
  assert.ok(hasCode(auditEnv({ PATH: value }), CODES.ENV_VALUE_TOO_LONG));
});

test('custom environment byte limit accepts exact boundary', () => {
  const env = sanitizeEnv({ PATH: '12345' }, { maxValueBytes: 5 });
  assert.equal(env.PATH, '12345');
});

test('custom environment byte limit rejects one byte over boundary', () => {
  const env = sanitizeEnv({ PATH: '123456' }, { maxValueBytes: 5 });
  assert.deepEqual({ ...env }, {});
  assert.ok(hasCode(auditEnv({ PATH: '123456' }, { maxValueBytes: 5 }), CODES.ENV_VALUE_TOO_LONG));
});

test('environment byte limit measures multibyte characters as bytes', () => {
  const env = sanitizeEnv({ PATH: 'ééé' }, { maxValueBytes: 5 });
  assert.deepEqual({ ...env }, {});
});

test('auditEnv reports case-variant duplicate keys', () => {
  const findings = auditEnv({ PATH: '/one', Path: '/two' });
  assert.ok(hasCode(findings, CODES.ENV_DUPLICATE_KEY));
});

test('auditEnv includeUnlisted reports informational unallowlisted key', () => {
  const findings = auditEnv({ CUSTOM: 'x' }, { includeUnlisted: true });
  const finding = findings.find((item) => item.code === CODES.ENV_NOT_ALLOWLISTED);
  assert.equal(finding.severity, 'info');
  assert.equal(finding.key, 'CUSTOM');
});

test('auditEnv does not report unallowlisted keys by default', () => {
  const findings = auditEnv({ CUSTOM: 'x' });
  assert.equal(hasCode(findings, CODES.ENV_NOT_ALLOWLISTED), false);
});

test('auditEnv does not report allowlisted keys as unlisted when includeUnlisted is true', () => {
  const findings = auditEnv({ PATH: '/bin' }, { includeUnlisted: true });
  assert.deepEqual(findings, []);
});

test('auditEnv never serializes secret values', () => {
  const secret = 'super-secret-value-for-test';
  const findings = auditEnv({ NODE_OPTIONS: secret, PATH: secret });
  const serialized = JSON.stringify(findings);
  assert.equal(serialized.includes(secret), false);
});

test('auditEnv findings are frozen and structured', () => {
  const findings = auditEnv({ NODE_OPTIONS: '--require x' });
  assert.equal(Object.isFrozen(findings), true);
  assert.equal(Object.isFrozen(findings[0]), true);
  assert.equal(findings[0].code, CODES.ENV_INJECTION);
  assert.equal(findings[0].key, 'NODE_OPTIONS');
  assert.equal(typeof findings[0].message, 'string');
});

test('dangerous key with invalid value produces independent findings', () => {
  const findings = auditEnv({ NODE_OPTIONS: 42 });
  assert.ok(hasCode(findings, CODES.ENV_INJECTION));
  assert.ok(hasCode(findings, CODES.ENV_VALUE_TYPE));
});

test('sanitizeEnv allows newlines in values because only NUL is structurally forbidden', () => {
  const env = sanitizeEnv({ PATH: 'line1\nline2' });
  assert.equal(env.PATH, 'line1\nline2');
});

test('sanitizeEnv accepts empty string values', () => {
  const env = sanitizeEnv({ PATH: '' });
  assert.equal(env.PATH, '');
});

for (const source of [null, undefined, 1, 'x', true, []]) {
  test('sanitizeEnv rejects invalid source type ' + String(source), () => {
    if (source === undefined) {
      // Undefined means process.env in the real API, so it is valid and covered elsewhere.
      return;
    }
    assertCode(() => sanitizeEnv(source), CODES.ENV_NOT_OBJECT);
  });
}

for (const source of [null, 1, 'x', true, []]) {
  test('auditEnv rejects invalid source type ' + String(source), () => {
    assertCode(() => auditEnv(source), CODES.ENV_NOT_OBJECT);
  });
}

for (const [label, options] of [
  ['non-object options', null],
  ['unknown option', { surprise: true }],
  ['non-array allowEnv', { allowEnv: 'PATH' }],
  ['oversized allowEnv', { allowEnv: Array.from({ length: 513 }, (_, index) => 'A' + index) }],
  ['invalid allowEnv key', { allowEnv: ['BAD KEY'] }],
  ['prototype allowEnv key', { allowEnv: ['constructor'] }],
  ['invalid maxValueBytes', { maxValueBytes: 0 }]
]) {
  test('environment options reject invalid configuration: ' + label, () => {
    assert.throws(() => sanitizeEnv({ PATH: '/bin' }, options), ShellCageError);
  });
}

test('sanitizeEnv default source is process.env and returns only safe defaults', () => {
  const env = sanitizeEnv();
  for (const key of Object.keys(env)) {
    assert.ok(DEFAULT_ALLOWED_ENV.includes(key));
  }
});

test('auditEnv default source is process.env and does not throw', () => {
  const findings = auditEnv();
  assert.equal(Array.isArray(findings), true);
});

test('allowEnv matching is case-insensitive for custom names', () => {
  const env = sanitizeEnv({ custom: 'x' }, { allowEnv: ['CUSTOM'] });
  assert.equal(env.CUSTOM, 'x');
});

test('first allowlist spelling wins when allowEnv itself has case variants', () => {
  const env = sanitizeEnv({ custom: 'x' }, { allowEnv: ['Custom', 'CUSTOM'] });
  assert.equal(env.Custom, 'x');
  assert.equal(env.CUSTOM, undefined);
});

test('auditEnv key is present for dangerous variable but value is absent', () => {
  const findings = auditEnv({ LD_PRELOAD: 'secret-object' });
  assert.equal(findings[0].key, 'LD_PRELOAD');
  assert.equal(Object.prototype.hasOwnProperty.call(findings[0], 'value'), false);
});
