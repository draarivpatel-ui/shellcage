import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertSafeArg,
  safeArg,
  safePathArg,
  buildArgv,
  auditArgv,
  CODES,
  ShellCageError
} from '../src/index.mjs';
import { hasCode } from './helpers.mjs';

function assertCode(fn, code) {
  assert.throws(fn, (error) => error instanceof ShellCageError && error.code === code);
}

for (const value of [
  'plain',
  'with spaces',
  'unicode café',
  'symbols !$()[]{}',
  '-flag',
  '--',
  '',
  'a'.repeat(4096)
]) {
  test('assertSafeArg accepts ordinary argument input ' + JSON.stringify(value.slice(0, 24)), () => {
    assert.equal(assertSafeArg(value), value);
  });
}

for (const [label, value] of [
  ['undefined', undefined],
  ['null', null],
  ['number', 1],
  ['boolean', true],
  ['object', {}],
  ['array', []],
  ['buffer', Buffer.from('x')]
]) {
  test('assertSafeArg rejects non-string input: ' + label, () => {
    assertCode(() => assertSafeArg(value), CODES.ARG_TYPE);
  });
}

test('assertSafeArg rejects NUL byte', () => {
  assertCode(() => assertSafeArg('a\0b'), CODES.ARG_NUL_BYTE);
});

for (const value of ['a\nb', 'a\rb', 'a\r\nb']) {
  test('assertSafeArg rejects line break ' + JSON.stringify(value), () => {
    assertCode(() => assertSafeArg(value), CODES.ARG_NEWLINE);
  });
}

for (const value of ['a\nb', 'a\rb', 'a\r\nb']) {
  test('assertSafeArg accepts line break with explicit allowNewlines ' + JSON.stringify(value), () => {
    assert.equal(assertSafeArg(value, { allowNewlines: true }), value);
  });
}

for (const codePoint of [0, 1, 7, 8, 9, 11, 12, 14, 27, 31, 127, 133, 159]) {
  const value = 'x' + String.fromCharCode(codePoint) + 'y';
  test('assertSafeArg rejects control code point ' + codePoint, () => {
    const expected = codePoint === 0 ? CODES.ARG_NUL_BYTE : CODES.ARG_CONTROL_CHAR;
    assertCode(() => assertSafeArg(value, { allowNewlines: true }), expected);
  });
}

for (const codePoint of [0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]) {
  const value = 'x' + String.fromCharCode(codePoint) + 'y';
  test('assertSafeArg rejects bidi control U+' + codePoint.toString(16).toUpperCase(), () => {
    assertCode(() => assertSafeArg(value), CODES.ARG_BIDI_CONTROL);
  });
}

test('assertSafeArg accepts exact default byte boundary', () => {
  assert.equal(assertSafeArg('x'.repeat(4096)).length, 4096);
});

test('assertSafeArg rejects one byte above default boundary', () => {
  assertCode(() => assertSafeArg('x'.repeat(4097)), CODES.ARG_TOO_LONG);
});

test('assertSafeArg measures multibyte characters as bytes', () => {
  assertCode(() => assertSafeArg('é'.repeat(2049)), CODES.ARG_TOO_LONG);
});

test('assertSafeArg accepts custom byte boundary', () => {
  assert.equal(assertSafeArg('abcde', { maxBytes: 5 }), 'abcde');
});

test('assertSafeArg rejects above custom byte boundary', () => {
  assertCode(() => assertSafeArg('abcdef', { maxBytes: 5 }), CODES.ARG_TOO_LONG);
});

test('assertSafeArg rejects excessive configured byte limit', () => {
  assertCode(() => assertSafeArg('x', { maxBytes: 65537 }), CODES.CONFIG_INVALID);
});

test('assertSafeArg rejects unknown option', () => {
  assertCode(() => assertSafeArg('x', { surprise: true }), CODES.CONFIG_OPTION_UNKNOWN);
});

for (const value of ['-', '-x', '--x', '--upload-pack=x']) {
  test('assertSafeArg allows leading dash for non-positional input ' + value, () => {
    assert.equal(assertSafeArg(value), value);
  });
  test('assertSafeArg rejects leading dash with rejectLeadingDash ' + value, () => {
    assertCode(() => assertSafeArg(value, { rejectLeadingDash: true }), CODES.ARG_LEADING_DASH);
  });
  test('assertSafeArg rejects leading dash with positional ' + value, () => {
    assertCode(() => assertSafeArg(value, { positional: true }), CODES.ARG_LEADING_DASH);
  });
}

test('safeArg is positional by default', () => {
  assertCode(() => safeArg('--danger'), CODES.ARG_LEADING_DASH);
  assert.equal(safeArg('safe value'), 'safe value');
});

test('safeArg permits empty positional by default', () => {
  assert.equal(safeArg(''), '');
});

test('safeArg honors allowEmpty false', () => {
  assertCode(() => safeArg('', { allowEmpty: false }), CODES.ARG_EMPTY);
});

test('safePathArg rejects empty path', () => {
  assertCode(() => safePathArg(''), CODES.ARG_EMPTY);
});

test('safePathArg rejects leading dash', () => {
  assertCode(() => safePathArg('--looks-like-option'), CODES.ARG_LEADING_DASH);
});

test('safePathArg accepts ordinary relative and absolute path text', () => {
  assert.equal(safePathArg('folder/file.txt'), 'folder/file.txt');
  assert.equal(safePathArg('/tmp/file.txt'), '/tmp/file.txt');
});

test('safePathArg remains lexical and does not reject parent traversal', () => {
  assert.equal(safePathArg('../outside.txt'), '../outside.txt');
});

test('buildArgv builds literal positional and path slots', () => {
  const argv = buildArgv([
    { type: 'literal', value: 'clone' },
    { type: 'positional', value: 'repo' },
    { type: 'path', value: 'dest' }
  ]);
  assert.deepEqual(argv, ['clone', 'repo', 'dest']);
  assert.equal(Object.isFrozen(argv), true);
});

test('buildArgv builds boolean flag slots', () => {
  assert.deepEqual(buildArgv([{ type: 'flag', name: '--verbose' }]), ['--verbose']);
});

test('buildArgv builds separate flag value slots', () => {
  assert.deepEqual(buildArgv([{ type: 'flag', name: '--depth', value: '1' }]), ['--depth', '1']);
});

test('buildArgv builds equals flag value slots', () => {
  assert.deepEqual(buildArgv([{ type: 'flag', name: '--filter', value: 'blob:none', join: 'equals' }]), ['--filter=blob:none']);
});

test('buildArgv supports flag as an alias for name', () => {
  assert.deepEqual(buildArgv([{ type: 'flag', flag: '-q' }]), ['-q']);
});

test('buildArgv allows a leading dash in an equals-joined value', () => {
  assert.deepEqual(buildArgv([{ type: 'flag', name: '--number', value: '-1', join: 'equals' }]), ['--number=-1']);
});

test('buildArgv rejects a leading dash in a separate flag value by default', () => {
  assertCode(() => buildArgv([{ type: 'flag', name: '--number', value: '-1' }]), CODES.ARG_LEADING_DASH);
});

test('buildArgv allows a leading dash separate flag value only with explicit opt-in', () => {
  assert.deepEqual(
    buildArgv([{ type: 'flag', name: '--number', value: '-1', allowLeadingDashValue: true }]),
    ['--number', '-1']
  );
});

test('buildArgv places safe positionals before end-of-options when they do not start with dash', () => {
  assert.deepEqual(buildArgv([
    { type: 'positional', value: 'safe' },
    { type: 'endOfOptions' }
  ]), ['safe', '--']);
});

test('buildArgv rejects leading-dash positional before end-of-options', () => {
  assertCode(() => buildArgv([{ type: 'positional', value: '--upload-pack=x' }]), CODES.ARG_LEADING_DASH);
});

test('buildArgv accepts leading-dash positional after end-of-options', () => {
  assert.deepEqual(buildArgv([
    { type: 'endOfOptions' },
    { type: 'positional', value: '--upload-pack=x' }
  ]), ['--', '--upload-pack=x']);
});

test('buildArgv accepts leading-dash path after end-of-options', () => {
  assert.deepEqual(buildArgv([
    { type: 'endOfOptions' },
    { type: 'path', value: '--file' }
  ]), ['--', '--file']);
});

test('buildArgv emits only one end-of-options marker', () => {
  assertCode(() => buildArgv([{ type: 'endOfOptions' }, { type: 'endOfOptions' }]), CODES.ARGV_SPEC_INVALID);
});

for (const [label, spec] of [
  ['non-array', 'x'],
  ['null slot', [null]],
  ['array slot', [[]]],
  ['missing type', [{ value: 'x' }]],
  ['unknown type', [{ type: 'mystery', value: 'x' }]],
  ['literal missing value', [{ type: 'literal' }]],
  ['literal unknown key', [{ type: 'literal', value: 'x', extra: true }]],
  ['flag missing name', [{ type: 'flag', value: 'x' }]],
  ['flag bad name space', [{ type: 'flag', name: '--bad name' }]],
  ['flag bad name equals', [{ type: 'flag', name: '--bad=x' }]],
  ['flag bad join', [{ type: 'flag', name: '--x', value: 'y', join: 'bad' }]],
  ['positional unknown key', [{ type: 'positional', value: 'x', extra: true }]],
  ['endOfOptions unknown key', [{ type: 'endOfOptions', value: '--' }]]
]) {
  test('buildArgv rejects invalid spec: ' + label, () => {
    assertCode(() => buildArgv(spec), CODES.ARGV_SPEC_INVALID);
  });
}

test('buildArgv rejects oversized slot list', () => {
  assertCode(() => buildArgv(Array.from({ length: 513 }, () => ({ type: 'literal', value: 'x' }))), CODES.ARGV_SPEC_INVALID);
});

test('buildArgv rejects control characters in literal slots', () => {
  assertCode(() => buildArgv([{ type: 'literal', value: 'x\ny' }]), CODES.ARG_NEWLINE);
});

test('buildArgv rejects control characters in flag values', () => {
  assertCode(() => buildArgv([{ type: 'flag', name: '--x', value: 'x\0y' }]), CODES.ARG_NUL_BYTE);
});

test('buildArgv rejects control characters in positional values', () => {
  assertCode(() => buildArgv([{ type: 'positional', value: 'x\x07y' }]), CODES.ARG_CONTROL_CHAR);
});

test('buildArgv rejects empty path even after end-of-options', () => {
  assertCode(() => buildArgv([{ type: 'endOfOptions' }, { type: 'path', value: '' }]), CODES.ARG_EMPTY);
});

test('buildArgv positional allowEmpty false is enforced', () => {
  assertCode(() => buildArgv([{ type: 'positional', value: '', allowEmpty: false }]), CODES.ARG_EMPTY);
});

test('buildArgv positional empty is allowed by default', () => {
  assert.deepEqual(buildArgv([{ type: 'positional', value: '' }]), ['']);
});

test('buildArgv rejects slot values above the byte cap', () => {
  assertCode(() => buildArgv([{ type: 'positional', value: 'x'.repeat(4097) }]), CODES.ARG_TOO_LONG);
});

test('buildArgv literal slots may be leading dashes because they are trusted fixed input', () => {
  assert.deepEqual(buildArgv([{ type: 'literal', value: '--' }]), ['--']);
});

test('buildArgv flag names may be short or long ASCII options', () => {
  assert.deepEqual(buildArgv([{ type: 'flag', name: '-v' }, { type: 'flag', name: '--long_1.x' }]), ['-v', '--long_1.x']);
});

test('auditArgv reports NUL byte arguments with index', () => {
  const findings = auditArgv('git', ['ok', 'bad\0arg']);
  const finding = findings.find((item) => item.code === CODES.ARG_NUL_BYTE);
  assert.equal(finding.index, 1);
});

test('auditArgv reports line break arguments with index', () => {
  const findings = auditArgv('git', ['ok', 'bad\narg']);
  const finding = findings.find((item) => item.code === CODES.ARG_NEWLINE);
  assert.equal(finding.index, 1);
});

test('auditArgv reports bidi controls', () => {
  const findings = auditArgv('git', ['x\u202E']);
  assert.ok(hasCode(findings, CODES.ARG_BIDI_CONTROL));
});

test('auditArgv reports oversized single argument', () => {
  const findings = auditArgv('git', ['x'.repeat(4097)]);
  assert.ok(hasCode(findings, CODES.ARG_TOO_LONG));
});

test('auditArgv reports non-string arguments', () => {
  const findings = auditArgv('git', [null]);
  assert.ok(hasCode(findings, CODES.ARG_TYPE));
});

test('auditArgv accepts unicode non-bidi argument text', () => {
  assert.deepEqual(auditArgv('git', ['café']), []);
});

test('auditArgv accepts spaces inside one argv element', () => {
  assert.deepEqual(auditArgv('git', ['a value with spaces']), []);
});

test('buildArgv rejects a flag slot with both name and flag keys', () => {
  assertCode(() => buildArgv([{ type: 'flag', name: '--x', flag: '--x' }]), CODES.ARGV_SPEC_INVALID);
});

test('buildArgv rejects non-boolean allowLeadingDashValue', () => {
  assertCode(() => buildArgv([{ type: 'flag', name: '--x', value: 'y', allowLeadingDashValue: 'yes' }]), CODES.ARGV_SPEC_INVALID);
});

test('buildArgv rejects non-boolean positional allowEmpty', () => {
  assertCode(() => buildArgv([{ type: 'positional', value: '', allowEmpty: 'no' }]), CODES.ARGV_SPEC_INVALID);
});

test('Object.prototype cannot supply an argv slot type', () => {
  Object.prototype.type = 'literal';
  try {
    assertCode(() => buildArgv([{ value: 'x' }]), CODES.ARGV_SPEC_INVALID);
  } finally {
    delete Object.prototype.type;
  }
});
