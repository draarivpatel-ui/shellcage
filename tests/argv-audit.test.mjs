import test from 'node:test';
import assert from 'node:assert/strict';
import { auditArgv, CODES } from '../src/index.mjs';
import { dangerousOnly, hasCode } from './helpers.mjs';

function dangerous(command, args) {
  return dangerousOnly(auditArgv(command, args));
}

function assertDanger(command, args, code = CODES.DANGEROUS_FLAG) {
  const findings = dangerous(command, args);
  assert.ok(findings.some((finding) => finding.code === code), JSON.stringify({ command, args, findings }));
  return findings;
}

function assertNoDanger(command, args) {
  assert.deepEqual(dangerous(command, args), []);
}

for (const shell of ['sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'fish']) {
  test('shell audit detects inline command flag: ' + shell, () => {
    const findings = assertDanger(shell, ['-c', 'printf hi']);
    assert.equal(findings[0].severity, 'critical');
  });
}

for (const shell of ['sh', 'bash', 'zsh']) {
  test('shell audit does not flag a script path without inline command: ' + shell, () => {
    assertNoDanger(shell, ['script.sh']);
  });
}

for (const args of [['/c', 'dir'], ['/k', 'dir']]) {
  test('cmd audit detects command flag ' + args[0], () => {
    assertDanger('cmd.exe', args);
  });
}

for (const flag of ['-c', '-command', '-enc', '-encodedcommand', '-e']) {
  test('powershell audit detects execution flag ' + flag, () => {
    assertDanger('pwsh', [flag, 'payload']);
  });
}

for (const args of [
  ['-c', 'core.sshCommand=bad'],
  ['-ccore.sshCommand=bad', 'clone'],
  ['--config-env', 'core.sshCommand=BAD'],
  ['--config-env=core.sshCommand=BAD'],
  ['--upload-pack', 'bad'],
  ['--upload-pack=bad'],
  ['--exec-path', '/tmp/tools'],
  ['--exec-path=/tmp/tools']
]) {
  test('git audit detects dangerous option ' + args[0], () => {
    assertDanger('git', args);
  });
}

for (const value of ['ext::sh -c id', 'ext::printf x', 'EXT::sh -c id']) {
  test('git audit detects ext transport gadget ' + JSON.stringify(value), () => {
    assertDanger('git', ['clone', value], CODES.DANGEROUS_GADGET);
  });
}

test('git audit accepts ordinary clone argv', () => {
  assertNoDanger('git', ['clone', 'https://example.invalid/repo.git', 'dest']);
});

test('git audit accepts ordinary safe global flags', () => {
  assertNoDanger('git', ['--version']);
});

test('git audit honors end-of-options for exact option spelling', () => {
  assertNoDanger('git', ['clone', '--', '--upload-pack=x']);
});

test('git audit still detects ext gadget after end-of-options', () => {
  assertDanger('git', ['clone', '--', 'ext::sh -c id'], CODES.DANGEROUS_GADGET);
});

for (const args of [
  ['--checkpoint-action', 'exec=sh x'],
  ['--checkpoint-action=exec=sh x'],
  ['--to-command', 'sh'],
  ['--to-command=sh'],
  ['-I', 'sh'],
  ['-Ish'],
  ['-xIf', 'archive.tar'],
  ['--use-compress-program', 'sh'],
  ['--use-compress-program=sh'],
  ['--rsh-command', 'sh'],
  ['--info-script', 'script'],
  ['-F', 'script'],
  ['-xFf', 'archive.tar']
]) {
  test('tar audit detects execution gadget ' + args[0], () => {
    assertDanger('tar', args);
  });
}

test('tar audit accepts ordinary extraction flags', () => {
  assertNoDanger('tar', ['-xf', 'archive.tar']);
});

for (const flag of ['-exec', '-execdir', '-ok', '-okdir']) {
  test('find audit detects execution primary ' + flag, () => {
    assertDanger('find', ['.', flag, 'sh', '{}', ';']);
  });
}

test('find audit accepts ordinary filters', () => {
  assertNoDanger('find', ['.', '-type', 'f', '-name', '*.txt']);
});

for (const args of [
  ['-K', 'config'],
  ['-Kconfig'],
  ['-sK', 'config'],
  ['--config', 'config'],
  ['--config=config'],
  ['-o', 'out'],
  ['-oout'],
  ['-so', 'out'],
  ['--output', 'out'],
  ['--output=out'],
  ['-T', 'secret'],
  ['-Tsecret'],
  ['-sT', 'secret'],
  ['--upload-file', 'secret'],
  ['--upload-file=secret']
]) {
  test('curl audit detects file or config risk ' + args[0], () => {
    const findings = assertDanger('curl', args);
    assert.ok(findings.some((finding) => finding.severity === 'high'));
  });
}

test('curl audit accepts simple HTTPS transfer', () => {
  assertNoDanger('curl', ['https://example.invalid/']);
});

test('curl audit honors end-of-options for exact output option', () => {
  assertNoDanger('curl', ['--', '-o']);
});

for (const tool of ['ssh', 'scp', 'sftp', 'rsync']) {
  test(tool + ' audit detects separate ProxyCommand option', () => {
    assertDanger(tool, ['-o', 'ProxyCommand=sh -c id']);
  });
  test(tool + ' audit detects attached ProxyCommand option', () => {
    assertDanger(tool, ['-oProxyCommand=sh -c id']);
  });
  test(tool + ' audit detects transport override -e', () => {
    assertDanger(tool, ['-e', 'sh']);
  });
}

test('ssh audit does not flag a benign option', () => {
  assertNoDanger('ssh', ['-o', 'BatchMode=yes', 'example.invalid']);
});

for (const args of [
  ['--rsh', 'sh'],
  ['--rsh=sh'],
  ['--rsync-path', 'sh'],
  ['--rsync-path=sh']
]) {
  test('rsync audit detects remote shell override ' + args[0], () => {
    assertDanger('rsync', args);
  });
}

for (const args of [
  ['-e', 'console.log(1)'],
  ['-econsole.log(1)'],
  ['--eval', 'console.log(1)'],
  ['--eval=console.log(1)'],
  ['-p', '1+1'],
  ['--print', '1+1'],
  ['-r', './preload.js'],
  ['-r./preload.js'],
  ['--require', './preload.js'],
  ['--require=./preload.js'],
  ['--import', './preload.mjs'],
  ['--import=./preload.mjs'],
  ['--experimental-loader', './loader.mjs']
]) {
  test('node audit detects eval or preload flag ' + args[0], () => {
    assertDanger('node', args);
  });
}

test('node audit accepts ordinary script execution', () => {
  assertNoDanger('node', ['server.js', '--port', '8080']);
});

test('node audit honors end-of-options', () => {
  assertNoDanger('node', ['--', '-e']);
});

for (const tool of ['python', 'python3', 'python3.11', 'pypy']) {
  test(tool + ' audit detects -c code execution', () => {
    assertDanger(tool, ['-c', 'print(1)']);
  });
  test(tool + ' audit detects module execution', () => {
    assertDanger(tool, ['-m', 'http.server']);
  });
}

test('python audit detects stdin execution marker', () => {
  assertDanger('python', ['-']);
});

test('python audit accepts ordinary script execution', () => {
  assertNoDanger('python', ['script.py']);
});

for (const [tool, args] of [
  ['perl', ['-e', 'print 1']],
  ['ruby', ['-e', 'puts 1']],
  ['ruby', ['-r', './x']],
  ['php', ['-r', 'echo 1;']]
]) {
  test('runtime audit detects eval or preload: ' + tool + ' ' + args[0], () => {
    assertDanger(tool, args);
  });
}

test('env audit detects a nested command', () => {
  assertDanger('env', ['FOO=bar', 'git', '--version'], CODES.DANGEROUS_GADGET);
});

test('env audit detects a nested command after end marker', () => {
  assertDanger('env', ['--', 'git', '--version'], CODES.DANGEROUS_GADGET);
});

test('env audit detects split-string mode', () => {
  assertDanger('env', ['-S', 'sh -c id']);
});

test('env audit accepts assignments without a nested command', () => {
  assertNoDanger('env', ['FOO=bar', 'PATH=/bin']);
});

for (const args of [['-I', '{}'], ['-J', '%'], ['--replace', '{}']]) {
  test('xargs audit detects replacement mode ' + args[0], () => {
    assertDanger('xargs', args);
  });
}

test('xargs audit accepts plain bounded use without replacement mode', () => {
  assertNoDanger('xargs', ['printf']);
});

test('dangerous findings include stable index and flag metadata', () => {
  const findings = assertDanger('git', ['clone', '--upload-pack', 'x']);
  const finding = findings[0];
  assert.equal(finding.code, CODES.DANGEROUS_FLAG);
  assert.equal(finding.index, 1);
  assert.equal(finding.flag, '--upload-pack');
  assert.equal(typeof finding.message, 'string');
  assert.equal(typeof finding.severity, 'string');
});

test('audit findings do not echo dangerous flag values', () => {
  const secretLike = 'proxycommand=sh -c secret-material';
  const findings = auditArgv('ssh', ['-o', secretLike]);
  const serialized = JSON.stringify(findings);
  assert.equal(serialized.includes(secretLike), false);
  assert.equal(serialized.includes('secret-material'), false);
});

test('auditArgv reports dangerous flags even when execution would explicitly allow them', () => {
  const findings = auditArgv('node', ['-e', 'x'], { allowDangerousFlags: true });
  assert.ok(hasCode(findings, CODES.DANGEROUS_FLAG));
});

test('end-of-options suppresses exact shell flag matching', () => {
  assertNoDanger('sh', ['--', '-c']);
});

test('end-of-options suppression does not hide invalid argument characters', () => {
  const findings = auditArgv('git', ['--', 'x\0']);
  assert.ok(hasCode(findings, CODES.ARG_NUL_BYTE));
});

for (const [command, args] of [
  ['git', ['status']],
  ['tar', ['-tf', 'archive.tar']],
  ['find', ['.', '-maxdepth', '1']],
  ['curl', ['--version']],
  ['ssh', ['-V']],
  ['rsync', ['--version']],
  ['node', ['--version']],
  ['python', ['--version']]
]) {
  test('safe common invocation has no dangerous finding: ' + command, () => {
    assertNoDanger(command, args);
  });
}

for (const args of [
  ['clone', '--config=core.sshCommand=synthetic'],
  ['clone', '--upload=synthetic'],
  ['--git-dir', 'repo', 'status'],
  ['--work-tree', 'tree', 'status'],
  ['-C', 'repo', 'status'],
  ['clone', '--template=template', 'repo']
]) {
  test('git audit detects additional repository or execution control ' + args[Math.min(1, args.length - 1)], () => {
    assertDanger('git', args);
  });
}

test('git audit does not flag an ordinary safe long option sharing no dangerous prefix', () => {
  assertNoDanger('git', ['clone', '--depth', '1', 'https://example.invalid/repo.git']);
});

for (const args of [
  ['--checkpoint-a=exec=synthetic', '-xf', 'archive.tar'],
  ['--use-compress-p=synthetic', '-xf', 'archive.tar'],
  ['--rmt-c=synthetic', '-xf', 'archive.tar'],
  ['--new-volume-s=synthetic', '-xf', 'archive.tar']
]) {
  test('tar audit detects unambiguous long-option abbreviation ' + args[0], () => {
    assertDanger('tar', args);
  });
}

test('tar audit does not flag the exact benign checkpoint option', () => {
  assertNoDanger('tar', ['--checkpoint', '-xf', 'archive.tar']);
});

for (const flag of ['-comm', '-commandw', '-enc', '\u2013command', '\u2014encodedcommand', '/command']) {
  test('powershell audit detects abbreviated unicode or slash execution flag ' + JSON.stringify(flag), () => {
    assertDanger('pwsh', [flag, 'synthetic']);
  });
}

test('powershell audit does not suppress execution flags after double dash', () => {
  assertDanger('pwsh', ['--', '-command', 'synthetic']);
});

test('cmd audit does not suppress command flags after double dash', () => {
  assertDanger('cmd.exe', ['--', '/c', 'dir']);
});

test('find audit does not suppress execution predicates after double dash', () => {
  assertDanger('find', ['--', '-exec', 'sh', '{}', ';']);
});

for (const args of [
  ['-O', 'https://example.invalid/file'],
  ['-J', '-O', 'https://example.invalid/file'],
  ['--remote-name', 'https://example.invalid/file'],
  ['--output-dir', 'out', 'https://example.invalid/file'],
  ['--dump-header', 'headers', 'https://example.invalid/file'],
  ['--trace-ascii', 'trace', 'https://example.invalid/file'],
  ['--cookie-jar', 'cookies', 'https://example.invalid/file']
]) {
  test('curl audit detects additional file output risk ' + args[0], () => {
    assertDanger('curl', args);
  });
}

test('ssh audit detects Match exec through option values without echoing the command', () => {
  const findings = assertDanger('ssh', ['-o', 'Match exec=synthetic-command']);
  assert.equal(JSON.stringify(findings).includes('synthetic-command'), false);
});
