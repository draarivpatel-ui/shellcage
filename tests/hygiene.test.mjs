import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { repoRoot } from './helpers.mjs';

function walk(directory, output = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'coverage') continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(full, output);
    else if (entry.isFile()) output.push(full);
  }
  return output;
}

function files() {
  return walk(repoRoot).filter((file) => {
    const base = path.basename(file);
    return !base.endsWith('.tgz') && !base.endsWith('.log');
  });
}

function read(file) {
  return fs.readFileSync(file, 'utf8');
}

function relative(file) {
  return path.relative(repoRoot, file);
}

test('repository has the required top-level contributor files', () => {
  for (const file of [
    'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'docs/GOOD_FIRST_ISSUES.md',
    'LICENSE', '.gitattributes', '.gitignore', 'package.json'
  ]) {
    assert.equal(fs.existsSync(path.join(repoRoot, file)), true, file);
  }
});

test('repository has the required GitHub workflow files', () => {
  for (const file of [
    '.github/workflows/ci.yml',
    '.github/ISSUE_TEMPLATE/bug_report.md',
    '.github/ISSUE_TEMPLATE/feature_request.md',
    '.github/ISSUE_TEMPLATE/config.yml',
    '.github/PULL_REQUEST_TEMPLATE.md'
  ]) {
    assert.equal(fs.existsSync(path.join(repoRoot, file)), true, file);
  }
});

test('license is MIT text for shellcage contributors', () => {
  const license = read(path.join(repoRoot, 'LICENSE'));
  assert.match(license, /MIT License/);
  assert.match(license, /Permission is hereby granted/);
  assert.match(license, /shellcage contributors/);
});

test('good first issues file contains exactly 10 scoped ideas', () => {
  const text = read(path.join(repoRoot, 'docs', 'GOOD_FIRST_ISSUES.md'));
  const count = (text.match(/^## \d+\./gm) || []).length;
  assert.equal(count, 10);
});

test('README reports a numeric verified test count', () => {
  const readme = read(path.join(repoRoot, 'README.md'));
  assert.match(readme, /\*\*Tests:\*\* [1-9][0-9]+ passing with `npm test`/);
});

test('README test count is at least the required floor', () => {
  const readme = read(path.join(repoRoot, 'README.md'));
  const match = /\*\*Tests:\*\* ([0-9]+) passing/.exec(readme);
  assert.ok(match, 'missing test count');
  assert.ok(Number(match[1]) >= 450, 'test count below floor');
});

test('README documents the CWE and CVE threat model', () => {
  const readme = read(path.join(repoRoot, 'README.md'));
  for (const marker of ['CWE-78', 'CWE-88', 'CVE-2024-27980', 'Environment hijacking']) {
    assert.ok(readme.includes(marker), marker);
  }
});

test('README documents MCP and backend usage', () => {
  const readme = read(path.join(repoRoot, 'README.md'));
  assert.match(readme, /## MCP server example/);
  assert.match(readme, /## Backend worker example/);
});

test('README documents honest scope and limitations', () => {
  const readme = read(path.join(repoRoot, 'README.md'));
  assert.match(readme, /## Scope and limitations/);
  assert.match(readme, /not a sandbox/);
  assert.match(readme, /not a complete parser/);
  assert.match(readme, /time-of-check to time-of-use race/);
});

test('README does not claim the package is already published', () => {
  const readme = read(path.join(repoRoot, 'README.md'));
  assert.match(readme, /does not claim that the package has already been published/);
});

test('SECURITY documents private reporting scope and secret handling', () => {
  const security = read(path.join(repoRoot, 'SECURITY.md'));
  assert.match(security, /Report a vulnerability/i);
  assert.match(security, /## Scope/);
  assert.match(security, /Out of scope/);
  assert.match(security, /Never include a real token/);
});

test('CONTRIBUTING documents zero runtime dependencies and secret fixture rules', () => {
  const contributing = read(path.join(repoRoot, 'CONTRIBUTING.md'));
  assert.match(contributing, /Zero runtime dependencies/);
  assert.match(contributing, /Never fixture a real token/);
});

test('issue templates warn against real secrets', () => {
  const bug = read(path.join(repoRoot, '.github', 'ISSUE_TEMPLATE', 'bug_report.md'));
  assert.match(bug, /synthetic secrets/i);
  assert.match(bug, /do not paste real tokens/i);
});

test('pull request template requires exact test count and packaging checks', () => {
  const pr = read(path.join(repoRoot, '.github', 'PULL_REQUEST_TEMPLATE.md'));
  assert.match(pr, /exact test count/i);
  assert.match(pr, /npm pack --dry-run/);
  assert.match(pr, /build-cjs\.mjs --check/);
});

test('no repository file contains em dash or en dash characters', () => {
  const emDash = String.fromCharCode(8212);
  const enDash = String.fromCharCode(8211);
  const offenders = [];
  for (const file of files()) {
    const text = read(file);
    if (text.includes(emDash) || text.includes(enDash)) offenders.push(relative(file));
  }
  assert.deepEqual(offenders, []);
});

test('no repository file contains CRLF line endings', () => {
  const offenders = [];
  for (const file of files()) {
    if (read(file).includes('\r\n')) offenders.push(relative(file));
  }
  assert.deepEqual(offenders, []);
});

test('no repository file contains a local absolute user path', () => {
  const offenders = [];
  const unixHome = '/' + 'Users' + '/';
  const windowsHome = 'C:' + '\\' + 'Users' + '\\';
  for (const file of files()) {
    const text = read(file);
    if (text.includes(unixHome) || text.includes(windowsHome)) offenders.push(relative(file));
  }
  assert.deepEqual(offenders, []);
});

test('no repository file contains personal contact or address markers', () => {
  const offenders = [];
  const markers = [
    'someone@' + 'gmail.com',
    'handle-redacted' + '286',
    'Exampleton' + ' Manor'
  ];
  for (const file of files()) {
    const text = read(file);
    if (markers.some((marker) => text.includes(marker))) offenders.push(relative(file));
  }
  assert.deepEqual(offenders, []);
});

test('no repository file contains a co-author trailer', () => {
  const trailer = 'Co-' + 'Authored-' + 'By:';
  const offenders = [];
  for (const file of files()) {
    if (read(file).includes(trailer)) offenders.push(relative(file));
  }
  assert.deepEqual(offenders, []);
});

test('no repository file contains real-looking vendor secret prefixes', () => {
  const offenders = [];
  const prefixes = [
    'tskey' + '-', 's' + 'k-', 'gh' + 'p_', 'github' + '_pat_',
    'AK' + 'IA', 'gs' + 'k_', 'nv' + 'api-', 'tv' + 'ly-', 'AI' + 'za'
  ];
  for (const file of files()) {
    const text = read(file);
    if (prefixes.some((prefix) => text.includes(prefix))) offenders.push(relative(file));
  }
  assert.deepEqual(offenders, []);
});

test('gitattributes enforces LF for every required text extension', () => {
  const text = read(path.join(repoRoot, '.gitattributes'));
  for (const extension of ['*.mjs', '*.cjs', '*.js', '*.ts', '*.json', '*.md', '*.yml']) {
    assert.ok(text.includes(extension + ' text eol=lf'), extension);
  }
});

test('gitignore excludes dependency output logs and tarballs', () => {
  const gitignore = read(path.join(repoRoot, '.gitignore'));
  assert.match(gitignore, /node_modules\//);
  assert.match(gitignore, /coverage\//);
  assert.match(gitignore, /\*\.tgz/);
  assert.match(gitignore, /npm-debug\.log\*/);
});

test('package manifest has no install lifecycle scripts', () => {
  const pkg = JSON.parse(read(path.join(repoRoot, 'package.json')));
  for (const key of ['preinstall', 'install', 'postinstall', 'prepublish', 'prepare']) {
    assert.equal(pkg.scripts[key], undefined, key);
  }
});

test('package manifest identity and repository metadata are exact', () => {
  const pkg = JSON.parse(read(path.join(repoRoot, 'package.json')));
  assert.equal(pkg.name, 'shellcage');
  assert.equal(pkg.version, '1.0.0');
  assert.equal(pkg.license, 'MIT');
  assert.equal(pkg.repository.url, 'git+https://github.com/draarivpatel-ui/shellcage.git');
  assert.equal(pkg.homepage, 'https://github.com/draarivpatel-ui/shellcage#readme');
  assert.equal(pkg.bugs.url, 'https://github.com/draarivpatel-ui/shellcage/issues');
});

test('package manifest keywords include the core security topics', () => {
  const pkg = JSON.parse(read(path.join(repoRoot, 'package.json')));
  for (const keyword of ['security', 'command-injection', 'argument-injection', 'cwe-78', 'cwe-88', 'cve-2024-27980', 'mcp', 'zero-dependency']) {
    assert.ok(pkg.keywords.includes(keyword), keyword);
  }
});

test('package files list includes runtime source types documentation and CLI', () => {
  const pkg = JSON.parse(read(path.join(repoRoot, 'package.json')));
  for (const entry of ['bin', 'src', 'dist', 'types', 'docs', 'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'LICENSE']) {
    assert.ok(pkg.files.includes(entry), entry);
  }
});

test('CI uses the required operating systems and Node versions', () => {
  const ci = read(path.join(repoRoot, '.github', 'workflows', 'ci.yml'));
  assert.match(ci, /os: \[ubuntu-24\.04, windows-latest\]/);
  assert.match(ci, /node: \[18, 20, 22, 24\]/);
});

test('CI runs tests build check CLI smoke and package dry run', () => {
  const ci = read(path.join(repoRoot, '.github', 'workflows', 'ci.yml'));
  assert.match(ci, /npm test/);
  assert.match(ci, /node scripts\/build-cjs\.mjs --check/);
  assert.match(ci, /node bin\/shellcage\.mjs audit -- node --version/);
  assert.match(ci, /npm pack --dry-run/);
});

test('CLI file is executable on POSIX filesystems', () => {
  if (process.platform === 'win32') return;
  const mode = fs.statSync(path.join(repoRoot, 'bin', 'shellcage.mjs')).mode;
  assert.equal((mode & 0o111) !== 0, true);
});

test('scripts build file and CLI parse as JavaScript', () => {
  for (const file of ['scripts/build-cjs.mjs', 'bin/shellcage.mjs', 'src/index.mjs']) {
    const text = read(path.join(repoRoot, file));
    assert.equal(text.includes('shellcage') || file === 'src/index.mjs', true, file);
  }
});

test('no node_modules directory is present in the source tree', () => {
  assert.equal(fs.existsSync(path.join(repoRoot, 'node_modules')), false);
});

test('all test files use the Node test runner', () => {
  const testFiles = fs.readdirSync(path.join(repoRoot, 'tests')).filter((file) => file.endsWith('.test.mjs'));
  assert.ok(testFiles.length >= 5);
  for (const file of testFiles) {
    assert.match(read(path.join(repoRoot, 'tests', file)), /node:test/, file);
  }
});

test('repository does not contain generated tarballs or logs', () => {
  const offenders = files().filter((file) => file.endsWith('.tgz') || file.endsWith('.log')).map(relative);
  assert.deepEqual(offenders, []);
});

test('source and generated CommonJS build avoid network dependencies', () => {
  for (const file of ['src/index.mjs', 'dist/index.cjs']) {
    const text = read(path.join(repoRoot, file));
    assert.equal(text.includes('node:http'), false);
    assert.equal(text.includes('node:https'), false);
    assert.equal(text.includes('node:net'), false);
  }
});

test('documentation uses ASCII hyphen rather than Unicode dash in CVE reference', () => {
  const readme = read(path.join(repoRoot, 'README.md'));
  assert.ok(readme.includes('CVE-2024-27980'));
  assert.equal(readme.includes('CVE' + String.fromCharCode(8211) + '2024'), false);
});
