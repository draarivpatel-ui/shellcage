import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import * as esm from '../src/index.mjs';
import { repoRoot, nodeExecOptions } from './helpers.mjs';

const require = createRequire(import.meta.url);
const cjs = require('../dist/index.cjs');

const expectedExports = [
  'SHELLCAGE_VERSION', 'CODES', 'DEFAULT_ALLOWED_ENV', 'ShellCageError',
  'createShellCage', 'validateInvocation', 'auditArgv', 'assertSafeArg',
  'safeArg', 'safePathArg', 'buildArgv', 'sanitizeEnv', 'auditEnv',
  'safeExecFile', 'safeSpawn'
];

test('ESM exports every public API name', () => {
  for (const name of expectedExports) assert.equal(typeof esm[name] !== 'undefined', true, name);
});

test('CJS exports every public API name', () => {
  for (const name of expectedExports) assert.equal(typeof cjs[name] !== 'undefined', true, name);
});

test('ESM and CJS export the same public API names', () => {
  const esmNames = expectedExports.slice().sort();
  const cjsNames = expectedExports.filter((name) => cjs[name] !== undefined).sort();
  assert.deepEqual(cjsNames, esmNames);
});

test('CJS default export is the CommonJS namespace object', () => {
  assert.equal(cjs.default, cjs);
});

test('ESM default export contains the same functions as named ESM exports', () => {
  for (const name of expectedExports.filter((name) => !['SHELLCAGE_VERSION', 'CODES', 'DEFAULT_ALLOWED_ENV', 'ShellCageError'].includes(name))) {
    assert.equal(esm.default[name], esm[name], name);
  }
});

test('ESM and CJS versions match package version', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
  assert.equal(esm.SHELLCAGE_VERSION, pkg.version);
  assert.equal(cjs.SHELLCAGE_VERSION, pkg.version);
});

test('ESM and CJS code catalogues are identical', () => {
  assert.deepEqual({ ...cjs.CODES }, { ...esm.CODES });
});

test('ESM and CJS default environment allowlists are identical and frozen', () => {
  assert.deepEqual([...cjs.DEFAULT_ALLOWED_ENV], [...esm.DEFAULT_ALLOWED_ENV]);
  assert.equal(Object.isFrozen(cjs.DEFAULT_ALLOWED_ENV), true);
  assert.equal(Object.isFrozen(esm.DEFAULT_ALLOWED_ENV), true);
});

test('ESM and CJS validation behavior matches for blocked shell', () => {
  const left = esm.validateInvocation('sh', [], { allowExecutables: ['sh'] });
  const right = cjs.validateInvocation('sh', [], { allowExecutables: ['sh'] });
  assert.deepEqual(right.findings, left.findings);
  assert.equal(left.ok, right.ok);
});

test('ESM and CJS argument validation behavior matches', () => {
  for (const api of [esm, cjs]) {
    assert.throws(() => api.safeArg('--bad'), (error) => error.code === 'SHELLCAGE_ARG_LEADING_DASH');
  }
});

test('ESM and CJS buildArgv output matches', () => {
  const spec = [
    { type: 'literal', value: 'clone' },
    { type: 'endOfOptions' },
    { type: 'positional', value: '--repo' }
  ];
  assert.deepEqual([...esm.buildArgv(spec)], [...cjs.buildArgv(spec)]);
});

test('ESM and CJS auditArgv findings match', () => {
  const left = esm.auditArgv('git', ['clone', '--upload-pack=x']);
  const right = cjs.auditArgv('git', ['clone', '--upload-pack=x']);
  assert.deepEqual(right, left);
});

test('ESM and CJS sanitizeEnv output matches', () => {
  const source = { PATH: '/bin', NODE_OPTIONS: '--require x', CUSTOM: 'x' };
  assert.deepEqual({ ...esm.sanitizeEnv(source) }, { ...cjs.sanitizeEnv(source) });
});

test('ESM and CJS auditEnv findings match', () => {
  const source = { NODE_OPTIONS: '--require x' };
  assert.deepEqual(esm.auditEnv(source), cjs.auditEnv(source));
});

test('ESM and CJS ShellCageError shape matches', () => {
  for (const api of [esm, cjs]) {
    try {
      api.safeArg('x\0');
      assert.fail('expected throw');
    } catch (error) {
      assert.equal(error instanceof api.ShellCageError, true);
      assert.equal(error.name, 'ShellCageError');
      assert.equal(typeof error.toJSON().message, 'string');
    }
  }
});

test('ESM safeExecFile executes successfully', async () => {
  const result = await esm.safeExecFile(process.execPath, ['-e', 'process.stdout.write("esm")'], nodeExecOptions());
  assert.equal(result.stdout, 'esm');
});

test('CJS safeExecFile executes successfully', async () => {
  const result = await cjs.safeExecFile(process.execPath, ['-e', 'process.stdout.write("cjs")'], nodeExecOptions());
  assert.equal(result.stdout, 'cjs');
});

test('package export map points at existing files', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
  for (const file of [pkg.module, pkg.main, pkg.types, pkg.exports['.'].import, pkg.exports['.'].require, pkg.exports['.'].types]) {
    assert.equal(fs.existsSync(path.join(repoRoot, file)), true, file);
  }
});

test('package bin entry points at executable CLI file without leading dot slash', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
  assert.equal(pkg.bin.shellcage, 'bin/shellcage.mjs');
  assert.equal(pkg.bin.shellcage.startsWith('./'), false);
  const cli = fs.readFileSync(path.join(repoRoot, pkg.bin.shellcage), 'utf8');
  assert.match(cli, /^#!\/usr\/bin\/env node/);
});

test('package dependencies and devDependencies are empty', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(pkg.devDependencies, {});
});

test('package test script uses the explicit Windows-safe glob', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
  assert.equal(pkg.scripts.test, 'node --test tests/*.test.mjs');
});

test('package engines require Node 18 or newer', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
  assert.equal(pkg.engines.node, '>=18.0.0');
});

test('type declarations mention every public API export', () => {
  const types = fs.readFileSync(path.join(repoRoot, 'types', 'index.d.ts'), 'utf8');
  for (const name of expectedExports) {
    assert.ok(types.includes(name), name);
  }
});

test('generated CommonJS build carries the generated-file notice', () => {
  const text = fs.readFileSync(path.join(repoRoot, 'dist', 'index.cjs'), 'utf8');
  assert.match(text, /Generated by scripts\/build-cjs\.mjs/);
});

test('generated CommonJS build has no ESM export declarations', () => {
  const text = fs.readFileSync(path.join(repoRoot, 'dist', 'index.cjs'), 'utf8');
  assert.equal(/^export\s/m.test(text), false);
});

test('ESM source uses only node core imports', () => {
  const text = fs.readFileSync(path.join(repoRoot, 'src', 'index.mjs'), 'utf8');
  const imports = text.match(/^import .*$/gm) || [];
  assert.ok(imports.length > 0);
  for (const line of imports) assert.ok(line.includes("'node:"), line);
});
