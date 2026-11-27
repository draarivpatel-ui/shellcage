import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import {
  ShellCageError,
  auditArgv,
  safeArg,
  validateInvocation,
} from '../src/index.mjs';

const propertyOptions = { seed: 20261127, numRuns: 100 };
const safeText = fc.stringMatching(/^[A-Za-z0-9][A-Za-z0-9 ._]{0,30}$/);
const pathSegment = fc.stringMatching(/^[a-z][a-z0-9]{0,12}$/);

test('benign positional arguments are accepted unchanged', () => {
  fc.assert(
    fc.property(safeText, (value) => {
      assert.equal(safeArg(value), value);
    }),
    propertyOptions,
  );
});

test('benign git invocations are accepted by the explicit allowlist policy', () => {
  fc.assert(
    fc.property(pathSegment, pathSegment, (repository, destination) => {
      const args = ['clone', `https://example.invalid/${repository}.git`, destination];
      const report = validateInvocation('git', args, { allowExecutables: ['git'] });
      assert.equal(report.ok, true, JSON.stringify(report.findings));
      assert.deepEqual(auditArgv('git', args), []);
    }),
    propertyOptions,
  );
});

test('control and bidirectional characters in positional arguments are rejected', () => {
  const hostileCharacter = fc.constantFrom('\0', '\n', '\r', '\t', '\u202e', '\u2066');
  fc.assert(
    fc.property(safeText, hostileCharacter, (base, character) => {
      assert.throws(
        () => safeArg(`${base}x${character}y`),
        (error) => error instanceof ShellCageError,
      );
    }),
    propertyOptions,
  );
});

test('generated shell and runtime execution flags remain dangerous findings', () => {
  const payload = fc.stringMatching(/^[a-z][a-z0-9 ]{0,24}$/);
  fc.assert(
    fc.property(payload, (text) => {
      for (const [command, args] of [
        ['sh', ['-c', text]],
        ['node', ['-e', text]],
        ['git', ['--upload-pack', text]],
        ['curl', ['--output', text]],
      ]) {
        assert.ok(
          auditArgv(command, args).some((finding) => finding.code === 'SHELLCAGE_DANGEROUS_FLAG'),
          `${command} did not report a dangerous flag`,
        );
      }
    }),
    propertyOptions,
  );
});
