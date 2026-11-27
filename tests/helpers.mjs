import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export function toolPath(name = 'tool') {
  return process.platform === 'win32' ? 'C:\\tools\\' + name : '/opt/tools/' + name;
}

export function codesFromReport(report) {
  return report.findings.map((finding) => finding.code);
}

export function codesFromFindings(findings) {
  return findings.map((finding) => finding.code);
}

export function hasCode(findings, code) {
  return findings.some((finding) => finding.code === code);
}

export function dangerousOnly(findings) {
  return findings.filter((finding) => finding.code === 'SHELLCAGE_DANGEROUS_FLAG' || finding.code === 'SHELLCAGE_DANGEROUS_GADGET');
}

export function makeTempDir(t, prefix = 'shellcage-test-') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => {
    try {
      fs.rmSync(directory, { recursive: true, force: true });
    } catch {
      // Best effort cleanup only.
    }
  });
  return directory;
}

export function runProcess(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      shell: false,
      windowsVerbatimArguments: false,
      cwd: options.cwd,
      env: options.env,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, options.timeoutMs || 8000);
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });
    child.on('error', reject);
    child.on('close', (exitCode, signal) => {
      clearTimeout(timeout);
      resolve({ exitCode, signal, stdout, stderr, timedOut });
    });
  });
}

export function runCli(args, options = {}) {
  return runProcess(process.execPath, [path.join(repoRoot, 'bin', 'shellcage.mjs'), ...args], options);
}

export function nodeExecOptions(extra = {}) {
  return {
    allowExecutables: [process.execPath],
    allowDangerousFlags: true,
    timeoutMs: 5000,
    ...extra
  };
}
