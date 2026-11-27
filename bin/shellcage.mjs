#!/usr/bin/env node
import fs from 'node:fs';
import { auditArgv, auditEnv, SHELLCAGE_VERSION } from '../src/index.mjs';

const MAX_ENV_FILE_BYTES = 1024 * 1024;

function usage() {
  return [
    'shellcage ' + SHELLCAGE_VERSION,
    '',
    'Usage:',
    '  shellcage audit [--json] -- <cmd> [args...]',
    '  shellcage audit-env [--json] [--env-json <file>]',
    '  shellcage --version',
    '  shellcage --help',
    '',
    'Exit codes: 0 clean, 1 risky findings, 2 usage or input error.'
  ].join('\n');
}

function neutralizeTerminalText(text) {
  return String(text).replace(/[\x00-\x1F\x7F-\x9F\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, (character) => {
    return '\\u' + character.codePointAt(0).toString(16).padStart(4, '0');
  });
}

function writeStdoutLine(line) {
  process.stdout.write(neutralizeTerminalText(line) + '\n');
}

function neutralizeJsonText(text) {
  return String(text).replace(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, (character) => {
    return '\\u' + character.codePointAt(0).toString(16).padStart(4, '0');
  });
}

function printJson(payload) {
  process.stdout.write(neutralizeJsonText(JSON.stringify(payload, null, 2)) + '\n');
}

function quotedTerminalValue(value) {
  return neutralizeTerminalText(JSON.stringify(value));
}

function findingLine(item) {
  const parts = [item.severity, item.code];
  if (typeof item.index === 'number') parts.push('index=' + item.index);
  if (typeof item.flag === 'string') parts.push('flag=' + quotedTerminalValue(item.flag));
  if (typeof item.key === 'string') parts.push('key=' + quotedTerminalValue(item.key));
  parts.push(item.message);
  return parts.join(' ');
}

function failUsage(message) {
  process.stderr.write('shellcage: ' + message + '\n\n' + usage() + '\n');
  process.exitCode = 2;
}

function parseAuditArgs(args) {
  const separator = args.indexOf('--');
  if (separator === -1 || separator + 1 >= args.length) return null;
  const before = args.slice(0, separator);
  let json = false;
  for (const token of before) {
    if (token === '--json') json = true;
    else return null;
  }
  return {
    json,
    command: args[separator + 1],
    commandArgs: args.slice(separator + 2)
  };
}

function runAudit(args) {
  const parsed = parseAuditArgs(args);
  if (!parsed) {
    failUsage('audit requires -- followed by an executable argv array');
    return;
  }
  const findings = auditArgv(parsed.command, parsed.commandArgs);
  const ok = findings.length === 0;
  if (parsed.json) {
    printJson({ mode: 'audit', ok, findings });
  } else if (ok) {
    writeStdoutLine('shellcage audit: clean');
  } else {
    writeStdoutLine('shellcage audit: risky findings for ' + quotedTerminalValue(parsed.command));
    for (const item of findings) writeStdoutLine(findingLine(item));
  }
  process.exitCode = ok ? 0 : 1;
}

function loadEnvJson(pathname) {
  let fd;
  try {
    fd = fs.openSync(pathname, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0));
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > MAX_ENV_FILE_BYTES) {
      throw new Error('environment JSON input is missing or too large');
    }
    const parsed = JSON.parse(fs.readFileSync(fd, 'utf8'));
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('environment JSON input must be an object');
    }
    return parsed;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function parseAuditEnvArgs(args) {
  const result = { json: false, envJson: null };
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (token === '--json') {
      if (result.json) return null;
      result.json = true;
    } else if (token === '--env-json') {
      if (result.envJson !== null || index + 1 >= args.length) return null;
      result.envJson = args[index + 1];
      index += 1;
    } else {
      return null;
    }
  }
  return result;
}

function runAuditEnv(args) {
  const parsed = parseAuditEnvArgs(args);
  if (!parsed) {
    failUsage('audit-env accepts only --json and optional --env-json <file>');
    return;
  }
  let source = process.env;
  if (parsed.envJson !== null) {
    try {
      source = loadEnvJson(parsed.envJson);
    } catch {
      process.stderr.write('shellcage: unable to load a valid environment JSON object\n');
      process.exitCode = 2;
      return;
    }
  }
  const findings = auditEnv(source);
  const ok = findings.length === 0;
  if (parsed.json) {
    printJson({ mode: 'audit-env', ok, findings });
  } else if (ok) {
    writeStdoutLine('shellcage audit-env: clean');
  } else {
    writeStdoutLine('shellcage audit-env: risky findings');
    for (const item of findings) writeStdoutLine(findingLine(item));
  }
  process.exitCode = ok ? 0 : 1;
}

function main(argv) {
  const command = argv[0];
  if (command === '--help' || command === '-h') {
    writeStdoutLine(usage());
    return;
  }
  if (command === '--version' || command === '-v') {
    writeStdoutLine('shellcage ' + SHELLCAGE_VERSION);
    return;
  }
  if (command === 'audit') {
    runAudit(argv.slice(1));
    return;
  }
  if (command === 'audit-env') {
    runAuditEnv(argv.slice(1));
    return;
  }
  failUsage(command === undefined ? 'missing command' : 'unknown command');
}

main(process.argv.slice(2));
