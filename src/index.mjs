import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

/*
 * shellcage core.
 *
 * Zero runtime dependencies. The CommonJS build in dist/index.cjs is
 * generated from this file by scripts/build-cjs.mjs so both module formats
 * have identical behavior.
 */

export const SHELLCAGE_VERSION = '1.0.0';

export const CODES = Object.freeze({
  CONFIG_OPTION_UNKNOWN: 'SHELLCAGE_CONFIG_OPTION_UNKNOWN',
  CONFIG_INVALID: 'SHELLCAGE_CONFIG_INVALID',
  SHELL_OPTION_FORBIDDEN: 'SHELLCAGE_SHELL_OPTION_FORBIDDEN',
  EXECUTABLE_TYPE: 'SHELLCAGE_EXECUTABLE_TYPE',
  EXECUTABLE_EMPTY: 'SHELLCAGE_EXECUTABLE_EMPTY',
  EXECUTABLE_TOO_LONG: 'SHELLCAGE_EXECUTABLE_TOO_LONG',
  EXECUTABLE_NUL_BYTE: 'SHELLCAGE_EXECUTABLE_NUL_BYTE',
  EXECUTABLE_CONTROL_CHAR: 'SHELLCAGE_EXECUTABLE_CONTROL_CHAR',
  EXECUTABLE_WHITESPACE: 'SHELLCAGE_EXECUTABLE_WHITESPACE',
  EXECUTABLE_NON_ASCII: 'SHELLCAGE_EXECUTABLE_NON_ASCII',
  EXECUTABLE_TRAVERSAL: 'SHELLCAGE_EXECUTABLE_TRAVERSAL',
  EXECUTABLE_RELATIVE_PATH: 'SHELLCAGE_EXECUTABLE_RELATIVE_PATH',
  EXECUTABLE_NOT_ALLOWLISTED: 'SHELLCAGE_EXECUTABLE_NOT_ALLOWLISTED',
  EXECUTABLE_ALLOWLIST_REQUIRED: 'SHELLCAGE_EXECUTABLE_ALLOWLIST_REQUIRED',
  EXECUTABLE_ALLOWLIST_INVALID: 'SHELLCAGE_EXECUTABLE_ALLOWLIST_INVALID',
  SHELL_BINARY: 'SHELLCAGE_SHELL_BINARY',
  BATCH_EXTENSION: 'SHELLCAGE_BATCH_EXTENSION',
  ARGS_NOT_ARRAY: 'SHELLCAGE_ARGS_NOT_ARRAY',
  ARGV_TOO_MANY: 'SHELLCAGE_ARGV_TOO_MANY',
  ARGV_TOO_LONG: 'SHELLCAGE_ARGV_TOO_LONG',
  ARG_TYPE: 'SHELLCAGE_ARG_TYPE',
  ARG_EMPTY: 'SHELLCAGE_ARG_EMPTY',
  ARG_NUL_BYTE: 'SHELLCAGE_ARG_NUL_BYTE',
  ARG_NEWLINE: 'SHELLCAGE_ARG_NEWLINE',
  ARG_CONTROL_CHAR: 'SHELLCAGE_ARG_CONTROL_CHAR',
  ARG_BIDI_CONTROL: 'SHELLCAGE_ARG_BIDI_CONTROL',
  ARG_TOO_LONG: 'SHELLCAGE_ARG_TOO_LONG',
  ARG_LEADING_DASH: 'SHELLCAGE_ARG_LEADING_DASH',
  ARGV_SPEC_INVALID: 'SHELLCAGE_ARGV_SPEC_INVALID',
  DANGEROUS_FLAG: 'SHELLCAGE_DANGEROUS_FLAG',
  DANGEROUS_GADGET: 'SHELLCAGE_DANGEROUS_GADGET',
  ENV_NOT_OBJECT: 'SHELLCAGE_ENV_NOT_OBJECT',
  ENV_INJECTION: 'SHELLCAGE_ENV_INJECTION',
  ENV_KEY_INVALID: 'SHELLCAGE_ENV_KEY_INVALID',
  ENV_KEY_PROTOTYPE: 'SHELLCAGE_ENV_KEY_PROTOTYPE',
  ENV_DUPLICATE_KEY: 'SHELLCAGE_ENV_DUPLICATE_KEY',
  ENV_VALUE_TYPE: 'SHELLCAGE_ENV_VALUE_TYPE',
  ENV_VALUE_NUL_BYTE: 'SHELLCAGE_ENV_VALUE_NUL_BYTE',
  ENV_VALUE_TOO_LONG: 'SHELLCAGE_ENV_VALUE_TOO_LONG',
  ENV_NOT_ALLOWLISTED: 'SHELLCAGE_ENV_NOT_ALLOWLISTED',
  CWD_TYPE: 'SHELLCAGE_CWD_TYPE',
  CWD_NOT_ABSOLUTE: 'SHELLCAGE_CWD_NOT_ABSOLUTE',
  CWD_NOT_FOUND: 'SHELLCAGE_CWD_NOT_FOUND',
  CWD_NOT_DIRECTORY: 'SHELLCAGE_CWD_NOT_DIRECTORY',
  CWD_OUTSIDE_ROOT: 'SHELLCAGE_CWD_OUTSIDE_ROOT',
  CWD_ROOT_INVALID: 'SHELLCAGE_CWD_ROOT_INVALID',
  TIMEOUT_INVALID: 'SHELLCAGE_TIMEOUT_INVALID',
  OUTPUT_LIMIT_INVALID: 'SHELLCAGE_OUTPUT_LIMIT_INVALID',
  STDIN_INVALID: 'SHELLCAGE_STDIN_INVALID',
  STDIN_TOO_LARGE: 'SHELLCAGE_STDIN_TOO_LARGE',
  SPAWN_FAILED: 'SHELLCAGE_SPAWN_FAILED'
});

export const DEFAULT_ALLOWED_ENV = Object.freeze(['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR']);

const DEFAULT_TIMEOUT_MS = 15000;
const MAX_TIMEOUT_MS = 120000;
const DEFAULT_MAX_STDOUT_BYTES = 1024 * 1024;
const DEFAULT_MAX_STDERR_BYTES = 1024 * 1024;
const DEFAULT_MAX_STDIN_BYTES = 1024 * 1024;
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_ARG_BYTES = 4096;
const MAX_ARG_BYTES = 65536;
const DEFAULT_MAX_ARGS = 512;
const MAX_ARGS_LIMIT = 4096;
const DEFAULT_MAX_ARGV_BYTES = 256 * 1024;
const MAX_ARGV_BYTES_LIMIT = 1024 * 1024;
const DEFAULT_MAX_ENV_VALUE_BYTES = 32768;
const MAX_ENV_VALUE_BYTES_LIMIT = 1024 * 1024;
const MAX_EXECUTABLE_BYTES = 1024;
const MAX_ENV_KEY_BYTES = 256;
const KILL_GRACE_MS = 250;

const CONTROL_CHAR_RE = /[\x00-\x1F\x7F-\x9F]/;
const ARG_CONTROL_RE = /[\x00-\x09\x0B\x0C\x0E-\x1F\x7F-\x9F]/;
const ARG_NEWLINE_RE = /[\r\n]/;
const BIDI_CONTROL_RE = /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/;
const NON_ASCII_RE = /[^\x00-\x7F]/;
const WHITESPACE_RE = /\s/;
const PRINTABLE_ENV_KEY_RE = /^[\x21-\x7E]+$/;
const WINDOWS_ABSOLUTE_RE = /^[A-Za-z]:[\\/]/;
const BATCH_EXTENSION_RE = /\.(bat|cmd|btm|vbs|vbe|js|jse|wsf|wsh|ps1|com)$/i;
const FLAG_NAME_RE = /^--?[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const PROTOTYPE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const ALLOWED_KILL_SIGNALS = new Set(['SIGTERM', 'SIGKILL', 'SIGINT', 'SIGHUP', 'SIGQUIT']);

const SHELL_EXECUTABLES = new Set([
  'sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'fish',
  'cmd', 'powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'command'
]);

const POWERSHELL_EXECUTABLES = new Set(['powershell', 'pwsh']);

const EXACT_DANGEROUS_ENV_NAMES = new Set([
  'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'LD_DEBUG',
  'NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'NODE_PATH',
  'PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONHOME', 'PYTHONINSPECT', 'PYTHONEXECUTABLE',
  'RUBYOPT', 'RUBYLIB', 'PERL5OPT', 'PERL5LIB',
  'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
  'BASH_ENV', 'ENV', 'CDPATH', 'IFS', 'SHELLOPTS', 'PS4', 'PROMPT_COMMAND', 'ZDOTDIR',
  'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_EXEC_PATH', 'GIT_CONFIG_PARAMETERS',
  'GIT_CONFIG_COUNT', 'GIT_EXT_TRANSPORT', 'GIT_EXTERNAL_DIFF', 'GIT_PAGER',
  'EDITOR', 'VISUAL', 'PAGER', 'COMSPEC', 'PATHEXT',
  'INPUTRC', 'TERMINFO', 'TERMINFO_DIRS', 'LESSOPEN', 'LESSCLOSE', 'SYSTEMD_PAGER'
]);

const DANGEROUS_ENV_PREFIXES = Object.freeze([
  'LD_', 'DYLD_', 'GIT_CONFIG_KEY_', 'GIT_CONFIG_VALUE_', 'BASH_FUNC_'
]);

const INVOCATION_OPTION_KEYS = new Set([
  'allowExecutables', 'allowShellBinary', 'allowBatchExtensions', 'allowDangerousFlags',
  'maxArgBytes', 'maxArgs', 'maxArgvBytes',
  'env', 'allowEnv', 'maxEnvValueBytes',
  'cwd', 'allowedCwdRoots',
  'timeoutMs', 'maxStdoutBytes', 'maxStderrBytes', 'maxStdinBytes', 'stdin',
  'killSignal', 'shell', 'windowsVerbatimArguments', 'windowsHide'
]);

const ARG_OPTION_KEYS = new Set([
  'allowNewlines', 'rejectLeadingDash', 'positional', 'maxBytes', 'allowEmpty'
]);

const ENV_OPTION_KEYS = new Set([
  'allowEnv', 'maxValueBytes', 'includeUnlisted'
]);

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function deepFreeze(value, seen = new Set()) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return value;
  if (Buffer.isBuffer(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return value;
  if (seen.has(value)) return value;
  seen.add(value);
  if (typeof value === 'object') {
    for (const key of Object.keys(value)) deepFreeze(value[key], seen);
  }
  return Object.freeze(value);
}

function byteLength(value) {
  return Buffer.byteLength(String(value), 'utf8');
}

function booleanValue(value, fallback, name) {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') fail(CODES.CONFIG_INVALID, name + ' must be a boolean');
  return value;
}

function integerValue(value, fallback, min, max, name, code) {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) {
    fail(code, name + ' must be a safe integer in range');
  }
  return value;
}

export class ShellCageError extends Error {
  constructor(code, message, details = {}) {
    super(String(code) + ': ' + String(message));
    this.name = 'ShellCageError';
    this.code = String(code);
    const source = isPlainObject(details) ? details : {};
    this.details = deepFreeze({ ...source });
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      details: { ...this.details }
    };
  }
}

function fail(code, message, details) {
  throw new ShellCageError(code, message, details);
}

function makeFinding(code, severity, message, extra = {}) {
  const item = {
    code: String(code),
    severity: String(severity),
    message: String(message)
  };
  for (const key of Object.keys(extra)) {
    if (extra[key] !== undefined) item[key] = extra[key];
  }
  return Object.freeze(item);
}

function freezeFindings(findings) {
  return Object.freeze(findings.map((item) => Object.freeze({ ...item })));
}

function errorFinding(error) {
  if (error instanceof ShellCageError) {
    return makeFinding(error.code, 'high', error.message.replace(error.code + ': ', ''));
  }
  return makeFinding(CODES.CONFIG_INVALID, 'high', 'invalid shellcage configuration');
}

function assertPlainObject(value, label) {
  if (!isPlainObject(value)) fail(CODES.CONFIG_INVALID, label + ' must be a plain object');
}

function assertOnlyKeys(options, allowed, label) {
  for (const key of Object.keys(options)) {
    if (!allowed.has(key)) fail(CODES.CONFIG_OPTION_UNKNOWN, label + ' contains an unknown option', { key });
  }
}

function normalizeInvocationOptions(options) {
  const source = options === undefined ? {} : options;
  assertPlainObject(source, 'options');
  assertOnlyKeys(source, INVOCATION_OPTION_KEYS, 'options');
  if (source.shell === true || source.windowsVerbatimArguments === true) {
    fail(CODES.SHELL_OPTION_FORBIDDEN, 'shell execution and verbatim Windows arguments are forbidden');
  }
  const normalized = {
    allowShellBinary: booleanValue(source.allowShellBinary, false, 'allowShellBinary'),
    allowBatchExtensions: booleanValue(source.allowBatchExtensions, false, 'allowBatchExtensions'),
    allowDangerousFlags: booleanValue(source.allowDangerousFlags, false, 'allowDangerousFlags'),
    maxArgBytes: integerValue(source.maxArgBytes, DEFAULT_MAX_ARG_BYTES, 1, MAX_ARG_BYTES, 'maxArgBytes', CODES.CONFIG_INVALID),
    maxArgs: integerValue(source.maxArgs, DEFAULT_MAX_ARGS, 1, MAX_ARGS_LIMIT, 'maxArgs', CODES.CONFIG_INVALID),
    maxArgvBytes: integerValue(source.maxArgvBytes, DEFAULT_MAX_ARGV_BYTES, 1, MAX_ARGV_BYTES_LIMIT, 'maxArgvBytes', CODES.CONFIG_INVALID)
  };
  if (source.allowExecutables !== undefined) normalized.allowExecutables = source.allowExecutables;
  if (source.env !== undefined) normalized.env = source.env;
  if (source.allowEnv !== undefined) normalized.allowEnv = source.allowEnv;
  if (source.maxEnvValueBytes !== undefined) normalized.maxEnvValueBytes = source.maxEnvValueBytes;
  if (source.cwd !== undefined) normalized.cwd = source.cwd;
  if (source.allowedCwdRoots !== undefined) normalized.allowedCwdRoots = source.allowedCwdRoots;
  if (source.timeoutMs !== undefined) normalized.timeoutMs = source.timeoutMs;
  if (source.maxStdoutBytes !== undefined) normalized.maxStdoutBytes = source.maxStdoutBytes;
  if (source.maxStderrBytes !== undefined) normalized.maxStderrBytes = source.maxStderrBytes;
  if (source.maxStdinBytes !== undefined) normalized.maxStdinBytes = source.maxStdinBytes;
  if (source.stdin !== undefined) normalized.stdin = source.stdin;
  if (source.killSignal !== undefined) normalized.killSignal = source.killSignal;
  if (source.windowsHide !== undefined) normalized.windowsHide = booleanValue(source.windowsHide, false, 'windowsHide');
  return normalized;
}

function splitExecutablePath(value) {
  return String(value).split(/[\\/]+/);
}

function executableBasename(value) {
  const parts = splitExecutablePath(value);
  return parts[parts.length - 1] || '';
}

function isPathLikeExecutable(value) {
  return String(value).includes('/') || String(value).includes('\\');
}

function isAbsoluteExecutable(value) {
  const text = String(value);
  return path.isAbsolute(text) || WINDOWS_ABSOLUTE_RE.test(text) || text.startsWith('\\\\');
}

function canonicalExecutableName(name) {
  let lower = String(name).toLowerCase();
  if (lower.endsWith('.exe')) lower = lower.slice(0, -4);
  return lower;
}

function executableNamesEqual(left, right) {
  if (process.platform === 'win32') return String(left).toLowerCase() === String(right).toLowerCase();
  return String(left) === String(right);
}

function inspectExecutableSyntax(command, findings) {
  if (typeof command !== 'string') {
    findings.push(makeFinding(CODES.EXECUTABLE_TYPE, 'high', 'executable must be a string'));
    return { valid: false, basename: '', pathLike: false, absolute: false };
  }
  if (command.length === 0) {
    findings.push(makeFinding(CODES.EXECUTABLE_EMPTY, 'high', 'executable must not be empty'));
    return { valid: false, basename: '', pathLike: false, absolute: false };
  }

  const basename = executableBasename(command);
  const pathLike = isPathLikeExecutable(command);
  const absolute = isAbsoluteExecutable(command);
  let valid = true;

  if (byteLength(command) > MAX_EXECUTABLE_BYTES) {
    valid = false;
    findings.push(makeFinding(CODES.EXECUTABLE_TOO_LONG, 'high', 'executable path exceeds the byte limit'));
  }
  if (command.includes('\0')) {
    valid = false;
    findings.push(makeFinding(CODES.EXECUTABLE_NUL_BYTE, 'high', 'executable contains a NUL byte'));
  }
  if (CONTROL_CHAR_RE.test(command.replaceAll('\0', ''))) {
    valid = false;
    findings.push(makeFinding(CODES.EXECUTABLE_CONTROL_CHAR, 'high', 'executable contains a control character'));
  }
  if (basename.length === 0) {
    valid = false;
    findings.push(makeFinding(CODES.EXECUTABLE_EMPTY, 'high', 'executable basename must not be empty'));
  }
  if (WHITESPACE_RE.test(basename)) {
    valid = false;
    findings.push(makeFinding(CODES.EXECUTABLE_WHITESPACE, 'high', 'executable basename must not contain whitespace'));
  }
  if (NON_ASCII_RE.test(basename)) {
    valid = false;
    findings.push(makeFinding(CODES.EXECUTABLE_NON_ASCII, 'high', 'executable basename must not contain non-ASCII confusables'));
  }
  if (splitExecutablePath(command).includes('..')) {
    valid = false;
    findings.push(makeFinding(CODES.EXECUTABLE_TRAVERSAL, 'high', 'executable path must not contain parent traversal'));
  }
  if (pathLike && !absolute) {
    valid = false;
    findings.push(makeFinding(CODES.EXECUTABLE_RELATIVE_PATH, 'high', 'executable path must be absolute when it contains a path separator'));
  }
  return { valid, basename, pathLike, absolute };
}

function validateAllowlistEntry(entry, index) {
  if (typeof entry !== 'string' || entry.length === 0) {
    fail(CODES.EXECUTABLE_ALLOWLIST_INVALID, 'allowlist entries must be non-empty strings', { index });
  }
  if (byteLength(entry) > MAX_EXECUTABLE_BYTES || entry.includes('\0') || CONTROL_CHAR_RE.test(entry)) {
    fail(CODES.EXECUTABLE_ALLOWLIST_INVALID, 'allowlist entry contains forbidden characters', { index });
  }
  const base = executableBasename(entry);
  if (base.length === 0 || WHITESPACE_RE.test(base) || NON_ASCII_RE.test(base)) {
    fail(CODES.EXECUTABLE_ALLOWLIST_INVALID, 'allowlist entry has an unsafe executable basename', { index });
  }
  if (splitExecutablePath(entry).includes('..')) {
    fail(CODES.EXECUTABLE_ALLOWLIST_INVALID, 'allowlist entry must not contain parent traversal', { index });
  }
  const pathLike = isPathLikeExecutable(entry);
  const absolute = isAbsoluteExecutable(entry);
  if (pathLike && !absolute) {
    fail(CODES.EXECUTABLE_ALLOWLIST_INVALID, 'allowlist paths must be absolute paths or bare executable names', { index });
  }
  if (absolute) {
    const normalized = path.normalize(entry);
    let real = normalized;
    try {
      real = fs.realpathSync(entry);
    } catch {
      real = normalized;
    }
    return Object.freeze({ kind: 'path', value: entry, normalized, real });
  }
  return Object.freeze({ kind: 'basename', value: entry, name: entry });
}

function normalizeAllowlist(value) {
  if (!Array.isArray(value) || value.length === 0) {
    fail(CODES.EXECUTABLE_ALLOWLIST_REQUIRED, 'an explicit non-empty executable allowlist is required');
  }
  if (value.length > 512) {
    fail(CODES.EXECUTABLE_ALLOWLIST_INVALID, 'executable allowlist exceeds the entry limit');
  }
  const entries = value.map((entry, index) => validateAllowlistEntry(entry, index));
  return Object.freeze(entries);
}

function realpathIfPossible(value) {
  const normalized = path.normalize(value);
  try {
    return fs.realpathSync(value);
  } catch {
    return normalized;
  }
}

function pathsEqual(left, right) {
  if (process.platform === 'win32') return String(left).toLowerCase() === String(right).toLowerCase();
  return String(left) === String(right);
}

function executableIsAllowlisted(command, info, allowlist) {
  for (const entry of allowlist) {
    if (entry.kind === 'basename' && executableNamesEqual(entry.name, info.basename)) return true;
  }
  if (!info.absolute) return false;
  const realCommand = realpathIfPossible(command);
  const normalizedCommand = path.normalize(command);
  for (const entry of allowlist) {
    if (entry.kind !== 'path') continue;
    if (pathsEqual(realCommand, entry.real) || pathsEqual(normalizedCommand, entry.normalized)) return true;
  }
  return false;
}

function inspectExecutablePolicy(command, info, options, findings) {
  if (!info.basename) return;
  const canonical = canonicalExecutableName(info.basename);
  if (SHELL_EXECUTABLES.has(canonical) && options.allowShellBinary !== true) {
    findings.push(makeFinding(CODES.SHELL_BINARY, 'critical', 'shell and script interpreter executables are blocked by default'));
  }
  if (BATCH_EXTENSION_RE.test(info.basename) && options.allowBatchExtensions !== true) {
    findings.push(makeFinding(CODES.BATCH_EXTENSION, 'critical', 'Windows batch and script executable extensions are blocked by default'));
  }
  if (options.allowExecutables !== undefined) {
    let allowlist;
    try {
      allowlist = normalizeAllowlist(options.allowExecutables);
    } catch (error) {
      findings.push(errorFinding(error));
      return;
    }
    if (!executableIsAllowlisted(command, info, allowlist)) {
      findings.push(makeFinding(CODES.EXECUTABLE_NOT_ALLOWLISTED, 'critical', 'executable is not present in the explicit allowlist'));
    }
  }
}

function checkSafeArg(value, options = {}) {
  const maxBytes = integerValue(
    options.maxBytes,
    DEFAULT_MAX_ARG_BYTES,
    1,
    MAX_ARG_BYTES,
    'maxBytes',
    CODES.CONFIG_INVALID
  );
  const allowNewlines = options.allowNewlines === true;
  const allowEmpty = options.allowEmpty !== false;
  const rejectLeadingDash = options.rejectLeadingDash === true || options.positional === true;

  if (typeof value !== 'string') return { code: CODES.ARG_TYPE, message: 'argument must be a string' };
  if (!allowEmpty && value.length === 0) return { code: CODES.ARG_EMPTY, message: 'argument must not be empty' };
  if (value.includes('\0')) return { code: CODES.ARG_NUL_BYTE, message: 'argument contains a NUL byte' };
  if (!allowNewlines && ARG_NEWLINE_RE.test(value)) return { code: CODES.ARG_NEWLINE, message: 'argument contains a line break' };
  if (ARG_CONTROL_RE.test(value)) return { code: CODES.ARG_CONTROL_CHAR, message: 'argument contains a control character' };
  if (BIDI_CONTROL_RE.test(value)) return { code: CODES.ARG_BIDI_CONTROL, message: 'argument contains a bidirectional override control' };
  if (byteLength(value) > maxBytes) return { code: CODES.ARG_TOO_LONG, message: 'argument exceeds the byte limit' };
  if (rejectLeadingDash && value.startsWith('-')) return { code: CODES.ARG_LEADING_DASH, message: 'positional argument must not begin with a dash' };
  return null;
}

export function assertSafeArg(value, options = {}) {
  const source = options === undefined ? {} : options;
  assertPlainObject(source, 'argument options');
  assertOnlyKeys(source, ARG_OPTION_KEYS, 'argument options');
  const problem = checkSafeArg(value, source);
  if (problem) fail(problem.code, problem.message);
  return value;
}

export function safeArg(value, options = {}) {
  const merged = { ...options, positional: true };
  assertSafeArg(value, merged);
  return value;
}

export function safePathArg(value, options = {}) {
  const merged = { ...options, positional: true, allowEmpty: false };
  assertSafeArg(value, merged);
  return value;
}

function inspectArgv(args, options, findings) {
  if (!Array.isArray(args)) {
    findings.push(makeFinding(CODES.ARGS_NOT_ARRAY, 'critical', 'arguments must be supplied as an array, never as a command line string'));
    return false;
  }
  if (args.length > options.maxArgs) {
    findings.push(makeFinding(CODES.ARGV_TOO_MANY, 'high', 'argument count exceeds the configured limit', { count: args.length }));
  }
  let totalBytes = 0;
  let allStrings = true;
  for (let index = 0; index < args.length; index += 1) {
    const problem = checkSafeArg(args[index], { maxBytes: options.maxArgBytes });
    if (problem) {
      if (problem.code === CODES.ARG_TYPE) allStrings = false;
      findings.push(makeFinding(problem.code, 'high', problem.message, { index }));
    } else {
      totalBytes += byteLength(args[index]);
    }
  }
  if (totalBytes > options.maxArgvBytes) {
    findings.push(makeFinding(CODES.ARGV_TOO_LONG, 'high', 'combined argument byte length exceeds the configured limit', { count: totalBytes }));
  }
  return allStrings;
}

function firstEndOfOptions(args) {
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--') return index;
  }
  return -1;
}

function activeOptionIndex(index, endIndex) {
  return endIndex === -1 || index < endIndex;
}

function longFlag(raw, flag) {
  const lower = raw.toLowerCase();
  return lower === flag || lower.startsWith(flag + '=');
}

function shortFlag(raw, flag) {
  return raw === flag || (raw.startsWith(flag) && !raw.startsWith('--') && raw.length > flag.length);
}

function shortClusterIncludes(raw, letter) {
  return raw.startsWith('-') && !raw.startsWith('--') && raw.length > 2 && raw.slice(1).includes(letter);
}

function addDanger(findings, severity, message, index, flag) {
  findings.push(makeFinding(CODES.DANGEROUS_FLAG, severity, message, { index, flag }));
}

function canonicalToolName(command) {
  return canonicalExecutableName(executableBasename(command));
}

function auditDangerousArgv(command, args, findings) {
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) return;
  const tool = canonicalToolName(command);
  const endIndex = firstEndOfOptions(args);
  const isPowerShell = POWERSHELL_EXECUTABLES.has(tool);
  const isShell = SHELL_EXECUTABLES.has(tool);

  for (let index = 0; index < args.length; index += 1) {
    const raw = args[index];
    const lower = raw.toLowerCase();
    const active = activeOptionIndex(index, endIndex);

    if (lower.startsWith('ext::')) {
      findings.push(makeFinding(CODES.DANGEROUS_GADGET, 'critical', 'git ext transport gadget can execute an external command', { index, flag: 'ext::' }));
    }

    if (!active) continue;

    if (isShell) {
      if ((tool === 'cmd' && (lower === '/c' || lower === '/k')) ||
          (isPowerShell && ['-c', '-command', '-enc', '-encodedcommand', '-e'].includes(lower)) ||
          (!isPowerShell && tool !== 'cmd' && raw === '-c')) {
        addDanger(findings, 'critical', 'shell interpreter command execution flag detected', index, raw);
        continue;
      }
    }

    if (tool === 'git') {
      if (raw === '-c' || shortFlag(raw, '-c')) {
        addDanger(findings, 'critical', 'git -c can redefine configuration and execution behavior', index, '-c');
      } else if (longFlag(raw, '--config-env')) {
        addDanger(findings, 'critical', 'git --config-env can import attacker controlled configuration', index, '--config-env');
      } else if (longFlag(raw, '--upload-pack')) {
        addDanger(findings, 'critical', 'git --upload-pack can execute an arbitrary helper', index, '--upload-pack');
      } else if (longFlag(raw, '--exec-path')) {
        addDanger(findings, 'high', 'git --exec-path changes where git resolves helper programs', index, '--exec-path');
      }
    }

    if (tool === 'tar') {
      if (longFlag(raw, '--checkpoint-action')) {
        addDanger(findings, 'critical', 'tar --checkpoint-action can execute commands while extracting', index, '--checkpoint-action');
      } else if (longFlag(raw, '--to-command')) {
        addDanger(findings, 'critical', 'tar --to-command pipes archive members into a command', index, '--to-command');
      } else if (shortFlag(raw, '-I') || shortClusterIncludes(raw, 'I') || longFlag(raw, '--use-compress-program')) {
        addDanger(findings, 'critical', 'tar compression helper flags can execute arbitrary commands', index, raw.includes('I') ? '-I' : '--use-compress-program');
      } else if (longFlag(raw, '--rsh-command') || longFlag(raw, '--info-script') || shortFlag(raw, '-F') || shortClusterIncludes(raw, 'F')) {
        addDanger(findings, 'critical', 'tar helper command flag detected', index, raw);
      }
    }

    if (tool === 'find') {
      if (['-exec', '-execdir', '-ok', '-okdir'].includes(raw)) {
        addDanger(findings, 'critical', 'find execution primary detected', index, raw);
      }
    }

    if (tool === 'curl') {
      if (shortFlag(raw, '-K') || shortClusterIncludes(raw, 'K') || longFlag(raw, '--config')) {
        addDanger(findings, 'high', 'curl config file input can change output and transfer behavior', index, raw.includes('K') ? '-K' : '--config');
      } else if (shortFlag(raw, '-o') || shortClusterIncludes(raw, 'o') || longFlag(raw, '--output')) {
        addDanger(findings, 'high', 'curl output flags can overwrite attacker selected files', index, raw.includes('o') ? '-o' : '--output');
      } else if (shortFlag(raw, '-T') || shortClusterIncludes(raw, 'T') || longFlag(raw, '--upload-file')) {
        addDanger(findings, 'high', 'curl upload flags can read attacker selected files', index, raw.startsWith('-T') ? '-T' : '--upload-file');
      }
    }

    if (['ssh', 'scp', 'sftp', 'rsync'].includes(tool)) {
      const next = index + 1 < args.length ? args[index + 1].toLowerCase() : '';
      const proxyInNext = next.includes('proxycommand') || next.includes('permitlocalcommand') || next.includes('localcommand');
      const proxyInRaw = lower.includes('proxycommand') || lower.includes('permitlocalcommand') || lower.includes('localcommand');
      if (raw === '-o' && proxyInNext) {
        addDanger(findings, 'critical', 'ssh option can execute a local proxy command', index, '-o');
      } else if (shortFlag(raw, '-o') && proxyInRaw) {
        addDanger(findings, 'critical', 'ssh option can execute a local proxy command', index, '-o');
      } else if (shortFlag(raw, '-e') || longFlag(raw, '--rsh') || longFlag(raw, '--rsync-path') || shortFlag(raw, '-S')) {
        addDanger(findings, 'critical', 'remote shell or transport override can execute arbitrary commands', index, raw);
      }
    }

    if (tool === 'node' || tool === 'nodejs' || tool === 'bun' || tool === 'deno') {
      if (shortFlag(raw, '-e') || longFlag(raw, '--eval') || shortFlag(raw, '-p') || longFlag(raw, '--print')) {
        addDanger(findings, 'critical', 'JavaScript runtime eval flag detected', index, raw);
      } else if (shortFlag(raw, '-r') || longFlag(raw, '--require') || longFlag(raw, '--import') || longFlag(raw, '--experimental-loader')) {
        addDanger(findings, 'critical', 'JavaScript runtime preload or import flag can execute attacker controlled code', index, raw);
      }
    }

    if (/^python(?:\d+(?:\.\d+)*)?$/.test(tool) || tool === 'pypy') {
      if (shortFlag(raw, '-c')) {
        addDanger(findings, 'critical', 'Python -c executes attacker controlled code', index, '-c');
      } else if (shortFlag(raw, '-m')) {
        addDanger(findings, 'high', 'Python -m executes a module selected by argv', index, '-m');
      } else if (raw === '-') {
        addDanger(findings, 'critical', 'Python stdin execution marker detected', index, '-');
      }
    }

    if (tool === 'perl' && shortFlag(raw, '-e')) {
      addDanger(findings, 'critical', 'Perl eval flag detected', index, '-e');
    }
    if (tool === 'ruby' && (shortFlag(raw, '-e') || shortFlag(raw, '-r'))) {
      addDanger(findings, 'critical', 'Ruby eval or require flag detected', index, raw);
    }
    if (tool === 'php' && shortFlag(raw, '-r')) {
      addDanger(findings, 'critical', 'PHP eval flag detected', index, '-r');
    }

    if (tool === 'env' && (shortFlag(raw, '-S') || longFlag(raw, '--split-string'))) {
      addDanger(findings, 'high', 'env split-string mode can hide a nested command inside one argument', index, raw);
    }

    if (tool === 'xargs' && (shortFlag(raw, '-I') || shortFlag(raw, '-J') || longFlag(raw, '--replace'))) {
      addDanger(findings, 'high', 'xargs replacement mode can turn stdin into command arguments', index, raw);
    }
  }

  if (tool === 'env') {
    const hasCommand = args.some((arg, index) => {
      if (!activeOptionIndex(index, endIndex)) return true;
      if (arg === '--' || arg.startsWith('-')) return false;
      return !/^[A-Za-z_][A-Za-z0-9_]*=/.test(arg);
    });
    if (hasCommand) {
      findings.push(makeFinding(CODES.DANGEROUS_GADGET, 'high', 'env can invoke a nested command that must be audited separately', { index: 0, flag: 'env' }));
    }
  }
}

function collectInvocationFindings(command, args, options, requireAllowlist, auditMode = false) {
  const findings = [];
  let normalized;
  try {
    normalized = normalizeInvocationOptions(options);
    if (requireAllowlist && normalized.allowExecutables === undefined) {
      fail(CODES.EXECUTABLE_ALLOWLIST_REQUIRED, 'an explicit non-empty executable allowlist is required');
    }
  } catch (error) {
    findings.push(errorFinding(error));
    normalized = {
      allowShellBinary: false,
      allowBatchExtensions: false,
      allowDangerousFlags: false,
      maxArgBytes: DEFAULT_MAX_ARG_BYTES,
      maxArgs: DEFAULT_MAX_ARGS,
      maxArgvBytes: DEFAULT_MAX_ARGV_BYTES
    };
  }

  const executableInfo = inspectExecutableSyntax(command, findings);
  inspectExecutablePolicy(command, executableInfo, normalized, findings);
  const argsAreStrings = inspectArgv(args, normalized, findings);
  if (argsAreStrings && (auditMode || normalized.allowDangerousFlags !== true)) {
    auditDangerousArgv(command, Array.isArray(args) ? args : [], findings);
  }
  return { findings, normalized, executableInfo, argsAreStrings };
}

export function validateInvocation(command, args = [], options = {}) {
  const collected = collectInvocationFindings(command, args, options, true);
  const findings = freezeFindings(collected.findings);
  const argvCopy = Array.isArray(args) ? args.slice() : [];
  return deepFreeze({
    ok: findings.length === 0,
    command: typeof command === 'string' ? command : '',
    args: argvCopy,
    findings
  });
}

export function auditArgv(command, args = [], options = {}) {
  const collected = collectInvocationFindings(command, args, options, false, true);
  return freezeFindings(collected.findings);
}

function assertValidInvocation(command, args, options) {
  const report = validateInvocation(command, args, options);
  if (!report.ok) {
    const first = report.findings[0];
    fail(first.code, first.message, { findings: report.findings });
  }
  return { command, args: args.slice() };
}

const SLOT_KEYS = Object.freeze({
  literal: new Set(['type', 'value']),
  flag: new Set(['type', 'name', 'flag', 'value', 'join', 'allowLeadingDashValue']),
  positional: new Set(['type', 'value', 'allowEmpty']),
  path: new Set(['type', 'value', 'allowEmpty']),
  endOfOptions: new Set(['type'])
});

function assertArgvSlotObject(slot, index) {
  if (!isPlainObject(slot)) fail(CODES.ARGV_SPEC_INVALID, 'argv builder slots must be plain objects', { index });
  if (typeof slot.type !== 'string') fail(CODES.ARGV_SPEC_INVALID, 'argv builder slot requires a type', { index });
  const allowed = SLOT_KEYS[slot.type];
  if (!allowed) return;
  for (const key of Object.keys(slot)) {
    if (!allowed.has(key)) fail(CODES.ARGV_SPEC_INVALID, 'argv builder slot contains an unknown key', { index, key });
  }
}

function validateFlagName(name, index) {
  if (typeof name !== 'string' || name === '--' || !FLAG_NAME_RE.test(name)) {
    fail(CODES.ARGV_SPEC_INVALID, 'flag slot name must be a simple ASCII option spelling', { index });
  }
}

export function buildArgv(spec) {
  if (!Array.isArray(spec)) fail(CODES.ARGV_SPEC_INVALID, 'argv builder input must be an array of typed slots');
  if (spec.length > DEFAULT_MAX_ARGS) fail(CODES.ARGV_SPEC_INVALID, 'argv builder input exceeds the slot limit');
  const output = [];
  let seenEnd = false;

  for (let index = 0; index < spec.length; index += 1) {
    const slot = spec[index];
    assertArgvSlotObject(slot, index);
    if (slot.type === 'endOfOptions') {
      if (seenEnd) fail(CODES.ARGV_SPEC_INVALID, 'argv builder accepts only one end-of-options marker', { index });
      seenEnd = true;
      output.push('--');
      continue;
    }

    if (slot.type === 'literal') {
      if (!Object.prototype.hasOwnProperty.call(slot, 'value')) {
        fail(CODES.ARGV_SPEC_INVALID, 'literal slot requires a value', { index });
      }
      assertSafeArg(slot.value, { positional: false, maxBytes: DEFAULT_MAX_ARG_BYTES });
      output.push(slot.value);
      continue;
    }

    if (slot.type === 'flag') {
      if (slot.name !== undefined && slot.flag !== undefined) {
        fail(CODES.ARGV_SPEC_INVALID, 'flag slot must use either name or flag, not both', { index });
      }
      if (slot.allowLeadingDashValue !== undefined && typeof slot.allowLeadingDashValue !== 'boolean') {
        fail(CODES.ARGV_SPEC_INVALID, 'allowLeadingDashValue must be a boolean', { index });
      }
      const name = slot.name !== undefined ? slot.name : slot.flag;
      validateFlagName(name, index);
      output.push(name);
      if (slot.value !== undefined) {
        const join = slot.join === undefined ? 'separate' : slot.join;
        if (join !== 'separate' && join !== 'equals') {
          fail(CODES.ARGV_SPEC_INVALID, 'flag slot join must be separate or equals', { index });
        }
        if (join === 'equals') {
          assertSafeArg(slot.value, { positional: false, maxBytes: DEFAULT_MAX_ARG_BYTES });
          output[output.length - 1] = name + '=' + slot.value;
        } else {
          assertSafeArg(slot.value, {
            positional: slot.allowLeadingDashValue === true ? false : true,
            maxBytes: DEFAULT_MAX_ARG_BYTES
          });
          output.push(slot.value);
        }
      }
      continue;
    }

    if (slot.type === 'positional' || slot.type === 'path') {
      if (!Object.prototype.hasOwnProperty.call(slot, 'value')) {
        fail(CODES.ARGV_SPEC_INVALID, 'positional and path slots require a value', { index });
      }
      if (slot.allowEmpty !== undefined && typeof slot.allowEmpty !== 'boolean') {
        fail(CODES.ARGV_SPEC_INVALID, 'allowEmpty must be a boolean', { index });
      }
      const positionalOptions = {
        positional: !seenEnd,
        allowEmpty: slot.type === 'path' ? false : slot.allowEmpty !== false,
        maxBytes: DEFAULT_MAX_ARG_BYTES
      };
      assertSafeArg(slot.value, positionalOptions);
      output.push(slot.value);
      continue;
    }

    fail(CODES.ARGV_SPEC_INVALID, 'unknown argv builder slot type', { index });
  }

  return Object.freeze(output);
}

function isDangerousEnvName(name) {
  const upper = String(name).toUpperCase();
  if (EXACT_DANGEROUS_ENV_NAMES.has(upper)) return true;
  for (const prefix of DANGEROUS_ENV_PREFIXES) {
    if (upper.startsWith(prefix)) return true;
  }
  return false;
}

function validateEnvKeyShape(key) {
  if (typeof key !== 'string' || key.length === 0) return CODES.ENV_KEY_INVALID;
  if (byteLength(key) > MAX_ENV_KEY_BYTES) return CODES.ENV_KEY_INVALID;
  if (key.includes('=') || key.includes('\0')) return CODES.ENV_KEY_INVALID;
  if (!PRINTABLE_ENV_KEY_RE.test(key)) return CODES.ENV_KEY_INVALID;
  if (PROTOTYPE_KEYS.has(key.toLowerCase())) return CODES.ENV_KEY_PROTOTYPE;
  return null;
}

function normalizeEnvOptions(options) {
  const source = options === undefined ? {} : options;
  assertPlainObject(source, 'environment options');
  assertOnlyKeys(source, ENV_OPTION_KEYS, 'environment options');
  const normalized = {
    maxValueBytes: integerValue(source.maxValueBytes, DEFAULT_MAX_ENV_VALUE_BYTES, 1, MAX_ENV_VALUE_BYTES_LIMIT, 'maxValueBytes', CODES.CONFIG_INVALID),
    includeUnlisted: booleanValue(source.includeUnlisted, false, 'includeUnlisted')
  };
  if (source.allowEnv === undefined) {
    normalized.allowEnv = DEFAULT_ALLOWED_ENV;
  } else {
    if (!Array.isArray(source.allowEnv)) fail(CODES.CONFIG_INVALID, 'allowEnv must be an array of environment variable names');
    if (source.allowEnv.length > 512) fail(CODES.CONFIG_INVALID, 'allowEnv exceeds the entry limit');
    for (const key of source.allowEnv) {
      const problem = validateEnvKeyShape(key);
      if (problem) fail(CODES.CONFIG_INVALID, 'allowEnv contains an invalid environment variable name', { key });
    }
    normalized.allowEnv = Object.freeze(source.allowEnv.slice());
  }
  return normalized;
}

function envAllowlistMap(allowEnv) {
  const map = new Map();
  for (const key of allowEnv) {
    const upper = key.toUpperCase();
    if (!map.has(upper)) map.set(upper, key);
  }
  return map;
}

function assertEnvSource(source) {
  if (source === null || typeof source !== 'object' || Array.isArray(source)) {
    fail(CODES.ENV_NOT_OBJECT, 'environment input must be an object');
  }
}

export function auditEnv(source = process.env, options = {}) {
  assertEnvSource(source);
  const normalized = normalizeEnvOptions(options);
  const allowed = envAllowlistMap(normalized.allowEnv);
  const findings = [];
  const seen = new Map();

  for (const key of Object.keys(source)) {
    const upper = key.toUpperCase();
    const keyProblem = validateEnvKeyShape(key);
    if (keyProblem === CODES.ENV_KEY_PROTOTYPE) {
      findings.push(makeFinding(CODES.ENV_KEY_PROTOTYPE, 'critical', 'environment key collides with a prototype pollution name', { key }));
    } else if (keyProblem) {
      findings.push(makeFinding(CODES.ENV_KEY_INVALID, 'high', 'environment key contains forbidden characters or is empty', { key: '[invalid key]' }));
    }

    if (seen.has(upper) && seen.get(upper) !== key) {
      findings.push(makeFinding(CODES.ENV_DUPLICATE_KEY, 'medium', 'environment contains duplicate keys that differ only by case', { key }));
    } else if (!seen.has(upper)) {
      seen.set(upper, key);
    }

    if (isDangerousEnvName(key)) {
      findings.push(makeFinding(CODES.ENV_INJECTION, 'critical', 'environment variable can hijack a runtime, linker, shell, or helper command', { key }));
    }

    if (normalized.includeUnlisted && !allowed.has(upper)) {
      findings.push(makeFinding(CODES.ENV_NOT_ALLOWLISTED, 'info', 'environment variable is not present in the explicit allowlist', { key }));
    }

    const value = source[key];
    if (typeof value !== 'string') {
      findings.push(makeFinding(CODES.ENV_VALUE_TYPE, 'high', 'environment value must be a string', { key }));
      continue;
    }
    if (value.includes('\0')) {
      findings.push(makeFinding(CODES.ENV_VALUE_NUL_BYTE, 'high', 'environment value contains a NUL byte', { key }));
    }
    if (byteLength(value) > normalized.maxValueBytes) {
      findings.push(makeFinding(CODES.ENV_VALUE_TOO_LONG, 'medium', 'environment value exceeds the byte limit', { key }));
    }
  }
  return freezeFindings(findings);
}

export function sanitizeEnv(source = process.env, options = {}) {
  assertEnvSource(source);
  const normalized = normalizeEnvOptions(options);
  const allowed = envAllowlistMap(normalized.allowEnv);
  const output = Object.create(null);

  for (const key of Object.keys(source)) {
    const upper = key.toUpperCase();
    const canonical = allowed.get(upper);
    if (canonical === undefined) continue;
    if (Object.prototype.hasOwnProperty.call(output, canonical)) continue;
    if (validateEnvKeyShape(key)) continue;
    if (isDangerousEnvName(key)) continue;
    const value = source[key];
    if (typeof value !== 'string') continue;
    if (value.includes('\0')) continue;
    if (byteLength(value) > normalized.maxValueBytes) continue;
    output[canonical] = value;
  }
  return Object.freeze(output);
}

function prepareEnvironment(options) {
  const source = options.env === undefined ? process.env : options.env;
  return sanitizeEnv(source, {
    allowEnv: options.allowEnv,
    maxValueBytes: options.maxEnvValueBytes
  });
}

function isAbsolutePathForCwd(value) {
  return path.isAbsolute(value) || WINDOWS_ABSOLUTE_RE.test(value) || String(value).startsWith('\\\\');
}

function realExistingDirectory(value, code) {
  let real;
  try {
    real = fs.realpathSync(value);
  } catch {
    fail(code, 'working directory does not exist or cannot be resolved');
  }
  let stat;
  try {
    stat = fs.statSync(real);
  } catch {
    fail(code, 'working directory cannot be inspected');
  }
  if (!stat.isDirectory()) fail(CODES.CWD_NOT_DIRECTORY, 'working directory is not a directory');
  return real;
}

function pathContained(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function prepareCwd(options) {
  const hasCwd = options.cwd !== undefined;
  const hasRoots = options.allowedCwdRoots !== undefined;
  if (!hasCwd && !hasRoots) return undefined;

  let candidate;
  if (hasCwd) {
    if (typeof options.cwd !== 'string' || options.cwd.length === 0 || options.cwd.includes('\0') || CONTROL_CHAR_RE.test(options.cwd)) {
      fail(CODES.CWD_TYPE, 'cwd must be a non-empty string without control characters');
    }
    if (!isAbsolutePathForCwd(options.cwd)) fail(CODES.CWD_NOT_ABSOLUTE, 'cwd must be an absolute path');
    candidate = realExistingDirectory(options.cwd, CODES.CWD_NOT_FOUND);
  } else {
    candidate = realExistingDirectory(process.cwd(), CODES.CWD_NOT_FOUND);
  }

  if (hasRoots) {
    if (!Array.isArray(options.allowedCwdRoots) || options.allowedCwdRoots.length === 0 || options.allowedCwdRoots.length > 64) {
      fail(CODES.CWD_ROOT_INVALID, 'allowedCwdRoots must be a non-empty array of absolute directories');
    }
    const roots = options.allowedCwdRoots.map((root) => {
      if (typeof root !== 'string' || root.length === 0 || root.includes('\0') || CONTROL_CHAR_RE.test(root) || !isAbsolutePathForCwd(root)) {
        fail(CODES.CWD_ROOT_INVALID, 'allowedCwdRoots entries must be absolute directory paths');
      }
      return realExistingDirectory(root, CODES.CWD_ROOT_INVALID);
    });
    if (!roots.some((root) => pathContained(root, candidate))) {
      fail(CODES.CWD_OUTSIDE_ROOT, 'working directory escapes every allowed root');
    }
  }
  return candidate;
}

function normalizeExecutionOptions(options) {
  const normalized = normalizeInvocationOptions(options);
  normalized.timeoutMs = integerValue(normalized.timeoutMs, DEFAULT_TIMEOUT_MS, 1, MAX_TIMEOUT_MS, 'timeoutMs', CODES.TIMEOUT_INVALID);
  normalized.maxStdoutBytes = integerValue(normalized.maxStdoutBytes, DEFAULT_MAX_STDOUT_BYTES, 1, MAX_OUTPUT_BYTES, 'maxStdoutBytes', CODES.OUTPUT_LIMIT_INVALID);
  normalized.maxStderrBytes = integerValue(normalized.maxStderrBytes, DEFAULT_MAX_STDERR_BYTES, 1, MAX_OUTPUT_BYTES, 'maxStderrBytes', CODES.OUTPUT_LIMIT_INVALID);
  normalized.maxStdinBytes = integerValue(normalized.maxStdinBytes, DEFAULT_MAX_STDIN_BYTES, 0, MAX_OUTPUT_BYTES, 'maxStdinBytes', CODES.OUTPUT_LIMIT_INVALID);
  if (normalized.stdin !== undefined && typeof normalized.stdin !== 'string' && !Buffer.isBuffer(normalized.stdin)) {
    fail(CODES.STDIN_INVALID, 'stdin must be a string or Buffer');
  }
  if (normalized.stdin !== undefined) {
    const size = Buffer.isBuffer(normalized.stdin) ? normalized.stdin.length : byteLength(normalized.stdin);
    if (size > normalized.maxStdinBytes) fail(CODES.STDIN_TOO_LARGE, 'stdin exceeds the configured byte limit');
  }
  if (normalized.killSignal !== undefined) {
    if (typeof normalized.killSignal !== 'string' || !ALLOWED_KILL_SIGNALS.has(normalized.killSignal)) {
      fail(CODES.CONFIG_INVALID, 'killSignal must be one of SIGTERM, SIGKILL, SIGINT, SIGHUP, or SIGQUIT');
    }
  } else {
    normalized.killSignal = 'SIGTERM';
  }
  normalized.envObject = prepareEnvironment(normalized);
  normalized.cwdPath = prepareCwd(normalized);
  return normalized;
}

function terminateChild(child, signal) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    child.kill(signal);
  } catch {
    return;
  }
}

function collectChildResult(child, command, options, startedAt) {
  return new Promise((resolve, reject) => {
    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let truncatedStdout = false;
    let truncatedStderr = false;
    let settled = false;
    let failedToStart = false;

    let forceKillTimer = null;
    function scheduleForceKill() {
      if (forceKillTimer !== null) return;
      forceKillTimer = setTimeout(() => terminateChild(child, 'SIGKILL'), KILL_GRACE_MS);
      if (typeof forceKillTimer.unref === 'function') forceKillTimer.unref();
    }

    const timeoutTimer = setTimeout(() => {
      timedOut = true;
      terminateChild(child, options.killSignal);
      scheduleForceKill();
    }, options.timeoutMs);
    if (typeof timeoutTimer.unref === 'function') timeoutTimer.unref();

    function killForTruncation() {
      terminateChild(child, options.killSignal);
      scheduleForceKill();
    }

    function cleanup() {
      clearTimeout(timeoutTimer);
      if (forceKillTimer !== null) clearTimeout(forceKillTimer);
    }

    child.stdout.on('data', (chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (stdoutBytes < options.maxStdoutBytes) {
        const remaining = options.maxStdoutBytes - stdoutBytes;
        const accepted = buffer.subarray(0, remaining);
        if (accepted.length > 0) stdoutChunks.push(Buffer.from(accepted));
        stdoutBytes += accepted.length;
        if (buffer.length > remaining) {
          truncatedStdout = true;
          killForTruncation();
        }
      } else if (buffer.length > 0) {
        truncatedStdout = true;
        killForTruncation();
      }
    });

    child.stderr.on('data', (chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (stderrBytes < options.maxStderrBytes) {
        const remaining = options.maxStderrBytes - stderrBytes;
        const accepted = buffer.subarray(0, remaining);
        if (accepted.length > 0) stderrChunks.push(Buffer.from(accepted));
        stderrBytes += accepted.length;
        if (buffer.length > remaining) {
          truncatedStderr = true;
          killForTruncation();
        }
      } else if (buffer.length > 0) {
        truncatedStderr = true;
        killForTruncation();
      }
    });

    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      failedToStart = true;
      cleanup();
      reject(new ShellCageError(CODES.SPAWN_FAILED, 'child process failed to start or emitted an error', {
        systemCode: typeof error.code === 'string' ? error.code : 'UNKNOWN'
      }));
    });

    child.on('close', (exitCode, signal) => {
      if (settled || failedToStart) return;
      settled = true;
      cleanup();
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1000000;
      resolve(Object.freeze({
        command,
        exitCode,
        signal,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        timedOut,
        truncatedStdout,
        truncatedStderr,
        durationMs
      }));
    });
  });
}

export function safeSpawn(command, args = [], options = {}) {
  assertValidInvocation(command, args, options);
  const normalized = normalizeInvocationOptions(options);
  if (normalized.maxStdoutBytes !== undefined || normalized.maxStderrBytes !== undefined) {
    fail(CODES.CONFIG_INVALID, 'safeSpawn cannot enforce stdout or stderr byte caps; use safeExecFile');
  }
  if (normalized.timeoutMs !== undefined) {
    normalized.timeoutMs = integerValue(normalized.timeoutMs, DEFAULT_TIMEOUT_MS, 1, MAX_TIMEOUT_MS, 'timeoutMs', CODES.TIMEOUT_INVALID);
  }
  if (normalized.maxStdinBytes !== undefined) {
    normalized.maxStdinBytes = integerValue(normalized.maxStdinBytes, DEFAULT_MAX_STDIN_BYTES, 0, MAX_OUTPUT_BYTES, 'maxStdinBytes', CODES.OUTPUT_LIMIT_INVALID);
  }
  if (normalized.stdin !== undefined) {
    if (typeof normalized.stdin !== 'string' && !Buffer.isBuffer(normalized.stdin)) {
      fail(CODES.STDIN_INVALID, 'stdin must be a string or Buffer');
    }
    const size = Buffer.isBuffer(normalized.stdin) ? normalized.stdin.length : byteLength(normalized.stdin);
    const limit = normalized.maxStdinBytes === undefined ? DEFAULT_MAX_STDIN_BYTES : normalized.maxStdinBytes;
    if (size > limit) fail(CODES.STDIN_TOO_LARGE, 'stdin exceeds the configured byte limit');
  }
  if (normalized.killSignal !== undefined && (typeof normalized.killSignal !== 'string' || !ALLOWED_KILL_SIGNALS.has(normalized.killSignal))) {
    fail(CODES.CONFIG_INVALID, 'killSignal must be one of SIGTERM, SIGKILL, SIGINT, SIGHUP, or SIGQUIT');
  }
  const env = prepareEnvironment(normalized);
  const cwd = prepareCwd(normalized);
  const spawnOptions = {
    shell: false,
    windowsVerbatimArguments: false,
    env,
    stdio: ['pipe', 'pipe', 'pipe']
  };
  if (cwd !== undefined) spawnOptions.cwd = cwd;
  if (normalized.windowsHide !== undefined) spawnOptions.windowsHide = normalized.windowsHide;

  const child = spawn(command, args, spawnOptions);
  if (normalized.stdin !== undefined) {
    child.stdin.on('error', () => {});
    child.stdin.end(normalized.stdin);
  } else {
    child.stdin.end();
  }
  if (normalized.timeoutMs !== undefined) {
    const timer = setTimeout(() => {
      terminateChild(child, normalized.killSignal || 'SIGTERM');
    }, normalized.timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
    child.once('close', () => clearTimeout(timer));
  }
  return child;
}

export function safeExecFile(command, args = [], options = {}) {
  assertValidInvocation(command, args, options);
  const normalized = normalizeExecutionOptions(options);
  const spawnOptions = {
    shell: false,
    windowsVerbatimArguments: false,
    env: normalized.envObject,
    stdio: ['pipe', 'pipe', 'pipe']
  };
  if (normalized.cwdPath !== undefined) spawnOptions.cwd = normalized.cwdPath;
  if (normalized.windowsHide !== undefined) spawnOptions.windowsHide = normalized.windowsHide;

  const startedAt = process.hrtime.bigint();
  const child = spawn(command, args, spawnOptions);
  child.stdin.on('error', () => {});
  if (normalized.stdin !== undefined) child.stdin.end(normalized.stdin);
  else child.stdin.end();
  return collectChildResult(child, command, normalized, startedAt);
}

function mergeOptions(base, overrides) {
  const source = overrides === undefined ? {} : overrides;
  assertPlainObject(source, 'option overrides');
  return { ...base, ...source };
}

const CAGE_ENV_OVERRIDE_KEYS = new Set(['allowEnv', 'maxEnvValueBytes', 'includeUnlisted']);

function mergeCageEnvOptions(base, overrides) {
  const source = overrides === undefined ? {} : overrides;
  assertPlainObject(source, 'environment option overrides');
  assertOnlyKeys(source, CAGE_ENV_OVERRIDE_KEYS, 'environment option overrides');
  return { ...base, ...source };
}

export function createShellCage(options = {}) {
  const base = normalizeInvocationOptions(options);
  if (base.allowExecutables === undefined) {
    fail(CODES.EXECUTABLE_ALLOWLIST_REQUIRED, 'an explicit non-empty executable allowlist is required');
  }
  normalizeAllowlist(base.allowExecutables);
  const configCopy = { ...base };
  if (Array.isArray(configCopy.allowExecutables)) configCopy.allowExecutables = configCopy.allowExecutables.slice();
  if (Array.isArray(configCopy.allowEnv)) configCopy.allowEnv = configCopy.allowEnv.slice();
  if (Array.isArray(configCopy.allowedCwdRoots)) configCopy.allowedCwdRoots = configCopy.allowedCwdRoots.slice();
  if (configCopy.env !== undefined) configCopy.env = { ...configCopy.env };
  if (Buffer.isBuffer(configCopy.stdin)) configCopy.stdin = Buffer.from(configCopy.stdin);
  const frozenBase = deepFreeze(configCopy);

  const cage = {
    validateInvocation(command, args = [], overrides = {}) {
      return validateInvocation(command, args, mergeOptions(frozenBase, overrides));
    },
    auditArgv(command, args = [], overrides = {}) {
      return auditArgv(command, args, mergeOptions(frozenBase, overrides));
    },
    safeExecFile(command, args = [], overrides = {}) {
      return safeExecFile(command, args, mergeOptions(frozenBase, overrides));
    },
    safeSpawn(command, args = [], overrides = {}) {
      return safeSpawn(command, args, mergeOptions(frozenBase, overrides));
    },
    sanitizeEnv(source = process.env, overrides = {}) {
      const merged = mergeCageEnvOptions(frozenBase, overrides);
      return sanitizeEnv(source, {
        allowEnv: merged.allowEnv,
        maxValueBytes: merged.maxEnvValueBytes
      });
    },
    auditEnv(source = process.env, overrides = {}) {
      const merged = mergeCageEnvOptions(frozenBase, overrides);
      return auditEnv(source, {
        allowEnv: merged.allowEnv,
        maxValueBytes: merged.maxEnvValueBytes,
        includeUnlisted: merged.includeUnlisted
      });
    },
    assertSafeArg,
    safeArg,
    safePathArg,
    buildArgv
  };
  return Object.freeze(cage);
}

const shellcage = Object.freeze({
  SHELLCAGE_VERSION,
  CODES,
  DEFAULT_ALLOWED_ENV,
  ShellCageError,
  createShellCage,
  validateInvocation,
  auditArgv,
  assertSafeArg,
  safeArg,
  safePathArg,
  buildArgv,
  sanitizeEnv,
  auditEnv,
  safeExecFile,
  safeSpawn
});

export default shellcage;
