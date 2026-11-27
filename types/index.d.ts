/// <reference types="node" />

import type { ChildProcess } from 'node:child_process';

export declare const SHELLCAGE_VERSION: '1.0.0';

export declare const CODES: {
  readonly CONFIG_OPTION_UNKNOWN: 'SHELLCAGE_CONFIG_OPTION_UNKNOWN';
  readonly CONFIG_INVALID: 'SHELLCAGE_CONFIG_INVALID';
  readonly SHELL_OPTION_FORBIDDEN: 'SHELLCAGE_SHELL_OPTION_FORBIDDEN';
  readonly EXECUTABLE_TYPE: 'SHELLCAGE_EXECUTABLE_TYPE';
  readonly EXECUTABLE_EMPTY: 'SHELLCAGE_EXECUTABLE_EMPTY';
  readonly EXECUTABLE_TOO_LONG: 'SHELLCAGE_EXECUTABLE_TOO_LONG';
  readonly EXECUTABLE_NUL_BYTE: 'SHELLCAGE_EXECUTABLE_NUL_BYTE';
  readonly EXECUTABLE_CONTROL_CHAR: 'SHELLCAGE_EXECUTABLE_CONTROL_CHAR';
  readonly EXECUTABLE_WHITESPACE: 'SHELLCAGE_EXECUTABLE_WHITESPACE';
  readonly EXECUTABLE_NON_ASCII: 'SHELLCAGE_EXECUTABLE_NON_ASCII';
  readonly EXECUTABLE_TRAILING_DOT: 'SHELLCAGE_EXECUTABLE_TRAILING_DOT';
  readonly EXECUTABLE_NTFS_STREAM: 'SHELLCAGE_EXECUTABLE_NTFS_STREAM';
  readonly EXECUTABLE_TRAVERSAL: 'SHELLCAGE_EXECUTABLE_TRAVERSAL';
  readonly EXECUTABLE_RELATIVE_PATH: 'SHELLCAGE_EXECUTABLE_RELATIVE_PATH';
  readonly EXECUTABLE_NOT_ALLOWLISTED: 'SHELLCAGE_EXECUTABLE_NOT_ALLOWLISTED';
  readonly EXECUTABLE_ALLOWLIST_REQUIRED: 'SHELLCAGE_EXECUTABLE_ALLOWLIST_REQUIRED';
  readonly EXECUTABLE_ALLOWLIST_INVALID: 'SHELLCAGE_EXECUTABLE_ALLOWLIST_INVALID';
  readonly SHELL_BINARY: 'SHELLCAGE_SHELL_BINARY';
  readonly BATCH_EXTENSION: 'SHELLCAGE_BATCH_EXTENSION';
  readonly ARGS_NOT_ARRAY: 'SHELLCAGE_ARGS_NOT_ARRAY';
  readonly ARGV_TOO_MANY: 'SHELLCAGE_ARGV_TOO_MANY';
  readonly ARGV_TOO_LONG: 'SHELLCAGE_ARGV_TOO_LONG';
  readonly ARG_TYPE: 'SHELLCAGE_ARG_TYPE';
  readonly ARG_EMPTY: 'SHELLCAGE_ARG_EMPTY';
  readonly ARG_NUL_BYTE: 'SHELLCAGE_ARG_NUL_BYTE';
  readonly ARG_NEWLINE: 'SHELLCAGE_ARG_NEWLINE';
  readonly ARG_CONTROL_CHAR: 'SHELLCAGE_ARG_CONTROL_CHAR';
  readonly ARG_BIDI_CONTROL: 'SHELLCAGE_ARG_BIDI_CONTROL';
  readonly ARG_TOO_LONG: 'SHELLCAGE_ARG_TOO_LONG';
  readonly ARG_LEADING_DASH: 'SHELLCAGE_ARG_LEADING_DASH';
  readonly ARGV_SPEC_INVALID: 'SHELLCAGE_ARGV_SPEC_INVALID';
  readonly DANGEROUS_FLAG: 'SHELLCAGE_DANGEROUS_FLAG';
  readonly DANGEROUS_GADGET: 'SHELLCAGE_DANGEROUS_GADGET';
  readonly ENV_NOT_OBJECT: 'SHELLCAGE_ENV_NOT_OBJECT';
  readonly ENV_INJECTION: 'SHELLCAGE_ENV_INJECTION';
  readonly ENV_KEY_INVALID: 'SHELLCAGE_ENV_KEY_INVALID';
  readonly ENV_KEY_PROTOTYPE: 'SHELLCAGE_ENV_KEY_PROTOTYPE';
  readonly ENV_DUPLICATE_KEY: 'SHELLCAGE_ENV_DUPLICATE_KEY';
  readonly ENV_VALUE_TYPE: 'SHELLCAGE_ENV_VALUE_TYPE';
  readonly ENV_VALUE_NUL_BYTE: 'SHELLCAGE_ENV_VALUE_NUL_BYTE';
  readonly ENV_VALUE_TOO_LONG: 'SHELLCAGE_ENV_VALUE_TOO_LONG';
  readonly ENV_NOT_ALLOWLISTED: 'SHELLCAGE_ENV_NOT_ALLOWLISTED';
  readonly CWD_TYPE: 'SHELLCAGE_CWD_TYPE';
  readonly CWD_NOT_ABSOLUTE: 'SHELLCAGE_CWD_NOT_ABSOLUTE';
  readonly CWD_NOT_FOUND: 'SHELLCAGE_CWD_NOT_FOUND';
  readonly CWD_NOT_DIRECTORY: 'SHELLCAGE_CWD_NOT_DIRECTORY';
  readonly CWD_OUTSIDE_ROOT: 'SHELLCAGE_CWD_OUTSIDE_ROOT';
  readonly CWD_ROOT_INVALID: 'SHELLCAGE_CWD_ROOT_INVALID';
  readonly TIMEOUT_INVALID: 'SHELLCAGE_TIMEOUT_INVALID';
  readonly OUTPUT_LIMIT_INVALID: 'SHELLCAGE_OUTPUT_LIMIT_INVALID';
  readonly STDIN_INVALID: 'SHELLCAGE_STDIN_INVALID';
  readonly STDIN_TOO_LARGE: 'SHELLCAGE_STDIN_TOO_LARGE';
  readonly SPAWN_FAILED: 'SHELLCAGE_SPAWN_FAILED';
};

export type ShellCageCode = (typeof CODES)[keyof typeof CODES];
export type AuditSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface AuditFinding {
  readonly code: ShellCageCode;
  readonly severity: AuditSeverity;
  readonly message: string;
  readonly index?: number;
  readonly key?: string;
  readonly flag?: string;
  readonly count?: number;
  readonly [detail: string]: unknown;
}

export interface ValidateInvocationResult {
  readonly ok: boolean;
  readonly command: string;
  readonly args: readonly string[];
  readonly findings: readonly AuditFinding[];
}

export interface SafeExecFileResult {
  readonly command: string;
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | string | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly truncatedStdout: boolean;
  readonly truncatedStderr: boolean;
  readonly durationMs: number;
}

export interface ShellCageErrorDetails {
  readonly [key: string]: unknown;
}

export declare class ShellCageError extends Error {
  readonly code: ShellCageCode;
  readonly details: ShellCageErrorDetails;
  constructor(code: ShellCageCode, message: string, details?: Record<string, unknown>);
  toJSON(): {
    name: 'ShellCageError';
    code: ShellCageCode;
    message: string;
    details: ShellCageErrorDetails;
  };
}

export interface InvocationOptions {
  readonly allowExecutables?: readonly string[];
  readonly allowShellBinary?: boolean;
  readonly allowBatchExtensions?: boolean;
  readonly allowDangerousFlags?: boolean;
  readonly maxArgBytes?: number;
  readonly maxArgs?: number;
  readonly maxArgvBytes?: number;
  readonly env?: Record<string, unknown>;
  readonly allowEnv?: readonly string[];
  readonly maxEnvValueBytes?: number;
  readonly cwd?: string;
  readonly allowedCwdRoots?: readonly string[];
  readonly timeoutMs?: number;
  readonly maxStdoutBytes?: number;
  readonly maxStderrBytes?: number;
  readonly maxStdinBytes?: number;
  readonly stdin?: string | Buffer;
  readonly killSignal?: 'SIGTERM' | 'SIGKILL' | 'SIGINT' | 'SIGHUP' | 'SIGQUIT';
  readonly shell?: false;
  readonly windowsVerbatimArguments?: false;
  readonly windowsHide?: boolean;
}


export interface RequiredInvocationOptions extends InvocationOptions {
  readonly allowExecutables: readonly string[];
}

export interface CreateShellCageOptions extends RequiredInvocationOptions {}

export interface ShellCageEnvOverrideOptions {
  readonly allowEnv?: readonly string[];
  readonly maxEnvValueBytes?: number;
  readonly includeUnlisted?: boolean;
}

export interface SafeArgOptions {
  readonly allowNewlines?: boolean;
  readonly rejectLeadingDash?: boolean;
  readonly positional?: boolean;
  readonly maxBytes?: number;
  readonly allowEmpty?: boolean;
}

export interface EnvOptions {
  readonly allowEnv?: readonly string[];
  readonly maxValueBytes?: number;
  readonly includeUnlisted?: boolean;
}

export interface LiteralArgvSlot {
  readonly type: 'literal';
  readonly value: string;
}

export interface FlagArgvSlot {
  readonly type: 'flag';
  readonly name?: string;
  readonly flag?: string;
  readonly value?: string;
  readonly join?: 'separate' | 'equals';
  readonly allowLeadingDashValue?: boolean;
}

export interface PositionalArgvSlot {
  readonly type: 'positional';
  readonly value: string;
  readonly allowEmpty?: boolean;
}

export interface PathArgvSlot {
  readonly type: 'path';
  readonly value: string;
  readonly allowEmpty?: boolean;
}

export interface EndOfOptionsArgvSlot {
  readonly type: 'endOfOptions';
}

export type ArgvSlot =
  | LiteralArgvSlot
  | FlagArgvSlot
  | PositionalArgvSlot
  | PathArgvSlot
  | EndOfOptionsArgvSlot;

export declare function validateInvocation(
  command: string,
  args?: readonly string[],
  options: RequiredInvocationOptions
): ValidateInvocationResult;

export declare function auditArgv(
  command: string,
  args?: readonly string[],
  options?: InvocationOptions
): readonly AuditFinding[];

export declare function assertSafeArg(value: string, options?: SafeArgOptions): string;
export declare function assertSafeArg(value: unknown, options?: SafeArgOptions): asserts value is string;

export declare function safeArg(value: string, options?: SafeArgOptions): string;
export declare function safePathArg(value: string, options?: SafeArgOptions): string;
export declare function buildArgv(spec: readonly ArgvSlot[]): readonly string[];

export declare function sanitizeEnv(
  source?: Record<string, unknown>,
  options?: EnvOptions
): Record<string, string>;

export declare function auditEnv(
  source?: Record<string, unknown>,
  options?: EnvOptions
): readonly AuditFinding[];

export declare function safeSpawn(
  command: string,
  args?: readonly string[],
  options: RequiredInvocationOptions
): ChildProcess;

export declare function safeExecFile(
  command: string,
  args?: readonly string[],
  options: RequiredInvocationOptions
): Promise<SafeExecFileResult>;

export interface ShellCage {
  validateInvocation(
    command: string,
    args?: readonly string[],
    overrides?: InvocationOptions
  ): ValidateInvocationResult;
  auditArgv(
    command: string,
    args?: readonly string[],
    overrides?: InvocationOptions
  ): readonly AuditFinding[];
  safeExecFile(
    command: string,
    args?: readonly string[],
    overrides?: InvocationOptions
  ): Promise<SafeExecFileResult>;
  safeSpawn(
    command: string,
    args?: readonly string[],
    overrides?: InvocationOptions
  ): ChildProcess;
  sanitizeEnv(source?: Record<string, unknown>, overrides?: ShellCageEnvOverrideOptions): Record<string, string>;
  auditEnv(source?: Record<string, unknown>, overrides?: ShellCageEnvOverrideOptions): readonly AuditFinding[];
  assertSafeArg: typeof assertSafeArg;
  safeArg: typeof safeArg;
  safePathArg: typeof safePathArg;
  buildArgv: typeof buildArgv;
}

export declare function createShellCage(options: CreateShellCageOptions): ShellCage;

export declare const DEFAULT_ALLOWED_ENV: readonly ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR'];

declare const shellcage: {
  readonly SHELLCAGE_VERSION: typeof SHELLCAGE_VERSION;
  readonly CODES: typeof CODES;
  readonly DEFAULT_ALLOWED_ENV: typeof DEFAULT_ALLOWED_ENV;
  readonly ShellCageError: typeof ShellCageError;
  readonly createShellCage: typeof createShellCage;
  readonly validateInvocation: typeof validateInvocation;
  readonly auditArgv: typeof auditArgv;
  readonly assertSafeArg: typeof assertSafeArg;
  readonly safeArg: typeof safeArg;
  readonly safePathArg: typeof safePathArg;
  readonly buildArgv: typeof buildArgv;
  readonly sanitizeEnv: typeof sanitizeEnv;
  readonly auditEnv: typeof auditEnv;
  readonly safeExecFile: typeof safeExecFile;
  readonly safeSpawn: typeof safeSpawn;
};

export default shellcage;
