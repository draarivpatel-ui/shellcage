# shellcage

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/draarivpatel-ui/shellcage/badge)](https://scorecard.dev/viewer/?uri=github.com/draarivpatel-ui/shellcage)

Zero-dependency command injection, argument injection and environment hijack defense for Node.js child processes.

`shellcage` is a small, auditable security library for applications that must execute local programs without turning attacker controlled input into a shell command. It is designed for MCP servers, automation workers, CI helpers, backend job runners and desktop agents that use `child_process` but must enforce a strict boundary around executable selection, argv construction, environment inheritance, working-directory containment, timeouts and output size.

- **Zero dependencies.** Only Node.js core modules are used.
- **No shell execution.** String command lines are rejected, `shell: false` is forced, and `windowsVerbatimArguments` is forbidden.
- **Explicit executable allowlist.** Commands are matched by basename or resolved absolute path. Shell interpreters and Windows batch or script extensions are blocked by default, including trailing-dot and NTFS alternate-data-stream spellings. Resolved absolute-path symlink targets are checked as well as the invoked basename.
- **CWE-88 positional argument defense.** Typed argv builder slots place untrusted values after `--` or validate them as non-flag positionals.
- **Environment scrubbing.** A minimal allowlist is combined with a hard denylist for dynamic linker, runtime, shell and Git hijack variables.
- **Bounded execution.** Timeouts, stdin byte limits and streaming stdout and stderr byte caps are enforced without unbounded buffering.
- **Dual module.** Native ESM and generated CommonJS entry points plus hand-authored TypeScript declarations.

**Tests:** 799 passing with `npm test` (Node 18+).

## Release status

This repository is release-ready source for `shellcage` version 1.0.0. It does not claim that the package has already been published to npm. Until a maintainer publishes it, run it from a source checkout or a privately built tarball.

## Threat model

`shellcage` addresses four concrete classes of child-process risk.

### CWE-78: operating system command injection

CWE-78 occurs when attacker controlled text is concatenated into a command line and interpreted by a shell. Metacharacters such as semicolons, pipes, command substitution and redirection then become new commands. `shellcage` removes the shell from the trust boundary: it accepts an executable plus an argv array, rejects shell interpreters by default, refuses `shell: true`, and never joins argv into a command line.

### CWE-88: argument injection

CWE-88 occurs when a value intended to be positional is interpreted as an option. Examples include a repository named `--upload-pack=...` passed to `git clone`, an archive member or path interpreted as `--checkpoint-action=...` by `tar`, a positional `-K` consumed by `curl`, or an input beginning with `--pre` passed to a search tool. `shellcage` provides typed argv construction so fixed flags and untrusted positionals are not confused. Untrusted positionals are either validated to reject a leading dash or placed after an explicit end-of-options marker.

### CVE-2024-27980 and Windows script execution

CVE-2024-27980 showed that Windows batch-file handling can make `child_process` behavior dangerous even when a caller did not intentionally use a shell. `shellcage` therefore rejects `.bat`, `.cmd`, `.btm`, `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, `.wsh`, `.ps1` and `.com` executables by default on every platform. This cross-platform rule prevents platform-specific behavior from silently reappearing when the same code is deployed on Windows.

### Environment hijacking

Child processes inherit more than data. Variables such as `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`, `PYTHONPATH`, `RUBYOPT`, `PERL5OPT`, `JAVA_TOOL_OPTIONS`, `BASH_ENV`, `GIT_SSH_COMMAND` and `GIT_CONFIG_PARAMETERS` can load code, replace helpers or change runtime behavior before the child reaches its own `main` function. `shellcage` starts from a minimal allowlist, applies a case-insensitive hard denylist, strips prototype-pollution keys and returns a frozen null-prototype environment object.

## Install and module formats

When published by a maintainer:

```sh
npm install shellcage
```

No install scripts, no native builds and no transitive dependencies are used.

### ESM

```js
import { createShellCage, buildArgv } from 'shellcage';
```

### CommonJS

```js
const { createShellCage, buildArgv } = require('shellcage');
```

### TypeScript

Types are included at `types/index.d.ts` and are referenced by the package export map. The declarations use Node.js types such as `Buffer` and `ChildProcess`; TypeScript consumers should have Node.js type declarations available in their own project, as is standard for Node libraries.

## Quick start

```js
import { createShellCage } from 'shellcage';

const cage = createShellCage({
  allowExecutables: ['/usr/bin/git'],
  allowedCwdRoots: ['/srv/workspaces'],
  allowEnv: ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR']
});

const argv = cage.buildArgv([
  { type: 'literal', value: 'clone' },
  { type: 'flag', name: '--depth', value: '1' },
  { type: 'endOfOptions' },
  { type: 'positional', value: userControlledRepository },
  { type: 'path', value: userControlledDestination }
]);

const result = await cage.safeExecFile('/usr/bin/git', argv, {
  cwd: trustedWorkspace,
  timeoutMs: 15000,
  maxStdoutBytes: 1024 * 1024,
  maxStderrBytes: 1024 * 1024
});

if (result.exitCode !== 0) {
  throw new Error('git clone failed');
}
```

The important property is not the specific `git` invocation. It is that `userControlledRepository` cannot become `--upload-pack` because it is either behind `--` or rejected when it starts with a dash.

## MCP server example

An MCP tool that exposes a bounded command should never pass a raw command string through to `exec` or `execFile` with `shell: true`. Validate schema input at the tool boundary, construct typed argv and use a cage with a narrow executable allowlist.

```js
import { createShellCage } from 'shellcage';

const pdfInfoCage = createShellCage({
  allowExecutables: ['/opt/tools/bin/pdfinfo'],
  allowEnv: ['PATH', 'LANG', 'LC_ALL', 'TMPDIR'],
  allowedCwdRoots: ['/var/mcp-work']
});

async function pdfInfoTool(input) {
  if (typeof input.fileName !== 'string') {
    throw new Error('fileName must be a string');
  }

  const argv = pdfInfoCage.buildArgv([
    { type: 'endOfOptions' },
    { type: 'path', value: input.fileName }
  ]);

  const result = await pdfInfoCage.safeExecFile('/opt/tools/bin/pdfinfo', argv, {
    cwd: '/var/mcp-work',
    timeoutMs: 5000,
    maxStdoutBytes: 64 * 1024,
    maxStderrBytes: 16 * 1024
  });

  return {
    exitCode: result.exitCode,
    stdout: result.stdout,
    truncated: result.truncatedStdout
  };
}
```

This still requires application-level authorization and path policy. `safePathArg` is lexical validation, not proof that the file is one the user may read.

## Backend worker example

```js
const cage = createShellCage({
  allowExecutables: ['ffmpeg'],
  allowEnv: ['PATH', 'LANG', 'LC_ALL', 'TMPDIR']
});

const argv = cage.buildArgv([
  { type: 'flag', name: '-hide_banner' },
  { type: 'flag', name: '-i', value: inputPath, allowLeadingDashValue: true },
  { type: 'flag', name: '-f', value: 'null' },
  { type: 'endOfOptions' },
  { type: 'literal', value: '-' }
]);

const result = await cage.safeExecFile('ffmpeg', argv, { timeoutMs: 30000 });
```

Use a separate authorization and filesystem layer to decide whether `inputPath` may be read. `shellcage` prevents the value from becoming an option and prevents environment or shell injection; it does not implement your product's file access policy.

## API

### `createShellCage(options)`

Creates a frozen policy object. `allowExecutables` is required and must be a non-empty array of basenames or absolute paths. Absolute entries are resolved with `fs.realpathSync` when they exist. Basename entries match the basename of the invoked executable.

Returned methods:

- `validateInvocation(command, args?, overrides?)`
- `auditArgv(command, args?, overrides?)`
- `safeExecFile(command, args?, overrides?)`
- `safeSpawn(command, args?, overrides?)`
- `sanitizeEnv(source?, overrides?)`
- `auditEnv(source?, overrides?)`
- `assertSafeArg`, `safeArg`, `safePathArg`, `buildArgv`

Overrides are shallowly merged per call. Array options such as `allowExecutables` and `allowEnv` are replaced, not concatenated.

### Policy options

The most important execution policy options are:

| Option | Default | Meaning |
| --- | --- | --- |
| `allowExecutables` | required | Non-empty basename or absolute-path allowlist. |
| `allowShellBinary` | `false` | Explicitly permit a shell interpreter executable. This does not permit inline command flags. |
| `allowBatchExtensions` | `false` | Explicitly permit Windows batch or script extensions. Avoid this outside a trusted migration boundary. |
| `allowDangerousFlags` | `false` | Explicitly permit flags and gadgets normally found by the execution audit. Prefer removing the flag instead. |
| `allowEnv` | minimal five-name list | Complete environment allowlist. Passing a custom list replaces the default list; it is not additive. |
| `allowedCwdRoots` | unset | Optional realpath containment roots for `cwd`. |

Basename execution inherits the operating system's executable lookup behavior. Where possible, prefer absolute allowlist entries and absolute invocations so the `PATH` lookup is not part of the trust decision. If a basename must be used, treat the scrubbed `PATH` value as security-sensitive configuration.

### `validateInvocation(command, args?, options?)`

Returns a frozen report without executing anything:

```js
{
  ok: false,
  command: 'git',
  args: ['clone'],
  findings: [
    {
      code: 'SHELLCAGE_EXECUTABLE_NOT_ALLOWLISTED',
      severity: 'critical',
      message: 'executable is not present in the explicit allowlist'
    }
  ]
}
```

Security and configuration failures are represented as findings rather than thrown from this function. `safeExecFile` and `safeSpawn` convert the first finding into a `ShellCageError` and attach all findings in `error.details.findings`.

### `auditArgv(command, args?, options?)`

Returns structured static findings for an argv array without requiring an allowlist. It detects high-risk flags and gadgets for tools including `git`, `tar`, `find`, `curl`, `ssh`, `scp`, `sftp`, `rsync`, `node`, Python runtimes, shell interpreters, `env` and `xargs`. Detection is conservative about documented abbreviated forms for PowerShell, Git and GNU tar. It also treats `--` as tool-specific rather than universal: `find` predicates, `cmd` command switches and PowerShell execution switches remain active findings after that token.

Unlike execution validation, auditing reports dangerous flags even when `allowDangerousFlags` is set. The audit is a detector and inventory tool, not a permission decision.

Findings use stable machine-readable codes such as:

- `SHELLCAGE_SHELL_BINARY`
- `SHELLCAGE_BATCH_EXTENSION`
- `SHELLCAGE_ARG_NUL_BYTE`
- `SHELLCAGE_ARG_LEADING_DASH`
- `SHELLCAGE_DANGEROUS_FLAG`
- `SHELLCAGE_DANGEROUS_GADGET`
- `SHELLCAGE_ENV_INJECTION`

The detector honors a conventional `--` end-of-options marker for exact option matching. Tool-specific parsers differ, so this is a conservative heuristic rather than a complete emulation of every CLI parser.

### `assertSafeArg(value, options?)`

Validates one argument and returns it. It throws `ShellCageError` for:

- non-string input
- NUL bytes
- line breaks unless `allowNewlines` is true
- other ASCII and C1 control characters
- bidirectional override controls
- byte length above `maxBytes`
- leading `-` when `positional` or `rejectLeadingDash` is true

### `safeArg(value, options?)`

Strict positional convenience wrapper. It enables positional validation, so a leading dash is rejected unless the value is deliberately placed after `--` by `buildArgv` instead.

### `safePathArg(value, options?)`

Strict positional path convenience wrapper. It is like `safeArg` but rejects an empty path. It performs lexical validation only. It does not prove existence, permissions, containment within a workspace or freedom from symlink races.

### `buildArgv(spec)`

Builds a frozen argv array from typed slots:

```js
buildArgv([
  { type: 'literal', value: 'clone' },
  { type: 'flag', name: '--depth', value: '1' },
  { type: 'flag', name: '--filter', value: 'blob:none', join: 'equals' },
  { type: 'endOfOptions' },
  { type: 'positional', value: repository },
  { type: 'path', value: destination }
]);
```

Slot types:

- `literal`: fixed trusted argv text controlled by the developer.
- `flag`: a validated ASCII flag, optionally with a separate or equals-joined value.
- `positional`: an untrusted positional value. Before `--`, a leading dash is rejected.
- `path`: an untrusted positional path value. Empty values are rejected.
- `endOfOptions`: emits one `--` marker. Positionals after it may begin with a dash because conventional parsers no longer treat them as options.

The builder is strict about unknown slot keys and duplicate end-of-options markers.

### `sanitizeEnv(source?, options?)`

Returns a frozen `Object.create(null)` environment containing only variables whose names are in `allowEnv`, after hard denylist exclusions. The default allowlist is:

```js
['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR']
```

Matching is case-insensitive for policy decisions. The output key uses the spelling supplied in `allowEnv`, preventing case-variant duplicate keys. Values must be strings, must not contain NUL bytes and must fit the configured byte limit.

The hard denylist includes, at minimum:

- dynamic linker variables such as `LD_*` and `DYLD_*`
- Node runtime variables such as `NODE_OPTIONS`, `NODE_EXTRA_CA_CERTS` and `NODE_PATH`
- Python, Ruby, Perl and Java runtime injection variables
- shell startup and expansion variables such as `BASH_ENV`, `ENV`, `IFS`, `SHELLOPTS`, `PS4`, `PROMPT_COMMAND` and exported Bash function names
- Git command and configuration variables such as `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_EXEC_PATH`, `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `GIT_EXT_TRANSPORT`, editor, askpass, proxy, repository-location and template variables, and numbered Git config key or value variables
- runtime and secret-exposure variables such as `NODE_REPL_EXTERNAL_MODULE`, `PYTHONUSERBASE`, `PYTHONBREAKPOINT`, `SSLKEYLOGFILE` and `DOTNET_STARTUP_HOOKS`
- helper command variables such as `EDITOR`, `VISUAL`, `PAGER`, `COMSPEC` and `PATHEXT`

Denylist entries win even when a caller explicitly puts the same name in `allowEnv`.

`HTTP_PROXY` and `HTTPS_PROXY` are not hard-denylisted because legitimate enterprise environments sometimes require them. They are still stripped unless explicitly allowlisted. Treat explicit proxy forwarding as a network-confusion and credential-exposure risk acceptance, especially for lowercase proxy variants consumed by some tools.

### `auditEnv(source?, options?)`

Returns findings for dangerous, invalid, duplicate, oversized or non-string environment entries without printing values. This function never includes an environment value in a finding. Pass `includeUnlisted: true` to add informational findings for names outside the allowlist.

### `safeExecFile(command, args?, options)`

Validates the invocation, scrubs the environment, validates `cwd`, and executes with `shell: false`. It returns a frozen result:

```js
{
  command,
  exitCode,
  signal,
  stdout,
  stderr,
  timedOut,
  truncatedStdout,
  truncatedStderr,
  durationMs
}
```

A nonzero exit code is a result, not an exception. Validation and spawn setup failures throw `ShellCageError`.

Important defaults and limits:

| Option | Default | Maximum |
| --- | ---: | ---: |
| `timeoutMs` | `15000` | `120000` |
| `maxStdoutBytes` | `1048576` | `67108864` |
| `maxStderrBytes` | `1048576` | `67108864` |
| `maxStdinBytes` | `1048576` | `67108864` |

Stdout and stderr caps are streaming caps. If a child exceeds a cap, shellcage stores only bytes up to the cap, marks the matching truncation flag and terminates the child. It does not buffer unbounded output before discovering the excess. When truncation splits a multibyte UTF-8 character, the incomplete trailing bytes are omitted rather than returned as a replacement character.

`timeoutMs` uses `SIGTERM` by default and escalates to `SIGKILL` after a short grace period. `killSignal` may be one of `SIGTERM`, `SIGKILL`, `SIGINT`, `SIGHUP` or `SIGQUIT`.

### `safeSpawn(command, args?, options)`

Applies the same executable, argv, environment and `cwd` validation, then returns the child process object. It is intended for callers that genuinely need streaming control. Output byte caps are only enforced by `safeExecFile`; a `safeSpawn` caller owns the streams and must bound them. Supplying `maxStdoutBytes` or `maxStderrBytes` to `safeSpawn` is rejected rather than silently ignored. If `timeoutMs` is supplied, the timeout is enforced.

### `cwd` containment

When `allowedCwdRoots` is supplied, the effective working directory is resolved with `fs.realpathSync` and must remain inside one resolved root. The boundary check uses path relatives, so `/srv/work` does not contain `/srv/work-other`. This blocks symlink escapes at validation time.

## CLI

The package installs a `shellcage` executable.

### Static argv audit

```sh
shellcage audit -- git clone --upload-pack=example repository
shellcage audit --json -- node -e 'console.log(1)'
```

Exit codes:

- `0`: no findings
- `1`: risky findings
- `2`: usage or input error

The audit does not execute the command.

### Environment audit

```sh
shellcage audit-env
shellcage audit-env --json
shellcage audit-env --env-json fixture.json
```

The environment audit prints keys and finding metadata only. It never prints environment values.

## Scope and limitations

`shellcage` is a validation and execution harness, not a sandbox.

- It does not provide kernel isolation, seccomp, job objects, namespaces, chroot, pledge or resource-control equivalents.
- It does not limit CPU, memory, file descriptors, network access or filesystem writes beyond timeout, stdin and captured output bounds.
- An allowlisted executable can still be dangerous. `git`, `tar`, interpreters and archive tools have many features that execute code or write files. Use `auditArgv`, deny dangerous flags and design the smallest possible command surface.
- The static audit is not a complete parser for every CLI. Long-option abbreviation, shell quoting rules, tool-specific end-of-options behavior and nested command languages are outside its scope.
- `allowDangerousFlags: true`, `allowShellBinary: true` and `allowBatchExtensions: true` are explicit risk acceptances. Combining them can recreate the exact injection boundary this library exists to remove.
- `safePathArg` does not authorize file access. Use application-level path policy, canonicalization and least-privilege filesystem permissions.
- Realpath checks reduce symlink escape risk at validation time but cannot eliminate every filesystem time-of-check to time-of-use race. Hard links cannot expose a single canonical target name, so executable content policy still depends on the integrity of allowlisted paths.
- Environment scrubbing cannot know every future runtime variable. The primary defense is the explicit allowlist, not the denylist.
- `safeSpawn` does not enforce stdout or stderr byte caps because the caller owns those streams.
- The library cannot make a deliberately invoked shell safe. Do not pass shell text to it.

## Security disclosure

Read `SECURITY.md` before reporting a vulnerability. Do not include real secrets, private paths or live exploit payloads in public issues.

## Contributing

Read `CONTRIBUTING.md` and `docs/GOOD_FIRST_ISSUES.md`. All changes must keep zero runtime dependencies, pass the deterministic test suite and keep the CommonJS build reproducible.
