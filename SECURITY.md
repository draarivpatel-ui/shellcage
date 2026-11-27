# Security policy

## Report a vulnerability

Please report suspected vulnerabilities privately through the repository's [GitHub Security Advisory form](https://github.com/draarivpatel-ui/shellcage/security/advisories/new). Do not open a public issue, pull request or discussion with exploit details.

Never include a real token, cookie, private key, victim hostname, proprietary path or secret-bearing environment dump in a report. Use synthetic values and redacted transcripts.

## Supported versions

| Version | Status |
| --- | --- |
| 1.0.x | Intended initial supported release |

Until the package is publicly released, this policy describes the source repository only.

## Scope

In scope:

- A validation bypass that allows a string command line or shell interpreter despite default policy.
- A bypass of the executable allowlist through path normalization, symlink resolution, case handling or extension confusion.
- A CWE-88 positional argument bypass in `buildArgv`, `safeArg` or `safePathArg`.
- A missing hard-denylist environment variable that directly causes runtime code loading or command substitution in a supported execution path.
- Unbounded memory use in stdout or stderr capture.
- A timeout or output cap that fails to terminate a child process.
- A leak of secret environment values through errors, findings or CLI output.

Out of scope:

- The fact that an explicitly allowlisted executable can perform dangerous actions when given dangerous flags.
- Findings that require `allowDangerousFlags`, `allowShellBinary` or `allowBatchExtensions` to be enabled.
- Lack of kernel sandboxing, network isolation or mandatory access control. Those are documented non-goals.
- A static audit false negative for an obscure tool-specific parser feature unless it affects one of the documented high-risk gadgets.
- Denial of service caused by the child process after it is validly executed, except for documented timeout and captured-output bounds.

## Severity guidance

Critical and high severity generally requires a default-configuration bypass with a credible path to command execution, argument injection, environment-controlled code loading or secret disclosure. Lower severity includes hardening gaps, incomplete diagnostics and conservative false positives that reduce safe usability.

## Coordinated disclosure

- Acknowledgment: within 48 hours.
- Initial assessment: within 7 calendar days.
- Fix or mitigation plan: within 30 calendar days for confirmed high-impact reports.
- Coordinated public disclosure: up to 90 days by default, adjusted by mutual agreement when exploitation or user risk requires a different date.
