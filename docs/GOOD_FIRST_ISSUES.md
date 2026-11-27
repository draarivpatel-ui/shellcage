# Good first issues

These ten starter specifications are intentionally narrow. Each should include tests, documentation updates when behavior changes and a regenerated CommonJS build.

## 1. Add a finding catalogue page

Create `docs/FINDINGS.md` that lists every exported stable code, its severity meaning and one safe example. Source the list from `CODES` rather than copying it blindly, and add a hygiene test that every code is documented.

## 2. Add a JSON schema for CLI output

Document the `shellcage audit --json` and `shellcage audit-env --json` shapes in `docs/CLI-JSON.md`. Add tests that compare a real CLI run against the documented required fields.

## 3. Add explicit TypeScript compile fixtures

Add a dependency-free type smoke fixture that uses `tsc` only when a contributor has TypeScript installed locally. It must not become a package dependency or a required CI step unless maintainers decide otherwise.

## 4. Expand PowerShell abbreviated flag detection

Research documented PowerShell abbreviated forms for encoded and inline command flags. Add precise audit tests for each supported form without flagging ordinary positional values after `--`.

## 5. Add GNU long-option abbreviation review

Pick one high-risk GNU long option family, such as `tar --checkpoint-action`, and document whether unambiguous abbreviations can bypass exact matching. Implement a conservative detector only for verified dangerous prefixes.

## 6. Add allowlist fingerprint pinning

Design an opt-in executable SHA-256 pinning API for absolute-path allowlist entries. Specify error codes, Windows case behavior and performance constraints before implementation.

## 7. Add nested env command decomposition

Improve `env` audit handling so simple assignments and options are skipped and the nested command is identified by index. Return structured metadata that lets callers audit the nested argv separately.

## 8. Add safeSpawn stream guard helper

Design an optional wrapper that lets `safeSpawn` callers enforce stdout and stderr caps without hiding ownership of the streams. Keep `safeExecFile` as the recommended bounded API.

## 9. Add Windows fixture matrix without Windows-only tests

Add platform-independent unit fixtures for drive-letter paths, UNC paths, `.bat` casing and `PATHEXT` variants. Tests must run on Linux and macOS without requiring those paths to exist.

## 10. Add threat-model examples for three real tools

Write three short threat-model recipes: one archive extraction tool, one VCS operation and one media converter. Each recipe must state what shellcage proves, what it does not prove and which application authorization layer remains necessary.
