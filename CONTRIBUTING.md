# Contributing to shellcage

Thank you for helping improve a security boundary that other applications depend on. This project intentionally has a small contribution surface.

## Non-negotiable constraints

- Zero runtime dependencies. Do not add a package dependency for parsing, globbing, testing or convenience.
- No install lifecycle scripts.
- Keep Node.js 18 compatibility.
- Keep ESM as the single source of truth in `src/index.mjs`.
- Regenerate the CommonJS build with `node scripts/build-cjs.mjs` and verify it with `node scripts/build-cjs.mjs --check`.
- Keep `shell: false` mandatory. Never add an API that accepts a raw command line or enables shell interpolation.
- Never fixture a real token, cookie, private key, production hostname or secret-bearing environment dump. Use synthetic values only.
- Do not weaken validation just because a common tool is inconvenient. Add an explicit opt-in with a narrow name and document the risk instead.

## Development workflow

1. Write a failing test in `tests/` for the behavior or attack case.
2. Implement the smallest focused change in `src/index.mjs`.
3. Regenerate `dist/index.cjs`.
4. Run `npm test`.
5. Run `node scripts/build-cjs.mjs --check`.
6. Run `npm pack --dry-run` and inspect the file list.
7. Include the exact test count in the pull request description.

## Test expectations

Tests must be deterministic and must not require network access, elevated privileges, a particular shell or a graphical session. Integration tests may execute `process.execPath` because it is the Node.js binary already running the test suite, but eval flags must remain explicitly opted in inside the test.

Every security rejection should assert the stable `code`, not only the message text. Message text can improve; codes are API compatibility surface.

## Documentation expectations

Update the README when behavior, defaults, limits or API shape changes. Threat-model language must remain precise. Do not claim complete protection against a CWE class when the library mitigates one boundary within that class.

## Commit and pull request expectations

- Keep patches focused.
- Do not include generated tarballs, coverage output, logs or `node_modules`.
- Do not rewrite public history without maintainer approval.
- Fill out the pull request checklist, including exact test count and packaging output.

## Security reports

Do not open a public issue for a suspected vulnerability. Follow `SECURITY.md`.
