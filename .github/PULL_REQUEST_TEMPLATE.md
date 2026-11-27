## Summary

- What changed?
- Which threat-model boundary does this affect?

## Verification

- [ ] `npm test` passes
- [ ] Exact test count reported here:
- [ ] `node scripts/build-cjs.mjs --check` passes
- [ ] CLI smoke test passes
- [ ] `npm pack --dry-run` inspected with zero unexpected files
- [ ] No runtime dependencies added
- [ ] No real secrets or secret-shaped fixtures added

## Security review

- [ ] New rejection behavior has stable error codes
- [ ] New tests cover positive and negative cases
- [ ] Documentation states residual risk honestly
- [ ] This patch does not weaken the no-shell default
