## What changes and why

<!-- One or two sentences. Link the issue: Closes #123 -->

## Checklist

- [ ] Unit tests and `scripts/dev/lint.sh` pass
- [ ] New behaviour has tests; a new module is in the integration matrix
- [ ] Every step stays idempotent and restores its files when it fails
- [ ] New settings are in `MOD_OPTIONS` and the README; `CHANGELOG.md` has an entry under "Unreleased"
- [ ] Secrets stay out of logs, command lines and notifications
