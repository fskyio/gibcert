# Contributing

## Before you start

For anything beyond a small bug fix, open an issue first so we can agree on the approach before you invest time in a patch.

## Guidelines

- Keep diffs narrow and task-focused. Avoid unrelated cleanup in the same patch.
- Match the existing style and package structure.
- Avoid adding new dependencies unless genuinely necessary.
- Run `make check` before submitting. All checks must pass.
- Update docs and generated files where relevant.

## Submitting

Open a pull/merge request against `main`. Small, focused patches are easier to review and more likely to land quickly.

## Reporting issues

File a bug report with the gibcert version (`gibcert version`), your OS and architecture, relevant config (sanitized), and the full error output.

For security issues, see [SECURITY.md](SECURITY.md).
