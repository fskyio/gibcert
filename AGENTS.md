# AGENTS

gibcert is a Go CLI for declarative TLS certificate management. Keep changes small, explicit, and easy to audit, especially around private keys, DNS credentials, deploy hooks, permissions, and ACME state.

## Basics

- Keep diffs narrow and task-focused
- Prefer existing package boundaries, helpers, and style
- Avoid new dependencies, broad rewrites, and unrelated cleanup
- Preserve portability unless editing platform-specific code
- Use only the ASCII character subset for code comments
- Add `Co-Authored-By` lines to all commits, indicating name and model used

## Legal headers

- Add the project Apache 2.0 header to new project-owned source files, starting with `SPDX-License-Identifier: Apache-2.0`
- Preserve upstream copyright and license notices in vendored or derived code
- Do not replace the upstream notices in `internal/acme/`; it is derived from Matthew Holt's `acmez` and carries its own license and notice files

## Checks

Prefer using the Makefile for routine tasks instead of raw `go` commands:

```sh
make build
make test
make lint
make fmt
make tidy
make check
```

Use narrower targets while iterating, then run the most relevant Make target before handing work back. `make test-pebble-eab` is for EAB/ACME integration changes and requires spinning up a new Pebble instance (this can be done from a Make target if the user has an OCI container runtime installed).

## Generated

- Run `make completions` after changing CLI commands, flags, help text, or completion behavior.
- Run `make tidy` after changing module dependencies.
- Do not hand-edit generated completion files unless fixing the generator.

## Docs

Update docs and manpages for significant user-visible changes:

- CLI: `docs/cli-reference.md`, `docs/man/gibcert.1`
- Config: `docs/configuration.md`, `docs/man/gibcert.scfg.5`, `etc/gibcert.scfg`
- Workflows/examples: `README.md`, `docs/usage.md`, `contrib/examples/`
- DNS exec/systemd: `docs/exec-dns-providers.md`, `docs/systemd.md`, `contrib/systemd/`
