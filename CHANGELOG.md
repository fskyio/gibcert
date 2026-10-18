# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `gibcert prune` removes local state the config no longer uses: orphan
  certificates that are expired, revoked, or unreadable (`--certs`, plus
  still-valid ones with `--include-valid`), unused ACME accounts (`--accounts`),
  unused local CAs (`--cas`), and superseded account key archives
  (`--account-keys`). It prints every item with a reason, `--dry-run` previews
  without touching state, and `--except ID` keeps individual items. Accounts and
  CAs that a surviving certificate still needs are kept. Account removal is
  local only. `--yes` requires naming at least one category.

## [0.3.0-rc.1] - 2026-10-11

Upgrading from 0.2.x: run `gibcert check` with the new binary before replacing
the old one. This release rejects some configurations that 0.2.1 accepted (see
the **Breaking** entries), and a configuration error stops `renew` for every
certificate.

### Added
- `names` directive in the `tlsa` block to publish TLSA records under explicit
  (sub)domains instead of the certificate's names. Wildcard names and IP
  addresses are rejected.
- `tlsa reconcile` accepts several certificate names or `--all` to reconcile
  every certificate with a `tlsa` block in one run, continuing past individual
  failures and reporting a summary.
- Native remote deployment over SSH. A `deploy` block can list `host` names, and
  top-level `host` blocks define the machines. gibcert runs `gibcert receive`
  on each host through the system `ssh` binary with strict host key checking.
  `before`/`after` hooks of such a target run on the remote host and their
  output is printed with a `HOST: ` prefix; `reload` hooks stay local. See
  `docs/remote-deploy.md`.
- `gibcert host test [NAME...]` checks connectivity and does a dry run of every
  deploy target on each host, with setup hints for permission failures. The dry
  run creates no directories, writes no material, and runs no hooks.
- `gibcert receive`, an internal command run over ssh on the remote host. Once
  it has read a request it finishes or rolls back even if the connection drops.
- `gibcert deploy --host NAME` restricts a deploy to targets installed on that
  host. `gibcert deploy` always contacts the selected hosts, repairing files
  changed on them.
- `plan`, `list`, and `show` report remote targets per host
  (`deploy CERT/TARGET@HOST`) from deploy records, without checking the local
  filesystem or contacting the host; `plan` stays offline.
- Failed deploys on a remote host are recorded per target and host, shown by
  `show` (`FAILED since TIME: ERROR`) and `list` (`failed`), and cleared by a
  later success. Other hosts are still attempted. `renew` and `apply` contact a
  host only when it has a recorded failure, material it has not received, or a
  changed `owner`, `group`, or `mode`, so an offline host that is already
  current does not fail the run.

### Changed
- **Breaking:** a deploy `before` hook requires an `after` hook. `after` also
  runs with `GIBCERT_EVENT=rollback-deploy` to recover when the `before` hook
  ran and then failed or the installation was rolled back.
- **Breaking:** an explicit `mode` on a deploy target with `key` or `key-der`
  must not grant other access or execute permission (for example `0644`).
  `mode` applies to every file of the target, so move the key to its own target
  if certificates must stay world-readable.
- **Breaking:** deploy destinations must not collide with another output path
  of the configuration on the same host, including after path normalization.
- **Breaking:** a `tlsa` block on a certificate whose names are all IP
  addresses requires `tlsa names`. Default TLSA owners come from DNS names only.
- Inherited private-key modes lose other-access and execute bits and keep owner
  and group access (for example `0644` becomes `0640`), with a warning. On Unix,
  inherited key attributes must come from a trusted file: its directory must
  not be writable by group or other, and its owner must be the gibcert process
  user or the directory's owner. Otherwise defaults apply, with a warning,
  unless the attributes are explicitly configured.
- Deploy targets stage every file and attribute before hooks, replace each file
  atomically, and roll back earlier replacements on installation errors.
  Backups of replaced files are owner-only until a rollback restores them.
- A symbolic link at a deploy destination is replaced by a regular file without
  reading through it, even when the link target's content is current; rollback
  restores the link.
- `renew` reconciles the deploy targets of every certificate on each run, not
  only of due ones: it restores drifted files and retries failed `after` hooks
  from valid stored material, without reissuance or renewal jitter. A
  certificate that is not due still satisfies `requires` when only its deploy
  or TLSA reconciliation fails.
- `plan`, `apply`, and `renew` reconcile TLSA records for current certificates
  when the published owners differ from the configured `tlsa` names and ports,
  when no records were published yet, or when no published record covers the
  stored key, instead of waiting for the next renewal. Records left under owners
  that are no longer configured are removed. A failed reconciliation does not
  hold back deploying stored material unless records were published and none
  covers its key.
- TLSA publishing and stale-record removal send DNS changes in batches for the
  `powerdns` and `rfc2136`/`nsupdate` drivers: one `PATCH` per zone, or one
  nsupdate message when `zone` is set, instead of one request per record.
  `exec` providers still receive one patch per RRset member, since
  `gibdns/draft-01` has no multi-RRset operation.

### Fixed
- Deploys skip a chown that would not change the owner or group, so a user that
  already owns files through a setgid directory can deploy without privileges.
- Publish TLSA records for local CA certificates and rotate them to the
  pre-published next key on renewal; signing previously skipped TLSA and
  dropped its metadata.
- Lowercase TLSA owner names and compare them case-insensitively, so changing
  only the case of a name no longer removes the records just republished.
- Release Windows and Plan 9 lock ownership on process termination, allowing
  later commands to acquire the lock safely.
- Validate complete ACME certificate responses against the requested key, names,
  and validity before replacing canonical material or promoting staged keys.
  Every requested name must appear among the leaf's SANs; SANs added by the CA
  are accepted, and a `notBefore` up to 5 minutes ahead of the local clock is
  tolerated.
- Bound standalone TLS-ALPN handshake time and concurrency, and close accepted
  transports and drain workers when issuance shuts the listener down.
- Enforce dns-persist wildcard policy from the ACME authorization flag while
  retaining base-domain and alias lookups.
- Reissue certificates when their configured names or known configured issuer
  change, while preserving valid configured failover and imported certificates.
  SANs the CA added on its own do not trigger reissuance, and certificates
  issued through a failover issuer by 0.1.0 or 0.2.0 are recognized.
- Preserve destination UID/GID when replacing deployed files, including the
  unspecified attribute of an owner-only or group-only override.
- `plan` no longer announces an `after` hook for changes that only touch mode or
  ownership, which never run hooks.
- When an `after` hook fails after files were installed, the certificate's
  `reload` commands now run; they were lost even after the hook later succeeded.
- `renew` runs reload commands already queued for earlier certificates when it
  stops because the state lock is busy.
- Install both manual pages with `make install` and include them in release
  archives and, gzip-compressed, in Debian packages, which also ship the remote
  deploy example.
- Correct the systemd hardening guidance to document the shipped unit's umask
  behavior and actual sandboxing protections.

## [0.2.1] - 2026-10-02

### Fixed

- `apply` no longer prints a deploy target's "up to date" status for every
  unchanged certificate while another certificate has pending work or fails.
- ACME renewal no longer claims an imported certificate as an ARI replacement
  when the current account did not issue it.

## [0.2.0] - 2026-09-13

### Added

- Frozen [`gibdns/draft-01`](https://gitfield.org/gibdns/gibdns) exec-json
  binding for DNS exec providers, with shared-RRset-safe ACME TXT and
  persistent TLSA edits.

### Changed

- DNS exec providers now speak `gibdns/draft-01` over stdin/stdout JSON. There
  is no compatibility mode for the pre-v0.2 `DNSREC_*` environment protocol.
- The example systemd service no longer sets `UMask=0077`.
- Document official gibdns providers (Cloudflare, deSEC, Gcore) and how to
  install them with the exec driver.

### Removed

- Support for the `DNSREC_*` exec DNS protocol.
- Operation-specific exec provider fields (`present`, `cleanup`, `add-record`,
  and `remove-record`). Use a single `command` for every gibdns method.

## [0.1.0] - 2026-06-06

### Added

- ACME certificate issuance with HTTP-01, DNS-01, TLS-ALPN-01, and
  dns-persist-01 challenges.
- Built-in CA profiles: Let's Encrypt, ZeroSSL, Google Trust Services, Buypass,
  and SSL.com.
- Local CA support for private certificates.
- DNS-01 providers: manual, exec hook, RFC 2136/nsupdate, and PowerDNS.
- DNS alias mode for scoping API tokens to a delegated zone.
- Standalone HTTP-01 and TLS-ALPN-01 listeners.
- Atomic deployment of cert, chain, fullchain, and key files with mode
  enforcement.
- Deploy hooks for service reloads after changed material is installed.
- Plan mode showing pending account, certificate, deploy, and hook actions.
- ACME Renewal Information (ARI) support.
- ACME profiles support.
- ACME IP identifier support.
- dns-persist-01: accounturi, issuer-domain-names, wildcard policy, and
  persistUntil.
- Certificate failover: explicit CA/account fallbacks for issuance outages or
  profile gaps.
- Certificate dependencies.
- Renewal and deploy groups.
- Automatic TLSA record publication and rotation.
- Exec DNS protocol for generic persistent record edits (TLSA, ECH, and future
  DNS-managed material).

[unreleased]: https://gitfield.org/fsky/gibcert/compare/v0.3.0-rc.1...HEAD
[0.3.0-rc.1]: https://gitfield.org/fsky/gibcert/compare/v0.2.1...v0.3.0-rc.1
[0.2.1]: https://gitfield.org/fsky/gibcert/compare/v0.2.0...v0.2.1
[0.2.0]: https://gitfield.org/fsky/gibcert/compare/v0.1.0...v0.2.0
[0.1.0]: https://gitfield.org/fsky/gibcert/releases/tag/v0.1.0
