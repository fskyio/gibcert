# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  `before`/`after` hooks of such a target run on the remote host; `reload`
  hooks stay local. See `docs/remote-deploy.md`.
- `gibcert host test [NAME...]` checks connectivity and does a dry-run
  installation of every deploy target on each host, with setup hints for
  permission failures.
- `gibcert receive`, an internal command run over ssh on the remote host.
- `gibcert deploy --host NAME` restricts a deploy to targets installed on that
  host.
- `plan`, `apply`, and `status` report remote targets per host
  (`deploy CERT/TARGET@HOST`), and `status` does not check them against the
  local filesystem.
- Failed deploys on a remote host are recorded per target and host, shown by
  `status`, and cleared by a later success. Other hosts are still attempted, and
  only unfinished hosts are retried by the next `renew` or `apply`.

### Changed
- `plan`, `apply`, and `renew` reconcile TLSA records for current certificates
  when the published owners differ from the configured `tlsa` names and ports,
  or when no records were published yet, instead of waiting for the next
  renewal. Records left under owners that are no longer configured are removed.

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
- Reject colliding deploy destinations and restrict inherited private-key modes
  to owner access; intentional group access requires an explicit safe mode.
- Validate complete ACME certificate responses against the requested key, names,
  and validity before replacing canonical material or promoting staged keys.
- Bound standalone TLS-ALPN handshake time and concurrency, and close accepted
  transports and drain workers when issuance shuts the listener down.
- Enforce dns-persist wildcard policy from the ACME authorization flag while
  retaining base-domain and alias lookups.
- Reissue certificates when their actual SAN set or known configured issuer
  changes, while preserving valid configured failover and imported certificates.
- Preserve destination UID/GID when replacing deployed files, including the
  unspecified attribute of an owner-only or group-only override.
- Stage complete deploy targets before hooks, roll back partial installation,
  and require a recovery hook for before actions that can stop services.
- Reconcile pending and drifted deployments during scheduled renewal even when
  certificates remain current, without reissuance or renewal jitter.
- Install both manual pages with `make install` and include them in release
  archives and Debian packages.
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

[unreleased]: https://gitfield.org/fsky/gibcert/compare/v0.2.0...HEAD
[0.2.0]: https://gitfield.org/fsky/gibcert/compare/v0.1.0...v0.2.0
[0.1.0]: https://gitfield.org/fsky/gibcert/releases/tag/v0.1.0
