# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Document official gibdns providers (Cloudflare, deSEC, Gcore) and how to
  install them with the exec driver.

## [0.2.0] - 2026-09-13

### Added

- Frozen [`gibdns/draft-01`](https://foundry.fsky.io/gibdns/gibdns) exec-json
  binding for DNS exec providers, with shared-RRset-safe ACME TXT and
  persistent TLSA edits.

### Changed

- DNS exec providers now speak `gibdns/draft-01` over stdin/stdout JSON. There
  is no compatibility mode for the pre-v0.2 `DNSREC_*` environment protocol.
- The example systemd service no longer sets `UMask=0077`.

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

[unreleased]: https://foundry.fsky.io/fsky/gibcert/compare/v0.2.0...HEAD
[0.2.0]: https://foundry.fsky.io/fsky/gibcert/compare/v0.1.0...v0.2.0
[0.1.0]: https://foundry.fsky.io/fsky/gibcert/releases/tag/v0.1.0
