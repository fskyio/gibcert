# Changelog

## Unreleased

### Features

- ACME certificate issuance with HTTP-01, DNS-01, TLS-ALPN-01, and dns-persist-01 challenges
- Built-in CA profiles: Let's Encrypt, ZeroSSL, Google Trust Services, Buypass, SSL.com
- Local CA support for private certificates
- DNS-01 providers: manual, gibdns exec, RFC 2136/nsupdate, PowerDNS
- DNS alias mode for scoping API tokens to a delegated zone
- Standalone HTTP-01 and TLS-ALPN-01 listeners
- Atomic deployment of cert, chain, fullchain, and key files with mode enforcement
- Deploy hooks for service reloads after changed material is installed
- Plan mode showing pending account, certificate, deploy, and hook actions
- ACME Renewal Information (ARI) support
- ACME profiles support
- ACME IP identifier support
- dns-persist-01: accounturi, issuer-domain-names, wildcard policy, persistUntil
- Certificate failover: explicit CA/account fallbacks for issuance outages or profile gaps
- Certificate dependencies
- Renewal and deploy groups
- Frozen `gibdns/draft-01` exec provider support for shared-RRset-safe ACME TXT
  and persistent TLSA edits
