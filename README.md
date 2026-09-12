# ༼ つ ◕_◕ ༽つ gibcert

> [!WARNING]
> This software is in early stages and has not yet been completed or thoroughly tested. Things may change or break. Use at your own risk, for now. There is no ETA for a v1 release.

gibcert is an awesome declarative TLS certificate manager. It lets you issue certificates from ACME or a local CA, automate certificate deployment, automate DANE, handle renewals and revocations, and more. It is a declarative tool, meaning you write what you want in a configuration file, review the pending changes, and then apply them. No more `--issue -d example.com -d www.example.com --challenge-type dns-01 blah blah blah`, we're not cavemen.

## Why does this exist?

An ACME client is a pretty important tool for a sysadmin if you are doing things related to TLS, but so many ACME clients have little to no thought put into them and are taped together with hopes and dreams. I won't name them, but the ones I've tried have a number of issues like bad (or no) plugin system, bad CLI design and horrible ergonomics, absolute spaghetti unmaintainable code, and... [RCE's](https://nvd.nist.gov/vuln/detail/CVE-2023-38198), somehow. This is why gibcert was born, as a portable and declarative certificate management tool, inspired by OpenBSD acme-client and IaC tools like Terraform, DNSControl, and so on.

## Features

**ACME**
- HTTP-01, DNS-01, TLS-ALPN-01, and dns-persist-01 challenges
- Built-in CA profiles: Let's Encrypt, ZeroSSL, Google Trust Services, Buypass, SSL.com
- ACME Renewal Information (ARI): server-driven renewal scheduling
- ACME profiles: request specific certificate types where supported
- IP identifier support
- CA failover: automatic fallback to alternate issuers during outages or rate-limits
- DNS-01 providers: manual, RFC 2136/nsupdate, PowerDNS out of the box
- Bring your own DNS providers: use external programs implementing
  [gibdns](docs/exec-dns-providers.md)
- DNS alias mode: keep API tokens scoped to a separate delegated zone
- Standalone HTTP-01 and TLS-ALPN-01 listeners when no external web server is available
- dns-persist-01 with accounturi, issuer-domain-names, wildcard policy, and persistUntil

**DANE / TLSA**
- Automatic TLSA record publication and rotation with safe pre-staging across renewals

**Operations**
- Atomic deployment of cert, chain, fullchain, and key files with strict mode enforcement
- Deploy hooks for reloading services after changed material is installed
- Certificate dependencies: sequence issuance across certs that rely on each other
- Renewal and deploy groups: share settings and template deploy paths across certs
- Plan mode: inspect every pending account, certificate, deploy, and hook action before committing
- Local CA support for private certificates

**Portability**
- Single static binary, one single dependency (statically linked)
- Runs on Linux, macOS, BSDs, Windows, Plan 9/9front, Illumos, and Solaris

## Build

```sh
make build
./gibcert version
```

Install the binary with:

```sh
make install PREFIX=/usr/local
```

## Quick Start

Writing config files to get TLS certificates might sound scary for some, but gibcert isn't rocket science. You just create a configuration file at the platform default path and go. Default config file locations:

| Platform | As root/system | As a regular user |
| --- | --- | --- |
| Linux, BSD, other Unix | `/etc/gibcert/gibcert.scfg` | `$XDG_CONFIG_HOME/gibcert/gibcert.scfg` |
| macOS | `/Library/Application Support/gibcert/gibcert.scfg` | `~/Library/Application Support/gibcert/gibcert.scfg` |
| Windows | - | `%AppData%\gibcert\gibcert.scfg` |
| Plan 9/9front | - | `$home/lib/gibcert/gibcert.scfg` |

You can always override the path with `--config` or the `GIBCERT_CONFIG` environment variable.

Here is a minimal example of a configuration that issues certs for example.com and www.example.com from Let's Encrypt:

```scfg
challenge http-01 {
  webroot /var/www/acme-challenge
}

certificate example.com {
  account letsencrypt
  names example.com www.example.com

  deploy nginx {
    fullchain /etc/nginx/tls/example.com/fullchain.pem
    key /etc/nginx/tls/example.com/privkey.pem
    after "systemctl reload nginx"
  }
}
```

Before you do anything, you can check what is about to be created or changed with:

```sh
gibcert plan
```

If you want to be super careful, you can also check your config's syntax for errors without showing the pending changes:

```sh
gibcert check
```

And once you are ready to make those changes, you can run:

```sh
gibcert apply
```

Cool, right?

### What about cron or systemd timers?

`gibcert renew` is all it takes to check all your certs for renewal. You don't need to write an entire shell script for that, like with certain ACME clients.

Here is an example for running it daily at 2AM with cron:

```cron
0 2 * * * /usr/bin/gibcert renew
```

You can add a `--verbose` flag as well to get more detailed logs for renewals.

For systemd timer users, the systemd unit examples are available in `contrib/systemd/`.

## Documentation

- [Usage Guide](docs/usage.md)
- [CLI Reference](docs/cli-reference.md)
- [Configuration Reference](docs/configuration.md)
- [Comparison And Fit](docs/comparison.md)
- [External DNS Providers](docs/exec-dns-providers.md)
- [Systemd Setup](docs/systemd.md)
- [Manpages](docs/man/)

Example configurations are in `contrib/examples/`.

## License

Copyright © 2026-present FSKY. This software is distributed under [Apache License 2.0](LICENSE); see
[`NOTICE`](NOTICE) for attribution.

It includes vendored ACME protocol code in [`internal/acme/`](internal/acme/) derived from [github.com/mholt/acmez](https://github.com/mholt/acmez), also under the Apache License 2.0.
