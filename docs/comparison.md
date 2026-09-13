# Comparison and fit

gibcert is a declarative certificate manager. It is closest to tools that issue
and renew ACME certificates, but it also overlaps with web servers, DNS
automation, local CA tooling, and operating-system-specific certificate
workflows.

This page is not a scoreboard. Many certificate tools are excellent when their
assumptions match your environment. The point is to explain where gibcert fits,
where it is deliberately different, and where another tool may be the better
choice.

## What gibcert optimizes for

gibcert is built around a desired-state workflow:

1. Write certificate, challenge, CA, deploy, and DNS settings in config.
2. Run `gibcert check` to validate the config.
3. Run `gibcert plan` to inspect pending account, issuance, renewal, deploy,
   hook, and state actions.
4. Run `gibcert apply` or `gibcert renew` to make changes.

That shape is useful when certificate management should be reviewable,
repeatable, and separate from any one web server or service manager.

gibcert is especially aimed at:

- Hosts where certificates are deployed to several services.
- Fleets where the same workflow should run across different operating systems.
- Environments that care about predictable file deployment, ownership, modes,
  and post-deploy hooks.
- DNS-01 deployments where DNS credentials should be isolated through alias
  zones or external provider programs.
- DANE/TLSA users who want certificate issuance and TLSA rotation handled in one
  workflow.
- Sites that want ACME and local CA certificates managed through the same tool.

## Web server integrated ACME

Tools such as Caddy, Traefik, and web server plugins are often the simplest
choice when the web server owns the full certificate lifecycle. They can be very
low-friction because the service that terminates TLS also knows which names it
needs and can renew certificates automatically.

gibcert is a better fit when certificate management should be independent of the
web server. That matters when certificates are shared across multiple services,
deployed to fixed paths, managed from a central config, or used for things other
than HTTP service certificates.

The tradeoff is that gibcert asks you to write explicit configuration. In
exchange, the certificate lifecycle becomes visible before changes are made.

## Traditional ACME clients

Tools such as Certbot, acme.sh, lego, and dehydrated are natural comparisons.
They are widely used, support many production setups, and may already be
packaged for your platform.

gibcert differs most in workflow. Instead of treating issuance as a command-line
operation with renewal state attached, gibcert treats certificates, accounts,
challenges, deploy targets, and hooks as declared resources. `plan` shows what
would change before `apply` commits it.

That makes gibcert a strong fit when you want an infrastructure-style workflow
without wrapping an ACME client in shell scripts. A traditional ACME client may
be a better fit when you need an existing plugin, a very small one-off setup, or
compatibility with deployment automation that is already built around that
client.

gibcert can import existing certificate material from several common ACME client
state directories, but import does not turn old renewal configuration into
gibcert config. The desired config remains explicit.

## Operating system tools

Some platforms provide simple native ACME tooling or established package-level
integration. OpenBSD `acme-client` is an important influence on gibcert: small,
direct, and pleasant to operate.

Native tools are often the right answer when the whole environment already
matches their assumptions. They are easy to audit in context and usually fit the
platform's service management and filesystem conventions.

gibcert is aimed at the cases where portability matters more. It is distributed
as a single static binary and uses platform-specific default paths while keeping
the same configuration model and commands across Linux, macOS, BSDs, Windows,
Plan 9/9front, illumos, and Solaris.

The tradeoff is that gibcert carries its own cross-platform behavior instead of
being a small native component of one operating system.

## DNS Automation

DNS-01 support is often where certificate tooling becomes operationally messy:
provider APIs differ, credentials need careful scoping, propagation behavior
varies, and challenge records may share owners.

gibcert includes built-in providers for manual DNS, RFC 2136/nsupdate, and
PowerDNS. For other providers, it uses the gibdns external provider protocol
instead of embedding every DNS API into the main program.

Official gibdns providers currently cover Cloudflare, deSEC, and Gcore. Install
the provider binary and point the `exec` driver's `command` at it. See
[External DNS Providers](exec-dns-providers.md) and the
[gibdns catalog](https://foundry.fsky.io/gibdns/gibdns/src/branch/main/docs/PROVIDERS.md).

That model is useful when you want provider integrations to be small,
separable, and testable outside of gibcert. It also lets the same provider
program handle both ACME challenge TXT records and persistent records such as
TLSA.

The tradeoff is that a DNS service without an official or community gibdns
provider needs a small adapter program. If another ACME client already has a
maintained built-in plugin for your provider and your deployment needs are
simple, that may be more convenient.

## Private PKI And Local CAs

Dedicated private PKI systems are the better choice when you need a full
identity platform: enrollment policies, device identity, interactive
administration, audit workflows, SCEP/EST/MDM integration, or a broader
certificate authority service.

gibcert's local CA support is smaller in scope. It is intended for users who
want private certificates to participate in the same config, renewal, deploy,
and hook workflow as public ACME certificates.

That makes it convenient for internal service certificates and test
environments, but it is not trying to replace a full PKI management platform.

## When gibcert May Not Be The Right Fit

gibcert may not be the best choice if:

- Your web server already manages certificates exactly the way you want.
- You need a specific provider integration that exists elsewhere and do not want
  to use an external provider program.
- You prefer imperative one-off commands over a configuration-first workflow.
- You need a complete enterprise PKI system rather than certificate lifecycle
  management for configured services.
- You want the smallest possible platform-native tool for one operating system.

## Summary

Use gibcert when you want certificate management to be portable, declarative,
reviewable, and service-independent.

Use another tool when its assumptions match your environment more directly.
That is a good outcome too: certificates are operational plumbing, and the best
tool is the one whose failure modes you understand.
