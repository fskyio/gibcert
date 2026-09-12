# Configuration Reference

gibcert uses the scfg configuration format. Blocks use braces, directives are whitespace separated, and values with spaces can be quoted.

```scfg
certificate example.com {
  names example.com www.example.com
}
```

## Includes

Use `include` at the top level to load another file, a glob, or a directory.

```scfg
include /etc/gibcert/conf.d/*.scfg
include sites
```

Relative includes are resolved from the directory of the including file. A directory include loads `*.scfg` files in sorted order. Include cycles are rejected.

## Durations

Most duration fields use Go duration syntax such as `30m`, `12h`, or `2160h`. gibcert also accepts an integer day suffix such as `30d` or `365d` for expiry-related fields.

## Built-in CA Profiles

These ACME CA profiles are available without a `ca` block:

| Name | Directory |
| --- | --- |
| `letsencrypt` | `https://acme-v02.api.letsencrypt.org/directory` |
| `letsencrypt-staging` | `https://acme-staging-v02.api.letsencrypt.org/directory` |
| `zerossl` | `https://acme.zerossl.com/v2/DV90` |
| `google` | `https://dv.acme-v02.api.pki.goog/directory` |
| `buypass` | `https://api.buypass.com/acme/directory` |
| `sslcom` | `https://acme.ssl.com/sslcom-dv/directory` |

A user-defined `ca` block with the same name overrides a built-in profile.

## Top-level Blocks

Top-level directives are:

- `include`
- `ca`
- `account`
- `provider`
- `challenge`
- `group`
- `certificate`

Unknown top-level directives are rejected.

## `ca`

Defines or overrides a CA profile.

```scfg
ca private {
  type acme
  directory https://ca.example/acme/directory
}
```

```scfg
ca internal {
  type local
  common-name "example internal CA"
  valid-for 3650d
  key {
    type ecdsa
    curve p256
  }
}
```

Directives:

| Directive | Applies to | Description |
| --- | --- | --- |
| `type acme|local` | All | CA type. Default is `acme`. |
| `directory URL` | ACME | ACME directory URL. Required for custom ACME CAs. |
| `persist-identifier NAME` | ACME | CA identifier embedded in `dns-persist-01` standing records. Built in for `letsencrypt` and `letsencrypt-staging`. |
| `profile NAME` | ACME | Default ACME certificate profile to request. Individual certificates can override it. Advertised profiles are shown by `gibcert ca show`. |
| `common-name NAME` | Local | Subject common name for the local CA certificate. Default is `gibcert <name> local CA`. |
| `valid-for DURATION` | Local | Local CA certificate validity. Default is 10 years. |
| `key { ... }` | Local | Local CA key settings. |

ACME CAs cannot set `common-name`, `valid-for`, or `key`.

## `account`

Defines an ACME account.

```scfg
account letsencrypt {
  ca letsencrypt
  email admin@example.com
}
```

Directives:

| Directive | Description |
| --- | --- |
| `ca NAME` | ACME CA profile. If omitted, the account name is used as the CA name. |
| `email ADDRESS` | Optional ACME account email contact. |
| `eab { ... }` | Optional External Account Binding for new account registration. |

Accounts can only use ACME CA profiles. Local CA profiles do not use accounts.

Certificates can also use an ACME `ca` directly instead of an explicit `account`. In that case gibcert creates an implicit account named `ca:<ca-name>` with no email contact.

Account, CA, and certificate names are also used as directory names under the state directory. They must be single path components: empty names, `.`, `..`, and names containing `/` or `\` are rejected.

External Account Binding is configured on explicit accounts:

```scfg
account zerossl {
  ca zerossl
  email admin@example.com
  eab {
    kid "external-account-id"
    hmac-key {
      file /etc/gibcert/zerossl-eab-key
    }
  }
}
```

`eab` requires `kid` and `hmac-key`. `hmac-key` must contain exactly one of:

| Directive | Description |
| --- | --- |
| `file PATH` | Read the HMAC key from a file. Leading and trailing whitespace is ignored. |
| `value VALUE` | Inline HMAC key value. |
| `env NAME` | Read the HMAC key from an environment variable. |
| `command ARGV...` | Run a command without a shell and use stdout, minus trailing newlines. |
| `systemd-credential NAME` | Read `$CREDENTIALS_DIRECTORY/NAME`, for services using systemd credentials. |

EAB is used only when registering a new ACME account. After the account exists, normal renewals do not need the EAB key.

Rotate an existing account key with:

```sh
gibcert account rotate-key letsencrypt
```

For implicit ACME accounts created by `ca NAME` on a certificate, use `ca:<ca-name>` as the account name. Account key rotation uses the ACME account key rollover flow and archives the previous local key next to `account.key`.

## Top-level `challenge`

Defines a global ACME challenge default. Only `http-01` is supported at the top level.

```scfg
challenge http-01 {
  webroot /var/www/acme-challenge
}
```

```scfg
challenge http-01 {
  listen ":80"
}
```

Directives (exactly one of `webroot` or `listen` is required):

| Directive | Description |
| --- | --- |
| `webroot PATH` | Directory whose `.well-known/acme-challenge` child is served by an external web server. |
| `listen ADDR` | Bind address for gibcert's built-in standalone HTTP server. Use `:80` to bind all interfaces. |

## `provider`

Defines a challenge provider. Today providers are used for DNS-01.

```scfg
provider dynamic-dns {
  type dns
  driver rfc2136
  server 192.0.2.53
  zone example.com

  secret tsig-key {
    file /etc/gibcert/rfc2136.key
  }
}
```

Directives:

| Directive | Description |
| --- | --- |
| `type dns` | Provider type. Required. |
| `driver DRIVER` | DNS driver. Required. Supported values are `exec`, `manual`, `nsupdate`, `rfc2136`, `pdns`, and `powerdns`. |
| `propagation provider|tool` | Whether the provider handles DNS propagation waiting. Default is `tool`. The exec/gibdns driver requires `tool`. |
| `secret NAME { ... }` | Secret for provider use. |
| Other directives | Stored as driver-specific fields. |

Each `secret` must contain exactly one of:

| Directive | Description |
| --- | --- |
| `file PATH` | Secret is read by the driver or passed as a file path. |
| `value VALUE` | Secret value is stored directly in config. Prefer `file` for real credentials. |
| `env NAME` | Secret value is read from an environment variable. |
| `command ARGV...` | Command is run without a shell and stdout is used as the secret. Trailing newlines are removed. |
| `systemd-credential NAME` | Secret is read from `$CREDENTIALS_DIRECTORY/NAME`. Useful with systemd `LoadCredential=`. |

Command secrets time out after 10 seconds. For `file` and `systemd-credential` secrets, leading and trailing whitespace is ignored.

### DNS driver `manual`

Prompts the operator to create and later remove a TXT record. This is useful for testing and one-off issuance.

```scfg
provider manual {
  type dns
  driver manual
}
```

### DNS driver `exec`

Runs an external provider implementing the frozen `gibdns/draft-01`
`exec-json` binding. This replaces the pre-v0.2 `DNSREC_*` environment
protocol without a compatibility mode.

```scfg
provider custom-dns {
  type dns
  driver exec
  command /usr/local/libexec/example-gibdns --profile production
  zone example.com
  api_url https://dns.example.net

  secret token {
    file /etc/gibcert/example-dns-token
  }
}
```

`command` is the complete argument vector. gibcert executes it directly without
a shell or an added method argument:

```text
/usr/local/libexec/example-gibdns --profile production
```

The provider reads one JSON request from stdin and writes one JSON response to
stdout. Diagnostic output goes to stderr. `present`, `cleanup`, `add-record`,
and `remove-record` configuration fields are rejected.

`zone` is the exact gibdns zone selector. Other provider fields are sent in
`provider.config` under their exact, case-sensitive names. A field with one
argument becomes a JSON string; multiple arguments become an array of strings.

All secret sources are resolved by gibcert and sent as strings in
`provider.secrets` through stdin. Secrets are omitted from capability requests
and are not placed in the provider environment.

The provider must implement `capabilities` and `rrset.patch` for the required
record types. It must either advertise concurrency-safe patching or support
`rrset.get` with `if_revision` and `if_absent`; otherwise gibcert rejects it.
Exec providers always use gibcert's propagation checker and cannot set
`propagation provider`.

See [External DNS Providers](exec-dns-providers.md) for the complete gibcert
binding, safety policy, and migration guidance.

### DNS drivers `rfc2136` and `nsupdate`

Use the `nsupdate` tool to add and remove TXT records. `rfc2136` and `nsupdate` are aliases.

```scfg
provider dynamic-dns {
  type dns
  driver rfc2136
  server 192.0.2.53
  zone example.com

  secret tsig-key {
    file /etc/gibcert/rfc2136.key
  }
}
```

Fields:

| Field | Description |
| --- | --- |
| `command PATH` | nsupdate executable. Default is `nsupdate`. |
| `server ADDRESS` | Optional nameserver passed in the nsupdate script. |
| `zone NAME` | Optional zone passed in the nsupdate script. |

The first secret with a `file` value is passed to nsupdate with `-k`.

### DNS drivers `powerdns` and `pdns`

Use the PowerDNS authoritative HTTP API. `powerdns` and `pdns` are aliases.

```scfg
provider powerdns {
  type dns
  driver powerdns
  api-url https://ns.example.com
  server-id localhost
  ttl 60
  propagation provider

  secret api-key {
    file /etc/gibcert/powerdns-api-key
  }
}
```

Fields:

| Field | Description |
| --- | --- |
| `api-url URL` | Base PowerDNS API URL. Required. |
| `server-id ID` | PowerDNS server id. Default is `localhost`. |
| `ttl SECONDS` | TXT record TTL. Default is `60`. |

The zone is detected automatically by listing zones on the server and picking
the longest suffix match for the challenge FQDN, so one provider block can
cover any zone the API key has access to.

Secrets:

| Secret | Description |
| --- | --- |
| `api-key` | PowerDNS API key. Required. |

## `group`

Defines a named bundle of certificate settings that one or more certificates
can inherit. Groups remove repetition when many certificates share the same
issuer, challenge, and deployment layout.

```scfg
group web {
  account letsencrypt

  challenge http-01 {
    webroot /var/www/acme-challenge
  }

  deploy nginx {
    fullchain /etc/nginx/tls/{cert}/fullchain.pem
    key /etc/nginx/tls/{cert}/privkey.pem
    after "systemctl reload nginx"
  }
}

certificate example.com {
  groups web
  names example.com www.example.com
}
```

A group may set any of these certificate settings: `account`, `ca`, `profile`,
`preferred-chain`, `valid-for`, `key`, `challenge`, `renew`, `deploy`, and
`reload`. It cannot set `names`, and it cannot reference other groups.

A certificate inherits a group's settings via `groups NAME...`, listing one or
more groups. Resolution works as follows:

- **Scalars** (`account`/`ca`, `profile`, `preferred-chain`, `valid-for`,
  `key`, `challenge`, `renew`): if the certificate sets the value it fully
  replaces the group's; otherwise the certificate inherits it. It is an error
  for two listed groups to set the same scalar: the certificate must resolve
  the ambiguity by setting it itself.
- **Deploys** are merged by name. A certificate `deploy` whose name matches an
  inherited one overrides only the fields it sets, leaving the rest inherited;
  a `deploy` with a new name is added alongside the inherited ones.

### Path templating

Deploy target paths (`cert`, `chain`, `fullchain`, `key`, `cert-der`,
`key-der`) may contain placeholders, which is what lets a single group write
per-certificate files:

| Placeholder | Expands to |
| --- | --- |
| `{cert}` | The certificate's block name. |
| `{name}` | The certificate's first subject name. |

Templating applies to every certificate's deploy paths, not just grouped ones.
Hook commands (`before`/`after`) and ownership fields are never templated, so
shell braces are left untouched. An unknown placeholder is a configuration
error.

## `certificate`

Defines one managed certificate.

```scfg
certificate example.com {
  account letsencrypt
  names example.com www.example.com

  challenge http-01 {
    webroot /var/www/acme-challenge
  }

  key {
    type ecdsa
    curve p256
    reuse
  }

  renew {
    before-expiry 30d
  }

  deploy nginx {
    fullchain /etc/nginx/tls/example.com/fullchain.pem
    key /etc/nginx/tls/example.com/privkey.pem
    owner root
    group www-data
    mode 0640
    after "systemctl reload nginx"
  }
}
```

Directives:

| Directive | Description |
| --- | --- |
| `account NAME` | ACME account to use. Mutually exclusive with `ca`. |
| `ca NAME` | CA profile to use. For ACME CAs, gibcert uses an implicit account. For local CAs, gibcert signs locally. Mutually exclusive with `account`. |
| `groups NAME...` | Inherit settings from one or more `group` blocks. See [`group`](#group). |
| `requires NAME...` | Other certificates that must be processed first; this certificate is skipped if any of them fails. See [Dependencies](#dependencies). |
| `wants NAME...` | Other certificates that should be processed first, without gating. See [Dependencies](#dependencies). |
| `names NAME...` | Subject names. Required. The first name becomes the local CA leaf common name. An entry that parses as an IP address is requested as an IP identifier (RFC 8738); IP identifiers require the `http-01` or `tls-alpn-01` challenge. |
| `valid-for DURATION` | Local CA certificate validity. Default is 90 days. Only valid with a local CA. |
| `preferred-chain NAME` | Prefer an ACME certificate chain whose last certificate subject or issuer matches `NAME`, for example `ISRG Root X1`. |
| `profile NAME` | ACME certificate profile to request for this certificate. Overrides the profile set on the CA. |
| `key { ... }` | Certificate key settings. |
| `challenge TYPE { ... }` | ACME challenge settings. Required for ACME unless a global HTTP-01 challenge is configured. |
| `renew { ... }` | Renewal settings. |
| `deploy NAME { ... }` | Deployment target. Optional; without one, the certificate is still issued and stored under the state directory, but no files are written elsewhere. |
| `reload COMMAND` | Command run once per `apply`/`renew` run when any deploy on this certificate changed. Identical commands across certificates are coalesced. Repeatable. See [Reload hooks](usage.md#reload-hooks). |
| `tlsa { ... }` | Manage DANE TLSA records for the certificate. Optional. |
| `failover { ... }` | Alternate ACME issuers tried when the primary issuer cannot issue. Only valid for ACME certificates. |

`preferred-chain` is only valid for ACME certificates. If the default chain does not match, gibcert asks the ACME server for alternate chains and stores the first offered chain matching the configured name. Issuance fails if no offered chain matches.

### Certificate `failover`

For ACME certificates, `failover` lists alternate issuers to try when the primary issuer (the certificate's `account` or `ca`) cannot issue (for example, during a CA outage, a rate-limit, or when the requested `profile` is unavailable).

```scfg
certificate example.com {
  account zerossl          # primary issuer
  names example.com www.example.com

  failover {
    ca letsencrypt         # implicit "ca:letsencrypt" account
    account sectigo        # explicit account
  }

  challenge http-01 {
    webroot /var/www/acme-challenge
  }

  deploy nginx {
    fullchain /etc/nginx/tls/example.com/fullchain.pem
    key /etc/nginx/tls/example.com/privkey.pem
  }
}
```

Each line is one issuer, resolved exactly like a certificate's primary issuer: `account NAME` uses an explicit account, and `ca NAME` uses the CA's implicit `ca:<name>` account. The two forms can be mixed, and entries are tried top to bottom.

Behavior:

- The **primary issuer is always attempted first**; a failover is only reached when every preceding issuer fails. A healthy primary is never skipped, so gibcert returns to it automatically on the next run rather than staying on a backup.
- Failover triggers on **any** issuance failure (network/outage, rate-limit, or a failed order such as an unavailable profile).
- If every issuer fails, issuance fails and the error reports each issuer's failure.
- Each failover entry must reference an ACME account or ACME CA, must differ from the primary and from the other entries, and `failover` itself is only valid for ACME certificates.

### Dependencies

`requires` and `wants` express ordering between certificates, modelled on
systemd's `Requires=` and `Wants=`. Both make the named certificates run before
this one; `requires` additionally **gates**: if a required certificate fails or
is itself skipped during the run, this certificate is skipped (not issued and
not deployed). `wants` is advisory ordering only: a wanted certificate that
fails does not skip the dependent.

```scfg
certificate bundle.example.com {
  account letsencrypt
  names bundle.example.com

  requires leaf-a leaf-b   # both run first; skip me if either fails
  wants metrics.example.com

  challenge http-01 {
    webroot /var/www/acme-challenge
  }
}
```

Dependencies apply to the whole-config reconcilers `gibcert apply` and `gibcert
renew`, which process certificates in dependency order. They do not pull
dependencies into single-certificate commands such as `gibcert issue <name>`. In
`renew`, only certificates that are actually due are processed; a required
certificate that is already valid (and therefore not renewed this run) counts as
satisfied. Gating only triggers when a required certificate is processed and
fails this run.

Each name must reference another certificate. A certificate cannot depend on
itself, list the same name twice, or list a name in both `requires` and `wants`,
and the dependency graph must be acyclic; all of these are reported by `gibcert
check`.

## `key`

Controls key generation for local CA keys and certificate keys.

```scfg
key {
  type ecdsa
  curve p256
  reuse
}
```

Directives:

| Directive | Description |
| --- | --- |
| `type ecdsa|rsa` | Key type. Default is `ecdsa`. |
| `curve p256|p384` | ECDSA curve. Default is `p256`. Only valid for ECDSA. |
| `bits 2048|3072|4096` | RSA size. Default is `2048` when omitted. Only valid for RSA. |
| `reuse` | Reuse an existing certificate key on renewal. Only valid for certificate keys. |

`reuse` is ignored when `gibcert issue --new-key` or `gibcert revoke --reissue` forces a new certificate key.

## Certificate `challenge`

ACME certificates support `http-01`, `dns-01`, `tls-alpn-01`, and `dns-persist-01`.

```scfg
challenge http-01 {
  webroot /var/www/acme-challenge
}
```

```scfg
challenge http-01 {
  listen ":80"
}
```

```scfg
challenge tls-alpn-01 {
  listen ":443"
}
```

```scfg
challenge dns-01 {
  provider dynamic-dns
  propagation-timeout 120s
}
```

```scfg
challenge dns-01 {
  provider acme-dns-zone-creds
  alias-domain acme-alias.example
}
```

```scfg
challenge dns-persist-01 {
  provider dynamic-dns
}
```

Directives:

| Directive | Applies to | Description |
| --- | --- | --- |
| `webroot PATH` | `http-01` | Webroot for challenge files. Falls back to the global HTTP-01 webroot if omitted. |
| `listen ADDR` | `http-01`, `tls-alpn-01` | Bind address for gibcert's built-in standalone listener. Mutually exclusive with `webroot` for HTTP-01. Required for TLS-ALPN-01. |
| `provider NAME` | `dns-01`, `dns-persist-01` | DNS provider name. Required for `dns-01`; only used by `dns-persist-01` for the one-time install via `gibcert dns-persist install`. |
| `propagation-timeout DURATION` | `dns-01` | Maximum time for tool-managed DNS propagation checks. Default is `120s`. |
| `alias-fqdn FQDN` | `dns-01`, `dns-persist-01` | Place the TXT record at this exact FQDN instead of `_acme-challenge.<domain>`. Useful with acme-dns or a delegated alias zone. Mutually exclusive with `alias-domain`. |
| `alias-domain DOMAIN` | `dns-01`, `dns-persist-01` | Place the TXT record at `_acme-challenge.<domain>.<alias-domain>`. Per-domain unique record, useful when one alias zone serves many domains. Mutually exclusive with `alias-fqdn`. |

For DNS providers with `propagation provider`, gibcert assumes the provider waits for propagation. This mode is not available to exec/gibdns providers. For `manual`, the operator controls the wait. For other DNS providers, gibcert waits until authoritative nameservers return the expected TXT record or the propagation timeout expires.

### Standalone listeners (`http-01` and `tls-alpn-01`)

`listen` makes gibcert bind a short-lived TCP listener during the challenge instead of relying on an external web server. The listener is closed as soon as the order is finalized. Binding `:80` or `:443` typically needs root or `CAP_NET_BIND_SERVICE`.

### DNS alias mode

CNAME `_acme-challenge.<your-domain>` to the alias target ahead of time, then point gibcert's DNS provider credentials at the alias zone. This keeps API tokens scoped to a separate delegated zone instead of your production DNS. `alias-fqdn` and `alias-domain` only change *where* the TXT record is published. Propagation checks still follow CNAMEs from the original `_acme-challenge.<domain>` record.

### `dns-persist-01`

`dns-persist-01` (IETF draft) replaces per-renewal TXT writes with a single standing TXT record at `_validation-persist.<domain>`. The record authorizes one ACME account at one CA to issue for the domain. Once installed, renewals do not modify DNS at all -- gibcert simply asks the CA to re-read the record.

Install the record once per domain using a configured DNS provider:

```sh
gibcert dns-persist install example.com-cert
```

Or print the records and publish them manually:

```sh
gibcert dns-persist install --print example.com-cert
```

Verify a standing record matches the expected CA and account:

```sh
gibcert dns-persist check example.com-cert
```

The CA identifier comes from the `persist-identifier` field on the `ca` block (built in for `letsencrypt` and `letsencrypt-staging`). During issuance, gibcert also honors `issuer-domain-names` and `accounturi` values from the CA's challenge object when the CA advertises them.

The standing record format is:

```
_validation-persist.example.com. IN TXT "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567890"
```

Wildcard identifiers require `policy=wildcard`:

```
_validation-persist.example.com. IN TXT "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567890; policy=wildcard"
```

If you add `persistUntil` manually, use a base-10 UNIX timestamp. gibcert treats malformed or expired `persistUntil` values as non-matching during preflight checks.

This challenge is based on a draft IETF spec; record format and challenge name may change.

## `renew`

Controls when a certificate is considered due.

```scfg
renew {
  before-expiry 30d
}
```

Directives:

| Directive | Description |
| --- | --- |
| `before-expiry DURATION` | Renew when the local certificate expires within this duration. If unset, gibcert uses one third of the current certificate lifetime, capped at 30 days. |

The default renewal window is based on the stored leaf certificate's actual `notBefore` and `notAfter` values, so short-lived ACME profiles automatically renew on a shorter cadence. Set `before-expiry` to use an exact fixed window instead.

## `deploy`

Copies stored canonical material to service paths and optionally runs a hook.

```scfg
deploy nginx {
  cert /etc/nginx/tls/example.com/cert.pem
  chain /etc/nginx/tls/example.com/chain.pem
  fullchain /etc/nginx/tls/example.com/fullchain.pem
  key /etc/nginx/tls/example.com/privkey.pem
  owner root
  group www-data
  mode 0640
  before "systemctl stop nginx"
  after "systemctl reload nginx"
}
```

Directives:

| Directive | Description |
| --- | --- |
| `cert PATH` | Leaf certificate destination. |
| `chain PATH` | Issuer chain destination. |
| `fullchain PATH` | Leaf plus issuer chain destination. |
| `key PATH` | Private key destination. |
| `cert-der PATH` | Leaf certificate destination in binary DER, for trust stores that expect DER. |
| `key-der PATH` | Private key destination in binary DER (the on-disk PKCS#8 encoding, unarmored). |
| `owner NAME` | Owner to set on deployed files. Requires privileges. |
| `group NAME` | Group to set on deployed files. Requires privileges. |
| `mode MODE` | File mode for deployed files, such as `0640`. Must be `0777` or lower. |
| `before COMMAND` | Command to run before changed material is deployed. Runs through the platform shell: `sh -c` on Unix-like systems, `cmd /C` on Windows, and `rc -c` on Plan 9. |
| `after COMMAND` | Command to run after changed material is deployed. Runs through the platform shell: `sh -c` on Unix-like systems, `cmd /C` on Windows, and `rc -c` on Plan 9. |

At least one of `cert`, `chain`, `fullchain`, `key`, `cert-der`, or `key-der` must be set. All deploy paths must be absolute. The DER targets emit the same material as `cert` and `key` in binary DER form; `chain`/`fullchain` have no DER form because concatenated DER certificates are not a portable format.

By default, new certificate files are created with mode `0644` and new private key files are created with mode `0600`. If a destination already exists and `mode` is omitted, gibcert preserves the existing mode.

Deploy writes files atomically and only reports a file as changed when content differs. Ownership and mode are still reconciled when content is already current.

## `tlsa`

Manage DANE TLSA records for the certificate. gibcert publishes one TLSA record per `(port, name)` pair using DANE-EE pinning of the certificate public key, and rotates the key safely across renewals by always keeping a next-renewal key pre-published.

```scfg
certificate example.com {
  account letsencrypt
  names example.com www.example.com

  challenge dns-01 {
    provider powerdns
  }

  tlsa {
    provider powerdns
    port 443
    port 853/tcp
    ttl 3600
  }

  deploy nginx {
    fullchain /etc/nginx/tls/example.com/fullchain.pem
    key /etc/nginx/tls/example.com/privkey.pem
    after "systemctl reload nginx"
  }
}
```

Directives:

| Directive | Description |
| --- | --- |
| `provider NAME` | DNS provider used to publish and remove TLSA records. Required. Must use a driver that supports persistent record edits: `exec`, `nsupdate`, `rfc2136`, `powerdns`, or `pdns`. |
| `port PORT[/PROTO]` | Repeatable. Port and transport for which TLSA records are published. Protocol defaults to `tcp`; `tcp`, `udp`, and `sctp` are accepted. |
| `ttl SECONDS` | TLSA record TTL. Default is `3600`. Must be less than the certificate renewal window so the next-renewal key has time to propagate. |
| `type USAGE SELECTOR MTYPE` | Certificate usage, selector, and matching type. Default is `3 1 1` (DANE-EE, SPKI, SHA-256). Only DANE-EE with SPKI selector is supported. Matching type 1 (SHA-256) or 2 (SHA-512) is accepted. |

### How the rotation works

For a certificate with `tlsa { ... }`, gibcert maintains two private keys at all times:

- `privkey.pem`: the key in the currently issued certificate.
- `privkey-next.pem`: a pre-staged key whose TLSA fingerprint is already published in DNS.

On every issuance, gibcert ensures both keys' TLSA records are published at every configured `(port, name)`. When a renewal is due and the staged next-key's TLSA has been published longer than `ttl`, gibcert issues the new certificate against the staged key, promotes it to `privkey.pem`, generates a new staged next-key, and publishes its TLSA. The retired key's TLSA is removed.

On the very first issuance for a TLSA-managed certificate, both records are published before the certificate is written to canonical storage, so DANE clients see the pin once the certificate is deployed.

If a DNS provider or network failure interrupts TLSA publishing after certificate material has been stored, run `gibcert tlsa reconcile <certificate>` to retry TLSA publication from the stored cert and key without creating a new ACME order.

`gibcert issue --new-key` and `gibcert revoke --reissue` bypass the pre-publish wait and generate a fresh key inline. DANE clients with cached records may fail until the old TLSA TTL expires.

### Supported DNS drivers

The `manual` driver does not implement persistent record edits and cannot be used as a TLSA provider. Use `exec`, `nsupdate`/`rfc2136`, or `powerdns`/`pdns`. See [External DNS Providers](exec-dns-providers.md) for the gibdns exec binding covering both ACME challenge TXT records and persistent record edits like TLSA.

## Local CA Notes

Local CA profiles are stored under `cas/<name>` in the state directory. Use:

```sh
gibcert ca export internal
```

to export the local CA certificate for trust stores.

Local CA certificates are created on demand when a configured certificate needs them. If a local CA is missing, unreadable, or expired, gibcert creates or renews it and resigns dependent certificates.
