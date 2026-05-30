# External DNS Providers

gibcert can delegate DNS record changes to an external command with the `exec`
DNS driver. This is useful when a DNS service does not have a built-in driver,
or when site policy requires all DNS changes to go through an existing internal
tool.

The exec driver speaks the [DNS Record Provider
Protocol](dns-record-protocol.md), a tool-neutral protocol for creating and
removing DNS records over environment variables and exit status. This document
covers how gibcert configures and invokes such a provider; see the protocol
spec for the authoritative variable and operation reference.

An exec provider is a small program or script that can:

- create a TXT record for `present`
- remove that TXT record for `cleanup`
- create an arbitrary record for `add-record` (used for persistent records like TLSA)
- remove an arbitrary record for `remove-record`
- optionally report what it supports for `capabilities`
- return a non-zero exit status when the DNS update failed

`present` and `cleanup` are used for ACME DNS-01 challenge TXT records, which
are ephemeral. `add-record` and `remove-record` are used for persistent records
that gibcert manages on the certificate's behalf, such as DANE TLSA records.
Both pairs carry the same record variables and differ only in how gibcert
treats failures and propagation.

## Provider Configuration

```scfg
provider custom-dns {
  type dns
  driver exec
  command /usr/local/libexec/gibcert-dns-hook
  zone example.com
  api-url https://dns.example.net

  secret token {
    file /etc/gibcert/custom-dns-token
  }
}
```

Reference it from a certificate:

```scfg
certificate wildcard-example.com {
  ca letsencrypt
  names example.com *.example.com

  challenge dns-01 {
    provider custom-dns
    propagation-timeout 120s
  }

  deploy app {
    fullchain /etc/app/tls/example.com/fullchain.pem
    key /etc/app/tls/example.com/privkey.pem
  }
}
```

## Command Forms

The recommended form is `command`:

```scfg
provider custom-dns {
  type dns
  driver exec
  command /usr/local/libexec/gibcert-dns-hook
}
```

With `command`, gibcert executes the configured program directly, passing the
operation as the first argument:

```text
/usr/local/libexec/gibcert-dns-hook present
/usr/local/libexec/gibcert-dns-hook cleanup
```

The `command` value should be the executable path. It is not run through a
shell, and additional arguments are not split out of the field.

For shell snippets or commands that need inline arguments, use separate
`present` and `cleanup` fields:

```scfg
provider custom-dns {
  type dns
  driver exec
  present "/usr/local/bin/dnsctl add --zone example.com"
  cleanup "/usr/local/bin/dnsctl delete --zone example.com"
}
```

`present` and `cleanup` are executed with the platform shell: `sh -c` on
Unix-like systems, `cmd /C` on Windows, and `rc -c` on Plan 9. These shell
snippets should read the operation from `DNSREC_OPERATION`; gibcert does not
append `present` or `cleanup` as an argument in this form. If `command` is set,
it takes precedence over `present` and `cleanup`.

## Protocol Version

gibcert implements version 1 of the DNS Record Provider Protocol and exports:

```text
DNSREC_PROTOCOL=1
```

Provider programs may reject unknown protocol versions. Within version 1,
gibcert may add new environment variables, but existing variables, operation
names, and exit status semantics keep their documented meaning.

## Operations

### `present`

`present` must create or update this TXT record:

```text
$DNSREC_RECORD_OWNER IN TXT "$DNSREC_RECORD_RDATA"
```

The command should exit with status 0 only after the DNS API accepted the
update. It does not need to wait for public propagation unless the provider is
configured with `propagation provider`.

### `cleanup`

`cleanup` should remove the TXT value that was added during `present`.

Cleanup should be idempotent. If the record or value is already gone, the
command should exit with status 0.

gibcert runs cleanup after the challenge attempt. If cleanup fails, gibcert
prints a warning and continues. This avoids hiding the original ACME result
behind a cleanup failure.

### `add-record`

`add-record` must create the record described by `DNSREC_RECORD_TYPE`,
`DNSREC_RECORD_OWNER`, and `DNSREC_RECORD_RDATA`, preserving other records at
the same owner. It must be idempotent: re-adding an existing record returns
success.

`DNSREC_RECORD_RDATA` is always the canonical presentation format. For TLSA
that is `usage selector mtype hex-data` (e.g. `3 1 1 abcdef...`); for an
HTTPS/SVCB record it is the full canonical rdata. The provider parses the rdata
itself as far as its DNS API requires; gibcert does not export per-type
convenience variables.

A non-zero exit fails the gibcert operation that triggered the record edit
(typically certificate issuance).

### `remove-record`

`remove-record` removes a single record matching `DNSREC_RECORD_TYPE`,
`DNSREC_RECORD_OWNER`, and `DNSREC_RECORD_RDATA`. It must preserve other records
at the same owner. It must be idempotent: removing a record that does not exist
returns success.

If remove-record fails, gibcert prints a warning and continues, then retries
the removal on the next reconciliation pass.

### `capabilities`

`capabilities` is optional. A provider that implements it prints line-oriented
output describing what it supports, for example:

```text
protocol 1
binding env
operations present cleanup add-record remove-record
types TXT TLSA HTTPS SVCB
```

Before publishing persistent records (for example for a `tlsa { provider ... }`
source), gibcert runs `capabilities` and fails fast with a clear error if the
provider advertises a set that omits the needed operations or record type. The
operation is optional: a provider that does not implement it (exits non-zero or
prints nothing recognizable) is allowed through, and any real lack of support
surfaces when the edit runs. A provider that handles only ACME challenges may
omit `capabilities` and the `add-record`/`remove-record` operations entirely.
Implementing `capabilities` is recommended if you intend to reuse the provider
with other tools that speak the protocol.

## Environment

gibcert passes the normal process environment plus the protocol's variables.
See [dns-record-protocol.md](dns-record-protocol.md) for the full reference. The
ones gibcert sets:

| Variable | Operations | Description |
| --- | --- | --- |
| `DNSREC_PROTOCOL` | all | Protocol version. Currently `1`. |
| `DNSREC_OPERATION` | all | `present`, `cleanup`, `add-record`, `remove-record`, or `capabilities`. |
| `DNSREC_RECORD_TYPE` | record ops | `TXT` for challenges; `TLSA` (and others in future) for persistent records. |
| `DNSREC_RECORD_OWNER` | record ops | Record owner name with a trailing dot, e.g. `_acme-challenge.example.com.` or `_443._tcp.example.com.` |
| `DNSREC_RECORD_RDATA` | record ops | Record rdata in canonical presentation format. |
| `DNSREC_RECORD_TTL` | `add-record` | Suggested TTL in seconds (only set when gibcert has a preferred TTL). |
| `DNSREC_DOMAIN` | `present`, `cleanup` | Base domain for the authorization. For `*.example.com`, this is `example.com`. |
| `DNSREC_IDENTIFIER` | `present`, `cleanup` | Original ACME identifier, such as `example.com` or `*.example.com`. |
| `DNSREC_TIMEOUT` | `present`, `cleanup` | Configured propagation timeout in seconds. |

Provider fields are passed as environment variables:

```scfg
provider custom-dns {
  type dns
  driver exec
  command /usr/local/libexec/gibcert-dns-hook
  api-url https://dns.example.net
  zone example.com
}
```

becomes:

```text
DNSREC_FIELD_API_URL=https://dns.example.net
DNSREC_FIELD_ZONE=example.com
```

The fields `command`, `present`, and `cleanup` are not exported as
`DNSREC_FIELD_*`.

Secrets are passed separately:

```scfg
secret api-token {
  file /etc/gibcert/custom-dns-token
}

secret tenant {
  value example
}

secret api-key {
  env DNS_API_KEY
}

secret password {
  command pass show dns/password
}
```

becomes:

```text
DNSREC_SECRET_API_TOKEN_FILE=/etc/gibcert/custom-dns-token
DNSREC_SECRET_TENANT=example
DNSREC_SECRET_API_KEY=<value of DNS_API_KEY>
DNSREC_SECRET_PASSWORD=<stdout from command>
```

For `file` secrets, gibcert passes the path. The external provider is
responsible for reading the file. For `systemd-credential` secrets, gibcert
passes the credential file path from `$CREDENTIALS_DIRECTORY`. For `value`,
`env`, and `command` secrets, gibcert passes the resolved value directly.

Command secrets are run without a shell, time out after 10 seconds, and use
stdout with trailing newlines removed.

Environment variable names are normalized by uppercasing the provider field or
secret name and converting `-` and `.` to `_`.

For exec providers, gibcert rejects provider fields or secrets that would
produce the same exported environment variable name after normalization. For
example, `api-token` and `api.token` both normalize to `API_TOKEN`.

## Propagation Waiting

By default, `exec` providers use tool-managed propagation waiting:

```scfg
provider custom-dns {
  type dns
  driver exec
  command /usr/local/libexec/gibcert-dns-hook
  propagation tool
}
```

In this mode, gibcert runs `present`, then queries authoritative nameservers
until the expected TXT record appears or `propagation-timeout` expires.

If your provider command already waits until authoritative nameservers serve
the record, set:

```scfg
provider custom-dns {
  type dns
  driver exec
  command /usr/local/libexec/gibcert-dns-hook
  propagation provider
}
```

With `propagation provider`, gibcert skips its own DNS propagation check. The
provider should treat `DNSREC_TIMEOUT` as its upper bound for waiting.

Setting `propagation-timeout 0s` on the certificate challenge also skips
tool-managed waiting.

## Exit Status And Output

Exit status controls success:

- `0`: operation succeeded
- non-zero: operation failed

For `present`, a non-zero exit status fails issuance or renewal. For `cleanup`,
a non-zero exit status is reported as a warning.

The provider's stdout and stderr are connected to gibcert's output. Avoid
printing secrets. Useful status messages are fine, especially when the provider
waits for propagation.

During quiet `gibcert renew`, provider output is normally hidden. If an exec
provider fails, gibcert keeps a bounded copy of stdout and stderr and includes
it with the error so the failure is diagnosable. The captured output is limited
and may be truncated.

Cleanup runs with a bounded timeout. If cleanup fails or times out, gibcert
prints a warning and continues.

## Implementation Checklist

- Make every record operation idempotent. Re-adding an existing record or
  removing a missing record must return success.
- Preserve other records at the same owner. Multiple ACME authorizations can
  share `_acme-challenge`, and TLSA owners may carry several pinned fingerprints
  during key rotation.
- Use `DNSREC_RECORD_RDATA` to add or remove only the matching record. Treat it
  as opaque canonical presentation text.
- Honor `DNSREC_TIMEOUT` if the provider waits for propagation during a challenge.
- Honor `DNSREC_RECORD_TTL` when set on `add-record`. Otherwise pick a
  reasonable default for the record type.
- Check `DNSREC_PROTOCOL` if your provider wants to fail fast on unsupported
  protocol changes.
- Look at `DNSREC_RECORD_TYPE` for `add-record`/`remove-record` and reject
  types you do not support.
- Prefer `secret NAME { file PATH }` or `secret NAME { env NAME }` for credentials.
- Avoid logging secret values or raw API tokens.
- Return non-zero when the DNS API rejects an update.

## Minimal Shell Provider

This example shows the protocol shape. Replace the `dnsctl` commands with your
DNS API client.

```sh
#!/bin/sh
set -eu

op="${1:-${DNSREC_OPERATION:-}}"

case "$op" in
  capabilities)
    echo "protocol 1"
    echo "binding env"
    echo "operations present cleanup add-record remove-record"
    echo "types TXT TLSA"
    ;;
  present|add-record)
    dnsctl record add \
      --zone "$DNSREC_FIELD_ZONE" \
      --name "$DNSREC_RECORD_OWNER" \
      --type "$DNSREC_RECORD_TYPE" \
      --rdata "$DNSREC_RECORD_RDATA" \
      --token-file "$DNSREC_SECRET_TOKEN_FILE"
    ;;
  cleanup|remove-record)
    dnsctl record delete \
      --zone "$DNSREC_FIELD_ZONE" \
      --name "$DNSREC_RECORD_OWNER" \
      --type "$DNSREC_RECORD_TYPE" \
      --rdata "$DNSREC_RECORD_RDATA" \
      --token-file "$DNSREC_SECRET_TOKEN_FILE"
    ;;
  *)
    echo "usage: $0 capabilities|present|cleanup|add-record|remove-record" >&2
    exit 2
    ;;
esac
```

Note that `present` and `add-record` collapse to the same code, as do `cleanup`
and `remove-record`: they carry the same record variables and differ only in
the lifecycle policy gibcert applies.

Use it with:

```scfg
provider custom-dns {
  type dns
  driver exec
  command /usr/local/libexec/gibcert-dns-hook
  zone example.com

  secret token {
    file /etc/gibcert/custom-dns-token
  }
}
```

## Testing A Provider

You can test the command outside gibcert by setting the same environment
variables:

```sh
# ACME challenge TXT record
export DNSREC_PROTOCOL=1
export DNSREC_OPERATION=present
export DNSREC_RECORD_TYPE=TXT
export DNSREC_RECORD_OWNER=_acme-challenge.example.com.
export DNSREC_RECORD_RDATA=test-value
export DNSREC_DOMAIN=example.com
export DNSREC_IDENTIFIER='*.example.com'
export DNSREC_TIMEOUT=120
export DNSREC_FIELD_ZONE=example.com
export DNSREC_SECRET_TOKEN_FILE=/etc/gibcert/custom-dns-token

/usr/local/libexec/gibcert-dns-hook present
/usr/local/libexec/gibcert-dns-hook cleanup

# TLSA record
export DNSREC_OPERATION=add-record
export DNSREC_RECORD_TYPE=TLSA
export DNSREC_RECORD_OWNER=_443._tcp.example.com.
export DNSREC_RECORD_RDATA="3 1 1 abcdef..."
export DNSREC_RECORD_TTL=3600

/usr/local/libexec/gibcert-dns-hook add-record
/usr/local/libexec/gibcert-dns-hook remove-record
```

After testing, run:

```sh
gibcert check
gibcert plan
```

Then issue against a staging CA before using a production CA.
