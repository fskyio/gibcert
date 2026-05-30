# DNS Record Provider Protocol

This document specifies a small, tool-neutral protocol for delegating DNS
record changes to an external command. A host program (the "tool") invokes a
provider command (a "provider") to create and remove records, both the
ephemeral TXT records used for ACME DNS-01 challenges and persistent records
the tool manages on a certificate's behalf, such as DANE TLSA or ECH-bearing
HTTPS/SVCB records.

The protocol is defined independently of any single tool so that the same
provider command can serve more than one host. gibcert is one implementation;
see [exec-dns-providers.md](exec-dns-providers.md) for its specifics.

## Design

The protocol separates the data model from the wire format.

- The **model** is an abstract request/response: an operation, an optional
  record `(type, owner, rdata, ttl)`, challenge context, provider fields, and
  secrets in; an exit status and, for some operations, line-oriented data out.
- The **binding** is how that model is carried. This version defines a single
  binding over environment variables and exit status (the "env binding"). A
  future version may add other bindings (for example a JSON binding for
  batching). A provider advertises the bindings it supports via `capabilities`.

Two invariants keep the model from growing a special case per record type:

1. Record data (`rdata`) is always a single string in canonical DNS
   presentation format. There are no per-type fields. A new record type is a
   new `type` value plus its canonical `rdata`; it needs no protocol change.
2. Each invocation concerns exactly one record.

## Variable Prefix

The env binding namespaces its variables with a prefix. The canonical prefix
is `DNSREC_`. A tool that emits these variables under a different prefix MUST
set `DNSREC_PREFIX` to the prefix string it uses so a provider can locate the
remaining variables. When `DNSREC_PREFIX` is unset, providers assume `DNSREC_`.

The rest of this document writes variables with the `DNSREC_` prefix.

## Protocol Version

`DNSREC_PROTOCOL` carries the protocol version, currently `1`. Within a version,
the tool may add new environment variables, but existing variable names,
operation names, and exit-status semantics keep their documented meaning.
Providers MAY reject an unknown `DNSREC_PROTOCOL` value.

## Operations

`DNSREC_OPERATION` names the operation:

| Operation | Purpose | Failure handling |
| --- | --- | --- |
| `capabilities` | Report supported operations, record types, and bindings. | Non-zero means the tool cannot use the provider. |
| `present` | Create the ephemeral challenge record. | Non-zero fails the challenge. |
| `cleanup` | Remove the ephemeral challenge record. | Non-zero is a warning. |
| `add-record` | Create a persistent record, preserving others at the owner. | Non-zero fails the triggering operation. |
| `remove-record` | Remove one persistent record, preserving others. | Non-zero is a warning; retried later. |

`present`/`cleanup` and `add-record`/`remove-record` carry the same record
variables. They differ only in lifecycle policy, which lives in the tool, not
the provider: `present`/`cleanup` records are ephemeral and the tool may wait
for propagation; `add-record`/`remove-record` records are persistent and the
tool reconciles them over time.

All record-bearing operations must be idempotent. Re-adding an existing record
or removing a missing record must return success. Providers must preserve other
records at the same owner: multiple authorizations can share
`_acme-challenge`, and a TLSA owner may carry several pinned fingerprints
during key rotation.

## Environment (env binding)

| Variable | Operations | Description |
| --- | --- | --- |
| `DNSREC_PROTOCOL` | all | Protocol version. Currently `1`. |
| `DNSREC_PREFIX` | all | Active variable prefix, when not `DNSREC_`. |
| `DNSREC_OPERATION` | all | The operation name. |
| `DNSREC_RECORD_TYPE` | record ops | DNS record type, e.g. `TXT`, `TLSA`, `HTTPS`, `SVCB`. |
| `DNSREC_RECORD_OWNER` | record ops | Record owner name with trailing dot, e.g. `_acme-challenge.example.com.` |
| `DNSREC_RECORD_RDATA` | record ops | Record rdata in canonical presentation format. |
| `DNSREC_RECORD_TTL` | `add-record` | Suggested TTL in seconds, when the tool has a preference. |
| `DNSREC_DOMAIN` | `present`, `cleanup` | Base domain for the authorization. For `*.example.com`, `example.com`. |
| `DNSREC_IDENTIFIER` | `present`, `cleanup` | Original ACME identifier, e.g. `example.com` or `*.example.com`. |
| `DNSREC_TIMEOUT` | `present`, `cleanup` | Propagation timeout in seconds, when set. |
| `DNSREC_FIELD_<NAME>` | all | Provider configuration field. |
| `DNSREC_SECRET_<NAME>` | all | Resolved secret value. |
| `DNSREC_SECRET_<NAME>_FILE` | all | Path to a file holding a secret. |

Canonical `rdata` examples:

```text
TXT    Vg7c...token
TLSA   3 1 1 abcdef...
HTTPS  1 . alpn="h2,h3" ech="AEX+DQ..."
```

## Output

For `present`, `cleanup`, `add-record`, and `remove-record`, the only result is
the exit status: `0` for success, non-zero for failure. A write-only provider
never needs to emit or parse structured data.

Operations that return data use line-oriented stdout, one item per line, to
stay shell-friendly and consistent with canonical `rdata`.

`capabilities` reports, in any order, lines of the form `KEY value...`:

```text
protocol 1
binding env
operations present cleanup add-record remove-record
types TXT TLSA HTTPS SVCB
```

A tool MAY invoke `capabilities` to fail fast before relying on an operation or
record type the provider does not support.

## Exit Status

- `0`: the operation succeeded.
- non-zero: the operation failed.

Whether a failure aborts or only warns depends on the operation, per the table
above. A provider should return non-zero when the underlying DNS API rejects an
update, and should avoid printing secret values to stdout or stderr.

## Provider Checklist

- Make every record operation idempotent.
- Preserve other records at the same owner; add or remove only the record
  matching `DNSREC_RECORD_OWNER`, `DNSREC_RECORD_TYPE`, and
  `DNSREC_RECORD_RDATA`.
- Treat `DNSREC_RECORD_RDATA` as opaque canonical presentation text; parse it
  only as much as your DNS API requires.
- Honor `DNSREC_RECORD_TTL` when set; otherwise pick a reasonable default.
- Implement `capabilities` if you want tools to negotiate before use.
- Read the active prefix from `DNSREC_PREFIX` if you must serve tools that use
  a non-default prefix.
