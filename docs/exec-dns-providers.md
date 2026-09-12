# External DNS Providers

gibcert delegates DNS changes to external programs through the `exec` DNS
driver. The driver implements the frozen
[`gibdns/draft-01`](https://foundry.fsky.io/gibdns/gibdns) protocol using its
`exec-json` binding.

The older `DNSREC_*` environment protocol is not supported. Starting with
gibcert v0.2, an exec provider must implement `gibdns/draft-01`.

## Provider configuration

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

`command` is an argument vector. gibcert executes it directly, without a shell
and without adding a protocol-specific argument. In the example above the
exact command is:

```text
/usr/local/libexec/example-gibdns --profile production
```

The same command handles `capabilities`, `rrset.get`, and `rrset.patch` by
reading the request method from standard input. The legacy operation-specific
`present`, `cleanup`, `add-record`, and `remove-record` fields are rejected.

`zone`, when present, becomes the exact `params.zone` selector in RRset
requests. It is not sent as provider-specific configuration. Leave it out only
when the provider advertises `features.zone_discovery: true`.

All other provider fields become `provider.config` members using their exact,
case-sensitive scfg names:

- one argument becomes a JSON string;
- multiple arguments become an array of JSON strings; and
- field names are not uppercased or otherwise normalized.

For example:

```scfg
api_url https://dns.example.net
tags production certificates
```

becomes:

```json
{
  "provider": {
    "config": {
      "api_url": "https://dns.example.net",
      "tags": ["production", "certificates"]
    }
  }
}
```

gibcert's scfg representation currently supplies strings and arrays of strings.
A provider requiring another JSON configuration type cannot be configured
through this driver yet.

## Secrets

Provider secrets use the normal gibcert secret sources:

```scfg
secret token {
  file /etc/gibcert/example-dns-token
}

secret tenant {
  value example
}

secret api_key {
  env DNS_API_KEY
}

secret password {
  command pass show dns/password
}

secret service_token {
  systemd-credential dns-service-token
}
```

gibcert resolves every source before invoking the provider. The resulting
strings are sent in `provider.secrets` through standard input. File paths,
secret values, and protocol data are never exported through environment
variables. Capability requests omit `provider.secrets` entirely.

Secret names are case-sensitive and are not normalized. Send only credentials
needed by this provider and scope them to the necessary zones and record types
where the DNS service supports that.

## Required provider behavior

An exec provider must implement `capabilities` and `rrset.patch` for the record
types with which it will be used:

- `TXT` for ACME DNS-01 and dns-persist-01 installation;
- `TLSA` for automatic DANE publication.

The provider may instead advertise the sole `record_types` value `"*"`.
gibcert then uses numeric `TYPE16` or `TYPE52` keys and RFC 3597 generic RDATA,
as required by the wildcard capability.

gibcert requires safe updates to shared RRsets. A provider can satisfy this in
one of two ways:

1. advertise `features.concurrent_safe_patch: true`; or
2. advertise `rrset.get` plus both `if_revision` and `if_absent` preconditions
   for `rrset.patch`.

In the second case, gibcert reads the RRset and issues a conditional patch. It
re-reads and recomputes after a conflict. A provider that offers neither safety
mechanism is rejected before mutation.

For DNS-01, gibcert patch-adds a quoted TXT RDATA value and later patch-removes
exactly that value. Other TXT members remain intact. No TTL is requested, so an
existing RRset keeps its TTL and the provider selects a TTL for a new RRset.

For TLSA publication, gibcert patch-adds the desired TLSA member with
`ttl_policy: exact`. Removal patches omit TTL so they cannot change the TTL of
remaining members.

## Invocation and output

For every request, gibcert:

1. starts a fresh provider process;
2. writes one UTF-8 JSON request to standard input and closes it;
3. reads one UTF-8 JSON response from standard output; and
4. collects standard error separately as bounded diagnostic output.

Stdout must contain only the protocol response. Logs and progress messages go
to stderr and must never contain secrets. gibcert validates duplicate JSON
members, UTF-8 and Unicode scalar values, protocol version, request ID,
method-specific results, and exit-status consistency.

The binding uses the exit statuses defined by gibdns:

- `0`: valid success response;
- `1`: valid provider error response;
- `2`: no valid request envelope was available.

Other statuses and malformed or contradictory responses are binding failures.
gibcert bounds provider runtime and output, terminates timed-out process groups
where the platform permits, and redacts known secret values from diagnostics.

## DNS propagation

Gibdns success means the provider control plane accepted the resulting RRset.
It does not mean the record has propagated to authoritative nameservers.

For DNS-01, gibcert performs its existing authoritative propagation check after
the patch succeeds. Exec providers cannot use `propagation provider`. Set the
challenge's `propagation-timeout` to `0s` only when deliberately skipping the
check, such as with an ACME test server that does not query DNS.

## Example certificate

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

## Migration from the pre-v0.2 exec protocol

There is no compatibility mode. Replace an old DNSREC hook or place a separate
gibdns adapter in front of it. In the gibcert configuration:

- keep `driver exec`;
- point `command` at the gibdns provider and include fixed arguments normally;
- remove operation-specific shell fields;
- remove `propagation provider`; and
- use the provider's exact gibdns configuration and secret names.

An old hook presented with a v0.2 request will fail because it receives JSON on
stdin, no operation argument, and no `DNSREC_*` variables.
