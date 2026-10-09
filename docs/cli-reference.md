# CLI Reference

## Synopsis

```text
gibcert [--config PATH] [--state-dir PATH] [--log-format FORMAT] [--syslog] <command> [args]
```

Global flags must appear before the command name.

## Global Flags

| Flag | Description |
| --- | --- |
| `--config PATH`, `-c PATH` | Path to the config file. Defaults to the platform config path. |
| `--state-dir PATH` | Path to the state directory. Defaults to the platform state path. |
| `--log-format FORMAT` | Log format. Supported values are `text` and `json`. Default is `text`. |
| `--syslog` | Also send logs to syslog. |

## Commands

### `gibcert help [command]`

Print global usage or command-specific usage.

### `gibcert version`

Print build version information.

### `gibcert check`

Parse and validate the config, then run preflight checks for root-only ownership settings, HTTP-01 webroot writability, and standalone listen address syntax.

Success output includes the number of configured accounts, providers, and certificates.

### `gibcert plan`

Show what `apply` would change. The plan can include:

- ACME account registration or update.
- Local CA creation or renewal.
- Certificate issuance, renewal, signing, or resigning.
- Deploy file creation, update, mode change, owner change, or group change.
- Deploy hooks that would run.
- TLSA record reconciliation when the published owners differ from the configured `tlsa` names and ports, or a current certificate has no published records yet.
- Orphan certificate state that exists locally but is no longer configured.

### `gibcert apply [--yes]`

Reconcile local state and deployed files with the config.

`apply` computes and prints a plan, asks for confirmation when ACME account, certificate, or TLSA record actions are required, issues or renews due certificates, reconciles TLSA records whose published owners differ from the configuration, then deploys all configured certificate material.

When a plan is nonempty, `apply` still reconciles every configured certificate; a failed renewal does not prevent unrelated certificates from being processed. It reports deploy targets only when their file content changed; unchanged targets are not listed.

| Flag | Description |
| --- | --- |
| `--yes` | Approve externally visible actions non-interactively. Required when confirmation is needed and stdin is not a TTY. |

### `gibcert issue [--new-key] <certificate>`

Issue one configured certificate.

For ACME certificates, this creates an ACME order and completes the configured challenge. For local CA certificates, this signs a leaf certificate from the configured local CA.

| Flag | Description |
| --- | --- |
| `--new-key` | Force certificate key rotation even if the certificate has `key.reuse`. |

### `gibcert renew [--max-jitter DURATION] [--no-jitter] [--verbose]`

Renew due certificates and reconcile all configured deploy targets.

A certificate is due when it is missing, unreadable, expired, inside its renewal window, has different configured SANs, or has a known issuer identity no longer accepted by the configuration. A configured local CA that is not ready also makes it due. `plan`, `apply`, `renew`, `list`, and `show` share this decision. SAN comparison ignores order, DNS case, and equivalent IP spellings but treats wildcards exactly. Issuer comparison includes account, CA, issuer type, and ACME directory; a still-configured failover issuer is accepted. Imported certificates and incomplete legacy metadata do not establish issuer ownership. If `renew.before-expiry` is unset, the renewal window is one third of the current certificate lifetime, capped at 30 days.

Deployment reconciliation also runs for otherwise-current certificates: missing or drifted files and pending per-target success hooks are retried from valid canonical material without reissuance or ACME jitter. The existing metadata, mode, and ownership rules apply. Content changes trigger the usual coalesced reloads; an unchanged target does not reload.

TLSA reconciliation likewise runs for otherwise-current certificates with a `tlsa` block when the published owners differ from the configured `names` and ports, or when no records were published yet. Records are republished from canonical material and records under owners that are no longer configured are removed; key rotation still waits for renewal.

| Flag | Description |
| --- | --- |
| `--max-jitter DURATION` | Sleep up to this duration before each ACME renewal. Default is `5m`. |
| `--no-jitter` | Disable renewal jitter. |
| `--verbose` | Print certificate validity, renewal, and deployment activity. |

### `gibcert account rotate-key <account>`

Rotate an existing ACME account key using the ACME account key rollover flow.

The account must already be registered locally. The previous local `account.key` is archived next to the new key. For implicit accounts created by using `ca NAME` directly on a certificate, pass `ca:<ca-name>`.

### `gibcert ca list`

List built-in and configured CA profiles. Local CAs also show readiness and expiry.

### `gibcert ca show <ca>`

Show one CA profile. For local CAs, this includes the common name, validity period, status, and canonical CA paths. For ACME CAs, gibcert fetches the directory and prints its advertised metadata: terms of service, website, ARI renewal-info endpoint, whether external account binding (EAB) is required, and any CAA identities the CA recognises.

### `gibcert ca export [--der] <ca>`

Write a local CA certificate to stdout. This only supports `type local` CA profiles. By default the certificate is written as PEM; pass `--der` to emit binary DER instead, which is convenient for importing into trust stores that expect DER.

### `gibcert dns-persist install [--print] <certificate>`

Install the `dns-persist-01` standing TXT record for each name in the certificate. Without `--print`, gibcert uses the certificate's configured DNS provider to publish the record. With `--print`, gibcert prints the records and writes nothing. Wildcard names are installed with `policy=wildcard`.

The certificate's ACME account must already exist locally (run `gibcert apply` once first so the account URI is known). The CA identifier comes from `persist-identifier` on the `ca` block; built in for `letsencrypt` and `letsencrypt-staging`.

| Flag | Description |
| --- | --- |
| `--print` | Print the record(s) without writing them. |

### `gibcert dns-persist check <certificate>`

Look up the `_validation-persist.<domain>` TXT record for each name in the certificate and verify it authorizes the configured account at the configured CA. Wildcard names require a matching `policy=wildcard` record. Exit status `1` if any record is missing or does not match.

### `gibcert tlsa reconcile (--all | <certificate>...)`

Reconcile DANE TLSA records for the named configured certificates, or for every configured certificate with a `tlsa` block, using stored canonical certificate material.

This command does not issue, renew, or deploy certificates. For each certificate it reads the stored `cert.pem` and `privkey.pem`, ensures the current and staged next-key TLSA records are published through the certificate's configured `tlsa` provider, removes stale records known from gibcert metadata, and writes refreshed TLSA metadata. It is useful after a DNS provider or network failure interrupted TLSA publishing after certificate material had already been stored, after pointing `tlsa` blocks at a new DNS provider, and to apply `tlsa` changes such as `ttl` or `type` before the next renewal. Records left at a previous provider are not removed. `apply` and `renew` run the same reconciliation automatically when the published owners differ from the configured `names` and ports.

| Flag | Description |
| --- | --- |
| `--all` | Reconcile every configured certificate that has a `tlsa` block. Cannot be combined with certificate names. |

Certificates are processed one at a time, in the order given (configuration order with `--all`), under one state lock. Each has its own 10 minute limit.

Named certificates are checked before any DNS change is made: an unknown name, or a certificate without a `tlsa` block, fails the whole run with status `1`. A name given more than once is reconciled once.

A failure while reconciling one certificate is reported with its name, and the remaining certificates are still processed. Exit status is `1` if any certificate failed. When more than one certificate is selected, or with `--all`, a final line summarizes how many were reconciled, skipped, and failed.

With `--all`, a certificate that has no stored certificate or key yet is reported as skipped rather than failed. A certificate named explicitly in that state fails.

### `gibcert deploy <certificate>`

Deploy stored canonical certificate material for one configured certificate to its configured deploy targets.

This command does not issue or renew the certificate.

### `gibcert revoke [--reason REASON] [--reissue] [--yes] <certificate>`

Revoke a stored ACME certificate at the CA.

Local CA certificates cannot be revoked through this command.

| Flag | Description |
| --- | --- |
| `--reason REASON` | Revocation reason. Default is `unspecified`. |
| `--reissue` | Issue and deploy a replacement after revocation. Uses a new certificate key. |
| `--yes` | Approve revocation non-interactively. |

Supported revocation reasons:

- `unspecified`
- `key-compromise`
- `ca-compromise`
- `affiliation-changed`
- `superseded`
- `cessation-of-operation`
- `certificate-hold`
- `privilege-withdrawn`
- `aa-compromise`

### `gibcert delete [--undeploy] [--revoke] [--reason REASON] [--yes] <certificate>`

Remove local certificate state. Optional flags can revoke the certificate first and remove previously deployed files.

| Flag | Description |
| --- | --- |
| `--undeploy` | Remove last deployed files when content still matches gibcert metadata. Files changed outside gibcert are skipped. |
| `--revoke` | Revoke the ACME certificate before deleting local state. |
| `--reason REASON` | Revocation reason for `--revoke`. Default is `unspecified`. |
| `--yes` | Approve deletion and revocation non-interactively. |

### `gibcert rename <old-name> <new-name>`

Rename stored certificate state and update the stored metadata name.

This command does not edit the configuration file. If the old name is still configured, gibcert prints a warning so you can update the matching `certificate` block.

### `gibcert list`

List configured certificates with compact certificate, issuer, renewal, and deploy status.

Certificate statuses are:

- `missing`: no readable local leaf certificate.
- `valid`: local certificate is current and is not due for renewal.
- `due`: local certificate needs renewal or replacement because of its renewal window, ARI, configured names or known issuer identity, or local CA readiness.
- `expired`: local certificate is expired.
- `revoked`: local metadata records a successful revocation.
- `meta-error`: local certificate metadata exists but is unreadable.

Deploy statuses are:

- `ok`: configured deploy files match the canonical stored material.
- `never`: configured deploy files are absent and no prior deploy is recorded.
- `missing`: previously deployed files are absent.
- `stale`: configured deploy files differ from canonical stored material.
- `partial`: configured deploy files have mixed statuses.
- `error`: at least one configured deploy path could not be read.
- `-`: no deploy target, or no canonical material is available yet.

### `gibcert show <certificate>`

Show one configured certificate, its issuer/account context, local status, renewal timing, stored metadata, canonical state paths, TLSA state, and deploy targets with per-file status.

### `gibcert import acme.sh [--dry-run] [--only NAME]... [--name NAME] [--force] <path>`

Import certificate material from an `acme.sh` state directory into gibcert's canonical state.

`--only` selects a source certificate by either its acme.sh directory name or its default gibcert target name. For example, `example.com_ecc` may also be selected as `example.com-ecc`.

By default, acme.sh ECC directories named `example.com_ecc` are stored as `example.com-ecc`. Use `--name` to override the target name when exactly one certificate is selected.

| Flag | Description |
| --- | --- |
| `--dry-run` | Print what would be imported without writing state. |
| `--only NAME` | Import only this source certificate. Repeatable. |
| `--name NAME` | Store a single imported certificate under this gibcert name. |
| `--force` | Overwrite existing canonical state and archive the previous private key. |

### `gibcert import certbot [--dry-run] [--only NAME]... [--name NAME] [--force] <path>`

Import certificate material from a Certbot state directory into gibcert's canonical state.

`<path>` is the root of the Certbot state directory, typically `/etc/letsencrypt`. The importer scans `<path>/live/` for certificate directories, reads the leaf certificate, private key, and chain from symlinks in each directory, and extracts the ACME directory URL from `<path>/renewal/<name>.conf`.

`--only` selects a source certificate by its Certbot certificate name (the directory name under `live/`).

| Flag | Description |
| --- | --- |
| `--dry-run` | Print what would be imported without writing state. |
| `--only NAME` | Import only this source certificate. Repeatable. |
| `--name NAME` | Store a single imported certificate under this gibcert name. |
| `--force` | Overwrite existing canonical state and archive the previous private key. |

### `gibcert import dehydrated [--dry-run] [--only NAME]... [--name NAME] [--force] <path>`

Import certificate material from a dehydrated state directory into gibcert's canonical state.

`<path>` is the base directory of the dehydrated installation, which must contain a `certs/` subdirectory. The importer scans `<path>/certs/` for per-certificate directories, reads `cert.pem`, `privkey.pem`, and `chain.pem` (following symlinks to timestamped files), and extracts the ACME directory URL from `<path>/config` using the `CA` variable. Short names like `letsencrypt` are resolved to their full URLs.

| Flag | Description |
| --- | --- |
| `--dry-run` | Print what would be imported without writing state. |
| `--only NAME` | Import only this source certificate. Repeatable. |
| `--name NAME` | Store a single imported certificate under this gibcert name. |
| `--force` | Overwrite existing canonical state and archive the previous private key. |

### `gibcert import lego [--dry-run] [--only NAME]... [--name NAME] [--force] <path>`

Import certificate material from a lego state directory into gibcert's canonical state.

`<path>` is the lego base directory, typically `.lego`. The importer scans `<path>/certificates/` for `*.key` files and reads the companion `.crt` and `.issuer.crt` files. When an `.issuer.crt` file is present, it is used as the chain and the `.crt` file is treated as the leaf certificate only. When `.issuer.crt` is absent, the `.crt` file is split into leaf and chain.

| Flag | Description |
| --- | --- |
| `--dry-run` | Print what would be imported without writing state. |
| `--only NAME` | Import only this source certificate. Repeatable. |
| `--name NAME` | Store a single imported certificate under this gibcert name. |
| `--force` | Overwrite existing canonical state and archive the previous private key. |

### `gibcert import pem [--dry-run] [--force] --name NAME --key KEY (--cert CERT [--chain CHAIN] | --fullchain FULLCHAIN)`

Import explicit PEM certificate material into gibcert's canonical state.

The importer derives certificate names, serial number, validity, and expiry from the leaf certificate. It does not infer renewal configuration, ACME account settings, challenge settings, or deploy targets; keep those in the config.

| Flag | Description |
| --- | --- |
| `--name NAME` | Store the imported certificate under this gibcert name. Required. |
| `--key KEY` | Private key PEM for the leaf certificate. Required. |
| `--cert CERT` | Leaf certificate PEM. Mutually exclusive with `--fullchain`. |
| `--chain CHAIN` | Chain certificate PEM. Only valid with `--cert`. |
| `--fullchain FULLCHAIN` | Fullchain PEM. The first certificate is treated as the leaf, and the remaining certificates as the chain. |
| `--dry-run` | Print what would be imported without writing state. |
| `--force` | Overwrite existing canonical state and archive the previous private key. |

## Exit Status

| Status | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Runtime error, config error, validation error, or cancelled confirmation. |
| `2` | Usage error or unsupported flag value. |
