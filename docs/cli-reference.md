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
- Orphan certificate state that exists locally but is no longer configured.

### `gibcert apply [--yes]`

Reconcile local state and deployed files with the config.

`apply` computes and prints a plan, asks for confirmation when ACME account or certificate actions are required, issues or renews due certificates, then deploys all configured certificate material.

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

Renew due certificates and deploy changed material.

A certificate is due when it is missing, unreadable, expired, or inside its renewal window. If `renew.before-expiry` is unset, the renewal window is one third of the current certificate lifetime, capped at 30 days.

| Flag | Description |
| --- | --- |
| `--max-jitter DURATION` | Sleep up to this duration before each ACME renewal. Default is `5m`. |
| `--no-jitter` | Disable renewal jitter. |
| `--verbose` | Print skipped, issued, and deployed certificates. |

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
- `valid`: local certificate exists and is outside the renewal window.
- `due`: local certificate exists and is inside the renewal window.
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
