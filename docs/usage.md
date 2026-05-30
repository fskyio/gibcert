# Usage Guide

This guide shows the common gibcert workflow: write a config, check it, preview the plan, apply it, then renew from a timer.

## Paths

On Linux and other FHS-style Unix systems, root uses:

- Config: `/etc/gibcert/gibcert.scfg`
- State: `/var/lib/gibcert`
- Runtime: `/run/gibcert`
- Cache: `/var/cache/gibcert`

On Linux, the BSDs, illumos, and Solaris, regular users follow XDG paths:

- Config: `$XDG_CONFIG_HOME/gibcert/gibcert.scfg` or `~/.config/gibcert/gibcert.scfg`
- State: `$XDG_STATE_HOME/gibcert` or `~/.local/state/gibcert`
- Runtime: `$XDG_RUNTIME_DIR/gibcert` if set, otherwise the state directory
- Cache: `$XDG_CACHE_HOME/gibcert` or `~/.cache/gibcert`

On macOS, regular users use:

- Config: `~/Library/Application Support/gibcert/gibcert.scfg`
- State: `~/Library/Application Support/gibcert/state`
- Runtime: `$TMPDIR/gibcert`
- Cache: `~/Library/Caches/gibcert`

On Windows, users use:

- Config: `%AppData%\gibcert\gibcert.scfg`
- State: `%LocalAppData%\gibcert\state`
- Runtime: `%LocalAppData%\gibcert\run`
- Cache: `%LocalAppData%\gibcert`

On Plan 9, users use:

- Config: `$home/lib/gibcert/gibcert.scfg`
- State: `$home/lib/gibcert/state`
- Runtime: the state directory
- Cache: `$home/lib/cache/gibcert`

You can override the main paths with global flags:

```sh
gibcert --config ./gibcert.scfg --state-dir ./state check
```

Global flags are parsed before the command name.

Environment overrides are also supported:

- `GIBCERT_CONFIG`
- `GIBCERT_STATE_DIR`
- `GIBCERT_RUNTIME_DIR`
- `GIBCERT_CACHE_DIR`

## First Configuration

The packaged config includes `/etc/gibcert/conf.d/*.scfg`. A simple HTTP-01 setup can live in `/etc/gibcert/conf.d/example.com.scfg`.

```scfg
account letsencrypt {
  ca letsencrypt
  email admin@example.com
}

challenge http-01 {
  webroot /var/www/acme-challenge
}

certificate example.com {
  account letsencrypt
  names example.com www.example.com

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

Your web server must serve files under:

```text
http://example.com/.well-known/acme-challenge/
```

from the configured `webroot`.

## Check And Preview

Validate syntax, references, deploy paths, root-only ownership settings, and HTTP-01 webroot writability:

```sh
gibcert check
```

Preview what `apply` would do:

```sh
gibcert plan
```

The plan can include account registration, certificate issuance or renewal, local CA creation, deploy updates, hooks, and orphaned local state.

## Apply Configuration

Run:

```sh
gibcert apply
```

If the plan includes externally visible ACME actions, gibcert asks for confirmation. In unattended environments, pass:

```sh
gibcert apply --yes
```

`apply` reconciles every configured certificate. It issues or renews due certificates, then deploys stored material to each `deploy` target.

## Renew From A Timer

For normal operation, run:

```sh
gibcert renew --verbose
```

`renew` only processes certificates that are missing, expired, or inside their renewal window. If `renew.before-expiry` is unset, the renewal window is one third of the current certificate lifetime, capped at 30 days. This keeps short-lived certificates on a shorter cadence while preserving the old 30-day window for typical 90-day certificates.

For ACME certificates, gibcert also consults ACME Renewal Information (ARI, RFC 9773) when the CA advertises it. Before deciding what is due, `renew` fetches each CA's suggested renewal window and caches it; if the CA suggests renewing earlier than the normal expiry-based window (for example during a mass-revocation event), the certificate becomes due then. ARI can only pull renewal earlier, never later, and a CA without ARI support or an unreachable server falls back silently to the expiry-based decision. The CA's `Retry-After` is honored, so cached suggestions are reused until it elapses.

ACME renewals sleep for a random duration up to 5 minutes before each renewal. This spreads load when many machines renew at the same time. Use `--no-jitter` to disable this or `--max-jitter 30m` to choose another maximum. Local CA renewals do not jitter.

See [Systemd Setup](systemd.md) for the shipped service and timer examples.

## Inspect State

List configured certificates with certificate, renewal, issuer, and deploy status:

```sh
gibcert list
```

Show one certificate with stored metadata, renewal timing, canonical paths, TLSA state, and deploy-file status:

```sh
gibcert show example.com
```

Show CA profiles:

```sh
gibcert ca list
gibcert ca show letsencrypt
```

For local CAs, export the CA certificate:

```sh
gibcert ca export internal > internal-ca.pem
```

## Manual Operations

Issue one certificate regardless of the renewal plan:

```sh
gibcert issue example.com
```

Force a new certificate key:

```sh
gibcert issue --new-key example.com
```

Deploy already stored material:

```sh
gibcert deploy example.com
```

Revoke an ACME certificate:

```sh
gibcert revoke --reason key-compromise --yes example.com
```

Revoke and immediately issue a replacement with a new key:

```sh
gibcert revoke --reason key-compromise --reissue --yes example.com
```

Delete local certificate state:

```sh
gibcert delete --yes example.com
```

Delete local state and remove previously deployed files if their content still matches gibcert metadata:

```sh
gibcert delete --undeploy --yes example.com
```

## Stored Files

For each certificate, gibcert stores canonical material under the state directory:

```text
certs/<name>/cert.pem
certs/<name>/chain.pem
certs/<name>/fullchain.pem
certs/<name>/privkey.pem
certs/<name>/meta.json
```

Deployed files are copies of this canonical material. Private keys are written with mode `0600` by default. Certificate files are written with mode `0644` by default. A `deploy.mode` setting overrides the mode for all files in that deploy target.

When a certificate key is replaced, gibcert archives the previous key in the certificate state directory and prunes older private key archives.

## Importing Existing Certificates

Importing copies existing certificate material into gibcert's canonical state. It does not create renewal config, ACME account config, challenge config, or deploy targets.

Import from an acme.sh state directory:

```sh
gibcert import acme.sh ~/.acme.sh
```

Import one acme.sh certificate and choose the gibcert state name:

```sh
gibcert import acme.sh --only example.com_ecc --name example.com ~/.acme.sh
```

Import from a Certbot state directory (typically `/etc/letsencrypt`):

```sh
gibcert import certbot /etc/letsencrypt
```

Import from a dehydrated base directory:

```sh
gibcert import dehydrated /etc/dehydrated
```

Import from a lego state directory:

```sh
gibcert import lego .lego
```

All directory-based importers support `--dry-run`, `--only`, `--name`, and `--force`:

```sh
gibcert import certbot --dry-run /etc/letsencrypt
gibcert import dehydrated --only example.com /etc/dehydrated
gibcert import lego --name my-cert .lego
```

Import explicit PEM files:

```sh
gibcert import pem --name example.com --fullchain fullchain.pem --key privkey.pem
```

Or import separate leaf and chain files:

```sh
gibcert import pem --name example.com --cert cert.pem --chain chain.pem --key privkey.pem
```

After importing, add a matching `certificate` block to the config and run `gibcert check`. Future issuance and renewal behavior comes from the config, not from imported metadata.

## Hooks

A deploy target can run a `before` hook before changed material is deployed and an `after` hook once changed material is in place. The `after` hook also runs when metadata shows the target has not previously seen the current material, so a failed reload is retried on the next deploy.

```scfg
deploy nginx {
  fullchain /etc/nginx/tls/example.com/fullchain.pem
  key /etc/nginx/tls/example.com/privkey.pem
  before "systemctl stop nginx"
  after "systemctl reload nginx"
}
```

Hooks run through the platform shell (`sh -c` on Unix-like systems, `cmd /C` on Windows, and `rc -c` on Plan 9) with these environment variables:

- `GIBCERT_HOOK_API`
- `GIBCERT_EVENT`
- `GIBCERT_CERT`
- `GIBCERT_DEPLOY_TARGET`
- `GIBCERT_CHANGED`
- `GIBCERT_CERT_PATH`
- `GIBCERT_CHAIN_PATH`
- `GIBCERT_FULLCHAIN_PATH`
- `GIBCERT_KEY_PATH`
- `GIBCERT_CERT_DER_PATH`
- `GIBCERT_KEY_DER_PATH`

`GIBCERT_CHANGED` is a comma-separated list of changed material kinds such as `cert`, `chain`, `fullchain`, `key`, `cert-der`, and `key-der`.
`GIBCERT_EVENT` is `before-deploy` for a `before` hook and `after-deploy` for an `after` hook.

### Reload hooks

A `before`/`after` hook runs per deploy, once for each certificate. When many certificates share the same reload command, for example a fleet of certificates all served by one nginx, that command runs once per certificate. A `reload` hook instead runs **once per `gibcert apply`/`gibcert renew` run**: identical reload commands are coalesced and executed a single time, after all of that run's deploys are in place.

```scfg
group web {
  account letsencrypt
  challenge http-01 {
    webroot /var/www/acme-challenge
  }
  deploy nginx {
    fullchain /etc/nginx/tls/{cert}/fullchain.pem
    key /etc/nginx/tls/{cert}/privkey.pem
  }
  reload "systemctl reload nginx"
}
```

`reload` can be set on a `group` or a `certificate`; grouped values are inherited and combined with the certificate's own. A reload command runs only if at least one deploy on a contributing certificate changed this run, so a no-op run reloads nothing. Because a reload is shared, it carries **no** per-certificate environment: it receives `GIBCERT_HOOK_API`, `GIBCERT_EVENT=reload`, and `GIBCERT_CHANGED_CERTS` (a comma-separated list of the certificates that triggered it), but none of the per-certificate `GIBCERT_CERT*`/path variables. Use a per-deploy `after` hook when you need that context.
