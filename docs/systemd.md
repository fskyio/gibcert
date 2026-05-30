# Systemd Setup

The repository includes example systemd units in `contrib/systemd/`.

- `gibcert.service` runs one renewal pass.
- `gibcert.timer` runs the service daily with additional randomized delay.

## Install Units

Install the binary first:

```sh
make install PREFIX=/usr
```

Then install the units:

```sh
install -Dm0644 contrib/systemd/gibcert.service /etc/systemd/system/gibcert.service
install -Dm0644 contrib/systemd/gibcert.timer /etc/systemd/system/gibcert.timer
systemctl daemon-reload
systemctl enable --now gibcert.timer
```

## Check A Configuration Before Enabling

```sh
gibcert --config /etc/gibcert/gibcert.scfg --state-dir /var/lib/gibcert check
gibcert --config /etc/gibcert/gibcert.scfg --state-dir /var/lib/gibcert plan
```

## Run Manually

```sh
systemctl start gibcert.service
journalctl -u gibcert.service
```

The shipped service runs:

```sh
/usr/bin/gibcert --config /etc/gibcert/gibcert.scfg --state-dir /var/lib/gibcert --log-format text renew --verbose
```

## Credentials

Secrets can be supplied with systemd credentials:

```ini
LoadCredential=powerdns-api-key:/etc/gibcert/powerdns-api-key
```

Then reference the credential in `gibcert.scfg`:

```scfg
secret api-key {
  systemd-credential powerdns-api-key
}
```

## Timer Behavior

The example timer runs once per day at 03:17 and has `RandomizedDelaySec=6h`. `gibcert renew` also has its own ACME jitter, with a default maximum of 5 minutes per due certificate.

The two delays solve different problems:

- The systemd timer spreads service starts across machines.
- gibcert jitter spreads individual ACME renewals inside one run.

## Service Hardening

The example service uses systemd directory helpers:

- `StateDirectory=gibcert`
- `CacheDirectory=gibcert`
- `RuntimeDirectory=gibcert`
- `ConfigurationDirectory=gibcert`

It also applies a restrictive umask and several hardening options. Adjust the service if your deploy hooks need extra permissions, access to paths blocked by hardening, or a different binary location.
