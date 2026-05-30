# Security

## Reporting a vulnerability

Please do not report security vulnerabilities through public issue trackers.

Send a description of the issue to **contact@fsky.io** over e-mail or **ethereal@telepath.im** on XMPP (with OMEMO). Include steps to reproduce, affected versions, and any relevant config or error output (sanitized). You will receive a response within a few days.

## Key and credential handling

- Private keys and account keys are written with mode `0600`.
- DNS API credentials are read from config at runtime and never written to disk by gibcert.
- Cert and key files are deployed atomically to avoid partial writes.

Run gibcert as a dedicated low-privilege user where possible. See [docs/systemd.md](docs/systemd.md) for a hardened systemd unit example.
