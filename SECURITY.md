# Security

## Reporting a vulnerability

Please do not report security vulnerabilities through public issue trackers.

Send a description of the issue to **contact@fsky.io** over e-mail or **ethereal@telepath.im** on XMPP (with OMEMO). Include steps to reproduce, affected versions, and any relevant config or error output (sanitized). You will receive a response within a few days.

## Key and credential handling

- Canonical certificate keys and account keys are written with mode `0600`. Deployed keys may retain trusted group access or use an explicit mode such as `0640`.
- DNS API credentials are read from config at runtime and never written to disk by gibcert.
- Deploy targets stage all files and attributes before hooks, replace each file atomically, and roll back earlier replacements on ordinary installation errors. Multi-file switching is not crash-atomic; use stop/start hooks to exclude concurrent service reads.
- Backups (`.gibcert-backup-*`) of replaced files are created owner-only (`0600`, owned by the gibcert process user) and get the original attributes back only when a rollback restores them.
- Destinations are opened without following symbolic links and must be regular files. A local symlink destination is never read through; it is replaced by a regular file with a warning. Remote receivers refuse symlink destinations.
- On Unix, a deployed private key inherits the existing file's attributes only when that file is trusted: its directory is not writable by group or other, and the file is owned by the gibcert process user or the directory's owner. This check applies when `mode` is omitted, or when running as root with `owner` or `group` omitted. Otherwise gibcert warns and uses its own defaults; explicit attributes always win.
- An inherited private-key mode loses other-access and execute bits (for example `0644` becomes `0640`, with a warning). An explicit `mode` on a key block may not grant other access or execute.
- For remote deploy, `restrict,command="gibcert receive"` in `authorized_keys` only prevents a pty, forwarding, and other commands. The receiver installs any absolute path the login user can write and runs any hook as that user, so the deploy key is equivalent to the login user's access (root if logging in as root). Use an unprivileged login user with a setgid directory. See [docs/remote-deploy.md](docs/remote-deploy.md).

Run gibcert as a dedicated low-privilege user where possible. See [docs/systemd.md](docs/systemd.md) for a hardened systemd unit example.
