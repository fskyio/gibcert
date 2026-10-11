# Remote Deploy

gibcert can install certificate material on other machines over SSH. A `deploy` block names one or more `host` blocks; gibcert runs `gibcert receive` on each host and sends the files through the ssh connection.

Use it when a certificate is issued on one machine (the controller) and consumed by services on others, and you want the same staging, rollback, and hook behavior as a local deploy without writing copy scripts. For targets that cannot run gibcert, see `contrib/deploy/`.

## How It Works

1. The controller runs `ssh [options] HOST gibcert receive` (the remote command is configurable).
2. It writes one JSON request to the receiver's standard input: the final file contents, destination paths, owner, group, mode, and the `before`/`after` hooks.
3. The receiver stages and installs the files with the same all-or-nothing staging, rollback, and hook rules as a local deploy, then writes one JSON response on standard output.

Once the receiver has read a request it finishes it, or rolls it back, even if the connection drops or it receives SIGHUP, SIGPIPE, SIGTERM, or SIGINT, so a `before` hook cannot leave a service stopped by an interrupted session. Only SIGKILL or a power loss can still interrupt an installation. The controller and the receiver must speak the same protocol version (currently 1); a mismatch is reported instead of guessed around.

Each remote host is independent. Hook output from a remote host is printed on standard error with a `HOST: ` prefix, also by `gibcert renew` without `--verbose`. Warnings from a remote host get the same prefix and are shown like local warnings. Text reported by a remote host is cleaned before it is printed or stored: control characters other than tab are removed, newlines become `; `, and text is capped at 2048 bytes.

## When Hosts Are Contacted

gibcert does not inspect remote hosts before deploying. It keeps a record of what it installed on each host: the content of every file, and the `owner`, `group`, and `mode` the target asked for.

- `gibcert renew` and `gibcert apply` skip a host whose records show the current material installed with the configured `owner`, `group`, and `mode`, and no failed attempt since. Such a host is not contacted at all, so a host that is offline but already up to date does not make the run fail. It is contacted again when there is new material, when one of those attributes changes in the configuration, or after a failed attempt.
- `gibcert deploy CERTIFICATE` contacts every selected host regardless of the records. Use it to repair a host whose files were changed or removed behind gibcert's back.
- `gibcert plan` works offline. It plans remote targets from the records and never connects to a host: a host whose records are current has no action, a failed attempt is planned as `retry` with the recorded error, material not recorded on the host is planned as an update of those kinds with the hooks, and a changed `owner`, `group`, or `mode` is planned as an update of the attributes alone, without hooks. Changes made on the host itself are not visible to `plan`.

## Requirements

- An OpenSSH client (`ssh`) on the controller's `PATH`. Plan 9 controllers are not supported.
- gibcert installed on each remote host, in a release that provides `gibcert receive` and speaks the same protocol version as the controller.
- A login user on each host that can write the deploy destinations (see [Unprivileged deploy user](#unprivileged-deploy-user)).
- The host key in a `known_hosts` file. Verification is strict, never prompts, and never trusts on first use.
- An identity file, or an agent or `~/.ssh/config` entry that provides the key. Authentication is non-interactive (BatchMode).

gibcert uses the system `ssh` binary. There is no embedded SSH client.

## Configuration

```scfg
host web1 {
  address web1.example.net
  user gibdeploy
  port 22
  identity-file /etc/gibcert/deploy_ed25519
  known-hosts /etc/gibcert/known_hosts
  timeout 30s
  remote-command /usr/local/bin/gibcert
}

certificate example.com {
  account letsencrypt
  names example.com www.example.com
  challenge http-01 {
    webroot /var/www/acme-challenge
  }

  deploy nginx {
    host web1 web2
    fullchain /etc/nginx/tls/example.com/fullchain.pem
    key /etc/nginx/tls/example.com/privkey.pem
    group ssl-cert
    mode 0640
    before "sudo -n systemctl stop nginx"
    after "sudo -n systemctl start nginx"
  }
}
```

This example logs in as the unprivileged user `gibdeploy`, which writes into a setgid directory owned by group `ssl-cert` (see [Unprivileged deploy user](#unprivileged-deploy-user)) and calls `systemctl` through narrow sudoers rules (see [Hooks](#hooks)). Do not set `owner` to another user, such as `owner root`, when the login user is unprivileged: only root can give a file to another user, so every install would fail.

`timeout` is only the ssh connect timeout (plus ssh keepalives); the installation itself is not time-limited. `remote-command` defaults to `gibcert` on the remote `PATH`. A target without `host` installs on the controller. Destination paths on remote hosts must be absolute POSIX-style paths. See [Configuration](configuration.md#host) for every directive and validation rule. A complete example is in `contrib/examples/remote-deploy.scfg`.

## Adding A Host

1. Add the `host` block and reference it from a `deploy` block with `host NAME`.
2. Put the host key in the configured `known-hosts` file, for example with `ssh-keyscan` verified out of band, or by connecting once manually.
3. Run `gibcert host test NAME`. It checks the connection and the remote gibcert, then does a dry-run installation of every target for that host. The dry run sends the stored certificate material, including the private key, through the ssh connection like a real deploy, but the receiver writes none of it: it creates no directories, runs no hooks, and checks write access, ownership, and mode with an empty temporary file in the destination directory (or its nearest existing parent) that it removes again. Fix anything it reports.
4. Run `gibcert plan` to see the `deploy CERT/TARGET@HOST` actions, then `gibcert apply`.

To push a certificate to a single host, run `gibcert deploy --host NAME CERTIFICATE`. Local targets and other hosts are skipped. It is an error if the host is unknown or the certificate has no target on it. Like every `gibcert deploy`, it contacts the host even when the records show it current.

## Failures And Retry

- A failure on one host does not roll back the others and does not stop them from being attempted. Local targets still abort at the first failure, as before.
- The command exits non-zero when any host failed. Results of the targets that succeeded are still reported, and `reload` hooks still run when any target changed.
- Within one host, the existing all-or-nothing staging and rollback apply.
- The failure is stored with the certificate, including the time it began and the error. `gibcert show CERTIFICATE` shows `FAILED since TIME: ERROR` for the target on that host and `gibcert list` shows `failed` in the `DEPLOY` column, until a later attempt succeeds.
- The next `gibcert renew` or `gibcert apply` retries only the hosts with a failed attempt or without a record of the current material and attributes; see [When hosts are contacted](#when-hosts-are-contacted).
- When the files were installed on a host but its `after` hook failed, the target counts as changed: it is reported as updated and the `reload` hooks still run. The `after` hook is retried on the next run.

## Unprivileged Deploy User

The recommended login user is a dedicated unprivileged one. It must be able to write the destinations itself, because gibcert does not escalate privileges (see [Not Supported](#not-supported)). A user that is root on the remote host needs no special setup.

Example, run as root on the remote host. Adjust the names:

```sh
install -d -o root -g prosody -m 2750 /etc/prosody/certs/gibcert   # setgid: new files inherit group prosody
setfacl -m u:gibdeploy:rwx /etc/prosody/certs/gibcert              # gibdeploy may write without being in the group
```

With `mode 0640` in the deploy block, deployed files end up owned by `gibdeploy` with group `prosody`, readable by the service. gibcert skips a chown that would not change anything, so no privilege is needed when the owner and group already match, for instance through the setgid directory.

An unprivileged user cannot chown to another user, cannot create files in directories it cannot write, and cannot read files it does not own with a restrictive mode. These are the three common permission failures:

| Failure | Cause | Fix |
| --- | --- | --- |
| Cannot create files in the destination directory | The login user has no write access to the directory. | Grant it, for example with the ACL above. |
| Cannot change owner or group | `owner`/`group` in the deploy block differs from what the login user can set. | Use a setgid directory and omit `owner`; set `group` only to a group the login user belongs to, or let the setgid directory supply it. |
| Cannot read an existing file | The file exists, is owned by another user, and is not readable by the login user (for example a 0600 key). | Hand the file over once: as root, `chown` it to the login user, or remove it. |

The receiver stages everything before it replaces any file or runs any hook, so a permission failure leaves the host unchanged. `gibcert host test` reproduces these failures without installing anything and prints an example fix filled in with your destination directories, `group`, and the remote user. Treat that output as an example, not as a command to paste blindly.

## Hooks

Per-deploy `before` and `after` hooks of a target with `host` run on the remote host, as the ssh login user, through the remote shell. The same stop/start and recovery semantics apply as locally. Hooks start with the default signal dispositions. Their output reaches the controller through a pipe; a hook that leaves a process running in the background does not hold the ssh session open: once the hook has exited, gibcert waits at most five seconds for that output, then continues with a warning. Redirect the output of background processes started by hooks.

If a hook needs privileges, give the login user a narrow sudoers rule for exactly that command and call it from the hook:

```scfg
after "sudo -n systemctl reload prosody"
```

`reload` hooks stay local: they run on the machine running gibcert and never on remote hosts. A remote `after` hook runs once per certificate deploy, so N certificates installed on one remote nginx reload that nginx N times through `after`.

## Not Supported

- **sudo and doas escalation.** The receiver refuses to run as root under sudo or doas. It executes the hook commands the controller sends, so a sudo rule that lets the deploy user run `gibcert receive` as root is an unrestricted root shell for anyone holding the deploy key. If the deploy must run as root, connect as root directly with a dedicated key. There is no `become` directive.
- **Windows and Plan 9 remote targets.** Destination paths must be absolute POSIX-style paths.
- **Removing material from remote hosts.** When a certificate is revoked or deleted with `--undeploy`, records installed on a remote host are skipped, with a status naming the host. Remove those files yourself.

## Security Notes

- Private keys travel only inside the ssh connection.
- The receiver rejects relative paths, key modes that grant access to others, and destinations that are symlinks.
- Use a dedicated ssh key and a dedicated unprivileged user for deployment.
- `restrict,command="..."` in `authorized_keys` limits what the deploy key can do over ssh: it blocks terminal allocation, port, agent, and X11 forwarding, and every command except `gibcert receive`:

  ```text
  restrict,command="/usr/local/bin/gibcert receive" ssh-ed25519 AAAA... gibcert-deploy
  ```

  This does not make the key harmless. Through `receive`, anyone holding the deploy key can write any file the login user can write and run any hook command as that user, so the key is equivalent to that user's access on the host, and to root when the login user is root. Log in as a dedicated unprivileged user that can write only the destination directories, for example through a setgid directory as described in [Unprivileged deploy user](#unprivileged-deploy-user), and protect the key like the certificate keys it deploys.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Host key verification failed | Add the host key to the `known-hosts` file (or the file ssh uses). gibcert never accepts unknown keys. |
| Permission denied (publickey) | Check `user`, `identity-file`, and that the public key is in the remote `authorized_keys`. Prompts are disabled, so a passphrase-protected key needs an agent. |
| gibcert not found on the host | Install gibcert there, or set `remote-command` to its absolute path. A non-interactive ssh session may have a shorter `PATH` than a login shell. |
| Protocol mismatch | The controller and the host speak different `receive` protocol versions. Install a matching gibcert release on the host. |
| Permission errors on the destination | See [Unprivileged deploy user](#unprivileged-deploy-user) and run `gibcert host test NAME`. |

## `gibcert receive` (internal)

`gibcert receive` is the receiving side. It is started over ssh and is not meant to be run by hand. It is hidden from help output, usage listings, and shell completions.

It takes no arguments or flags, reads no configuration, and starts before any path resolution or logging. It reads one JSON request on standard input and writes one JSON response on standard output; standard output carries nothing else. Hook output goes to standard error, and warnings travel inside the response. Once a request has been read, it catches SIGHUP, SIGPIPE, SIGTERM, and SIGINT so that the installation completes or is rolled back; hooks still start with the default signal dispositions.
