# Deploy Hook Examples

This directory contains example deploy hooks for copying certificate material
after a gibcert deploy target changes. They are meant as starting points:
read them, adapt them to your environment, and test them before using them with
production private keys.

The examples below use repository-relative script paths for readability. In a
real deployment, install or copy the script somewhere stable and use an
absolute path in the hook command.

gibcert runs deploy hooks through the platform shell and provides paths through
environment variables:

- `GIBCERT_CERT_PATH`
- `GIBCERT_CHAIN_PATH`
- `GIBCERT_FULLCHAIN_PATH`
- `GIBCERT_KEY_PATH`
- `GIBCERT_CERT_DER_PATH`
- `GIBCERT_KEY_DER_PATH`

The examples copy every configured path variable whose file exists. They use
conventional destination names such as `fullchain.pem`, `privkey.pem`,
`cert.pem`, and `chain.pem`.

On Windows, gibcert runs hook commands through `cmd /C`. Invoke PowerShell
examples explicitly with `powershell -NoProfile -ExecutionPolicy Bypass -File
...` or `pwsh -NoProfile -File ...`. The Windows snippets use forward slashes
in paths because scfg treats backslash as an escape character.

## SSH and rsync

`ssh-rsync.sh` copies changed material to one or more SSH hosts using `rsync`.
It creates a temporary directory below the remote destination, uploads files
there, then renames them into place on the remote host.

The script preserves the modes from the local staging files. If your remote
service needs ownership changes, sudo, labels, or service-specific bundle
construction, copy this script and add those steps explicitly.

Required environment:

- `GIBCERT_DEPLOY_HOSTS`: space-separated SSH hosts, such as `web1 web2`.
- `GIBCERT_DEPLOY_REMOTE_DIR`: remote directory to receive the files.

Optional environment:

- `GIBCERT_DEPLOY_SSH`: SSH command path. Default: `ssh`.
- `GIBCERT_DEPLOY_RSYNC`: rsync command path. Default: `rsync`.
- `GIBCERT_DEPLOY_RELOAD`: remote command to run after files are installed.

Example:

```scfg
certificate example.com {
  account letsencrypt
  names example.com www.example.com

  challenge dns-01 {
    provider dns
  }

  deploy remote-web {
    fullchain /var/lib/gibcert/export/example.com/fullchain.pem
    key /var/lib/gibcert/export/example.com/privkey.pem
    mode 0600
    after "GIBCERT_DEPLOY_HOSTS='web1 web2' GIBCERT_DEPLOY_REMOTE_DIR=/etc/nginx/tls/example.com GIBCERT_DEPLOY_RELOAD='systemctl reload nginx' contrib/deploy/ssh-rsync.sh"
  }
}
```

## rclone

`rclone-copy.sh` and `rclone-copy.ps1` copy changed material to one or more
rclone destinations.
This is useful when your rclone config already describes SFTP remotes, object
storage, or another backend. The script writes each destination through a
temporary remote name and then asks rclone to move it into place.

Required environment:

- `GIBCERT_RCLONE_DESTS`: space-separated rclone destination directories.

Optional environment:

- `GIBCERT_RCLONE`: rclone command path. Default: `rclone`.

Example:

```scfg
deploy rclone {
  fullchain /var/lib/gibcert/export/example.com/fullchain.pem
  key /var/lib/gibcert/export/example.com/privkey.pem
  mode 0600
  after "GIBCERT_RCLONE_DESTS='sftp-web1:/etc/nginx/tls/example.com sftp-web2:/etc/nginx/tls/example.com' contrib/deploy/rclone-copy.sh"
}
```

Windows example:

```scfg
deploy rclone-windows {
  fullchain C:/ProgramData/gibcert/export/example.com/fullchain.pem
  key C:/ProgramData/gibcert/export/example.com/privkey.pem
  after "set GIBCERT_RCLONE_DESTS=sftp-web1:/etc/nginx/tls/example.com sftp-web2:/etc/nginx/tls/example.com&& powershell -NoProfile -ExecutionPolicy Bypass -File C:/ProgramData/gibcert/hooks/rclone-copy.ps1"
}
```

## Local Windows copy

`local-copy.ps1` copies changed material to a local Windows directory and can
restart one Windows service afterwards.

Required environment:

- `GIBCERT_DEPLOY_DIR`: local destination directory.

Optional environment:

- `GIBCERT_DEPLOY_SERVICE`: Windows service name to restart after files are
  installed.

Example:

```scfg
deploy windows-service {
  fullchain C:/ProgramData/gibcert/export/example.com/fullchain.pem
  key C:/ProgramData/gibcert/export/example.com/privkey.pem
  after "set GIBCERT_DEPLOY_DIR=C:/ProgramData/example-service/tls&& set GIBCERT_DEPLOY_SERVICE=example-service&& powershell -NoProfile -ExecutionPolicy Bypass -File C:/ProgramData/gibcert/hooks/local-copy.ps1"
}
```
