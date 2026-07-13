# Infiproxy Proxy Cores

Infiproxy treats proxy cores as external host services.

The panel should generate and validate configs, then let systemd supervise each core. This keeps production deploys simple and makes rollback explicit: every core binary lives under a versioned directory, while `current` points to the active release.

## Layout

```text
/opt/infiproxy/cores/xray/{version}/xray
/opt/infiproxy/cores/xray/current -> /opt/infiproxy/cores/xray/{version}

/opt/infiproxy/cores/sing-box/{version}/sing-box
/opt/infiproxy/cores/sing-box/current -> /opt/infiproxy/cores/sing-box/{version}

/opt/infiproxy/cores/hysteria/{version}/hysteria
/opt/infiproxy/cores/hysteria/current -> /opt/infiproxy/cores/hysteria/{version}

/opt/infiproxy/cores/tuic/{version}/tuic-server
/opt/infiproxy/cores/tuic/current -> /opt/infiproxy/cores/tuic/{version}

/opt/infiproxy/cores/mtproto/{version}/mtproto-proxy
/opt/infiproxy/cores/mtproto/current -> /opt/infiproxy/cores/mtproto/{version}

/etc/infiproxy-cores/{core}/config.*
/etc/infiproxy-cores/mtproto/mtproto.env
/etc/infiproxy-cores/mtproto/proxy-secret
/etc/infiproxy-cores/mtproto/proxy-multi.conf
/var/lib/infiproxy/core-updates/{core}/{version}
```

## Update Rules

1. Download into `/var/lib/infiproxy/core-updates/{core}/{version}`.
2. Verify SHA256 before extracting or activating.
3. Run the staged binary's version command.
4. Validate the staged config.
5. Switch the `current` symlink atomically.
6. Restart one systemd service.
7. Check service health and journal.
8. Roll back the symlink and restart if validation or health checks fail.

Do not overwrite active binaries in place.

## Install Script

Use `deploy/cores/install-core.sh` for checksum-verified installs and updates.

```bash
sudo deploy/cores/install-core.sh \
  --core xray \
  --version 26.3.27 \
  --url 'https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip' \
  --sha256 '<sha256-from-release>' \
  --binary xray \
  --restart infiproxy-xray.service
```

You can also import a pre-downloaded archive:

```bash
sudo deploy/cores/install-core.sh \
  --core sing-box \
  --version 1.13.14 \
  --archive ./sing-box.tar.gz \
  --sha256 '<sha256>' \
  --binary sing-box
```

The script refuses to switch `current` if checksum verification fails or the
staged binary does not answer `--version`.

Telegram MTProto is the exception to the `--version` probe because the official
`mtproto-proxy` binary is not shaped like the Go/Rust proxy cores. For that
core, the installer runs a bounded help/usage smoke test, then leaves service
startup to systemd.

After installing the MTProxy binary, run:

```bash
sudo infiproxy-manager
```

Choose `Telegram MTProto setup` to download Telegram's `proxy-secret` and
`proxy-multi.conf`, generate a 32-hex client secret, write
`/etc/infiproxy-cores/mtproto/mtproto.env`, and print the `t.me/proxy` import
link.
