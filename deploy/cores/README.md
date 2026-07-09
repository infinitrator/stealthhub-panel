# StealthHub Proxy Cores

StealthHub Panel treats proxy cores as external host services.

The panel should generate and validate configs, then let systemd supervise each core. This keeps production deploys simple and makes rollback explicit: every core binary lives under a versioned directory, while `current` points to the active release.

## Layout

```text
/opt/stealthhub/cores/xray/{version}/xray
/opt/stealthhub/cores/xray/current -> /opt/stealthhub/cores/xray/{version}

/opt/stealthhub/cores/sing-box/{version}/sing-box
/opt/stealthhub/cores/sing-box/current -> /opt/stealthhub/cores/sing-box/{version}

/opt/stealthhub/cores/hysteria/{version}/hysteria
/opt/stealthhub/cores/hysteria/current -> /opt/stealthhub/cores/hysteria/{version}

/opt/stealthhub/cores/tuic/{version}/tuic-server
/opt/stealthhub/cores/tuic/current -> /opt/stealthhub/cores/tuic/{version}

/etc/stealthhub-cores/{core}/config.*
/var/lib/stealthhub-panel/core-updates/{core}/{version}
```

## Update Rules

1. Download into `/var/lib/stealthhub-panel/core-updates/{core}/{version}`.
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
  --restart stealthhub-xray.service
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
