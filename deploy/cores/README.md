# Infiproxy Proxy Cores

Infiproxy treats proxy cores as external host services running as the dedicated
`infiproxy-runtime` identity.

The unprivileged panel records desired state. The root reconciler uses the
built-in adapter registry to generate and validate runtime configs, while
systemd supervises each core. Every core binary lives under a versioned
directory and `current` points to the active release, making rollback explicit.

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

/opt/infiproxy/cores/mihomo/{version}/mihomo
/opt/infiproxy/cores/mihomo/current -> /opt/infiproxy/cores/mihomo/{version}

/etc/infiproxy-cores/{core}/config.*
/etc/infiproxy-cores/mihomo/config.yaml
/var/lib/infiproxy-maintenance/core-updates/{core}/{version}
```

## Update Rules

1. Download into `/var/lib/infiproxy-maintenance/core-updates/{core}/{version}`.
2. Verify SHA256 before extracting or activating.
3. Run the staged binary's version command.
4. Validate the staged config.
5. Switch the `current` symlink atomically.
6. Restart one systemd service.
7. Check service health and journal.
8. Roll back the symlink and restart if validation or health checks fail.

Do not overwrite active binaries in place.

## Install Script

The supported operator entrypoint is the shared module updater. It resolves the
exact release pinned by the installed root-owned manifest, verifies it, and
preserves the service state:

```bash
sudo infiproxy-module-update --check xray
sudo infiproxy-module-update --update xray
```

Use `deploy/cores/install-core.sh` only for an advanced checksum-verified manual
import when an upstream release cannot be reached automatically.

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
  --version 1.13.20 \
  --archive ./sing-box.tar.gz \
  --sha256 '<sha256>' \
  --binary sing-box
```

The script refuses to switch `current` if checksum verification fails or the
staged binary does not answer its runtime-specific version command. Mihomo uses
`-v`; its single-file `.gz` release is decompressed under the same bounded
extraction policy as archive-based cores.

Exact supported pins and adapter capabilities are defined in
[`docs/runtime-compatibility.md`](../../docs/runtime-compatibility.md).
