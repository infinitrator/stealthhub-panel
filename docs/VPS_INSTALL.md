# VPS Install

StealthHub Panel uses a bare-metal systemd deployment model.

This is the preferred release path for the first field tests because the panel
is expected to manage host-level proxy cores, service files, logs, ports, and
rollback-safe config updates.

## Server Requirements

- Ubuntu 22.04/24.04 or Debian 12.
- Root or sudo access.
- Rust stable toolchain for source builds.
- SQLite, OpenSSL headers, pkg-config, curl, git.
- Nginx or Caddy in front of the panel for HTTPS.

Install build dependencies:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev sqlite3 curl git nginx
```

## Install From Git

```bash
git clone https://github.com/infinitrator/stealthhub-panel.git
cd stealthhub-panel
cargo build --release -p stealthhub-panel
sudo bash deploy/install.sh
```

The installer creates:

```text
/usr/local/bin/stealthhub-panel
/etc/stealthhub-panel/stealthhub-panel.env
/var/lib/stealthhub-panel/stealthhub.sqlite
/opt/stealthhub/cores
/etc/stealthhub-cores
/etc/systemd/system/stealthhub-panel.service
```

Check the service:

```bash
systemctl status stealthhub-panel.service
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
```

Open `/admin/setup` through HTTPS and create the first admin account.

## Reverse Proxy

Keep the panel bound to localhost:

```env
STEALTHHUB_BIND=127.0.0.1:8080
STEALTHHUB_COOKIE_SECURE=true
```

Use `deploy/nginx-stealthhub-panel.conf.example` as the Nginx starting point.

After changing `/etc/stealthhub-panel/stealthhub-panel.env`:

```bash
sudo systemctl restart stealthhub-panel.service
```

## Install Or Update Cores

Proxy cores are external services. Each core is installed into a versioned
directory and activated through a `current` symlink.

Example:

```bash
sudo deploy/cores/install-core.sh \
  --core xray \
  --version 26.3.27 \
  --url 'https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip' \
  --sha256 '<sha256-from-release>' \
  --binary xray \
  --restart stealthhub-xray.service
```

The script does not activate a core until the archive checksum is valid and
the staged binary responds to `--version`.

Runtime layout:

```text
/opt/stealthhub/cores/{core}/{version}/{binary}
/opt/stealthhub/cores/{core}/current
/var/lib/stealthhub-panel/core-updates/{core}/{version}
/etc/stealthhub-cores/{core}/config.*
```

## Rollback

List installed versions:

```bash
ls -la /opt/stealthhub/cores/xray
```

Switch back:

```bash
sudo ln -sfn /opt/stealthhub/cores/xray/<previous-version> /opt/stealthhub/cores/xray/.rollback.next
sudo mv -Tf /opt/stealthhub/cores/xray/.rollback.next /opt/stealthhub/cores/xray/current
sudo systemctl restart stealthhub-xray.service
sudo systemctl status stealthhub-xray.service
```

## Update Panel

```bash
git pull --ff-only
cargo build --release -p stealthhub-panel
sudo bash deploy/install.sh
sudo systemctl status stealthhub-panel.service
```

The installer keeps the existing environment file by default. Use
`sudo bash deploy/install.sh --force-env` only when you explicitly want to
replace `/etc/stealthhub-panel/stealthhub-panel.env`.
