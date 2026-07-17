# Infiproxy

Infiproxy is a single-server Rust panel for managing users, Mihomo/Clash-compatible
subscriptions, routing rules, protocol profiles and supervised proxy runtimes.

It is built for a simple VPS deployment model: **bare metal Linux + systemd +
SQLite + one SSH TUI**. The panel does not implement proxy protocols itself.
Network traffic is handled by external cores such as Xray, sing-box, Hysteria,
TUIC and Telegram MTProxy.

## Quick Install

Recommended target: a fresh Ubuntu 22.04/24.04 or Debian 12 VPS.

One command for the full guided install:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash -s -- --guided --with-nginx
```

The command installs build dependencies, Rust when needed, clones the project to
`/opt/infiproxy/source`, builds the release binary, installs systemd units and
opens the guided SSH TUI. The TUI then walks through panel repair, HTTPS,
optional core imports, Telegram MTProto and final service checks.
Headscale can also be configured from the same TUI cycle when a mesh hub is
needed.

If the guided UI was skipped or the SSH session was interrupted:

```bash
sudo infiproxy-manager --guided
```

## What You Need

- A VPS with root access.
- Ubuntu/Debian is recommended; Fedora/RHEL-like systems with `dnf` are also
  supported by the bootstrapper.
- A domain is optional but recommended for HTTPS.
- For Cloudflare HTTPS automation: an API token with `Zone:Read` and `DNS:Edit`
  permissions for the target zone.
- For proxy cores: official release archive URLs and SHA256 checksums. The TUI
  asks for these values and performs checksum verification before activation.

## First Run

After the quick install, follow the TUI prompts. The normal path is:

```text
Guided deployment cycle
Panel install/repair
HTTPS with Cloudflare DNS-01
Verified core archive import
Telegram MTProto setup
Final service status
```

When HTTPS is configured, open:

```text
https://<your-domain>/admin/setup
```

Without HTTPS, use an SSH tunnel first:

```bash
ssh -L 8080:127.0.0.1:8080 root@<server>
```

Then open locally:

```text
http://127.0.0.1:8080/admin/setup
```

## SSH Manager

The installed TUI is the main operations surface:

```bash
sudo infiproxy-manager
```

It includes:

- Guided deployment cycle.
- Service status dashboard.
- Restart and reload actions.
- Panel environment editor.
- HTTPS and Cloudflare certificate setup.
- Verified proxy core installer.
- Telegram MTProto setup.
- Headscale mesh hub setup.
- Panel update scheduler and immediate update trigger.
- Panel logs.
- Root-level uninstall and cleanup flows.

## Updates And Autostart

The panel and every runtime are installed as systemd-managed components.
`infiproxy.service` starts the Rust panel after boot. Installed proxy modules
use their own services and the core installer enables the selected service after
a verified binary update:

```text
infiproxy-xray.service
infiproxy-sing-box.service
infiproxy-hysteria.service
infiproxy-tuic.service
infiproxy-mtproto.service
headscale.service
```

Panel self-updates are split into two layers:

- The web panel checks GitHub once per hour and stores update state in
  `/var/lib/infiproxy/panel-update-state.env`.
- `infiproxy-panel-update.timer` runs the root updater hourly and applies a
  pending update at the UTC maintenance hour configured in Settings.
- `infiproxy-panel-update.path` watches for
  `/var/lib/infiproxy/panel-update-now.request`; the owner-admin "Update Now"
  button creates this file for immediate update.
- The root updater uses `/opt/infiproxy/source`, rebuilds the release binary and
  reruns the idempotent installer, so reboot recovery and package layout stay
  identical to a fresh install.

Change the update repository, ref and UTC maintenance hour in
`/admin/settings`. For forked deployments, keep the repository value in
`owner/repo` format and the ref as a branch, tag or safe git ref.

## Proxy Cores

Infiproxy prepares systemd units and config directories, but proxy core binaries
are installed only from verified archives. This avoids silently trusting an
unverified binary during panel installation.

Runtime paths:

```text
/opt/infiproxy/cores/xray/current/xray
/opt/infiproxy/cores/sing-box/current/sing-box
/opt/infiproxy/cores/hysteria/current/hysteria
/opt/infiproxy/cores/tuic/current/tuic-server
/opt/infiproxy/cores/mtproto/current/mtproto-proxy
```

Systemd units:

```text
infiproxy-xray.service
infiproxy-sing-box.service
infiproxy-hysteria.service
infiproxy-tuic.service
infiproxy-mtproto.service
```

Inside the TUI, choose:

```text
Core installer helper
```

For each core, paste:

- Core version label.
- Official release archive URL.
- SHA256 checksum.

The installer downloads or imports the archive, verifies SHA256, extracts into a
versioned directory, runs a bounded smoke test and atomically switches the
`current` symlink.

## Telegram MTProto

Telegram MTProto is managed as a separate server runtime, not as a Mihomo
outbound. In the TUI, choose:

```text
Telegram MTProto setup
```

The guided setup downloads Telegram `proxy-secret` and `proxy-multi.conf`,
generates a 32-hex client secret, writes:

```text
/etc/infiproxy-cores/mtproto/mtproto.env
```

and prints an import link:

```text
https://t.me/proxy?server=<host>&port=<port>&secret=<secret>
```

Refresh Telegram upstream config from the same menu when needed.

## Headscale Mesh Hub

Infiproxy can also install and configure Headscale, a self-hosted Tailscale
coordination server. In the TUI, choose:

```text
Headscale hub setup
```

The guided setup:

- Downloads the official Headscale release.
- Verifies the downloaded asset with upstream `checksums.txt`.
- Installs the Debian package on Ubuntu/Debian or falls back to a standalone
  binary on other supported Linux hosts.
- Writes `/etc/headscale/config.yaml`.
- Creates a dedicated Nginx HTTPS site at
  `/etc/nginx/sites-available/infiproxy-headscale.conf`.
- Issues a Let's Encrypt certificate through Cloudflare DNS-01.
- Starts `headscale.service`.
- Can create a Headscale user and pre-auth key for client onboarding.

Headscale must use a **DNS-only** Cloudflare record. Do not enable Cloudflare
proxying for the Headscale hostname.

Client example:

```bash
tailscale up --login-server https://hs.example.com --authkey <key>
```

## Port Plan

The default deployment avoids internal port collisions:

```text
TCP 80/443              Nginx public edge for panel and Headscale hostnames
TCP 127.0.0.1:8080      Infiproxy panel
TCP 127.0.0.1:8088      Headscale control server
TCP 127.0.0.1:9098      Headscale metrics/debug
TCP 127.0.0.1:50443     Headscale local gRPC
TCP/UDP 8443            Telegram MTProto proxy
UDP 443                 Hysteria2 starter config
UDP 11443               TUIC starter config
```

Hysteria2 uses QUIC/UDP on `443`, while Nginx uses TCP `443`; these are separate
sockets and can coexist. Headscale intentionally does not use its upstream
example default `127.0.0.1:8080` because that belongs to the panel.

## Updates

Run the same command again:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash -s -- --guided --with-nginx
```

Or update from the installed checkout:

```bash
cd /opt/infiproxy/source
sudo bash deploy/bootstrap.sh --guided --with-nginx
```

The installer keeps existing env and core configs unless you explicitly choose
to overwrite them. Existing env files are backed up before replacement.

## Important Paths

```text
/opt/infiproxy/source
/usr/local/bin/infiproxy
/usr/local/sbin/infiproxy-manager
/etc/infiproxy/infiproxy.env
/var/lib/infiproxy/infiproxy.sqlite
/etc/systemd/system/infiproxy.service
/etc/systemd/system/infiproxy-*.service
/opt/infiproxy/cores
/etc/infiproxy-cores
/var/log/infiproxy-cores
```

Default panel environment:

```env
INFIPROXY_BIND=127.0.0.1:8080
INFIPROXY_DB=sqlite:///var/lib/infiproxy/infiproxy.sqlite?mode=rwc
INFIPROXY_DB_MAX_CONNECTIONS=2
INFIPROXY_COOKIE_SECURE=true
INFIPROXY_ENABLE_DEMO_USER=false
INFIPROXY_ENABLE_DANGER_SHELL=true
```

The web danger shell is owner-only and intended for break-glass administration.
For destructive host operations, prefer `sudo infiproxy-manager` over SSH.

## Manual Commands

Dry-run the installer:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash -s -- --check
```

Install from a fork:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash -s -- \
  --repo https://github.com/<user>/<repo>.git \
  --ref main \
  --guided \
  --with-nginx
```

Install or update a core without the TUI:

```bash
sudo /opt/infiproxy/source/deploy/cores/install-core.sh \
  --core xray \
  --version <version> \
  --url '<release-archive-url>' \
  --sha256 '<sha256>' \
  --binary xray
```

## Local Development

```bash
INFIPROXY_BIND=127.0.0.1:8080 \
INFIPROXY_DB='sqlite://./infiproxy.local.sqlite?mode=rwc' \
INFIPROXY_ENABLE_DEMO_USER=true \
cargo run -p stealthhub-panel
```

Open:

```text
http://127.0.0.1:8080/admin/setup
```

Create a test user:

```bash
cargo run -p stealthhub-cli -- create-user --username test-local --traffic-limit-gb 10
cargo run -p stealthhub-cli -- list-users
```

## Project Checks

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
bash -n deploy/bootstrap.sh deploy/install.sh deploy/panel-update.sh deploy/cores/install-core.sh deploy/infiproxy-manager.sh
bash deploy/install.sh --check
```

## License

Infiproxy is licensed under the **GNU Affero General Public License v3.0 or
later**.

See:

- [`LICENSE`](./LICENSE)
- [`LICENSE.ru.md`](./LICENSE.ru.md)
- [`NOTICE`](./NOTICE)
