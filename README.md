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
- Internet access to GitHub releases. The module updater selects the correct
  official asset for the server architecture and verifies it before activation.

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

With `whiptail` available it uses a full-screen gray/white interface with green
accents, nested menus, input boxes and protected secret prompts. The same
operations retain a plain terminal fallback for rescue environments.

It includes:

- Guided deployment cycle.
- Service status dashboard.
- Restart and reload actions.
- Panel environment editor.
- HTTPS and Cloudflare certificate setup.
- Independent runtime-module manager with installed/latest comparison.
- Telegram MTProto setup.
- Headscale mesh hub setup.
- Panel update scheduler and immediate update trigger.
- Panel logs.
- Root-level uninstall and cleanup flows.

## Updates And Autostart

The panel and every runtime are installed as systemd-managed components.
`infiproxy.service` starts the Rust panel after boot. Every configured module
keeps its own systemd unit and returns to its previous enabled/active state after
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

- The web panel checks GitHub every two hours and stores update state in
  `/var/lib/infiproxy/panel-update-state.env`.
- `infiproxy-panel-update.timer` runs the root updater every 15 minutes and applies a
  pending update at the server-local maintenance hour configured in Settings.
  A fresh install defaults to `05:00`; custom `HH:MM` values run in the first
  15-minute scheduler window at or after that time.
- `infiproxy-panel-update.path` watches for
  `/var/lib/infiproxy/panel-update-now.request`; the owner-admin "Update Now"
  button creates this file for immediate update.
- The root updater uses `/opt/infiproxy/source`, rebuilds the release binary and
  reruns the idempotent installer. Before changing the source revision it creates
  fail-closed backups of the binary, SQLite database, panel/core/Headscale
  settings, module manifests and Nginx configuration. A failed update restores
  the previous database, configs, binary and source revision. Root-only logs,
  backups, build files and applied-version markers live in
  `/var/lib/infiproxy-maintenance`, separate from web-writable state.

Change automatic-update enablement and maintenance time in `/admin/settings`.
The repository and ref are pinned in root-owned `/etc/infiproxy-update.conf`
during bootstrap; this prevents a stolen web-admin session from replacing the
root update source. Change channels by rerunning bootstrap with `--repo` and
`--ref`.

## Runtime Modules

Open `Modules` in the web panel or `Runtime modules` in the SSH manager. The
runtime list is loaded from root-owned manifests rather than compiled into the
panel. Each active module can be checked, installed, updated, disabled for
automatic updates or removed independently. Removing a module preserves its
configuration and places it back in the available catalog.

Manifest parsing and GitHub metadata validation use the native
`/usr/local/libexec/infiproxy-module-manifest` Rust helper. Python is not part
of the base panel or module updater; it is installed only with the optional
Certbot Cloudflare DNS plugin.

Release downloads use bounded retries and timeouts. Set
`INFIPROXY_FORCE_IPV4=true` for the root updater only when a host has broken IPv6;
the default keeps normal dual-stack behavior. Every module update preserves its
config and creates a root-only backup under
`/var/lib/infiproxy-maintenance/module-backups` before switching the verified
binary. Core-specific smoke tests validate the executable, but a successful
binary install does not replace final config and service readiness checks.

The installer provides catalog manifests for Xray, sing-box, Hysteria, TUIC,
Telegram MTProto and Headscale. A root operator can import another compatible
generic GitHub-release manifest from the SSH manager. Browser sessions can only
activate manifests already approved in that root-owned catalog; they cannot
submit repositories, download commands or systemd unit names.

For a new generic provider, the SSH manager also asks for its systemd unit when
the expected `infiproxy-<module-id>.service` is not installed. The unit is
accepted only when it runs the module's versioned binary as the unprivileged
`infiproxy` user, contains no extra `Exec*` hooks and enables
`NoNewPrivileges` plus `ProtectSystem=strict`.

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

The normal TUI flow is:

```text
Runtime modules
Show installed/latest status
Install or update one module
```

Release assets come from the repository pinned in each validated manifest.
GitHub's asset digest or the upstream checksum sidecar is verified before a
bounded smoke test and atomic `current` symlink switch. A generic module may
control only `infiproxy-<module-id>.service` and its own
`/etc/infiproxy-cores/<module-id>/` configuration tree. If an active service
fails after restart, the updater restores the previous symlink and service.
Config files are never replaced by a module update.

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

- Installs a versioned official Headscale binary through the shared module
  updater and verifies its SHA256 digest.
- Writes `/etc/headscale/config.yaml`.
- Creates a dedicated Nginx HTTPS site at
  `/etc/nginx/sites-available/infiproxy-headscale.conf`.
- Issues a Let's Encrypt certificate through Cloudflare DNS-01.
- Starts `headscale.service`.
- Can create a Headscale user and pre-auth key for client onboarding.

The owner-admin can also use `/admin/headscale` to inspect users and nodes,
create users and pre-auth keys, expire a node, and clear the last protected
result. The web process never executes Headscale: typed requests are consumed
by the existing root maintenance worker.

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

Direct maintenance commands:

```bash
sudo infiproxy-module-update --check-all
sudo infiproxy-module-update --update xray
sudo systemctl start infiproxy-panel-update.service
```

## Uninstall

Use the SSH manager and review the generated command list before confirmation:

```bash
sudo infiproxy-manager --uninstall panel
sudo infiproxy-manager --uninstall full
sudo infiproxy-manager --uninstall factory
```

`panel` removes the control plane and its update machinery while leaving module
binaries and services. `full` removes the complete Infiproxy runtime footprint.
`factory` also removes the source checkout and manager integration. OS packages
such as Git, Rust or Nginx are deliberately not purged because the installer
cannot prove whether they existed before Infiproxy.

## Important Paths

```text
/opt/infiproxy/source
/usr/local/bin/infiproxy
/usr/local/sbin/infiproxy-manager
/usr/local/sbin/infiproxy-module-update
/usr/local/libexec/infiproxy-module-manifest
/usr/local/libexec/infiproxy-headscale-control
/etc/infiproxy/infiproxy.env
/etc/infiproxy-update.conf
/etc/infiproxy-modules.d
/etc/infiproxy-modules.available.d
/var/lib/infiproxy/infiproxy.sqlite
/var/lib/infiproxy-maintenance
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
```

Shell and terminal execution are intentionally unavailable in the web panel.
Use the structured controls, config editors or `sudo infiproxy-manager` over SSH.

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

Install or update a module without the TUI:

```bash
sudo infiproxy-module-update --check xray
sudo infiproxy-module-update --update xray
```

The web frontend is isolated under
`crates/stealthhub-panel/src/views/`, with the shared page shell in `ui.rs` and
all styling in `assets/panel.css`. Route handlers, authentication, module
updates and storage do not contain page markup, so visual changes are delivered
through the normal in-place panel update without a reinstall.

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
bash -n deploy/bootstrap.sh deploy/install.sh deploy/panel-update.sh deploy/module-update.sh deploy/cores/install-core.sh deploy/infiproxy-manager.sh deploy/infiproxy-profile.sh
bash deploy/install.sh --check
```

## License

Infiproxy is licensed under the **GNU Affero General Public License v3.0 or
later**.

See:

- [`LICENSE`](./LICENSE)
- [`LICENSE.ru.md`](./LICENSE.ru.md)
- [`NOTICE`](./NOTICE)
