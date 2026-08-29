# Infiproxy

Infiproxy is a single-server Rust panel for managing users, Mihomo/Clash-compatible
subscriptions, routing rules, protocol profiles and supervised proxy runtimes.

It is built for a simple VPS deployment model: **bare metal Linux + systemd +
SQLite + one SSH TUI**. The panel does not implement proxy protocols itself.
Network traffic is handled by external cores such as Xray, sing-box, Hysteria,
TUIC and Mihomo.

Full Russian operator and networking documentation is available in the
[`wiki/`](./wiki/Home.md): installation, every web/TUI control, protocols,
routing, modules, backups, security and troubleshooting.
After the one-time GitHub Wiki initialization, the same versioned pages are
published at the [Infiproxy GitHub Wiki](https://github.com/infinitrator/stealthhub-panel/wiki).

Current release line: `0.1.0-beta.1`.

## Quick Install

Primary target: a fresh Ubuntu 24.04 LTS or Debian 12 VPS. Ubuntu 22.04 LTS is
kept as a compatibility target, but the release gate is centered on the newer
base systems.

One command for the full guided install:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash -s -- --guided --with-nginx
```

The command installs build dependencies, Rust when needed, clones the project to
`/opt/infiproxy/source`, builds the release binary, installs systemd units and
opens the guided SSH TUI. The TUI then walks through panel repair, HTTPS,
optional core imports and final service checks.

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
- Panel update scheduler and immediate update trigger.
- Panel logs.
- Root-level uninstall and cleanup flows.

## Updates And Autostart

The panel and every runtime are installed as systemd-managed components.
`infiproxy.service` starts the Rust panel after boot. Runtime units are loaded
from root-approved manifests rather than a compiled list. The privileged
`infiproxy-reconcile` worker stages, validates, applies and verifies generated
runtime candidates; an installed but unused module remains inactive.

Panel self-updates are split into two layers:

- `infiproxy-panel-update.timer` runs the root checker/updater every 15 minutes,
  writes a sanitized status mirror, and applies a
  pending update at the server-local maintenance hour configured in Settings.
  A fresh install defaults to `05:00`; custom `HH:MM` values run in the first
  15-minute scheduler window at or after that time.
- `infiproxy-panel-update.path` watches for
  `/var/lib/infiproxy/panel-update-now.request`; the owner-admin "Update Now"
  button creates this file for immediate update.
- The unprivileged web process reads that mirror and never queries GitHub or
  chooses a repository/ref.
- The root updater uses `/opt/infiproxy/source`, rebuilds all panel helper binaries and
  reruns the idempotent installer. Before changing the source revision it creates
  fail-closed backups of the panel and control-helper binaries, SQLite database,
  panel/core settings, module manifests and Nginx configuration. A
  failed update restores the previous database, configs, binaries and source
  revision. Root-only logs, backups, build files and applied-version markers live in
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

Release downloads use HTTPS-only redirects, bounded retries/timeouts and archive
size/extraction limits. Set
`INFIPROXY_FORCE_IPV4=true` for the root updater only when a host has broken IPv6;
the default keeps normal dual-stack behavior. Every module update preserves its
config and creates a root-only backup under
`/var/lib/infiproxy-maintenance/module-backups` before switching the verified
binary. Core-specific smoke tests validate the executable, but a successful
binary install does not replace final config and service readiness checks.

The installer provides catalog manifests for Xray, sing-box, Hysteria, TUIC and
Mihomo. A root operator can import another compatible
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
/opt/infiproxy/cores/mihomo/current/mihomo
```

Systemd units:

```text
infiproxy-xray.service
infiproxy-sing-box.service
infiproxy-hysteria.service
infiproxy-tuic.service
infiproxy-mihomo.service
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

## Port Plan

The default deployment avoids internal port collisions:

```text
TCP 80/443              Nginx public edge for the panel hostname
TCP 127.0.0.1:8080      Infiproxy panel
TCP 12443               Trojan TLS/uTLS starter profile
TCP 13443               Snell v5 starter profile
TCP 14443               Mieru TCP starter profile
UDP 443                 Hysteria2 starter config
UDP 11443               TUIC starter config
```

Hysteria2 uses QUIC/UDP on `443`, while Nginx uses TCP `443`; these are separate
sockets and can coexist.

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
INFIPROXY_SETUP_TOKEN=<installer-generated-64-hex-token>
INFIPROXY_CURRENT_COMMIT=<installed-git-commit>
```

`INFIPROXY_CURRENT_COMMIT` is a compatibility/diagnostic value. The
authoritative deployed revision is
`/var/lib/infiproxy-maintenance/panel-last-applied.sha`, written by root only
after installation and readiness verification.

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
export INFIPROXY_SETUP_TOKEN="$(openssl rand -hex 32)"
INFIPROXY_BIND=127.0.0.1:8080 \
INFIPROXY_DB='sqlite://./infiproxy.local.sqlite?mode=rwc' \
INFIPROXY_COOKIE_SECURE=false \
cargo run -p stealthhub-panel
```

Open:

```text
http://127.0.0.1:8080/admin/setup
```

## Publishing A Beta Release

Run the checks below, commit the complete release state, push `main`, and wait
for the **Rust** workflow to succeed. Then create the annotated beta tag:

```bash
git tag -a v0.1.0-beta.1 -m 'Infiproxy 0.1.0 beta 1'
git push origin v0.1.0-beta.1
```

The **Release** workflow builds the Linux x86_64 package with Rust 1.96.0,
publishes `infiproxy-linux-x86_64.tar.gz` and its SHA-256 file, and marks tags
containing `-` as prereleases. Do not move or reuse a published tag. The normal
one-command installer follows the reviewed `main` update channel; for an exact
immutable beta installation use the tagged bootstrap:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/v0.1.0-beta.1/deploy/bootstrap.sh \
  | sudo bash -s -- --ref v0.1.0-beta.1 --guided --with-nginx
```

An installation pinned to a tag does not discover later commits on `main`.
Rerun bootstrap with `--ref main` only when you intentionally switch that host
to the rolling update channel.

## Project Checks

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo audit
cargo deny check
bash deploy/tests/wiki-check.sh
cargo build --locked -p stealthhub-panel --bins
bash deploy/tests/updater-regression.sh
bash deploy/tests/http-smoke.sh
bash deploy/install.sh --check
bash deploy/bootstrap.sh --check --src-dir "$PWD"
```

## License

Infiproxy is licensed under the **GNU Affero General Public License v3.0 or
later**.

See:

- [`LICENSE`](./LICENSE)
- [`LICENSE.ru.md`](./LICENSE.ru.md)
- [`NOTICE`](./NOTICE)
