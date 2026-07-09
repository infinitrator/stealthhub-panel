# StealthHub Panel

**StealthHub Panel** is a fast single-node Rust control panel for managing a personal proxy server and generating stable **Clash Mi / Mihomo-compatible** subscription configs.

The project is designed around one practical goal: keep the server simple, predictable, and controllable from a web GUI without relying on heavy multi-service panels.

> Status: release-candidate field build.
> Current focus: protected admin GUI, users, protocol settings, routing, Mihomo subscriptions, proxy-core deployment, and VPS systemd installs.

---

## Why this project exists

Most existing proxy panels are either too heavy, too broad, or too fragile for a small personal server. StealthHub Panel takes the opposite approach:

* one server / one node first;
* Rust backend for speed and reliability;
* SQLite instead of MongoDB or Redis;
* simple GUI instead of a heavy SPA;
* Clash Mi / Mihomo YAML as the primary client target;
* predictable routing profiles;
* no unnecessary protocol zoo.

The panel is being built for a setup where the user should eventually be able to manage the server almost entirely from the GUI: users, subscriptions, routing, protocol settings, system services, logs, backups, and deployment.

---

## Core ideas

StealthHub Panel is not intended to implement proxy protocols from scratch.

Instead, it acts as a **control plane**:

```text
StealthHub Panel  →  users / settings / subscriptions / configs / system control
Proxy cores       →  actual network transport
Clash Mi          →  primary client consuming Mihomo YAML
```

This keeps the panel small, auditable, and easier to maintain.

---

## Planned protocol stack

The primary client target is **Clash Mi / Mihomo**, so the server-side configuration and subscriptions are designed around Mihomo-compatible YAML.

Planned profiles:

| Profile                         | Role                                   |
| ------------------------------- | -------------------------------------- |
| VLESS + REALITY + XHTTP         | main careful TCP profile               |
| Shadowsocks 2022 + ShadowTLS v3 | compatible TCP fallback                |
| AnyTLS                          | experimental modern TLS-shaped profile |
| Hysteria2                       | high-speed fallback, not the default   |
| TUIC                            | optional QUIC-based speed fallback     |

The default client routing should not blindly proxy everything. The intended model is:

```text
Banking / local / RU services → DIRECT
AI / development / selected services → AUTO-SAFE
Streaming / heavy traffic → SPEED
Everything else → configurable
```

---

## Current MVP features

Implemented:

* Rust workspace structure;
* `stealthhub-core` crate;
* `stealthhub-panel` web server;
* `stealthhub-cli` helper commands;
* SQLite storage;
* user table;
* admin table;
* server-side admin sessions;
* initial admin setup page;
* admin login/logout;
* Argon2id password hashing;
* in-memory login rate limiting;
* CSRF protection for authenticated admin forms;
* security headers for web responses;
* key/value settings storage foundation;
* global settings editor;
* local secret-value storage foundation;
* protocol profile model for Xray/sing-box/Hysteria/TUIC-oriented configs;
* default protocol-profile seeding;
* protocol profile parameter editor;
* DB-backed Mihomo YAML generation from settings + profiles + secret references;
* DB-backed routing rule-set storage;
* routing rule-set editor for Mihomo `RULE-SET` imports;
* token-based Mihomo subscription endpoint;
* optional demo user initialization for local development;
* basic web GUI;
* user creation;
* user enable/disable;
* subscription token reset;
* user delete;
* simple HTML error pages for admin actions;
* protocol overview page;
* system overview page;
* proxy cores overview page;
* local proxy-core install detection under `.runtime/cores`;
* proxy core systemd templates;
* proxy core config placeholders;
* safe proxy-core install/update script;
* readiness endpoint with SQLite check;
* bare-metal systemd deployment templates;
* bare-metal install script;
* rule-provider endpoints;
* health endpoint.

Current routes:

```text
GET  /
GET  /admin/setup
POST /admin/setup
GET  /admin/login
POST /admin/login
POST /admin/logout
GET  /admin
GET  /admin/users
GET  /admin/settings
POST /admin/settings
GET  /admin/protocols
POST /admin/protocols/{name}/update
GET  /admin/routing
POST /admin/routing
GET  /admin/system
GET  /admin/cores
POST /admin/users/create
POST /admin/users/{id}/toggle
POST /admin/users/{id}/reset-token
POST /admin/users/{id}/delete
GET  /health
GET  /ready
GET  /sub/{token}/mihomo.yaml
GET  /rules/{name}
```

---

## Repository structure

```text
stealthhub-panel/
├── Cargo.toml
├── Cargo.lock
├── crates/
│   ├── stealthhub-core/
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── mihomo.rs
│   │       ├── models.rs
│   │       ├── rules.rs
│   │       └── storage.rs
│   ├── stealthhub-panel/
│   │   └── src/
│   │       └── main.rs
│   └── stealthhub-cli/
│       └── src/
│           └── main.rs
└── .github/
    └── workflows/
        └── rust.yml
```

---

## Development

Requirements:

* Rust stable;
* Cargo;
* SQLite;
* Git.

Run checks:

```bash
cargo fmt
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run locally:

```bash
STEALTHHUB_BIND=127.0.0.1:8080 \
STEALTHHUB_DB='sqlite://./stealthhub.sqlite?mode=rwc' \
STEALTHHUB_ENABLE_DEMO_USER=true \
cargo run -p stealthhub-panel
```

For production behind HTTPS, enable the `Secure` flag on the admin session cookie:

```bash
STEALTHHUB_COOKIE_SECURE=true
```

Open:

```text
http://127.0.0.1:8080
http://127.0.0.1:8080/admin
http://127.0.0.1:8080/admin/users
http://127.0.0.1:8080/admin/protocols
http://127.0.0.1:8080/admin/routing
http://127.0.0.1:8080/admin/system
http://127.0.0.1:8080/health
http://127.0.0.1:8080/ready
```

On the first run, open `/admin` or `/admin/setup` and create the first admin account. After that, `/admin` and `/admin/users` require login. Public subscription and rule-provider endpoints stay public so Mihomo-compatible clients can fetch configs.

The local demo subscription at `/sub/demo/mihomo.yaml` is created only when `STEALTHHUB_ENABLE_DEMO_USER=true`. Keep it disabled on production servers.

Generate demo Mihomo YAML from CLI:

```bash
cargo run -p stealthhub-cli -- generate-mihomo
```

Create a local test user in the default development database:

```bash
cargo run -p stealthhub-cli -- create-user --username test-local --traffic-limit-gb 10
cargo run -p stealthhub-cli -- list-users
```

Then run the panel against the same database and open the printed subscription path:

```bash
STEALTHHUB_BIND=127.0.0.1:8080 \
STEALTHHUB_DB='sqlite://./stealthhub.local.sqlite?mode=rwc' \
cargo run -p stealthhub-panel
```

---

## Deployment target

The current deployment target is **bare metal + systemd**, not Docker.

That is intentional for the single-node control-panel model: StealthHub Panel will need to inspect and control host services, write proxy-core configs, read logs, validate ports, and later apply rollback-safe changes. Running the panel as a normal Linux service keeps those system boundaries explicit and avoids coupling production deploys to a local development machine.

Repository deployment templates:

```text
deploy/stealthhub-panel.env.example
deploy/stealthhub-panel.service
deploy/install.sh
deploy/nginx-stealthhub-panel.conf.example
deploy/cores/
```

Expected server layout:

```text
/usr/local/bin/stealthhub-panel
/etc/stealthhub-panel/stealthhub-panel.env
/var/lib/stealthhub-panel/stealthhub.sqlite
```

Minimal server install:

```bash
cargo build --release -p stealthhub-panel
sudo bash deploy/install.sh
```

For production, put Nginx/Caddy in front of the panel, keep `STEALTHHUB_BIND=127.0.0.1:8080`, set `STEALTHHUB_COOKIE_SECURE=true`, and check:

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
systemctl status stealthhub-panel
```

Full VPS instructions: [docs/VPS_INSTALL.md](docs/VPS_INSTALL.md).

---

## Proxy cores

The panel is designed to control external proxy cores instead of embedding protocol implementations.

Initial runtime stack:

| Core     | Role                                             | Service                         |
| -------- | ------------------------------------------------ | ------------------------------- |
| Xray     | VLESS + REALITY + XHTTP/TCP primary profile      | `stealthhub-xray.service`       |
| sing-box | SS2022 + ShadowTLS, AnyTLS compatibility profile | `stealthhub-sing-box.service`   |
| Hysteria | Hysteria2 speed fallback                         | `stealthhub-hysteria.service`   |
| TUIC     | optional TUIC speed fallback                     | `stealthhub-tuic.service`       |

Repository templates:

```text
deploy/cores/README.md
deploy/cores/install-core.sh
deploy/cores/core-update-manifest.example.toml
deploy/cores/systemd/*.service
deploy/cores/configs/*
```

Expected runtime layout:

```text
/opt/stealthhub/cores/{core}/{version}
/opt/stealthhub/cores/{core}/current
/etc/stealthhub-cores/{core}/config.*
/var/lib/stealthhub-panel/core-updates/{core}/{version}
```

Local development uses the same versioned layout under `.runtime/cores`:

```text
.runtime/cores/xray/current/xray
.runtime/cores/sing-box/current/sing-box
.runtime/cores/hysteria/current/hysteria
.runtime/cores/tuic/current/tuic-server
```

The `.runtime` directory is intentionally ignored by Git. Download releases there, verify SHA256 before execution, and keep production installs under `/opt/stealthhub/cores`.

Safe update policy:

```text
download to staging
verify SHA256
validate binary and config
switch current symlink atomically
restart one service
check health and journal
roll back symlink if the service fails
```

Do not overwrite active core binaries in place. Do not let the panel download and execute a release without checksum verification and config validation.

Core install example:

```bash
sudo deploy/cores/install-core.sh \
  --core xray \
  --version 26.3.27 \
  --url 'https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip' \
  --sha256 '<sha256-from-release>' \
  --binary xray \
  --restart stealthhub-xray.service
```

---

## Subscription format

The panel currently exposes a Mihomo-compatible subscription endpoint:

```text
/sub/{token}/mihomo.yaml
```

Example:

```text
/sub/demo/mihomo.yaml
```

The generated config contains:

* proxy definitions;
* proxy groups;
* rule providers;
* direct rules;
* speed group;
* fallback group;
* load-balance group.

The endpoint is generated as Mihomo-compatible YAML.

---

## Rule providers

The panel can serve rule-provider files for Mihomo:

```text
/rules/banking-direct.yaml
/rules/direct-local.yaml
/rules/proxy-ai.yaml
/rules/streaming.yaml
```

Current GUI support:

* edit built-in rule sets from the panel;
* enable/disable rule sets;
* choose the generated `RULE-SET` target group;
* validate classical rule payload before saving.

---

## Roadmap

### v0.1 — Users and subscriptions

* SQLite users;
* token-based subscriptions;
* optional demo user;
* basic users page;
* create user form.

### v0.2 — User lifecycle

* enable / disable users; ✅
* reset subscription token; ✅
* delete users; ✅
* better form validation; ✅
* safer error pages. ✅

### v0.3 — Admin authentication

* login page; ✅
* password hashing; ✅
* session cookies; ✅
* logout; ✅
* initial admin setup; ✅
* optional 2FA later.

### v0.4 — Real protocol settings

* settings storage foundation; ✅
* secret-value storage foundation; ✅
* protocol profile model; ✅
* default protocol profile seeding; ✅
* protocol overview page; ✅
* Mihomo config builder from DB-backed profiles; ✅
* GUI protocol settings;
* generated config validation;
* separate profiles for safe, speed, fallback, and balance modes.

### v0.5 — System control

* bare-metal deployment target; ✅
* system overview page; ✅
* proxy cores overview page; ✅
* proxy core service templates; ✅
* readiness endpoint; ✅
* systemd service template; ✅
* service status;
* systemd restart/reload;
* logs viewer;
* firewall status;
* port checks;
* disk/RAM/CPU overview.

### v0.6 — Deployment from GUI

* `git pull`;
* build release binary;
* restart service;
* view deploy logs;
* rollback previous build.

### v1.0 — Single-node production target

* stable web GUI;
* admin auth;
* user management;
* subscription management;
* routing profiles;
* service control;
* backups;
* safe config apply with rollback.

---

## Security model

StealthHub Panel is intended to run on a private server and should be protected carefully.

Planned security features:

* admin login; ✅
* password hashing; ✅
* server-side session storage; ✅
* CSRF protection for admin actions; ✅
* basic security headers; ✅
* secure session cookies when `STEALTHHUB_COOKIE_SECURE=true`;
* optional IP allowlist;
* login rate limiting; ✅
* 2FA / passkeys;
* backup and restore;
* config validation before apply;
* atomic config updates;
* rollback on failed service restart.

Current MVP has basic admin authentication, but it is still not production-ready. Do not expose it publicly without HTTPS, a strong admin password, firewall or reverse-proxy restrictions, and careful operational hardening.

Current limitations:

* no 2FA/passkey support yet;
* login rate limiting is in-memory and resets on panel restart;
* no IP allowlist yet;
* local secret values are stored in SQLite plaintext for now, so protect the database file and host permissions;
* destructive actions use CSRF protection but do not yet have dedicated confirmation pages.

---

## Design principles

* Keep the core simple.
* Prefer one stable path over many half-working options.
* Avoid unnecessary background services.
* Avoid storing secrets in Git.
* Generate predictable configs.
* Validate before applying.
* Make every dangerous action reversible.
* Make the GUI fast enough that SSH becomes optional for routine work.

---

## License

StealthHub Panel is licensed under the **GNU Affero General Public License v3.0 or later**.

SPDX identifier:

```text
AGPL-3.0-or-later
```

You may use, study, copy, modify, and redistribute this project, including for commercial purposes, but any distributed or network-accessible modified version must remain available under AGPL-compatible terms.

Because StealthHub Panel is a network server application, AGPL is important: if you modify the panel and let users interact with that modified version over a network, you must provide those users access to the corresponding source code of your modified version.

In simple terms:

* you may use the project;
* you may modify it;
* you may fork it;
* you may use it commercially;
* you must keep copyright and license notices;
* you must publish the source code of modified versions when distributing them or providing network access to them;
* you cannot turn a modified version into a closed-source hosted service.

See:

* [`LICENSE`](./LICENSE) — full legal license text;
* [`LICENSE.ru.md`](./LICENSE.ru.md) — Russian explanation;
* [`NOTICE`](./NOTICE) — attribution notice.


---

## Author

Built by [@infinitrator](https://github.com/infinitrator) as a personal single-node proxy control panel experiment.
