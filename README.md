# StealthHub Panel

**StealthHub Panel** is a fast single-node Rust control panel for managing a personal proxy server and generating stable **Clash Mi / Mihomo-compatible** subscription configs.

The project is designed around one practical goal: keep the server simple, predictable, and controllable from a web GUI without relying on heavy multi-service panels.

> Status: early development / MVP.
> Current focus: protected admin GUI, users, token-based subscriptions, Mihomo YAML generation, and a clean Rust foundation.

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
* `stealthhub-cli` CLI skeleton;
* SQLite storage;
* user table;
* admin table;
* server-side admin sessions;
* initial admin setup page;
* admin login/logout;
* Argon2id password hashing;
* CSRF protection for authenticated admin forms;
* security headers for web responses;
* key/value settings storage foundation;
* local secret-value storage foundation;
* protocol profile model for Xray/sing-box/Hysteria/TUIC-oriented configs;
* default protocol-profile seeding;
* DB-backed Mihomo YAML generation from settings + profiles + secret references;
* token-based Mihomo subscription endpoint;
* demo user initialization;
* basic web GUI;
* user creation;
* user enable/disable;
* subscription token reset;
* user delete;
* simple HTML error pages for admin actions;
* protocol overview page;
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
GET  /admin/protocols
POST /admin/users/create
POST /admin/users/{id}/toggle
POST /admin/users/{id}/reset-token
POST /admin/users/{id}/delete
GET  /health
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
cargo test --workspace
```

Run locally:

```bash
STEALTHHUB_BIND=127.0.0.1:8080 \
STEALTHHUB_DB='sqlite://./stealthhub.sqlite?mode=rwc' \
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
http://127.0.0.1:8080/health
```

On the first run, open `/admin` or `/admin/setup` and create the first admin account. After that, `/admin` and `/admin/users` require login. Public subscription and rule-provider endpoints stay public so Mihomo-compatible clients can fetch configs.

Generate demo Mihomo YAML from CLI:

```bash
cargo run -p stealthhub-cli -- generate-mihomo
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

The goal is to make this endpoint directly usable by Clash Mi and other Mihomo-compatible clients.

---

## Rule providers

The panel can serve rule-provider files for Mihomo:

```text
/rules/banking-direct.yaml
/rules/direct-local.yaml
/rules/proxy-ai.yaml
/rules/streaming.yaml
```

Planned GUI features:

* edit rule sets from the panel;
* enable/disable rule sets;
* import external rule sets;
* sync rules from GitHub/raw URLs;
* validate rule-provider syntax before applying.

---

## Roadmap

### v0.1 — Users and subscriptions

* SQLite users;
* token-based subscriptions;
* demo user;
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
* login rate limiting;
* 2FA / passkeys;
* backup and restore;
* config validation before apply;
* atomic config updates;
* rollback on failed service restart.

Current MVP has basic admin authentication, but it is still not production-ready. Do not expose it publicly without HTTPS, a strong admin password, firewall or reverse-proxy restrictions, and careful operational hardening.

Current limitations:

* no 2FA/passkey support yet;
* no login rate limiting yet;
* no IP allowlist yet;
* local secret values are stored in SQLite plaintext for now, so protect the database file and host permissions;
* destructive actions use CSRF protection but do not yet have dedicated confirmation pages.

Suggested commit message for the current auth/lifecycle milestone:

```text
add admin authentication
```

If committing manually:

```bash
git add Cargo.toml Cargo.lock README.md crates/stealthhub-core/Cargo.toml crates/stealthhub-core/src/models.rs crates/stealthhub-core/src/storage.rs crates/stealthhub-panel/Cargo.toml crates/stealthhub-panel/src/main.rs
git commit -m "add admin authentication"
```

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
