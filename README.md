# StealthHub Panel

**StealthHub Panel** is a fast single-node Rust control panel for managing a personal proxy server and generating stable **Clash Mi / Mihomo-compatible** subscription configs.

The project is designed around one practical goal: keep the server simple, predictable, and controllable from a web GUI without relying on heavy multi-service panels.

> Status: early development / MVP.
> Current focus: users, token-based subscriptions, Mihomo YAML generation, and a clean Rust foundation.

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
* token-based Mihomo subscription endpoint;
* demo user initialization;
* basic web GUI;
* basic user lifecycle actions in progress;
* rule-provider endpoints;
* health endpoint.

Current routes:

```text
GET  /
GET  /admin
GET  /admin/users
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

Open:

```text
http://127.0.0.1:8080
http://127.0.0.1:8080/admin
http://127.0.0.1:8080/admin/users
http://127.0.0.1:8080/health
```

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

* enable / disable users;
* reset subscription token;
* delete users;
* better form validation;
* safer error pages.

### v0.3 — Admin authentication

* login page;
* password hashing;
* secure session cookies;
* logout;
* initial admin setup;
* optional 2FA later.

### v0.4 — Real protocol settings

* GUI protocol settings;
* Mihomo config builder;
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

* admin login;
* password hashing;
* secure session cookies;
* optional IP allowlist;
* backup and restore;
* config validation before apply;
* atomic config updates;
* rollback on failed service restart.

Current MVP is not production-ready and should not be exposed publicly without additional protection.

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

MIT

---

## Author

Built by [@infinitrator](https://github.com/infinitrator) as a personal single-node proxy control panel experiment.
