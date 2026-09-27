# Development Guide

## Prerequisites

- Rust 1.96 with Cargo and rustfmt/clippy components;
- Bash, Git, SQLite, curl, and standard Unix tools;
- ShellCheck for deployment-script linting;
- optional Gitleaks and cargo-deny for security gates.

Use a disposable development database and never point local commands at a
production host.

## Build and Test

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo build --locked --release -p stealthhub-panel
```

Run repository contracts:

```bash
bash deploy/tests/wiki-check.sh
bash deploy/tests/install-state-regression.sh
bash deploy/tests/updater-regression.sh
find deploy -type f -name '*.sh' -exec bash -n {} +
find deploy -type f -name '*.sh' -exec shellcheck -x {} +
```

The networked runtime suite downloads exact upstream assets and is deliberately
separate:

```bash
bash deploy/tests/runtime-compatibility.sh
```

## Local Panel

Set a disposable database URL and bind only to loopback. The initial visit to
`/admin/setup` creates the first owner account. Setup refuses to start without
a token of at least 32 characters.

```bash
mkdir -p .runtime
export INFIPROXY_DB=sqlite://$PWD/.runtime/infiproxy.sqlite?mode=rwc
export INFIPROXY_BIND=127.0.0.1:8080
export INFIPROXY_COOKIE_SECURE=false
export INFIPROXY_SETUP_TOKEN="$(openssl rand -hex 32)"
cargo run -p stealthhub-panel
```

Root reconciliation and systemd/module operations are not emulated by this
command. UI state may therefore show unavailable privileged resources.

## Change Discipline

- Keep protocol knowledge inside adapters and capability declarations truthful.
- Do not add shell execution paths controlled by HTTP values.
- Use stable migrations; never rewrite existing operator data destructively.
- Preserve redaction in errors, Debug output, snapshots, and fixtures.
- Update README/Wiki/contracts in the same change when behavior or pins change.
- Keep web and TUI changes aligned with `docs/design-system.md`. New themes
  override semantic token values rather than component rules. When a source
  mark changes, regenerate its favicon derivatives and change the versioned
  icon/manifest URL so deployed browsers cannot reuse the previous identity.
- Add tests at the narrowest contract boundary and run the full workspace gates.

See `CONTRIBUTING.md` for pull-request expectations.
