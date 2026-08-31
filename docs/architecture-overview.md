# Architecture Overview

Infiproxy is a Rust control plane for a small Linux proxy node. Its deployment
uses separate identities and explicit files rather than a privileged web
process.

## Processes

| Process | Identity | Responsibility |
|---|---|---|
| `infiproxy` | `infiproxy:infiproxy` | HTTP UI/API, authentication, SQLite desired state, subscriptions, status views |
| `infiproxy-reconcile` | root, systemd oneshot | Trusted adapter execution, runtime config validation, atomic activation, rollback |
| runtime services | `infiproxy-runtime:infiproxy-runtime` | Xray, sing-box, Hysteria, TUIC, and Mihomo data plane |
| panel updater | root, systemd oneshot | Build and atomically install a pinned repository/ref |
| module updater | root, systemd oneshot | Verify and install exact manifest-pinned runtime releases |
| `infiproxy-manager` | root/operator over SSH | Installation, certificates, secrets, lifecycle, diagnostics, and recovery |

The panel writes only under `/var/lib/infiproxy`. Root-owned request files and
systemd path units bridge approved operations to privileged helpers. Request
schemas are bounded and cannot contain executable paths or shell commands.

## Control Flow

1. An authenticated mutation is validated, authorized, CSRF-checked, and
   committed to SQLite as a new desired generation.
2. A wake request schedules the root reconciler.
3. Trusted adapters render and validate all candidates before live mutation.
4. The reconciler snapshots, installs, activates, verifies, and atomically
   publishes the applied generation, or restores the prior state.
5. Subscription requests read applied-compatible profile and routing state and
   render a Mihomo document for the bearer token.

Panel and runtime updates are independent from desired-state reconciliation.
Installing a runtime binary does not activate it and does not dynamically load
adapter code.

## Primary Boundaries

- SQLite is control-plane state, not a place for runtime-only private keys.
- `/etc/infiproxy/secrets.d` contains root-managed server secrets referenced by
  opaque IDs.
- `/etc/infiproxy-cores` contains runtime config and TLS material readable by
  the dedicated runtime group, not by the web process.
- `/etc/infiproxy-update.conf` is the single root-owned source for both manual
  and scheduled panel updates.
- `/etc/infiproxy-modules.d` is installed module inventory; trusted adapter
  registration remains compiled into the binary.

See [Security Boundaries](security-boundaries.md), [Adapter Contract](adapter-contract.md),
and [Reconciliation Contract](architecture-reconciler.md).
