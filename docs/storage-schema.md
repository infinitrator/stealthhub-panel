# Storage Schema

Infiproxy uses SQLite at `/var/lib/infiproxy/infiproxy.sqlite`. Migrations are
idempotent and recorded in `schema_migrations`; operators must use supported
backup/restore procedures rather than editing the live database.

## Main Tables

| Area | Tables | Purpose |
|---|---|---|
| Authentication | `admins`, `admin_sessions` | Password hashes, owner ordering, hashed sessions and expiry |
| Users | `users` | Subscription identity, enablement, limits, expiry, runtime credential generation and counters |
| Settings | `settings`, `bootstrap_state` | Validated control-plane settings and one-time bootstrap state |
| Profiles | `protocol_profiles` | Stable adapter ID, schema version, endpoint, role, JSON config, preferred core and managed resource ID |
| Secrets | `secret_values` | Legacy/control-plane secret storage; runtime-only values use root files and references |
| Desired state | `reconcile_state`, `adapter_state` | Generations, convergence status, active runtimes and opaque adapter observations |
| User sync | `runtime_user_sync` | Per-runtime authorization observations for a generation |
| Routing | `client_dns_policy`, `client_transport_pools`, `client_transport_pool_members`, `client_routing_rules`, `routing_rule_sets`, `routing_rule_entries`, `routing_rule_sources` | Mihomo DNS, groups, ordered rules and providers |
| Administrative audit | `audit_events` | Actor/action/object/outcome snapshots with bounded secret-free metadata, append-only through normal application interfaces |

The exact schema is authoritative in `crates/stealthhub-core/src/storage.rs`.
Unknown columns must be preserved by migrations and restore tooling.

## Transaction Rules

Runtime-affecting domain changes and desired generation creation happen in one
database transaction. Applied generation advances only after privileged health
verification. Compare-and-swap publication prevents an old worker from
publishing over newer intent.

The worker reads one coherent snapshot of current profile/user/setting rows and
their generation. SQLite does not retain a complete historical desired graph
for each generation. Reconcile candidates, file snapshots, and the sanitized
operation journal live in the private root-owned maintenance transaction tree,
not in separate SQLite snapshot/operation tables.

Deleting or toggling a user can change runtime authorization and therefore
creates a generation. Resetting only the subscription bearer token does not.
Traffic counters and limits are stored and displayed, but this release does not
provide a runtime traffic collector or quota-enforcement loop.

## Backup and Recovery

Use SQLite's online `.backup` operation while the panel is running, or stop all
writers before a file-level copy. A valid recovery set also includes root-owned
secrets/configuration and runtime state; the database alone is insufficient.
Never copy WAL/SHM files independently and never replace the live database while
services are writing.

Because `audit_events` is part of the same SQLite database, online backups
naturally preserve audit history. No normal application API updates, deletes,
or silently expires these rows. Migration 10 installs SQLite triggers that
reject row updates and deletes, and `.backup` preserves those triggers and
indexes with the schema. This is defense in depth, not cryptographic
immutability: root or a database owner can drop the triggers or replace the
database.

The operator procedure is maintained in
[`wiki/12-BACKUP-RESTORE-UNINSTALL.md`](../wiki/12-BACKUP-RESTORE-UNINSTALL.md).
