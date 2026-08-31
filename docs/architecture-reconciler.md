# Reconciliation Contract

This document specifies the current desired-state engine. It is an engineering
contract, not a production runbook. Operator procedures live in the versioned
Wiki.

## Boundary

The unprivileged panel validates requests and commits desired state to SQLite.
It cannot invoke systemd or write runtime configuration. A constrained request
file wakes `infiproxy-reconcile.service`; the root-owned reconciler loads one
transactionally coherent desired snapshot and trusted built-in adapter registries.

Generic reconciliation code selects adapters through IDs, capabilities, and
traits. Protocol-specific rendering remains under `adapters/`; generic storage,
request handlers, and transaction orchestration must not branch on protocol
names.

## State Model

Every runtime-affecting transaction updates the domain rows and increments a
monotonic desired generation in the same SQLite transaction. The worker reads a
coherent snapshot of those current rows. The database does not retain a full
historical desired snapshot for every generation. Control state records desired
and applied generation, status, operation ID, affected resources, timestamps,
sanitized failure detail, and the active runtime set.

Statuses are:

- `Pending`: durable desired state exists but has not converged;
- `Applying`: one reconciler owns the operation;
- `Applied`: health checks passed and the generation was published;
- `Failed`: failure happened before live mutation;
- `RolledBack`: live mutation failed and prior state was restored and verified;
- `Unsupported`: no trusted compatible adapter can satisfy the graph;
- `RecoveryRequired`: automatic compensation could not prove a safe state.

Writing desired state never implies successful activation.

## Transaction

For generation G, the worker:

1. takes the global OS lock and no-ops if G is already applied;
2. loads snapshot G, validates the resource graph, and selects compatible cores;
3. resolves secret references only at the rendering boundary;
4. creates a private transaction directory and durable operation journal;
5. renders and stages every candidate;
6. performs structural and available native validation before mutation;
7. snapshots files, service states, listeners, and adapter-owned resources;
8. verifies that G is still the desired generation;
9. installs candidates atomically and transitions services deterministically;
10. verifies health, required listeners, forbidden listeners, and feasible user
    authorization observations;
11. publishes `applied_generation = G` with compare-and-swap semantics;
12. records a sanitized terminal operation and removes private staging data.

Durable phases are `Prepared`, `Staged`, `Validated`, `Snapshotted`, `Installed`,
`Activated`, `Healthy`, `Publishing`, `RollbackStarted`, and terminal outcomes.
Live mutation cannot start before every candidate validates and every required
snapshot is durable.

## Failure and Recovery

A post-mutation error restores all adapter snapshots and previous service
states in reverse order, then verifies the restored state. Verified
compensation produces `RolledBack`. Failed or unprovable compensation produces
`RecoveryRequired`; it never advances the applied generation.

At startup, journals before live mutation are safely failed and their staging
is discarded. A nonterminal journal after mutation is rolled back unless both
generation publication and per-resource verification are durably proven.
Unknown state is never silently adopted.

The OS lock excludes concurrent privileged transactions. Generation checks
collapse duplicate wakeups, a stale worker aborts before mutation, and the final
compare-and-swap prevents an older generation from overwriting newer intent.

## Resources and Core Selection

Each enabled profile produces an adapter-owned desired resource and listener
claim. Core selection considers only explicitly advertised capabilities,
installed version compatibility, retained operator preference, and deterministic
priority. An installed module binary is not by itself a registered adapter.

The selected core composes all of its server fragments into one candidate.
Runtime removal is blocked while desired or applied resources depend on it.
Infrastructure resources participate in the same transaction but retain
exclusive file ownership boundaries.

User mutations affecting runtime authorization create a new generation.
Subscription-token reset is a client bearer-token operation and does not alter
runtime credentials unless an adapter explicitly declares that dependency.

## Security Invariants

- The panel remains unprivileged and never controls systemd directly.
- Runtime commands, binaries, units, and destination paths are fixed by trusted
  code; HTTP and desired JSON cannot select shell commands.
- Desired state stores secret references, not runtime-only secret values.
- Errors, snapshots, journals, status mirrors, and logs must remain redacted.
- Staging directories are private and live files use atomic replacement.
- Root-owned manifests, requests, runtime paths, and TLS material are validated
  for type, owner, group, mode, size, and effective runtime access.
- Missing adapters, unsupported capabilities, and incompatible exact pins fail
  before runtime mutation.

## Change Checklist

Changes to adapters, desired state, or reconciliation require tests for graph
validation, capability selection, candidate validation, rollback, crash
recovery, generation races, redaction, and listener ownership. Runtime pin or
renderer changes additionally require `bash deploy/tests/runtime-compatibility.sh`.
The ordinary CI suite must remain offline and must not access a deployed host.

See also [Adapter Contract](adapter-contract.md),
[Architecture Overview](architecture-overview.md), and
[Runtime Compatibility](runtime-compatibility.md).
