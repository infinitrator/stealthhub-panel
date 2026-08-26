# Infiproxy adapter and reconciliation architecture

## Status and compatibility baseline

This document defines the control-plane architecture introduced after
`53b423c4f4d33708595dbcdbb247d06d2d4e5dab`. It is deliberately deployment
neutral: development and tests must not mutate a production host.

The migration preserves the legacy `protocol_profiles` table and copies every
known row into the adapter-backed schema without changing its name, enabled
flag, endpoint, role, configuration payload, or secret references. Existing
subscriptions and rule-provider URLs remain available during migration.

Migration itself is generation zero and performs no runtime mutation. Known
legacy profiles receive their compatibility-selected adapter and a stable
resource identity, while unknown rows remain preserved and unsupported. The
first later runtime-affecting edit reconciles all enabled known profiles, so a
production upgrade must first back up and compare the existing hand-written
runtime configuration and provision every root-only server secret.

## Module boundaries

Generic modules contain no concrete protocol or runtime-core matching:

- `adapter`: stable IDs, manifests, capabilities, opaque versioned JSON,
  protocol/core interfaces, registries, and redacted secret access;
- `desired`: desired/applied generations, resource graph, statuses, and
  sanitized operation summaries;
- `reconcile`: adapter-agnostic planning, staging, validation, apply, health,
  listener verification, rollback, and crash recovery;
- `subscription`: Mihomo document assembly, abstract policy roles, routing
  groups, and rule providers;
- `storage`: durable generations, immutable desired snapshots, operation
  journal, compare-and-swap completion, and idempotent migration.

Adapter-specific modules contain all implementation knowledge:

- `adapters/protocols/*`: protocol validation, secret references, user
  participation, client rendering, server fragments, and schema migration;
- `adapters/cores/*`: core capabilities, candidate composition, validation,
  service lifecycle, listener checks, snapshots, and rollback;
- `adapters/infrastructure/*`: public hostname, frontend, certificate, and
  readiness reconciliation.

Migration compatibility code may recognize legacy serialized IDs, but generic
request handlers, users, routing, subscription assembly, and reconciliation do
not branch on those IDs.

## Adapter identity and discovery

Adapter IDs are stable lowercase strings. Configuration is opaque JSON paired
with a positive schema version. Capabilities are stable strings and are the
only generic protocol-to-core compatibility mechanism.

Registries accept adapter objects at runtime. Adding an adapter package changes
only adapter registration/bootstrap code, not generic orchestration. Tests use
the same registry API to inject adapters unknown to the generic engine.

Production adapter manifests are root-owned regular files. A privileged worker
rejects writable, symlinked, oversized, schema-incompatible, or invalid-ID
manifests. Infiproxy does not load dynamic libraries. A future external adapter
executable must use a bounded, versioned request protocol and a root-approved
fixed path; HTTP input can never select an executable path or command.

## Protocol adapter contract

A protocol adapter owns:

- stable ID, display name, adapter/schema versions, and required capabilities;
- opaque configuration validation and migration;
- secret-reference discovery without returning values;
- whether and how a panel user participates in runtime authorization;
- Mihomo client proxy-object rendering;
- server-fragment rendering for a selected compatible core;
- optional defaults and protocol-specific health requirements.

The generic subscription assembler receives already-rendered JSON proxy
objects. It knows profile IDs and abstract roles, but does not know protocol or
core IDs.

## Core adapter contract

A core adapter owns:

- stable ID, capabilities, and installed/version state;
- composition of protocol server fragments into a complete candidate;
- candidate staging and native validation;
- snapshot, atomic installation, and previous-state restoration;
- controlled service enable/disable/reload/restart;
- health and required/forbidden listener verification;
- sanitized diagnostics and recovery verification.

Installation/update/removal is separate from activation. An installed core may
remain disabled when no desired resource selects it. Removal is blocked while
an applied or desired dependency exists, unless a compatible replacement is
successfully reconciled first.

## Infrastructure adapter contract

Public subscription/node hostnames are infrastructure resources, not ordinary
settings. Their adapter owns frontend configuration, certificate provisioning,
validation, and health. The UI presents a changed hostname as `Pending` until
the frontend and certificate are verified. Protocol adapters never contain
Nginx or certificate logic.

## Desired and applied state

Every runtime-affecting mutation creates an immutable desired snapshot and
increments a monotonic generation in the same SQLite transaction. State tracks:

- desired and applied generation;
- `Pending`, `Applying`, `Applied`, `Failed`, `RolledBack`, `Unsupported`, or
  `RecoveryRequired`;
- operation ID and affected resource IDs;
- timestamps, sanitized error, and rollback status.

Desired records contain secret references only. Secret values are resolved by
the process that needs them and are wrapped in redacted types whose `Debug` and
display output cannot reveal plaintext.

Writing desired state does not claim that it is applied. A constrained request
file only wakes the root worker; it cannot contain commands, paths, adapter
executables, or secret values.

## Reconciliation transaction

For desired generation `G`, the worker:

1. acquires one global lock;
2. no-ops if `G` is already applied;
3. loads immutable snapshot `G` and validates the graph;
4. resolves protocol adapters and compatible installed core adapters by
   capabilities and policy;
5. resolves secret references at the narrowest required boundary;
6. creates a private transaction directory and durable journal;
7. renders and stages every affected candidate;
8. validates every candidate before any live mutation;
9. snapshots files and service/listener state;
10. verifies that `G` is still the desired generation;
11. installs all candidates and changes services in deterministic order;
12. performs health, required listener, forbidden listener, and feasible
    authorization checks;
13. compare-and-swap commits `applied_generation = G` only after verification;
14. records a sanitized completed operation.

Any post-mutation failure restores all snapshots and previous service states,
then verifies the previous known-good state. A successful compensation records
`RolledBack`; failed compensation records `RecoveryRequired` and never advances
the applied generation.

## Durable phases and crash recovery

The operation journal is updated and synced at phase boundaries:

- `Prepared`, `Staged` and `Validated`: no live mutation;
- `Snapshotted`: previous state is durable;
- `Installed`, `Activated` and `Healthy`: one or more live resources may have
  changed but the generation is not yet published;
- `Publishing`: compare-and-swap publication is in progress;
- `RollbackStarted`: compensation is in progress;
- `RolledBack`, `Applied`, `Failed`, or `RecoveryRequired`: terminal states.

On startup, pre-mutation operations are safely failed and their staging is
discarded. Mutated operations are rolled back unless the applied generation
was atomically published and every mutated resource was durably marked
verified. Unknown or unverifiable state is never silently accepted. Terminal
transaction directories are removed so resolved secrets do not accumulate.

## Concurrency and idempotency

The OS lock prevents two privileged apply transactions. Generation checks
collapse duplicate requests. A stale worker aborts before live installation;
the final database update uses compare-and-swap semantics so generation `10`
cannot overwrite desired generation `11`. Reapplying an already-applied
generation is a no-op.

## User lifecycle

User create/enable/disable/delete and runtime credential changes produce a new
desired generation. Generic user code does not know credentials. Each enabled
protocol adapter declares participation and renders its authorization fragment.
All affected core candidates validate before any changes. Subscription-token
rotation remains a separate client bearer-credential operation unless an
adapter explicitly declares a dependency.

## Panel update source of truth

The authoritative deployed revision is the root-written applied marker created
only after installation and readiness verification. A sanitized root-owned
status mirror exposes that revision to the panel. A build-time/source revision
may be shown separately for diagnostics, but a stale environment value cannot
override the applied marker or produce `current` for a mismatched SHA.

GitHub checking belongs to the root updater, which may use its root-only
credential and writes only repository/ref/current/latest/status/timestamps to a
non-secret status mirror. The unprivileged web process never reads the root
credential and does not need to call the GitHub API.

## Migration and rollback

Migration is additive and idempotent:

1. create adapter profile, control-state, snapshot, and operation tables;
2. copy each legacy profile by stable migration mapping;
3. preserve the original row and serialized payload as rollback metadata;
4. validate that source and migrated row counts, names, enabled flags, roles,
   endpoints, and secret references match;
5. create generation zero as an imported baseline without scheduling runtime
   mutation;
6. continue reading subscriptions from adapter profiles after validation.

Unknown legacy rows are retained, marked unsupported, and surfaced in status;
they are never discarded. Before explicit runtime adoption, rollback to the old
binary remains possible because the legacy table is untouched. After edits in
the new schema, rollback requires restoring the pre-migration SQLite backup.

## Security invariants

- web panel remains unprivileged and never controls systemd directly;
- root credentials and runtime-only secrets remain root-readable;
- request files have fixed schemas, bounded sizes, safe IDs, and no commands;
- root manifests and adapter paths require strict ownership/mode checks;
- staging and snapshots use private directories and atomic file replacement;
- logs, errors, operation JSON, and tests redact all secret values;
- no shell is constructed from HTTP values;
- missing adapters or incompatible capabilities cause `Unsupported` with zero
  runtime mutation.

## Exact reviewed deployment procedure

Development must not deploy automatically. Replace `RELEASE_SHA` and backup
paths below only after CI is green for that exact commit.

1. Keep two SSH sessions, enter `tmux`, and stop automatic update triggers:

   ```bash
   sudo systemctl stop infiproxy-panel-update.timer infiproxy-panel-update.path
   sudo systemctl stop infiproxy-module-update.timer infiproxy-module-update.path
   ```

2. Create and verify the online SQLite/config backup described in
   `wiki/12-BACKUP-RESTORE-UNINSTALL.md`. Also record:

   ```bash
   sudo git -C /opt/infiproxy/source rev-parse HEAD
   sudo systemctl list-unit-files 'infiproxy*' headscale.service
   sudo ss -lntup
   curl -fsS http://127.0.0.1:8080/ready
   ```

3. Fetch and build the reviewed detached commit without changing runtime:

   ```bash
   sudo git -C /opt/infiproxy/source fetch --force --prune origin
   sudo git -C /opt/infiproxy/source checkout --detach RELEASE_SHA
   sudo env PATH=/root/.cargo/bin:$PATH cargo build --locked --release \
     --manifest-path /opt/infiproxy/source/Cargo.toml \
     -p stealthhub-panel --bins
   ```

4. Install idempotently. Schema migration starts at generation zero, so the
   newly enabled reconciler performs a no-op until the first runtime mutation:

   ```bash
   cd /opt/infiproxy/source
   sudo INFIPROXY_INSTALL_COMMIT=RELEASE_SHA bash deploy/install.sh --with-nginx
   ```

5. Before changing a user/profile/domain, provision every private server secret
   with `sudo infiproxy-manager` -> **Privileged runtime secrets**. To migrate an
   existing Xray REALITY key without printing it, first inspect the JSON schema,
   then use the matching `jq` selector through a root-only pipe. For the common
   Xray shape:

   ```bash
   sudo bash -o pipefail -c 'umask 077; \
     jq -er "[.inbounds[]?.streamSettings?.realitySettings?.privateKey // empty][0]" \
       /etc/infiproxy-cores/xray/config.json | \
     install -m 0600 -o root -g root /dev/stdin \
       /etc/infiproxy/secrets.d/xray.reality.private_key'
   sudo test -s /etc/infiproxy/secrets.d/xray.reality.private_key
   ```

6. Confirm the subscription certificate covers `subscription_domain`, the
   `node_domain` resolves publicly, all selected module binaries exist, and the
   migrated enabled flags/ports match the recorded baseline. The first later
   runtime mutation reconciles every enabled supported profile.

7. Perform one controlled mutation, then require successful convergence:

   ```bash
   sudo systemctl start infiproxy-reconcile.service
   sudo systemctl status infiproxy-reconcile.service --no-pager --full
   sudo journalctl -u infiproxy-reconcile.service -n 200 --no-pager
   sudo ss -lntup
   curl -fsS http://127.0.0.1:8080/ready
   ```

   In the Dashboard, require `Applied` and equal desired/applied generations.
   Recheck the public subscription, all enabled rule providers, and one real
   client handshake for each active adapter pair.

8. Re-enable update timers only after the canary succeeds:

   ```bash
   sudo systemctl enable --now infiproxy-panel-update.timer \
     infiproxy-panel-update.path infiproxy-module-update.timer \
     infiproxy-module-update.path infiproxy-reconcile.timer \
     infiproxy-reconcile.path
   ```

## Exact rollback procedure

If no runtime generation was applied, restore the previous control binaries,
source commit and pre-migration SQLite backup. If reconciliation changed live
state, stop all writers first and restore the database and runtime files from
the same pre-deployment backup set:

```bash
sudo systemctl stop infiproxy-reconcile.path infiproxy-reconcile.timer
sudo systemctl stop infiproxy-panel-update.path infiproxy-panel-update.timer
sudo systemctl stop infiproxy-module-update.path infiproxy-module-update.timer
sudo systemctl stop infiproxy.service
# Restore infiproxy.sqlite using sqlite3 .restore or the documented install step.
# Restore /etc/infiproxy*, Nginx sites, units and previous control binaries.
sudo rm -f /etc/systemd/system/infiproxy-reconcile.{service,timer,path}
sudo rm -f /usr/local/libexec/infiproxy-reconcile
sudo systemctl daemon-reload
sudo git -C /opt/infiproxy/source checkout --detach 53b423c4f4d33708595dbcdbb247d06d2d4e5dab
cd /opt/infiproxy/source
sudo env PATH=/root/.cargo/bin:$PATH cargo build --locked --release \
  -p stealthhub-panel --bins
sudo INFIPROXY_INSTALL_COMMIT=53b423c4f4d33708595dbcdbb247d06d2d4e5dab \
  bash deploy/install.sh --with-nginx
```

Restore each recorded enabled/active service state, then verify the production
baseline listeners, `/ready`, subscription and all four rule providers. Do not
delete the failed reconcile journal or transaction snapshots until the cause
has been preserved for review. The concrete baseline backup remains
`/var/backups/infiproxy/pre-codex-baseline-20260826-171823` on production; this
repository does not assume it is locally available.
