# Adapter Contract

Infiproxy isolates concrete protocol and runtime knowledge behind trusted Rust
traits. Generic registries and reconciliation select by stable IDs and
capabilities; they must not grow protocol-specific conditionals.

## Protocol Adapters

A protocol adapter owns its manifest, schema version, field validation, secret
references, user participation, listener network, client rendering, server
fragment, maturity, and validated runtime metadata. Configuration is opaque
JSON outside the adapter.

Adapter IDs are stable lowercase identifiers. Existing field semantics cannot
change without a schema migration. Rendered output must be deterministic and
must never expose server-only secret values in client documents or diagnostics.

## Core Adapters

A core adapter declares only capabilities its composer accepts. It owns the
fixed executable, destination config, service unit, exact validated version,
candidate composition, native validation, snapshots, atomic installation,
service transitions, health/listener checks, and rollback.

Capabilities are a security and correctness contract. Every advertised
capability must have composer regression coverage. Generic selection must
return no core when none truthfully supports a profile.

## Infrastructure Adapters

Infrastructure adapters own narrowly scoped resources. The subscription
frontend owns only its dedicated Nginx site and validates existing certificate
material; node readiness performs mutation-free DNS checks. Ownership must not
overlap installer-owned or unrelated resources.

## Discovery

Built-in registries are compiled from trusted code. Module manifests install
and update runtime binaries but are not a dynamic plugin ABI. A new runtime
requires a CoreAdapter implementation, trusted registration, tests, and a new
panel release.

## Required Tests

- manifest/API/schema validation and duplicate-ID rejection;
- accepted and rejected configuration values;
- client/server rendering and secret redaction;
- capability-to-composer alignment and selection behavior;
- exact-version compatibility and native validation where available;
- snapshot, rollback, listener, and user-sync behavior;
- generic registry tests using synthetic adapters unknown to orchestration.

Runtime changes must also pass `bash deploy/tests/runtime-compatibility.sh`.
Current pins and rejected combinations are recorded in
[Runtime Compatibility](runtime-compatibility.md).
