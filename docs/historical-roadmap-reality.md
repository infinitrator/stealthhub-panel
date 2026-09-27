# Historical Roadmap Reality

This is an archaeological record, not a new product roadmap. It was reconstructed
from the complete Git history so deleted plans do not silently become current
promises.

## Versions found

The earliest durable plan is the beta release contract added at `3d09b8e` and
expanded through `79ce920`. It targeted a compact bare-metal product: local
authentication, users, profiles, root-owned modules, health, atomic config
writes, update backups/rollback, and a guided SSH workflow. The deleted
`wiki/15-RELEASE-0.1-BETA.md` also explicitly left real client handshakes,
off-host restore drills, reboot recovery, certificate renewal, and forced
update rollback for VPS acceptance.

A later implementation sequence is visible in commit lineage:

- product shell/routing intelligence: `ad24d0c`, `760ade9`, `da56c64`,
  `f6cfd79`, verified by `243a482`;
- protocol profile lifecycle V2: `4fd8ad6`, verified by `fcb4b03`;
- runtime telemetry/accounting foundation: `f4c5e5b`, documented by `cbcb142`;
- Phase 4 quota enforcement is named as future work in `cbcb142`.

The remembered later labels “Deep Data-plane Health”, “API Tokens & Scopes”,
“Bulk / Operations UX”, and “Final Product & Production Hardening” do not survive
verbatim in any reachable roadmap file or commit message. Their intent is still
recoverable from the release risks, architecture docs, and subsequent hardening
commits; they are classified below without pretending the approximate names are
an authoritative current plan.

## Reality matrix

| Historical item | Evidence | Original intention | Current reality | Classification / action |
|---|---|---|---|---|
| Beta product and deploy shell | `3d09b8e`, `87002e5` | Installable panel, modules, SSH operations | Installed units, bounded helpers, smoke and installer contracts exist | **DONE** |
| Atomic desired/applied reconciliation | `f9d8696`, `a53d1f9` | Transactional configs, journal, rollback, recovery | Durable generations, maintenance lock, atomic state, crash recovery, PID-owned listener checks | **DONE** |
| Product shell / routing intelligence | `ad24d0c`–`243a482` | Coherent operator UI and truthful topology | Web/TUI topology and route status are implemented | **DONE** |
| Protocol profile lifecycle V2 | `4fd8ad6`, `fcb4b03` | Typed create/edit/delete and safe capability selection | Implemented with optimistic concurrency, audit, reconciliation, tests | **DONE** |
| Runtime telemetry foundation | `f4c5e5b`, `cbcb142` | Bounded observed state without fake accounting | Supported/unavailable/stale/error/unsupported are distinct; 4096-row bound | **DONE** |
| Real quota enforcement | future Phase 4 reference in `cbcb142` | Validated runtime counters drive access | Stored quota gate exists; native per-user accounting remains unsupported | **FUNCTIONAL / POST-LAUNCH** — defer |
| Deep data-plane health | beta field checklist; `e9d1a0f`; adapter health docs | Go beyond process-running status | Version, service, required/forbidden socket and PID ownership checks exist; real protocol handshakes still require a client | **NEEDS PRODUCTION EVIDENCE** — do not fabricate traffic |
| API tokens and scopes | later plan intent; no implementation commit | Automation API with scoped credentials | No safe API platform exists and stable operation does not require one | **FUNCTIONAL / POST-LAUNCH** — defer |
| Bulk operations UX | later plan intent | High-volume operator workflows | Narrow routing bulk import/deduplicate exists; generalized bulk mutation is unnecessary for safety | **FUNCTIONAL / POST-LAUNCH** — defer |
| Updater exact revision and rollback | beta contract; `daaa41c`, `7f2107f`, `e9d1a0f` | Never publish an unready revision; restore old state | Exact SHA, forward-artifact backup, readiness gate, rollback, and applied marker are tested | **DONE** |
| SQLite/WAL backup correctness | deleted beta backup contract and current operator guide | Consistent rollback snapshot | Online `.backup` existed, but the updater trusted successful exit without validating the artifact | **STABILITY / IMPLEMENT NOW** — nonempty + integrity verification added before update and restore |
| TLS readiness and expiry | `ea6fac5`, `57473b4`, `afa9ba1`, infrastructure adapter | Validate effective unprivileged access and certificate suitability | Parse, hostname, expiry and runtime-access checks exist; live renewal remains a field acceptance item | **DONE / NEEDS PRODUCTION EVIDENCE** |
| Runtime version and supply-chain integrity | `f42c992`–`7d99b3d`, `cff08a8`, `d1ffceb` | Exact validated pins, bounded extraction, truthful markers | Exact manifests/digests, archive bounds, binary validation, symlink/marker mismatch checks | **DONE** |
| systemd/process hardening | beta release contract and current units | Restart safely without widening root access | `Restart=on-failure`, `RestartSec=3`, `ProtectSystem=strict`, `NoNewPrivileges=true`, narrow writable paths | **DONE** |
| Off-host backup and restore drill | deleted beta risk/acceptance sections | Survive loss of the VPS | Correct procedure is documented; backend and credentials are operator-specific | **NEEDS PRODUCTION EVIDENCE** — do not add upload/exfiltration |
| Retired Headscale/MTProto plan | `79ce920`, `f053340` | Earlier bundled features | Product integration was intentionally removed | **OBSOLETE** |

## Stability conclusion for this pass

The high-value missing local invariant was verification of updater-created
SQLite backups. This pass adds that narrow guard and regression tests. Existing
process/listener ownership, rollback, bounded retries, telemetry freshness,
certificate checks, exact runtime pins, state atomicity, and systemd hardening
already cover the remaining deterministic workstation-testable items.

Real proxy handshakes, certificate renewal, reboot recovery, forced failures on
the target distributions, external port scans, and encrypted off-host restore
remain deployment evidence. Quotas, API scopes, and generalized bulk UX remain
post-launch product work rather than stability prerequisites.
