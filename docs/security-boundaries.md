# Security Boundaries

This document records security assumptions, not a claim of formal verification.

## Identities and Privilege

The web application runs as `infiproxy` and is not a member of the runtime
group. Proxy cores run as `infiproxy-runtime`. Only constrained systemd helpers
run as root. The panel cannot invoke systemd, alter `/etc`, or execute an
interactive shell.

Owner-only web mutations include protocols, routing, secrets, module lifecycle,
configuration actions, and uninstall preview/request paths. Any authenticated
admin can perform user management and common settings actions. The owner is the
lowest admin ID; this is not a general RBAC system.

## Secrets

Admin passwords use Argon2 password hashing. Session and subscription bearer
tokens are stored as hashes where their verification model permits. Server-only
runtime secrets are root-managed under `/etc/infiproxy/secrets.d` and SQLite
stores references. Private-key content must never enter logs, operation JSON,
status mirrors, backups intended as public diagnostics, or subscriptions.

TLS readiness resolves the real `infiproxy-runtime` group and checks ownership,
safe modes, ancestor traversal, and effective access. Symlink targets are
validated but never chmod/chown-normalized by the installer.

## HTTP Boundary

Authentication, authorization, CSRF validation, bounded bodies, trusted proxy
handling, secure cookie policy, origin-aware redirects, and security headers
are enforced by the application. Production exposure is expected through the
installer-managed HTTPS reverse proxy; the Rust listener remains loopback-only.

The Configs page is currently a read-only allowlisted inspector. It is not a
general file editor or shell.

## Privileged Requests

Web-triggered privileged operations use fixed-schema request files with strict
owner, type, mode, size, and value validation. Helpers choose commands, paths,
repositories, refs, module IDs, and units from trusted configuration; user input
cannot provide arbitrary commands.

Manual and scheduled panel updates use the same root-owned
`/etc/infiproxy-update.conf`. The default ref is `main`; non-main operation
requires an explicit operator override during installation.

## Administrative Audit

The owner-only `/admin/audit` view reads bounded pages from SQLite
`audit_events`. Normal application interfaces expose append and bounded reads,
but no row mutation API; SQLite triggers additionally reject UPDATE and DELETE.
This is not tamper-proof against root, direct database replacement, or an
operator who deliberately removes those triggers. Typed metadata cannot accept
arbitrary request content or credentials. User, settings, secret, profile and
routing audited storage paths write their domain change and event in one
transaction. Privileged requests use the `requested`
outcome: completion and rollback evidence remains in the separate root-owned
reconciler/maintenance journal and is not copied blindly to SQLite.

Filesystem request publication and the following SQLite audit INSERT cannot be
one ACID transaction. If publication succeeds and audit insertion fails, the UI
returns an explicit error saying the request may already be queued; operators
must inspect state before retrying. No completion event is inferred from
request-file creation. Module auto-update policy also crosses SQLite and its
filesystem state mirror, so an audit failure is reported clearly but cannot
atomically undo both domains.

The administrative audit records successful state changes and accepted
privileged requests. It is not a debug/request log, and rejected forms or
validation failures are intentionally not recorded as successful events.

## Residual Operator Responsibilities

- Restrict SSH, protect root and Cloudflare credentials, and apply OS updates.
- Keep off-host, encrypted, tested backups of SQLite, `/etc/infiproxy*`, Nginx,
  and required runtime state.
- Treat bearer subscription URLs as credentials and rotate after disclosure.
- Review exact runtime pin changes and canary them before production rollout.
- Investigate `RecoveryRequired`; do not repeatedly force reconciliation.
- Do not expose port 8080 or private runtime/admin files publicly.

Vulnerability reporting is defined in the repository root `SECURITY.md`.
