# Security Policy

## Supported Version

Infiproxy is currently beta software. Security fixes target the latest commit
on `main`; older commits and non-main development branches are not supported
release channels.

## Reporting a Vulnerability

Use GitHub's **Report a vulnerability** private-reporting form in the Security
tab of this repository when it is available. Include affected revision,
deployment model, reproducible steps, impact, and a minimal proof of concept.
Redact all real credentials, private keys, subscription URLs, databases, and
production addresses.

If private reporting is unavailable, open a public issue only to request a
private contact channel. Do not include vulnerability details or secrets in
that issue.

Please allow maintainers time to reproduce, assess, and coordinate a fix before
public disclosure. There is currently no paid bug-bounty program and no promise
of a specific response time.

## Scope Notes

Reports are especially useful for authentication/authorization bypass,
secret disclosure, unsafe privileged request handling, command/path injection,
update integrity failures, reconciliation escape or rollback defects, and
cross-user subscription access. General hardening suggestions without a
security impact may be filed as ordinary issues.
