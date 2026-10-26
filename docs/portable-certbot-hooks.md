# Portable Certbot hooks (draft integration)

This branch adds root-owned Certbot deploy hooks installed by `deploy/install.sh`. The installer preserves any existing, customized hook rather than overwrite it. **Do not merge into the production update branch before the integration tests below are completed.**

## Domain configuration

The proxy data plane and panel Nginx HTTPS domains are intentionally independent. Issue the proxy certificate for the desired **client SNI hostname** with Certbot DNS-01. Store only the hostname (one lowercase DNS name, with trailing newline) in:

`/etc/infiproxy/core-tls-domain` (root:root, mode 0600)

Example for a *new* server with the certificate already issued:

```bash
printf '%s\n' 'node.example.com' | sudo install -m 0600 -o root -g root /dev/stdin /etc/infiproxy/core-tls-domain
sudo bash /etc/letsencrypt/renewal-hooks/deploy/infiproxy-core-tls.sh --sync
```

Never copy the production domain, private key or Cloudflare credentials into the repository. The setup should eventually be driven by an explicit SSH manager action; the current install does **not** issue core certificates automatically.

On renewal, Certbot supplies `RENEWED_LINEAGE`. The core hook ignores renewals for any lineage other than the configured core domain; the Nginx hook validates and reloads Nginx after renewal when active.

## Core TLS layout

For new installs and migrated installs, `/etc/infiproxy-cores/tls/current` points to a release directory containing `fullchain.pem` and `privkey.pem`, both root:infiproxy-runtime 0640. Stable file paths resolve through `current`. The hook validates certificate expiration, the configured hostname, and public/private key agreement before switching to the new release.

## Required pre-merge tests

- Bash syntax and ShellCheck for hooks and installer.
- Shell fixtures: missing configuration; unrelated renewed lineage; bad permissions; expired certificate; SAN mismatch; mismatched private key; fresh publication; legacy upgrade; unchanged certificate; failed reconciler; failed systemd restart; idempotent install.
- Systemd sandbox and readiness validation after replacing the stable files with symlinks.
- Test with a disposable Ubuntu 24.04 VPS or VM, including automatic Certbot renewal and rollback.
- Restore system configs and TLS release directories on failed panel upgrades; confirm that old and new installer versions can coexist across rollback.
- Avoid a service-interrupting migration on production until these tests pass.

## Explicit limitations

The current shell hook is not yet a production-approved complete deployment workflow. It installs the renewal integration, but does not manage initial ACME issuance, Cloudflare token permissions, renewal scheduling or core hostname selection through the main web/TUI flow. Review and complete these requirements before promoting this work to `main`.
