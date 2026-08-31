# Contributing to Infiproxy

Contributions should be small, reviewable, and preserve the separation between
the unprivileged panel and privileged helpers.

## Before a Change

1. Open or reference an issue for behavior with non-obvious compatibility or
   security consequences.
2. Do not include production databases, addresses, tokens, private keys,
   certificates, logs containing credentials, or generated runtime state.
3. Keep protocol-specific behavior in adapters. Generic storage, registry, and
   reconciliation code must select through traits and capabilities.
4. Treat runtime versions as exact compatibility pins, not dependency hints.

## Required Gates

Run the commands in [`docs/development.md`](docs/development.md), including
formatting, Clippy with warnings denied, workspace tests, deployment contracts,
Bash syntax, and ShellCheck. Changes to runtime renderers or pins also require
the networked runtime compatibility suite.

Add regression coverage for every fixed defect. Documentation and Wiki pages
must change in the same pull request when operator-visible behavior, paths,
permissions, defaults, or supported versions change.

## Commits and Reviews

Use focused commits with imperative messages. Explain security boundaries,
migration/rollback effects, and tests in the pull request. Do not combine
format-only churn with behavior changes. Never deploy from a review branch as a
substitute for CI and an explicit release decision.

Report security vulnerabilities through [`SECURITY.md`](SECURITY.md), not a
public issue containing exploit or secret details.
