# Релиз и совместимость

[Назад: диагностика](14-TROUBLESHOOTING-AND-REFERENCE) | [К оглавлению](Home) |
[Далее: архитектура адаптеров](16-ADAPTER-ARCHITECTURE)

## 1. Статус

Текущая workspace version: 0.1.0-beta.1.

Beta означает:

- schema migrations и atomic reconciler покрыты тестами;
- exact runtime pins и generated configs имеют compatibility gates;
- installer/updaters имеют regression contracts;
- production operator все еще обязан держать off-host backup;
- experimental protocol compositions требуют отдельного field canary;
- ограничения ниже являются частью release contract.

Не называйте release stable до документированного migration/rollback drill и
нескольких независимых production canaries.

## 2. Поддерживаемая платформа

Основная цель:

- Ubuntu 24.04 LTS или Debian 12;
- systemd;
- x86_64 или aarch64;
- root для install/workers;
- Nginx для public HTTPS;
- SQLite на локальной filesystem.

Bootstrap также содержит dnf path, но release CI выполняется на Ubuntu.
Containers, Kubernetes, musl, non-systemd init и network filesystem для SQLite
не являются проверенным deployment contract.

## 3. Runtime pins

| Runtime | Exact pin |
|---|---|
| Mihomo | v1.19.30 |
| Xray | v26.3.27 |
| sing-box | v1.13.20 |
| Hysteria | app/v2.12.2 |
| TUIC | tuic-server-1.0.0 |

Module updater не пересекает pin автоматически. Более новый upstream release
может отображаться как available, но exact compatibility меняется только после
обновления manifests, code baselines, parser/composer tests и
docs/runtime-compatibility.md.

## 4. Panel update channel

Production default:

    REPO=infinitrator/stealthhub-panel
    REF=main

Installer не наследует checkout branch. Non-main ref требует explicit
INFIPROXY_UPDATE_REF/--ref. Manual и scheduled updates читают один root-owned
/etc/infiproxy-update.conf. Panel SQLite может включить schedule и выбрать
time, но не подменяет source.

Release tag installation:

    curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/v0.1.0-beta.1/deploy/bootstrap.sh \
      | sudo bash -s -- --ref v0.1.0-beta.1 --guided --with-nginx

Host, pinned to a tag, не увидит новые main commits. Переключение channel -
явное operator решение через повторный bootstrap.

## 5. Release gates

Локально:

    cargo fmt --all -- --check
    cargo check --locked --workspace --all-targets --all-features
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
    cargo test --locked --workspace --all-targets --all-features
    bash deploy/tests/wiki-check.sh
    bash deploy/tests/install-state-regression.sh
    bash deploy/tests/updater-regression.sh
    bash deploy/tests/http-smoke.sh
    find deploy -type f -name '*.sh' -exec bash -n {} +
    find deploy -type f -name '*.sh' -exec shellcheck -x {} +
    cargo deny check --all-features

Exact runtime compatibility gate требует network и official assets:

    bash deploy/tests/runtime-compatibility.sh

Gitleaks должен использовать repository .gitleaks.toml и проверять normal push
range. Перед крупным history rewrite/fast-forward дополнительно запускайте
full-history scan той же scanner version, что CI.

## 6. CI

Rust workflow:

- pinned GitHub Actions;
- Rust 1.96.0 + rustfmt/clippy;
- fmt/check/clippy/test;
- documentation contracts;
- Gitleaks;
- ShellCheck;
- installer/updater/http deployment contracts;
- cargo-deny.

Release workflow для tag v*:

- builds release panel on Linux x86_64;
- packages binary, deploy/, wiki/, README и licenses;
- publishes tar.gz + SHA-256;
- marks hyphenated tags as prerelease.

Wiki workflow синхронизирует versioned wiki/*.md в GitHub Wiki после validation.

## 7. Процедура выпуска

1. Убедитесь, что branch main содержит только reviewed commits.
2. Запустите все release gates.
3. Проверьте git status и diff.
4. Дождитесь green Rust workflow exact SHA.
5. Создайте immutable annotated tag:

       git tag -a v0.1.0-beta.1 -m 'Infiproxy 0.1.0 beta 1'
       git push origin v0.1.0-beta.1

6. Дождитесь Release workflow.
7. Проверьте archive checksum и запуск на чистом staging VPS.
8. Проверьте install, setup, update, reconcile, rollback и uninstall.
9. Только затем разрешайте production update.

Не перемещайте опубликованный tag и не переиспользуйте его имя.

## 8. Обязательный staging canary

- fresh guided install;
- first-owner setup через tunnel/HTTPS;
- SQLite backup + restore drill;
- install одного exact runtime;
- один stable TCP profile;
- temporary user create/disable/delete;
- desired/applied convergence;
- real client handshake;
- panel update no-op/current path;
- module check/update/rollback simulation;
- reboot/autostart;
- panel-only и full uninstall на disposable host.

## 9. Известные ограничения

| Область | Ограничение |
|---|---|
| Maturity | Beta, не stable |
| Traffic | Stored fields без collector/enforcement |
| Auth | Нет MFA, granular RBAC, session inventory |
| Audit | Нет append-only admin audit log |
| Secrets | Shared values и bearer tokens без application encryption в SQLite |
| Subscription | Bearer token в URL |
| Configs | Web inspector read-only; нет generic editor/shell |
| Profiles | UI update-only; нет create/delete/core selector |
| Users | Нет edit limit/expiry/UUID после create |
| Revoke | Shared credentials нельзя отозвать индивидуально |
| Health | Public ready проверяет SQLite, не data plane |
| Protocols | Experimental compositions требуют field canary |
| Supply chain | Panel updater доверяет configured Git ref без signature/attestation |
| Backup | Нет встроенного scheduled encrypted off-host backup |
| Platform | CI centered on Ubuntu/systemd x86_64 |

## 10. Compatibility policy

- Stable profile значит exact parser/server config tests прошли, а не что
  protocol подходит любой сети.
- Experimental значит exact syntax/composer accepted, но field interoperability
  требует дополнительного rollout.
- Unsupported combination не должна появляться в CoreRegistry selection.
- Runtime capability должна соответствовать composer; regression tests
  проверяют drift.
- New runtime version сначала тестируется isolated, затем staging, потом pin
  меняется во всех manifests/code/docs одновременно.
- Automatic runtime updates остаются explicit per-module opt-in.

Точная таблица:
[Runtime compatibility](17-RUNTIME-COMPATIBILITY).

## 11. Документационный gate

Behavior change обязан обновить:

- README, если меняется landing-page contract;
- operator Wiki, если меняется button/path/workflow;
- docs, если меняется stable architecture/internal contract;
- wiki-check.sh, если новый stable identifier можно проверить без brittle prose.

Stale names, old update refs, retired modules и недействующие ports не должны
оставаться как активные инструкции.
