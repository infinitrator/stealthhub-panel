# Milestone-аудит Infiproxy 0.1 beta

[Назад: диагностика](14-TROUBLESHOOTING-AND-REFERENCE) | [К оглавлению](Home) | [Публикация Wiki](00-WIKI-PUBLISHING)

## 1. Статус

| Поле | Значение |
|---|---|
| Версия workspace | `0.1.0-beta.1` |
| Дата контрольного прохода | 26 августа 2026 |
| Целевой deployment | Bare-metal Linux, systemd, Nginx, SQLite |
| Основные ОС | Ubuntu 24.04 LTS, Debian 12 |
| Решение | Готово к ограниченному полевому beta-тесту после успешного CI на release commit |
| Не является | Security certification, pentest третьей стороной или production-GA |

Beta означает, что control plane, installer/updater contracts и локальные
end-to-end сценарии сведены в одну проверяемую точку. Она не означает, что любая
комбинация внешнего proxy-runtime, сети, DNS и VPS-провайдера проверена проектом.

## 2. Что входит в milestone

- первый owner с setup token, Argon2 login, server-side sessions и CSRF;
- смена admin password с отзывом всех его сессий;
- users, quota/expiry state и bearer subscription tokens;
- клиентские Mihomo profiles и fail-closed secret resolution;
- owner-only secret editor без обратного показа значений;
- строгий редактор встроенных Mihomo rule-provider;
- динамические root-owned module manifests и независимые updates;
- host/service health, IP diagnostics и read-only System map;
- owner-only allowlist Configs с backup, parser check и atomic replace;
- SSH-TUI и Cloudflare DNS-01/Nginx guided setup;
- panel/module backup, rollback, update schedule и uninstall modes;
- generic protocol/core adapters, desired/applied generations и root reconciler;
- durable operation journal, verified rollback и crash recovery;
- root-only private server secrets и sanitized reconciliation observability;
- source-controlled GitHub Wiki с автоматической публикацией.

## 3. Метод аудита

Проверка сочетает несколько независимых слоев:

1. Ручной review границ доверия, authentication/authorization и файловых путей.
2. Rust compiler для всех targets/features и Clippy с `-D warnings`.
3. Unit/integration tests workspace.
4. `cargo-audit` против RustSec и `cargo-deny` для advisories/licenses/sources.
5. `cargo-machete` для неиспользуемых direct dependencies.
6. ShellCheck и `bash -n` для installer/updater/TUI scripts.
7. Actionlint для GitHub Actions.
8. Gitleaks по Git history и текущему working tree.
9. HTTP end-to-end сценарий с реальным release/debug process и временной SQLite.
10. Updater regression harness без изменения host systemd.
11. Nu HTML Checker для фактически отрендеренных admin pages.
12. Chromium-based desktop/mobile review: overflow, labels, focus и target sizes.
13. Bounded concurrency benchmark публичного liveness endpoint.
14. Сверка форматов Mihomo и GitHub Wiki с первичной документацией.

Ни один scanner не доказывает отсутствие уязвимостей. Результат относится к
проверенной ревизии и меняется вместе с кодом, dependencies и окружением.

## 4. Исправленные классы проблем

### 4.1. Authentication и sessions

- первичная регистрация требует случайный setup token;
- first-owner insert стал атомарным и закрывает concurrent setup race;
- username/password errors не раскрывают существование аккаунта;
- неизвестный username выполняет dummy Argon2 verification;
- login ограничен по username и trusted source, есть задержка и `Retry-After`;
- Argon2 hash/verify используют общий лимит из двух blocking workers;
- session cookie ограничена `Path=/admin`, `HttpOnly`, `SameSite=Lax`, optional
  `Secure`; legacy root-path cookie принудительно истекает;
- password rotation транзакционно отзывает все server-side sessions.

### 4.2. HTTP и browser boundary

- admin/config/subscription responses получают `no-store` там, где это нужно;
- CSP больше не допускает inline CSS и полностью запрещает JavaScript;
- trace span пишет matched route, а не URI с bearer token;
- приложение доверяет `X-Real-IP` только от loopback peer и не использует
  client-supplied `X-Forwarded-For`;
- public `/health` и `/ready` не раскрывают host metadata;
- default request body равен 64 KiB, Configs ограничен 1 MiB;
- generated Nginx скрывает `/sub/` из access log, перезаписывает forwarded IP,
  включает HSTS/TLS 1.2–1.3 и bounded request/proxy timeouts.

### 4.3. Configs, secrets и subscriptions

- runtime profiles по умолчанию disabled, production demo user удален;
- subscription без enabled profile, обязательного секрета или с legacy static
  UUID завершается fail-closed, а не публикует placeholder;
- secret values доступны для create/rotate/delete только owner и никогда не
  возвращаются в HTML;
- Configs owner-only; SSH/Nginx read-only;
- JSON/YAML/TOML/dotenv проверяются parser-level до записи;
- config replace использует sibling backup, private temporary file, `fsync` и
  atomic rename; symlink components и special files отклоняются;
- routing payload принимает только поддержанные Mihomo classical conditions и
  запрещает embedded target, nested provider и control characters.

### 4.4. Root workers и supply chain

- web process создает только типизированные request-файлы и не имеет shell;
- panel/module request replace не следует заранее подложенному symlink;
- module manifests и generic service units проходят allowlist validation;
- release downloads требуют HTTPS, bounded redirects/timeouts и SHA-256/digest;
- archive installer ограничивает download/extraction и отклоняет path traversal,
  symlinks и special entries;
- module update сохраняет config, проверяет binary, откатывает symlink/service;
- panel updater работает с exact fetched commit, собирает `--locked`, создает
  fail-closed backup и откатывает source/binary/DB/configs при неуспехе;
- panel update не принимает non-fast-forward branch history относительно уже
  примененного commit без явного root-level override;
- fixed HTTPS API/download calls в SSH-TUI используют TLS 1.2+, HTTPS-only
  redirects, retries и timeouts;
- logs/backups имеют retention bounds и находятся вне web-writable state.

### 4.5. Интерфейс и доступность

- устранен document-wide horizontal overflow на всех сложных таблицах при
  ширине viewport 390 px; прокручивается только локальный table container;
- все 14 admin pages проверены на desktop и mobile layouts;
- focus indicators заменены на непрозрачный `accent-dark` с контрастом 7.45:1
  к белому фону;
- малый navigation label и placeholder text получили контраст выше 4.5:1;
- frontend остается server-rendered без JavaScript/runtime asset pipeline.

## 5. Проверки и результаты

### 5.1. Static gate

Все команды ниже должны завершаться с exit code `0` на release commit:

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo +1.96.0 check --locked --workspace --all-targets --all-features
cargo audit
cargo deny check
cargo machete
gitleaks git --redact
gitleaks dir . --redact
actionlint
bash deploy/tests/wiki-check.sh
```

Workspace запрещает `unsafe` через inherited Cargo lint. Compatible dependency
update dry-run не должен показывать доступных обновлений на дату release gate.

Контроль Rust dependencies повторен 29 августа 2026; версии внешних runtimes в
таблице сверены 29 августа через official GitHub latest-release API и при установке заново разрешаются
из upstream manifest:

| Компонент | Проверенная stable/latest версия |
|---|---|
| Rust toolchain и заявленный MSRV | `1.96.0` |
| Прямые Rust dependencies | `cargo outdated --root-deps-only`: обновлений нет |
| Xray-core | `v26.3.27` |
| sing-box | `v1.13.19` |
| Hysteria | `app/v2.12.2` |
| TUIC server | `tuic-server-1.0.0` |
| Mihomo | `v1.19.30` |

Module manifests не фиксируют эти номера: updater каждый раз разрешает latest
release из указанного root-owned manifest, проверяет asset/digest и лишь
затем переключает `current`. Транзитивные дубликаты crates остаются только там,
где независимые upstream libraries требуют разные совместимые API-линии; проект
не подменяет их вручную и проверяет обе линии через RustSec и `cargo-deny`.

### 5.2. Script/deployment gate

```bash
for file in deploy/*.sh deploy/cores/*.sh deploy/tests/*.sh; do
  bash -n "$file"
done

shellcheck -x deploy/*.sh deploy/cores/*.sh deploy/tests/*.sh
cargo build --locked -p stealthhub-panel --bins
target/debug/infiproxy-module-manifest list deploy/modules.d
bash deploy/tests/updater-regression.sh
bash deploy/tests/http-smoke.sh
bash deploy/install.sh --check
bash deploy/bootstrap.sh --check --src-dir "$PWD"
```

### 5.3. Dynamic HTTP coverage

End-to-end harness проверяет:

- минимальные health/readiness probes;
- неправильный и правильный setup token;
- cookie scope, CSP и no-store;
- все admin GET pages;
- CSRF rejection и 64 KiB body limit;
- strict boolean/hostname parsing и XSS escaping;
- user lifecycle и subscription token rotation;
- fail-closed YAML до secret/profile configuration;
- secret non-disclosure, profile generation и удаление secret;
- routing deny/allow paths;
- module/panel typed queues;
- symlink replacement resistance request-файлов;
- password rotation, old-password rejection и session revocation;
- login rate limit и `Retry-After`.

Контрольный запуск 29 августа дал 130 успешных Rust tests: 80 core, 4
manifest-helper, 2 reconciler-helper и 44 panel. В это число входят
failure-injection, migration, routing/DNS, user observation, listener conflict,
ETag, password-hash compatibility, generation и redaction tests. HTTP,
install-state и updater regression harness завершились без ошибок.

Nu HTML Checker `26.8.6` не обнаружил HTML/CSS structural errors на 19
документах широкого прохода; финальный release rerun повторно проверил 16
публичных/admin pages и фактически встроенный CSS. Chromium review всех 14 admin
pages на desktop и viewport 390x844 не обнаружил document overflow, unlabeled
controls или targets меньше установленного порога. Отдельно просмотрены Health,
System и mobile Modules; визуальный язык остается плотным серо-белым с зелеными
состояниями, без плиточной пустоты и декоративного JavaScript.

### 5.4. Indicative performance

Локальный release process на macOS во время контрольного прохода:

| Метрика | Результат |
|---|---:|
| Размер stripped panel binary | около 6.3 MiB |
| Resident memory после запуска до dependency migration | около 10.1 MiB |
| `/health`, 3000 requests, concurrency 30 | 3000 successful, 0 failed |
| Throughput в локальном benchmark | около 8126 requests/second |
| Средняя latency в локальном benchmark | около 3.69 ms/request |

Это smoke measurement, не capacity promise для Linux VPS: TLS/Nginx, SQLite
workload, network latency и внешние runtimes меняют результат.

После перехода на `base64 0.23.1`, `getrandom 0.4.3` и Rust `1.96.0` release
binary, HTTP harness и updater regression были повторно собраны/пройдены. Числа
benchmark выше сохраняются как ориентир предыдущего контрольного замера, а не
как непроверенное обещание идентичной производительности новой сборки.

## 6. Runtime demo/test artifacts

В production startup отсутствуют:

- demo user и переменная его включения;
- предсказуемый admin/password;
- автоматически enabled proxy profile;
- fallback credential/UUID в subscription;
- shell/terminal endpoint;
- browser-defined repository, binary URL или systemd unit.

Test fixtures остаются только в `#[cfg(test)]` и `deploy/tests/`, используют
временные базы/порты и не устанавливаются как production state.
Starter runtime configs могут содержать явные placeholder/empty credentials,
но services не должны запускаться до их замены и configtest; это fail-closed
installation scaffold, а не demo account.

## 7. Принятые beta-ограничения

| Риск | Почему остается | Обязательная компенсация |
|---|---|---|
| Mutable Git branch доверяется root updater | Нет commit signature/attestation policy | Protected branch, reviewed commits, staging/manual approval |
| Нет MFA и полноценной RBAC | `0.1` использует компактную owner/admin модель | Закрытый admin network, один owner, password manager |
| Secrets не шифруются на уровне приложения | Для генерации YAML нужны plaintext values | FS permissions, encrypted off-host backup, host hardening |
| Subscription token находится в URL path | Требование совместимого import URL | TLS, `/sub/` log suppression, secure delivery, reset on leak |
| Нет traffic collector | Runtime-specific accounting не унифицирован | Не обещать quota enforcement; внешний collector |
| Continuous user-drift polling не вынесен в отдельный per-runtime badge | User observation выполняется как обязательная post-apply verification | Следить за generation/status; запускать reconcile после внешнего изменения runtime и проверять client test |
| Нет scheduled off-host backup | Storage backend намеренно не навязан | Restic/Borg/provider snapshot и restore drill |
| Нет immutable admin audit trail | SQLite/journal не являются WORM | Central journal shipping и минимальное число admins |

## 8. Что обязательно проверить на чистом VPS

Локальный audit не заменяет следующий acceptance cycle на disposable Ubuntu
24.04/Debian 12 host:

1. One-command bootstrap и first-owner setup через SSH tunnel.
2. Nginx/Cloudflare DNS-01 с отдельным scoped token и реальным certificate renew.
3. Один TCP runtime и один UDP runtime с реальным Mihomo client.
4. Trojan/Snell/Mieru handshake через реальный Mihomo client.
5. Module update, forced service failure и автоматический rollback.
6. Panel update на новый commit и rollback при failed readiness.
8. Reboot: panel, enabled runtimes, timers/path units возвращаются автоматически.
9. Encrypted off-host backup и restore на втором чистом host.
10. Внешний port scan IPv4/IPv6 и проверка отсутствия публичных local listeners.

Cloudflare writes, certificate issuance, destructive uninstall и reboot не
запускаются из developer workstation audit, потому что требуют отдельного
одноразового VPS и контролируемой DNS-zone.

## 9. Release gate

Release commit считается beta-candidate только если одновременно:

- локальные static/dynamic gates из раздела 5 проходят;
- GitHub Actions **Rust** зеленый на exact commit;
- release artifact имеет опубликованный SHA-256;
- Wiki workflow синхронизировал все страницы после одноразового создания Home;
- в Git diff нет credentials, demo runtime state или непроверенного binary;
- operator зафиксировал backup и rollback path для первого field host.

При провале любого пункта версия остается candidate и не должна автоматически
раскатываться на основной VPS.

## 10. Первичные источники

- [GitHub Wiki: adding and editing pages](https://docs.github.com/en/communities/documenting-your-project-with-wikis/adding-or-editing-wiki-pages)
- [Cargo `rust-version`](https://doc.rust-lang.org/cargo/reference/rust-version.html)
- [RustSec advisory database](https://rustsec.org/)
- [Nu HTML Checker](https://validator.github.io/validator/)
- [Mihomo configuration](https://wiki.metacubex.one/en/config/)
- [systemd sandboxing](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [Cloudflare API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
- [Let's Encrypt integration guide](https://letsencrypt.org/docs/integration-guide/)

Этот файл фиксирует evidence и границы `0.1.0-beta.1`; подробные процедуры
остаются в тематических страницах Wiki.
