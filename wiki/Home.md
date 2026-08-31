# Infiproxy: руководство оператора

Эта Wiki описывает текущую ветку Infiproxy 0.1.0-beta.1. Источник истины для
поведения системы - код, root-owned manifests и systemd units в основном
репозитории. Wiki публикуется из каталога wiki/, поэтому ее версия должна
совпадать с установленным commit панели.

Infiproxy - control plane для одного Linux VPS. Панель хранит пользователей,
профили, routing policy и желаемое состояние, но не реализует proxy-протоколы.
Трафик обрабатывают внешние runtime-модули: Xray, sing-box, Hysteria, TUIC и
Mihomo.

## С чего начать

1. [Быстрый старт](01-QUICK-START) - подготовка VPS, установка, HTTPS и первый
   владелец.
2. [Архитектура и основы сетей](02-ARCHITECTURE-AND-NETWORKING) - TCP/UDP,
   DNS, TLS, reverse proxy и схема control/data plane.
3. [Веб-интерфейс](03-WEB-INTERFACE) - назначение каждой страницы, кнопки и
   границы доступа.
4. [Пользователи и подписки](04-USERS-AND-SUBSCRIPTIONS) - UUID, bearer token,
   отключение, удаление и реальные ограничения учета трафика.
5. [Профили и выбор runtime](05-PROTOCOL-PROFILES-AND-RUNTIMES) - lifecycle
   профиля, capability selection, ports и secrets.
6. [Proxy-протоколы](06-PROXY-PROTOCOLS) - как устроены поддерживаемые
   композиции и какие runtime их принимают.
7. [Маршрутизация](07-ROUTING) - DNS policy, transport pools, правила и
   rule-provider.
8. [Модули и обновления](08-MODULES-AND-UPDATES) - установка, pinning,
   verification, rollback и auto-update.
9. [Desired state и reconciliation](09-RECONCILIATION-AND-DESIRED-STATE) -
   поколения, атомарное применение и восстановление после сбоя.
10. [System и SSH manager](10-SYSTEM-AND-TUI) - root TUI, HTTPS, secrets,
    журналы и опасные операции.
11. [Конфигурация](11-CONFIGURATION) - пути, переменные окружения и текущие
    возможности web Configs.
12. [Backup, restore и uninstall](12-BACKUP-RESTORE-UNINSTALL) - согласованные
    копии SQLite и проверяемое восстановление.
13. [Безопасная эксплуатация](13-SECURITY-OPERATIONS) - границы привилегий,
    hardening, incident response.
14. [Диагностика и справочник](14-TROUBLESHOOTING-AND-REFERENCE) - симптомы,
    команды и карта файлов/services.
15. [Релиз и совместимость](15-RELEASE-AND-COMPATIBILITY) - beta-gates,
    ограничения и процедура выпуска.
16. [Архитектура адаптеров](16-ADAPTER-ARCHITECTURE) - developer-oriented
    protocol/core/infrastructure contracts.
17. [Runtime compatibility](17-RUNTIME-COMPATIBILITY) - точные pins и проверенные
    сочетания.

## Быстрый выбор раздела

| Задача | Раздел |
|---|---|
| Установить на чистый VPS | [Быстрый старт](01-QUICK-START) |
| Понять кнопку в панели | [Веб-интерфейс](03-WEB-INTERFACE) |
| Выдать или отозвать подписку | [Пользователи](04-USERS-AND-SUBSCRIPTIONS) |
| Выбрать protocol/runtime/port | [Профили](05-PROTOCOL-PROFILES-AND-RUNTIMES) |
| Настроить правила клиента | [Маршрутизация](07-ROUTING) |
| Обновить бинарник runtime | [Модули](08-MODULES-AND-UPDATES) |
| Разобраться с Pending/Failed | [Reconciliation](09-RECONCILIATION-AND-DESIRED-STATE) |
| Выдать сертификат панели | [System и TUI](10-SYSTEM-AND-TUI) |
| Сделать backup или удалить систему | [Backup/uninstall](12-BACKUP-RESTORE-UNINSTALL) |
| Восстановить доступ администратора | [Диагностика](14-TROUBLESHOOTING-AND-REFERENCE) |

## Что реализовано

- Первый owner, Argon2id password, hashed sessions, CSRF и login throttling.
- Пользователи, UUID и отдельные subscription tokens.
- Mihomo YAML, account page и YAML rule providers.
- Версионированные protocol profiles и автоматический capability-based выбор
  совместимого core; общего core selector в текущем web UI нет.
- Встроенные protocol adapters и 5 bundled runtime modules.
- DNS policy, transport pools, routing policy, normalized rule entries и remote
  rule sources.
- Desired/applied generations, root reconciler, rollback и crash recovery.
- Root-approved module catalog и независимые binary updates.
- Pinned panel update source, scheduled и immediate update paths.
- Guided SSH manager, Cloudflare DNS-01/Certbot flow и root-only secret editor.

## Что не следует предполагать

- Поля traffic limit/used не означают live accounting: collector и quota
  enforcement отсутствуют.
- /health проверяет процесс, а /ready - SQLite; это не data-plane probe.
- Установленный runtime не обязательно активен или выбран профилем.
- Успешный binary smoke test не доказывает реальный клиентский handshake.
- Reset subscription token отзывает URL, но не стирает уже импортированные UUID
  или shared credentials.
- Shared-credential протокол не дает индивидуального server-side revoke без
  ротации общего секрета.
- Web Configs в текущем release - allowlisted read-only inspector. Изменение
  root configs и применение выполняются через SSH manager.
- Web uninstall - только preview. Исполнение доступно root в SSH manager.
- Автоматическое обновление runtime выключено по умолчанию для каждого модуля.

## Модель безопасности в одном абзаце

Web-процесс infiproxy записывает только SQLite и bounded request files. Root
workers повторно проверяют request schema, ownership, manifests, paths и
версии. Proxy services работают как infiproxy-runtime. Root-only server secrets
находятся в /etc/infiproxy/secrets.d; общие client/server secrets пока хранятся
в SQLite без прикладного шифрования. Panel и module updaters остаются
supply-chain trust boundaries, поэтому нужны защищенная ветка, проверяемые
backups и staging.

## Версия документации

Перед опасной операцией сопоставьте документацию и установленный commit:

    sudo git -C /opt/infiproxy/source rev-parse HEAD
    sudo cat /var/lib/infiproxy-maintenance/panel-last-applied.sha

Если значения различаются, сначала откройте Wiki для фактически установленной
ревизии. Не переносите команды между release lines без проверки.

Технические контракты для разработчиков находятся в каталоге
[docs/](https://github.com/infinitrator/stealthhub-panel/tree/main/docs).
Главная страница репозитория:
[README](https://github.com/infinitrator/stealthhub-panel).
