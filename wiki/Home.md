# Infiproxy Wiki

Эта wiki описывает фактическое поведение Infiproxy: установку, веб-интерфейс,
SSH-TUI, сетевую модель, Mihomo-подписки, внешние proxy-runtime,
обновления, резервные копии, безопасность и восстановление. Документация
версионируется вместе с исходным кодом; точная ревизия доступна в истории Git.

> [!IMPORTANT]
> Infiproxy является панелью управления и генератором клиентских подписок.
> Она не передает пользовательский трафик сама. Xray, sing-box, Hysteria,
> TUIC и Mihomo работают отдельными процессами. Для
> поддержанных protocol/core adapters вкладка **Protocols** формирует desired
> state, а отдельный root reconciler атомарно применяет server config только
> после validation, health/listener checks и с rollback.

## Как читать wiki

Для первого развертывания пройдите документы в таком порядке:

1. [Быстрый старт и первая настройка](01-QUICK-START).
2. [Архитектура и основы сетей](02-ARCHITECTURE-AND-NETWORKING).
3. [Веб-интерфейс: все страницы и кнопки](03-WEB-INTERFACE).
4. [Пользователи и подписки](04-USERS-AND-SUBSCRIPTIONS).
5. [Профили Mihomo](05-MIHOMO-PROFILES).
6. [Proxy-протоколы и серверные ядра](06-PROXY-PROTOCOLS).
7. [Маршрутизация Mihomo](07-ROUTING).
8. [Модули и обновления](08-MODULES-AND-UPDATES).
9. [Система и SSH-TUI](10-SYSTEM-AND-TUI).
10. [Конфигурационные файлы](11-CONFIGURATION).
11. [Бэкапы, восстановление и удаление](12-BACKUP-RESTORE-UNINSTALL).
12. [Безопасная эксплуатация](13-SECURITY-OPERATIONS).
13. [Диагностика и справочник](14-TROUBLESHOOTING-AND-REFERENCE).
14. [Milestone-аудит версии 0.1 beta](15-RELEASE-0.1-BETA).
15. [Публикация GitHub Wiki](00-WIKI-PUBLISHING).
16. [Адаптеры и атомарное применение](16-ADAPTERS-AND-RECONCILIATION).

## Уровни готовности операций

В документации используются четыре точных обозначения:

| Обозначение | Что происходит |
|---|---|
| **Сразу** | Веб-обработчик меняет SQLite или файл во время текущего запроса. |
| **В очередь** | Панель создает типизированный request-файл; root-worker выполняет его отдельно. |
| **Только просмотр** | Кнопка открывает страницу, внешний источник или план команд и ничего не меняет. |
| **Root-TUI** | Операция выполняется только из `sudo infiproxy-manager` либо отдельной root-командой. |

Такое разделение принципиально: веб-процесс работает от непривилегированного
пользователя `infiproxy`, а maintenance-worker запускается systemd от `root`.

## Что уже автоматизировано

- установка панели и systemd-интеграции одной командой;
- создание первого владельца и администраторских сессий;
- пользователи, сроки действия и Mihomo subscription URL;
- клиентские Mihomo-профили и встроенные rule-provider;
- desired/applied generations и атомарная синхронизация поддержанных runtime;
- динамический каталог runtime-модулей;
- проверяемые обновления бинарников с атомарным переключением версии;
- обновление самой панели с pre-update backup и rollback;
- Cloudflare DNS-01, Let's Encrypt и Nginx через root-TUI;
- установка и атомарная настройка Trojan, Snell и Mieru через Mihomo;
- owner-only хранилище client-side secret values без обратного показа значений;
- root-only хранилище private server secrets через SSH-TUI;
- allowlist-редактор конфигов, health/readiness и локальная IP-диагностика;
- смена пароля администратора с отзывом всех существующих сессий.

## Границы автоматизации

- только зарегистрированные protocol/core adapter combinations участвуют в
  server reconciliation; внешний module manifest сам по себе не добавляет
  renderer в панель;
- private server keys не принимаются из браузера и создаются/вращаются через
  **Privileged runtime secrets** в root-TUI;
- изменение считается рабочим только при совпадении desired/applied generation
  и статусе `Applied`;
- счетчик `traffic_used_bytes` хранится и проверяется, но встроенного сборщика
  статистики с proxy-ядер в этой ревизии нет;
- вкладка **System** показывает состояние и точные root-команды, но не управляет
  systemd из HTTP; привилегированный путь — SSH-TUI;
- web-uninstall показывает runbook, но не выполняет удаление;
- IP Check не отправляет IP во все базы автоматически, а дает явные ссылки.

## Два рекомендуемых профиля эксплуатации

### Рекомендуемый

- свежая Ubuntu 24.04 LTS или Debian 12;
- отдельный VPS только для Infiproxy;
- панель слушает только `127.0.0.1:8080`;
- отдельный HTTPS hostname панели за Nginx;
- Cloudflare token ограничен одной зоной и минимальными DNS-правами;
- включены только реально настроенные runtime-модули;
- внешний зашифрованный backup вывозится с VPS;
- обновления сначала проверяются на резервном узле или в maintenance window.

### Допустимый для теста

- один VPS и один домен с разными hostname;
- доступ к панели только через SSH tunnel без публичного Nginx;
- один полностью настроенный proxy-runtime;
- ручная проверка `/ready`, systemd и клиентского подключения после изменений;
- локальные root-only бэкапы до появления внешнего backup-хранилища.

Этот профиль годится для полевых испытаний, но не заменяет резервное копирование
на другой хост и ограничение административного доступа.

## Официальные первичные источники

Сетевые разделы сверены с официальными материалами проектов:

- [Mihomo documentation](https://wiki.metacubex.one/en/)
- [Project X / Xray documentation](https://xtls.github.io/en/)
- [sing-box documentation](https://sing-box.sagernet.org/)
- [Hysteria 2 documentation](https://v2.hysteria.network/docs/)
- [TUIC protocol repository](https://github.com/tuic-protocol/tuic)
- [Cloudflare API documentation](https://developers.cloudflare.com/fundamentals/api/)

При расхождении wiki с установленной версией runtime приоритет имеют
`<binary> --version`, локальный конфиг и документация именно этой версии.

Текущая линия проекта: `0.1.0-beta.1`. Границы готовности и доказательства
проверок перечислены в [milestone-аудите](15-RELEASE-0.1-BETA).
