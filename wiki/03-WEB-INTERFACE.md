# Веб-интерфейс: страницы и действия

[Назад: архитектура](02-ARCHITECTURE-AND-NETWORKING) | [К оглавлению](Home) |
[Далее: пользователи](04-USERS-AND-SUBSCRIPTIONS)

## 1. Общий контракт

Интерфейс рендерится сервером на Rust/Maud, использует один CSS asset и не
зависит от JavaScript. Все authenticated POST actions требуют session cookie и
CSRF token. Формы ограничены 64 KiB; config route имеет отдельный лимит 1 MiB.

Верхняя полоса показывает administrator, owner status и update notice.

| Элемент | Доступ | Что делает |
|---|---|---|
| Update Now | owner | Создает bounded request для root panel updater |
| Logout | любой admin | Удаляет текущую session record и истекает cookie |

Update Now не принимает repository/ref из браузера. Manual и automatic paths
используют один root-owned /etc/infiproxy-update.conf.

## 2. Навигация

| Пункт | URL | Назначение |
|---|---|---|
| Home | / | Публичные ссылки на основные разделы |
| Dashboard | /admin | Сводка users, generations, runtimes и shortcuts |
| Account | /admin/account | Текущий admin и смена password |
| Users | /admin/users | User lifecycle и subscription URLs |
| Settings | /admin/settings | Domains, panel name и update schedule |
| Protocols | /admin/protocols | Protocol profiles и adapter inventory |
| Secrets | /admin/secrets | Shared secrets, owner-only |
| Routing | /admin/routing | DNS, pools, policies, rule sets/sources |
| Modules | /admin/cores | Runtime inventory и typed lifecycle |
| IP Check | /admin/ip | Local network diagnostics и external reputation links |
| System | /admin/system | Host/service observations и uninstall preview |
| Configs | /admin/configs | Owner-only allowlisted read-only config inspector |
| Health | /admin/health | Detailed authenticated health/inventory |
| Audit | /admin/audit | Owner-only, bounded administrative change history |
| Credits | /admin/credits | Project/component information |

`/admin/audit` показывает append-only через штатные интерфейсы события
страницами по 50 записей. SQLite triggers запрещают UPDATE/DELETE, но root может
удалить triggers или заменить БД, поэтому журнал не является криптографически
immutable или tamper-proof. Поле
`succeeded` означает завершенную SQLite-мутацию; `requested` означает только
прием ограниченного запроса root-helper, а не успешное завершение операции.

## 3. Initial admin setup

URL: /admin/setup.

| Поле/кнопка | Результат |
|---|---|
| Setup token | Сравнивается constant-time с INFIPROXY_SETUP_TOKEN |
| Username | Создает первый admin/owner |
| Password + confirmation | Минимум 12 символов, Argon2id hash |
| Create admin | Атомарно создает только первого admin и открывает session |

Setup доступен только пока admins table пуста. Сервер не запускается без
setup-token длиной минимум 32 символа в этом состоянии. Повторный setup после
создания owner запрещен.

## 4. Login и Account

Login использует username/password. Неудачи имеют фиксированную задержку,
rate-limit по username+source и bounded Argon2 worker pool. Сообщение не
раскрывает, существует ли username.

Account:

| Кнопка | Что делает |
|---|---|
| Change Password | Проверяет текущий password, валидирует новый, меняет hash |

Успешная ротация отзывает остальные sessions и создает новую текущую session.
Username через web UI не меняется. UI управления всеми sessions отсутствует.

## 5. Dashboard

Dashboard только наблюдает:

- desired/applied generation и reconcile status;
- число users;
- runtime/resource inventory;
- count-only user sync;
- shortcuts Open Users/Settings/Protocols/Routing/System/Modules.

Кнопки Open ... выполняют переход, а не mutation. Applied не является
end-to-end доказательством client connectivity.

## 6. Settings

| Поле | Кто меняет | Эффект |
|---|---|---|
| Panel name | любой admin | Metadata/UI name |
| Subscription host | любой admin | Public subscription/rule-provider host |
| Node host | любой admin | Starter proxy endpoint host/infrastructure readiness |
| Panel auto-update | owner | Включает/выключает scheduled panel apply |
| Maintenance time | owner | Local server HH:MM, default 05:00 |
| GitHub repository | read-only | Root-pinned REPO |
| Git reference | read-only | Root-pinned REF |
| Save Settings | admin; owner для update fields | Валидирует и сохраняет значения |

Изменение domains увеличивает desired generation, потому что они участвуют в
infrastructure resources. Save не выдает сертификат автоматически.

## 7. Users

| Действие | Кто | Результат |
|---|---|---|
| Create | любой admin | UUID/token, optional stored limit/expiry, generation |
| open | любой admin | Account page по bearer URL |
| download | любой admin | Mihomo YAML по bearer URL |
| Disable/Enable | любой admin | Меняет effective access и generation |
| Reset token | любой admin + confirm page | Немедленно заменяет bearer token |
| Delete user | любой admin + confirm page | Удаляет row и запускает generation |

Traffic fields не редактируются после create через текущий UI. Runtime collector
и quota enforcement отсутствуют. Подробности:
[Пользователи и подписки](04-USERS-AND-SUBSCRIPTIONS).

## 8. Protocols

Страница показывает protocol adapter inventory, runtime/resource status,
count-only user sync и каждый starter profile.

| Элемент | Кто | Что делает |
|---|---|---|
| Enabled switch | owner | Включает/выключает profile |
| Server address | owner | Меняет client endpoint |
| Server port | owner | Меняет listener claim/client port |
| Adapter fields | owner | Меняет text или secret reference |
| Save profile | owner | Валидирует adapter schema, сохраняет и queue reconcile |

UI не создает/удаляет profiles и не меняет adapter/preferred runtime. Полный
contract: [Профили и runtimes](05-PROTOCOL-PROFILES-AND-RUNTIMES).

## 9. Secrets

Owner-only страница для shared client/server secrets.

| Действие | Результат |
|---|---|
| Save secret | Создает или заменяет bounded value по валидному reference name |
| Delete secret | Требует точное подтверждение reference name и удаляет value |

Value после записи не отображается обратно. Имена показываются, plaintext нет.
REALITY private key и другие server-only references через эту страницу не
принимаются; используйте root SSH manager.

Удаление required secret может сделать subscription generation или reconcile
недоступными. Сначала отключите зависимый profile либо подготовьте замену.

## 10. Routing

Все mutations owner-only.

### DNS policy

Save DNS policy сохраняет enabled, IPv6, respect-rules, enhanced mode и списки
bootstrap/remote/direct resolvers. Resolver проходит scheme/IP/system
validation.

### Transport pools

| Кнопка | Результат |
|---|---|
| Create pool | Создает select/url-test/fallback/load-balance pool |
| Save pool | Обновляет members, health parameters, fallback и strategy |
| Delete pool | Удаляет pool после проверки зависимостей/replacement |

Members могут ссылаться на profile, capability, role, другой pool, all,
DIRECT или REJECT. Cycles и unresolved references отклоняются.

### Inline routing policies

Create/Save policy задает stable ID, display name, priority, Mihomo condition и
target. Delete policy удаляет правило. Target должен разрешаться в enabled
pool/profile/capability либо DIRECT/REJECT.

### Rule sets и entries

| Кнопка | Результат |
|---|---|
| Save rule set | Создает/обновляет slug, effect, target, enabled и payload |
| Export / preview YAML | Открывает публичный /rules/{slug}.yaml |
| Clone | Копирует rule set под новым slug |
| Delete rule set | Удаляет set и связанные entries/sources |
| Save entry | Создает/редактирует normalized rule |
| Delete entry | Удаляет одну запись |
| Bulk add | Добавляет много values выбранного kind |
| Deduplicate | Удаляет дубликаты внутри set |
| Filter/Clear | Только меняет отображаемый список |

Remote source:

| Кнопка | Результат |
|---|---|
| Save source | Сохраняет HTTPS URL, format, interval и enabled |
| Refresh now | Немедленно загружает bounded source и нормализует entries |
| Delete source | Удаляет source metadata |

Background source checker просыпается каждые 5 минут и обновляет только due
enabled sources. HTTP URL, private/loopback targets и oversized payload
отклоняются.

## 11. Modules

Runtime inventory read-only для любого admin; lifecycle controls видит owner.

| Кнопка | Результат |
|---|---|
| Check all | Обновляет upstream metadata всех active manifests |
| Check | Проверяет один module |
| Install latest / Update | Создает typed root request |
| Auto On/Off + Save | Меняет per-module opt-in |
| Start/Stop/Restart | Создает typed systemd lifecycle request |
| Remove | Требует module ID; blocked при enabled dependent resource |
| Available catalog / Install latest | Активирует уже root-approved manifest |

Браузер не передает repo, asset URL, shell command, binary path или service
name. Import нового manifest доступен только root SSH manager.

## 12. IP Check

Analyze IP валидирует IPv4/IPv6 и показывает локальные diagnostics. Open у
каждой reputation database открывает внешний сайт и передает ему IP. Это не
единый автоматический score и не гарантия чистоты.

Speed diagnostics показывают команды/внешние инструменты; панель не запускает
нагрузочный тест автоматически.

## 13. System

System показывает OS, kernel, uptime, load, memory, root disk, cookie mode,
control-plane units и discovered runtimes. Service table read-only: Action -
команда для SSH manager, а не web execution.

Owner-only preview:

| Кнопка | Что показывает |
|---|---|
| Preview panel-only removal | Control-plane cleanup, runtime modules remain |
| Preview full footprint removal | Panel + managed runtime footprint |
| Preview factory footprint cleanup | Максимальный известный footprint без purge OS packages |

Preview экранируется как текст и ничего не выполняет. Запуск удаления только
через sudo infiproxy-manager.

## 14. Configs

Текущий release показывает allowlisted files:

- panel environment;
- Nginx site;
- SSH daemon config;
- configs active module manifests.

Все текущие specs имеют editable=false. Поэтому Save with backup не
отображается, web-процесс не меняет root configs. Route сохранения остается
защищенной owner/CSRF/allowlist validation, но без editable target не является
доступной функцией.

Изменяйте configs через SSH manager, затем выполняйте указанную validation и
reload команду. Не считайте Configs встроенным shell/editor.

## 15. Health

Authenticated Health показывает:

- SQLite readiness и cookie mode;
- host sensors;
- control-plane service states;
- adapter/runtime/resource inventory;
- desired/applied generation;
- count-only user sync;
- описание probe boundaries.

Публичные /health и /ready возвращают минимальный plain text. /ready проверяет
SQLite, но не все proxy listeners.

## 16. Credits и коды ответа

Credits содержит repository link и список компонентов. Open GitHub уводит на
внешний сайт.

Основные HTTP результаты:

| Код | Значение |
|---:|---|
| 200/303 | Успех или redirect после POST |
| 400 | Поле/config не прошли validation |
| 401 | Нет/невалидная session или subscription token |
| 403 | CSRF, owner boundary, disabled/expired/over-limit subscription |
| 404 | Resource отсутствует |
| 409 | Setup уже закрыт или конфликт |
| 429 | Login rate limit / Argon2 workers busy |
| 503 | SQLite/subscription configuration не ready |

Ошибка UI не означает автоматический rollback всех внешних ручных действий.
Для runtime mutation всегда проверяйте reconcile status и journal.
