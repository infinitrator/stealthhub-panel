# Веб-интерфейс: все страницы и кнопки

[Назад: архитектура](02-ARCHITECTURE-AND-NETWORKING.md) | [К оглавлению](Home.md) | [Далее: пользователи](04-USERS-AND-SUBSCRIPTIONS.md)

## Общие правила интерфейса

Веб-интерфейс отрисовывается сервером на Rust/Axum/Maud. Отдельного JavaScript
SPA, Node.js и frontend build pipeline нет. Изменяющие запросы используют POST,
admin session и CSRF token.

### Верхняя панель

| Элемент | Доступ | Действие |
|---|---|---|
| Username | любой admin | Показывает текущую учетную запись. |
| `owner` badge | только первый admin | Показывает, что admin имеет минимальный ID в таблице. |
| Update notification | owner | Появляется, когда checker обнаружил новый commit. |
| **Update Now** | owner, **в очередь** | Создает `/var/lib/infiproxy/panel-update-now.request`; root path unit запускает updater. |
| **Logout** | admin, **сразу** | Удаляет текущую server-side session и очищает cookie. |

`Update Now` не обновляет бинарник внутри HTTP-запроса. После нажатия следите за
`/var/lib/infiproxy-maintenance/panel-update-run.log` и `/ready`.

### Боковая навигация

| Пункт | URL | Назначение |
|---|---|---|
| Home | `/` | Публичная стартовая страница со ссылками на основные admin-разделы. |
| Dashboard | `/admin` | Сводка архитектуры и переходы. |
| Account | `/admin/account` | Учетная запись и безопасная смена пароля. |
| Users | `/admin/users` | Пользователи и subscription tokens. |
| Settings | `/admin/settings` | Глобальные hostnames и panel updater. |
| Protocols | `/admin/protocols` | Клиентские proxy-объекты Mihomo. |
| Secrets | `/admin/secrets` | Owner-only значения, подставляемые в клиентский YAML. |
| Routing | `/admin/routing` | Встроенные rule-provider. |
| Modules | `/admin/cores` | Динамический реестр runtime-модулей. |
| Headscale | `/admin/headscale` | Пользователи/nodes mesh hub. |
| IP Check | `/admin/ip` | Локальная диагностика и ссылки на reputation DB. |
| System | `/admin/system` | Host sensors, services и uninstall preview. |
| Configs | `/admin/configs` | Allowlist-редактор файлов. |
| Health | `/admin/health` | Подробная диагностика после admin-authentication. |
| Credits | `/admin/credits` | Версия, лицензия, GitHub и компоненты. |

## Home

Публичная `/` показывает ссылки **Dashboard**, **Users**, **Protocols** и
**Routing**. Они не обходят авторизацию: admin-route перенаправляет на login.

## Initial admin setup

Страница `/admin/setup` доступна только пока в таблице `admins` нет записей.

| Поле/кнопка | Что делает |
|---|---|
| **Setup token** | Сверяет installer-generated one-time secret длиной не менее 32 символов. |
| **Username** | Имя длиной 3–64 символа. |
| **Password** | Пароль минимум 12 символов. |
| **Confirm password** | Защита от опечатки. |
| **Create admin** | Хеширует пароль Argon2 в bounded blocking worker, атомарно создает первую admin-запись и session. |

Первый admin является owner. После создания страница setup больше не должна
принимать повторную регистрацию.

## Admin login

| Поле/кнопка | Что делает |
|---|---|
| **Username** | Ищет admin без раскрытия, существует ли имя. |
| **Password** | Проверяется Argon2 вне async executor. |
| **Login** | При успехе создает случайную 32-byte session, хранит только SHA-256 hash и ставит cookie. |

Ограничитель допускает пять неудач за 15 минут для username и источника. При
неудаче есть постоянная задержка около 500 мс. Только синтаксически корректный
`X-Real-IP` доверяется, когда непосредственный peer loopback, то есть ожидается
локальный Nginx. Клиентский `X-Forwarded-For` не используется.

## Account

Страница показывает имя, роль и время создания текущего администратора.

| Поле/кнопка | Что делает |
|---|---|
| **Current password** | Повторно подтверждает учетную запись через Argon2. |
| **New password** | Принимает 12–1024 символа. |
| **Confirm new password** | Защищает от опечатки. |
| **Change Password** | Транзакционно меняет hash и отзывает все admin-сессии, включая текущую. |

После успеха браузер возвращается на login. Старый пароль и все ранее выданные
cookie больше не работают.

## Dashboard

Status strip показывает архитектурные константы, а не live monitoring:

- **Admin: protected** — раздел требует session;
- **Storage: SQLite** — тип хранилища;
- **Client: Mihomo YAML** — формат подписки;
- **Mode: single-node** — текущая deployment model.

| Кнопка | Тип | Результат |
|---|---|---|
| **Open Users** | просмотр | Переход в Users. |
| **Open Settings** | просмотр | Переход в Settings. |
| **Open Protocols** | просмотр | Переход в Protocols. |
| **Open Routing** | просмотр | Переход в Routing. |
| **Open System** | просмотр | Переход в System. |
| **Open Modules** | просмотр | Переход в Modules. |

## Settings

### Поля

| Поле | Ограничение | Влияние |
|---|---|---|
| **Panel name** | 2–80 символов | Отображаемое имя и generated metadata. |
| **Subscription host** | hostname, нормализуется | Формирует HTTPS URL подписок и rules. |
| **Node host** | hostname/IP | Подставляется как `server` в клиентские профили. |
| **Panel auto-update** | owner-only Enabled/Disabled | Управляет ночным обновлением панели. |
| **Maintenance time** | owner-only `HH:MM` | Первый 15-минутный timer slot в/после времени VPS. |
| **GitHub repository** | read-only | Root-pinned source из `/etc/infiproxy-update.conf`. |
| **Git reference** | read-only | Root-pinned branch/tag/ref. |

**Save Settings** записывает обычные значения в SQLite. Для owner изменение
update settings также обновляет state, который читает root updater. Не-owner
видит update-поля disabled и не может изменить их через штатную форму.

### Generated client endpoints

Раздел только показывает:

- шаблон `https://<subscription-host>/sub/{token}/mihomo.yaml`;
- шаблон `https://<subscription-host>/rules/{name}`;
- node host;
- время последней проверки, current/latest SHA и план обновления.

## Users

Полный жизненный цикл описан в
[Пользователях и подписках](04-USERS-AND-SUBSCRIPTIONS.md).

| Кнопка/ссылка | Тип | Результат |
|---|---|---|
| **Create** | сразу | Создает UUID, random token, quota/expiry. |
| `open` | просмотр | Публичная account/import page. |
| `download` | просмотр | Отдает Mihomo YAML. |
| **Disable** | сразу | Запрещает account page import и YAML. |
| **Enable** | сразу | Снимает ручную блокировку, но не отменяет expiry/quota. |
| **Reset token** | просмотр | Открывает отдельное подтверждение. |
| **Reset token** на confirmation | сразу | Генерирует новый token; старый URL сразу недействителен. |
| **Delete** | просмотр | Открывает отдельное подтверждение. |
| **Delete user** на confirmation | сразу | Удаляет пользователя и token. |
| **Cancel** | просмотр | Возвращает без изменений. |

## Protocols

Это редактор **клиентской стороны Mihomo**, не server inbound generator.

Status strip показывает число профилей, enabled, число сохраненных secret names
и subscription host. Transport matrix является справкой и ничего не меняет.

### Общие элементы каждого профиля

| Элемент | Что делает |
|---|---|
| **Enabled** switch | Включает профиль в следующий generated YAML. Не запускает runtime. |
| **Server address** | Endpoint, который использует клиент Mihomo. |
| **Server port** | Remote port `1..65535`. |
| Protocol-specific fields | SNI/path и **имена** записей в `secret_values`. |
| **Save profile** | Обновляет существующую запись в SQLite; не валидирует/перезапускает серверный core. |

Kind и role профиля в GUI read-only. Создания/удаления профилей через текущий
веб-интерфейс нет. Подробно: [Профили Mihomo](05-MIHOMO-PROFILES.md).

## Secrets

Страница доступна только owner. Значения используются исключительно при
генерации Mihomo YAML и после сохранения никогда не возвращаются браузеру.

| Поле/кнопка | Что делает |
|---|---|
| **Secret name** | Принимает до 128 ASCII letters/digits и символы `.`, `_`, `-`. |
| **Secret value** | Принимает непустое значение до 8192 bytes. |
| **Store secret** | Создает запись либо атомарно заменяет значение существующего имени. |
| **Delete** | Требует вручную набрать точное имя и удаляет значение. |

Таблица показывает только имена, привязка к профилям вычисляется по
ссылкам из Protocols. Удаление секрета, нужного enabled-профилю, переводит
subscription generation в fail-closed `503`, а не публикует имя/placeholder.

## Routing

На странице четыре фиксированных rule set. Для каждого:

| Элемент | Что делает |
|---|---|
| **Enabled** switch | Публикует provider и включает `RULE-SET` в generated YAML. |
| **Target group** | Выбирает `DIRECT`, `AUTO-SAFE`, `SPEED`, `RU-ACCESS`, `MANUAL`, `REJECT`. |
| **Classical payload** | Редактирует одно правило Mihomo на строку. |
| **Save rule set** | Валидирует payload и сохраняет этот set в SQLite. |

Нельзя создать произвольный slug или вложить `RULE-SET`/`SUB-RULE` внутрь
payload. Подробно: [Маршрутизация](07-ROUTING.md).

## Modules

Страница строится из root-owned manifests, поэтому список динамический.

### Runtime registry

| Кнопка | Доступ/тип | Результат |
|---|---|---|
| **Check all** | owner, сразу для metadata | Обращается к GitHub API и обновляет known latest state; бинарники не меняет. |
| Auto **On/Off** + **Save** | owner, сразу | Меняет policy автоматического обновления модуля. |
| **Check** | owner, сразу для metadata | Проверяет upstream только выбранного модуля. |
| **Manage** | owner, просмотр | Для Headscale переходит в dedicated page. |
| **Install latest** | owner, в очередь | Request root-worker для неустановленного runtime. |
| **Update latest** | owner, в очередь | Request root-worker для установленного runtime. |
| **Remove** | owner, в очередь | Работает только если в поле набран точный module ID; config сохраняется. |

Название update/install зависит от installed state. Request не гарантирует
успех: результат проверяется по state/log/service.

### Available catalog

**Install latest** активирует только manifest, заранее помещенный root installer
в `/etc/infiproxy-modules.available.d`. Браузер не передает URL, repo, shell
command или systemd unit.

Подробно: [Модули и обновления](08-MODULES-AND-UPDATES.md).

## Headscale

Страница owner-only.

| Кнопка/поле | Тип | Результат |
|---|---|---|
| **Refresh users and nodes** | в очередь | Просит helper выполнить `users list` и `nodes list`. |
| **Open configuration** | просмотр | Переходит в Configs; сам config не меняет. |
| **Clear result** | в очередь | Стирает last result/pre-auth key из protected snapshot. |
| Username + **Create user** | в очередь | Создает user с `[A-Za-z0-9._-]`, длина до 63. |
| User ID | ввод | Числовой owner для pre-auth key. |
| Expiration | ввод | `1..9999` минут или часов, например `30m`, `24h`. |
| **Reusable** | флаг | Разрешает использовать key больше одного раза. |
| **Ephemeral node** | флаг | Помечает зарегистрированный node ephemeral. |
| **Create pre-auth key** | в очередь | Генерирует key и временно показывает его в snapshot. |
| Node ID + **Expire node** | в очередь | Expire key выбранного node; ему нужна повторная регистрация. |

Headscale CLI запускает root helper с фиксированным набором argv, timeout 20 с и
лимитом output 64 КиБ. Подробно: [Headscale](09-HEADSCALE.md).

## IP Check

| Элемент | Тип | Результат |
|---|---|---|
| IP address | ввод | Принимает только literal IPv4/IPv6, не hostname. |
| **Analyze IP** | локально | Классифицирует адрес, делает PTR через `host`/`dig` и route lookup через `ip`/`route`. |
| **Open** у provider | внешний просмотр | Открывает lookup конкретной third-party базы. |

Панель не агрегирует reputation score и не отправляет address в providers в
фоне. Ссылки ведут в Spamhaus, AbuseIPDB, VirusTotal, Cisco Talos, GreyNoise,
Shodan, Censys, RIPEstat, BGP.Tools, IPinfo, Scamalytics, Project Honey Pot,
StopForumSpam и BarracudaCentral.

Speed diagnostics — это текстовые команды `ping`, `curl`, `iperf3`, `mtr`.
Страница их не запускает, чтобы не создавать скрытую нагрузку/трафик.

## System

### Host overview

Показывает OS/kernel, uptime/load average, память и root disk из локального Linux.
Это snapshot на момент HTTP-запроса, не time-series monitoring.

### Service control

Таблица является read-only operational map: она показывает live state unit,
путь конфига, команду проверки и точную root-команду применения. Кнопок
restart/reload в HTTP нет. Выполняйте эти действия через
`sudo infiproxy-manager`, чтобы web service не получал systemd/root privileges.

### Uninstall planner

Три кнопки **Preview ... removal/cleanup** только показывают runbook. Они не
передают его shell и ничего не удаляют. Реальное удаление находится в root-TUI.

## Configs

Раздел owner-only. Для каждого allowlisted файла:

| Элемент | Что делает |
|---|---|
| Path/size/status | Только показывает выбранный путь и лимит. |
| Textarea | Редактирует полный текст только для явно разрешенных runtime-файлов; Nginx и SSH read-only. |
| **Save with backup** | Проверяет JSON/YAML/TOML/dotenv, создает sibling backup и атомарно заменяет файл. |
| **Back to Configs** | Возврат после отчета. |
| **Open System actions** | Переход к read-only operational map. |

Save не запускает native core configtest и не перезапускает сервис. Встроенный
parser проверяет JSON/YAML/TOML/dotenv; Nginx/SSH остаются read-only и должны
проверяться родными утилитами из TUI. Symlink path, NUL и превышение размера
отвергаются. Подробно:
[Конфигурационные файлы](11-CONFIGURATION.md).

## Health и Ready

- `/health` всегда возвращает минимальный `ok\n`;
- `/ready` возвращает `ready\n` после успешного SQLite query;
- `/health` означает только liveness HTTP process;
- `/ready` выполняет SQLite query и возвращает HTTP 503 при ошибке;
- обе probe-страницы публичные и не содержат host details;
- `/admin/health` требует admin session и показывает подробный dashboard.

Health dashboard показывает process/components, app uptime, version, deployment,
OS/load/memory/disk и service sensors. Он не делает end-to-end proxy request.

## Credits

**Open GitHub** открывает внешний репозиторий. GitHub stars на странице не
загружаются API-вызовом; это статическая ссылка, поэтому панель не зависит от
GitHub при обычном рендеринге Credits.

## Коды результата и ожидания

| Результат | Значение |
|---|---|
| Redirect обратно в раздел | Обычно запись принята или request поставлен. |
| `401` subscription | Token отсутствует/неверен. |
| `403` subscription | User disabled, expired или quota reached. |
| `404` rule provider | Slug неизвестен либо set disabled. |
| `503 /ready` | SQLite query не прошел. |

Для queued action HTTP redirect не является подтверждением update/install.
