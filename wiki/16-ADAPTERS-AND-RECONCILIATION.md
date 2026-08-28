# Адаптеры и атомарное применение

Этот раздел описывает runtime control plane Infiproxy. Он нужен при миграции
существующего VPS, добавлении протокола или ядра и разборе состояния, когда
настройка сохранена в панели, но еще не действует на сервере.

## 1. Три независимых слоя

| Слой | Что хранит | Чего не делает |
|---|---|---|
| Desired state | Профили, пользователи, настройки, ссылки на секреты и монотонное поколение в SQLite. | Не утверждает, что runtime уже изменен. |
| Adapter registry | Контракты протоколов, ядер и инфраструктуры, их схемы и capabilities. | Не выбирает команды из HTTP-ввода. |
| Root reconciler | Candidate, native validation, snapshot, install, service activation, health/listener checks и rollback. | Не принимает произвольный shell или путь к executable. |

Web-процесс работает как `infiproxy`. Он транзакционно сохраняет изменение и
создает ограниченный request-файл. Root-worker
`/usr/local/libexec/infiproxy-reconcile` просыпается через
`infiproxy-reconcile.path` или safety timer и сам перечитывает целостное
состояние из SQLite. Request не содержит конфиг, secret, команду или путь.

Основной поток является однонаправленным по authority:

```text
DATABASE / DESIRED STATE
          |
          v
PROTOCOL ADAPTERS -> CORE ADAPTERS -> RUNTIME
```

Обратный путь используется только для доказательства результата:

```text
RUNTIME -> CORE/PROTOCOL OBSERVATION -> DRIFT/HEALTH -> PANEL STATUS
```

Runtime config никогда не создает и не изменяет пользователей SQLite.

## 2. Desired generation и Applied generation

Каждое изменение, влияющее на серверный runtime, увеличивает
`desired_generation`. Например: создание/включение профиля, создание,
блокировка или удаление пользователя, изменение node/subscription domain.
Название панели и политика обновлений runtime-поколение не увеличивают.

`applied_generation` меняется только после того, как все затронутые candidates:

1. Сформированы адаптерами.
2. Проверены до изменения live-файлов.
3. Установлены атомарно.
4. Активированы в детерминированном порядке.
5. Прошли healthcheck и проверку обязательных/запрещенных listeners.
6. Опубликованы compare-and-swap операцией.

Если числа различаются, сохранение принято панелью, но сервер еще не подтвердил
его. Не выдавайте новый профиль клиенту как рабочий, пока статус не `Applied`.

## 3. Динамический inventory и статусы

Dashboard, Health, System, Modules, Protocols и обзор Configs используют один
application-level inventory. Он собирается из зарегистрированных protocol/core/
infrastructure adapters, root-owned module manifests, installed binaries,
systemd units, desired/applied generations и сохраненного adapter state. View не
ищут runtime самостоятельно и не содержат списков имен ядер или протоколов.

Состояния adapter:

| Состояние | Значение |
|---|---|
| `Available` | Adapter зарегистрирован, его runtime доступен. |
| `AdapterOnly` | Контракт adapter есть, но совместимый runtime не установлен. |
| `Historical` | Adapter отсутствует, но его opaque configuration сохранена. |
| `UnsupportedSchema` | Adapter найден, но сохраненная schema новее понятной ему версии. |

Состояния runtime: `AvailableNotInstalled`, `InstalledInactive`,
`ActiveHealthy`, `ActiveDegraded`, `Failed`, `MissingAdapter`. Состояния
resource: `AdapterOnly`, `ConfiguredPending`, `AppliedHealthy`,
`AppliedDegraded`, `Unsupported`, `CoreUnavailable`, `Disabled`. Ошибка одного
systemd/binary/manifest probe становится `unknown` или degraded detail и не
роняет весь Health dashboard.

Ни наличие бинарника, ни `active` unit сами по себе не означают `Applied`.
Подтвержденное состояние требует совпадающих generation и успешной runtime
проверки.

## 4. Reconcile-статусы

| Статус | Значение | Действие оператора |
|---|---|---|
| `Pending` | Есть более новое desired generation. | Подождать path/timer и открыть status worker. |
| `Applying` | Root-worker выполняет транзакцию. | Не перезапускать вручную затронутые units. |
| `Applied` | Поколение подтверждено целиком. | Выполнить внешний клиентский probe. |
| `Failed` | Ошибка произошла до live mutation. | Исправить schema/secret/module и повторить. |
| `RolledBack` | Live mutation началась, но предыдущая версия восстановлена. | Проверить journal и причину исходной ошибки. |
| `Unsupported` | Нет нужного adapter/capability. | Установить совместимый модуль или отключить профиль. |
| `RecoveryRequired` | Автоматический rollback нельзя полностью доказать. | Остановить изменения и восстановить snapshot вручную. |

Команды диагностики:

```bash
sudo systemctl status infiproxy-reconcile.service --no-pager --full
sudo journalctl -u infiproxy-reconcile.service -n 200 --no-pager
sudo systemctl start infiproxy-reconcile.service
```

Служебные файлы находятся в root-owned
`/var/lib/infiproxy-maintenance/reconcile`. Не редактируйте generation, journal
или snapshot вручную во время активной операции.

## 5. Контракт protocol adapter

Protocol adapter владеет стабильным ID, версией JSON schema, GUI-полями,
проверкой config, ссылками на client/server secrets, участием пользователей,
Mihomo client object и server fragment. Generic subscription assembler знает
только абстрактную роль (`AutoSafe`, `Speed`, `Compatibility`, `RuAccess`,
`Manual`) и уже отрисованный объект.

Совместимость с ядром выражается capability-строками. Generic reconciler не
ветвится по имени протокола. Preferred core является политикой выбора, а не
жесткой связью: без preference выбирается установленный совместимый adapter.

`UserParticipation` явно фиксирует, использует ли protocol отдельных
пользователей. Для `PerUserUuid` adapter получает только enabled desired users и
рендерит их в candidate. После активации core adapter повторно читает live config
и сравнивает normalized identity set с ожидаемым. В статус/ошибку попадают только
counts и тип drift, но не UUID или credential values. Если обязательное
наблюдение не поддерживается, identities отличаются или runtime config не
читается, операция откатывается и applied generation не продвигается.

Manifest также содержит декларативную композицию `protocol + transport +
security + optional flow` и maturity. UI выводит только комбинации, для которых
один adapter реализует client render, server fragment и runtime capability.

После reconcile root-worker выполняет read-only observation и атомарно заменяет
`runtime_user_sync`. Статусы видны на Protocols, Runtimes и Users. Таблица
содержит только profile/runtime ID, counts и время; observation не меняет users.

## 6. Контракт core adapter

Core adapter владеет сборкой полного server config, native validation,
snapshot/rollback, atomic install, systemd lifecycle, health и listener checks.
Установка бинарного модуля отделена от активации: наличие `current` symlink не
означает, что unit должен работать. Неиспользуемое ядро остается выключенным.

Удаление runtime блокируется, если его ID присутствует в applied state или без
него enabled-профиль потеряет последнюю совместимую capability. Сначала
установите замену, переключите preference, дождитесь `Applied`, затем удаляйте.

Каждый server fragment также объявляет `ListenerClaim`: network (`tcp`/`udp`) и
порт. Reconciler собирает весь listener plan и отклоняет повторяющуюся пару
`(network, port)` до stage, snapshot или live mutation. TCP и UDP на одном
числовом порту считаются разными sockets. Shared frontend представлен stable-ID
ресурсами `Domain`, `Certificate`, `TlsFrontend`, `DecoyTarget`, `Listener` и
`PortAllocation`. Generic reconciler проверяет dependencies, cycles и listener
collisions до mutation; один adapter владеет всем Nginx-набором.

## 7. Server secrets

Ссылки на secrets хранятся в profile JSON, но root-only значения должны
находиться отдельными regular files:

```text
/etc/infiproxy/secrets.d/<reference>
owner root:root
mode 0600
maximum 8192 bytes
```

Private server key нельзя создавать через браузер. Используйте:

```bash
sudo infiproxy-manager
# Privileged runtime secrets -> Create or rotate
```

TUI скрывает ввод, пишет через private temporary file, выполняет atomic rename
и запускает reconcile. Public/client secret может храниться в SQLite, когда он
не является server-only. Значения, UUID и subscription token имеют redacted
`Debug` и не входят в journal/error.

Для legacy SQLite используйте **Adopt a legacy SQLite server-only reference**
или точный эквивалент:

```bash
sudo /usr/local/libexec/infiproxy-reconcile \
  --adopt-server-secret xray.reality.private_key
```

Helper сначала сверяет adapter-классификацию, затем атомарно создает и читает
обратно root-only файл, и только после этого удаляет значение из SQLite. Если
root-копия уже существует, повторный запуск безопасен; несовпадающие копии
останавливают migration без вывода plaintext.

## 8. Infrastructure ownership

Admin frontend остается installer/TUI-owned в
`/etc/nginx/sites-available/infiproxy.conf`. Reconciler не изменяет его.
Subscription/rules adapter владеет только
`/etc/nginx/sites-available/infiproxy-subscription.conf` и одноименным symlink:

- `/sub/` передается панели без access log;
- `/rules/` передается панели;
- `/ready` используется для локально привязанной HTTPS-проверки;
- любой другой root path получает `404`.

До live mutation adapter проверяет отсутствие duplicate `server_name`, наличие
и hostname/expiry существующего Let's Encrypt certificate и staged Nginx
syntax. **Certificate issuance не реализован этим adapter**: сначала выпустите
certificate через HTTPS/Cloudflare TUI. `node_domain` является отдельным
DNS-readiness ресурсом и не создает cover-vhost.

## 9. Durable adapter state

SQLite является независимым durable data layer, а не cache реализации. Данные
разделены концептуально на users/subscriptions, panel/routing settings, desired
profiles/resources, applied generation/operation metadata и generic
`adapter_state`.

`adapter_state` использует стабильные строковые `adapter_kind`, `adapter_id` и
`resource_id`, положительную adapter-owned `schema_version`, `enabled` и opaque
`config_json`. В durable identity не записываются Rust type names или enum
discriminants. Если package отсутствует, JSON не десериализуется в его Rust-тип,
не заменяется defaults и не удаляется.

**Removing an adapter does not delete its persisted configuration.**

После удаления UI показывает historical/missing запись, а reconciler не
выполняет runtime mutation для неизвестного adapter. Возврат package с тем же
stable ID запускает `migrate_state` этого adapter. Успешная миграция
транзакционно повышает schema и снова присоединяет конфигурацию; несовместимая
будущая schema остается нетронутой.

**Reinstalling an adapter with the same stable adapter ID reconnects preserved
configuration after adapter-owned schema migration.**

## 10. Политика миграций SQLite

Legacy baseline создается идемпотентным additive DDL. Все новые изменения после
baseline имеют монотонный integer ID в `schema_migrations` и выполняются в
транзакции. Версия durable schema не связана с `CARGO_PKG_VERSION`.

Обязательная политика:

1. Не удалять неизвестные profile, setting, adapter ID или JSON fields.
2. Не подменять непонятное значение default-настройкой.
3. Предпочитать новые таблицы/колонки и обратимо заполняемые значения.
4. Destructive transformation допустима только с явным backup и доказуемым преобразованием.
5. Повторный startup обязан быть idempotent.
6. Неуспешная adapter-owned migration оставляет исходную строку без изменений.
7. Старые данные должны оставаться читаемыми или хотя бы непрозрачно сохраненными.
8. Каждая release migration проверяется на offline-копии старой схемы.

Текущие additive migrations после adapter baseline включают:

- v3: `client_transport_pools`, ordered members, `client_routing_rules` и
  сохранение существующих `routing_rule_sets`;
- v4: singleton `client_dns_policy`, независимый от transport policy.
- v5: редактируемые metadata и health-параметры pools/policies;
- v6: normalized rule entries и bounded remote rule sources;
- v7: count-only `runtime_user_sync`;
- v8: one-time bootstrap markers, не восстанавливающие удалённые defaults.

Bootstrap завершается durable marker-ом. Повторный startup не изменяет
отредактированные строки и не создаёт заново удалённые оператором defaults.

## 11. Client routing pipeline

```text
DOMAIN/RULE -> RULE SET или INLINE RULE -> TRANSPORT POOL
            -> ENABLED PROFILE -> PROTOCOL ADAPTER -> MIHOMO OBJECT
```

Pool и rule targets используют стабильные IDs. Mihomo generator не содержит
фиксированный список proxy groups: он валидирует сохраненную policy, разрешает
role/profile/pool selectors и строит groups динамически. Cyclic pool graph,
missing enabled profile/pool и invalid target приводят к fail-closed ошибке.
DNS policy компилируется отдельно, но использует DIRECT rule-set bindings для
`nameserver-policy`.

## 12. Offline database compatibility harness

Harness никогда не ищет production DB самостоятельно и отказывается принимать
`/var/lib/infiproxy/infiproxy.sqlite`. Сначала создайте согласованную offline
копию штатным SQLite backup-механизмом, затем перенесите ее в checkout, например
в `target/compat/production-copy.sqlite`. Не передавайте простой copy файла с
непустым `-wal`: harness остановится и попросит сделать корректный backup.

```bash
mkdir -p target/compat
# Поместите сюда уже созданную offline SQLite backup-копию.
cargo run --locked --release -p stealthhub-panel \
  --bin infiproxy-db-compat -- \
  target/compat/production-copy.sqlite
```

Команда создает рядом отдельный файл
`*.compat-working-<uuid>.sqlite`, запускает текущий `init_db` дважды и печатает
machine-readable JSON. Она сравнивает count и SHA-256 всех существовавших
столбцов durable-таблиц, включая unknown JSON, users/subscription records,
flags, limits, expiration, addresses, ports, routing/settings, desired/applied
metadata и historical adapter state. Также проверяются `integrity_check`,
`foreign_key_check` и отношение `0 <= applied_generation <= desired_generation`.

Значения, username, UUID, token, secret, address и JSON в отчет не выводятся.
При failure working copy сохраняется для ручного анализа. Исходная offline copy
не мигрируется.

## 13. Миграция существующего сервера

Перед обновлением остановите auto-update и сделайте backup по
[разделу 12](12-BACKUP-RESTORE-UNINSTALL). Миграция schema идемпотентна,
сохраняет известные и неизвестные profile rows и создает generation zero без
изменения live runtime.

Known legacy profiles получают adapter mapping и стабильный resource ID.
Поэтому **первое последующее runtime-изменение** может пересобрать все enabled
profiles. До него обязательно:

1. Сравнить существующие `/etc/infiproxy-cores` с ожидаемыми GUI-профилями.
2. Убедиться, что каждый required runtime module установлен.
3. Перенести private server credentials через TUI adoption; не копировать их в
   browser-managed Secrets.
4. Проверить сертификат subscription hostname и публичное DNS-разрешение node
   hostname; значения `*.infiproxy.local` намеренно не управляют Nginx.
5. Оставить вторую SSH-сессию и выполнить одно контролируемое изменение.
6. Дождаться `Applied`, проверить listeners и подключение тестового клиента.

Adoption сам удаляет legacy SQLite value только после проверки root-копии.

## 14. Crash recovery

Перед live mutation worker сохраняет snapshots и durable journal. Если процесс
прерван до mutation, операция становится `Failed`. После mutation worker
восстанавливает ресурсы в обратном порядке и прежнее состояние enabled/active.
Новое поколение после crash принимается только если applied CAS уже завершен и
каждый измененный ресурс был отмечен verified. Иначе требуется rollback.

При `RecoveryRequired`:

```bash
sudo systemctl stop infiproxy-reconcile.path infiproxy-reconcile.timer
sudo systemctl status infiproxy-reconcile.service --no-pager --full
sudo journalctl -u infiproxy-reconcile.service -n 300 --no-pager
sudo ss -lntup
```

Не удаляйте transaction tree до сохранения его копии. Восстановите configs,
SQLite и units из одного согласованного backup, проверьте native configtest,
затем включите worker снова.

## 15. Добавление нового адаптера

Для нового protocol adapter нужны manifest, schema migration, field metadata,
client/server secret references, client renderer, server fragment и тесты
внешней регистрации. Для core adapter нужны capabilities, compose/stage,
native validate, snapshot/install/rollback, service state, health/listeners и
failure-injection tests.

Production registry компилируется из доверенных Rust adapter packages.
Root-owned module manifest устанавливает/обновляет бинарник, но сам по себе не
загружает код адаптера в web-процесс. Dynamic libraries и executable path из
HTTP намеренно не поддерживаются.

Минимальные обязательные сценарии: неизвестный adapter, incompatible core,
idempotent no-op, stale/concurrent generation, validation failure до mutation,
ошибка второго core, activation/health/listener failure, crash recovery,
user create/disable/delete, missing secret, disabled/unused core и смена
публичного домена с неуспешным frontend healthcheck.
