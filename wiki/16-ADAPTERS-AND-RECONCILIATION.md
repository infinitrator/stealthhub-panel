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

## 3. Статусы

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

## 4. Контракт protocol adapter

Protocol adapter владеет стабильным ID, версией JSON schema, GUI-полями,
проверкой config, ссылками на client/server secrets, участием пользователей,
Mihomo client object и server fragment. Generic subscription assembler знает
только абстрактную роль (`AutoSafe`, `Speed`, `Compatibility`, `RuAccess`,
`Manual`) и уже отрисованный объект.

Совместимость с ядром выражается capability-строками. Generic reconciler не
ветвится по имени протокола. Preferred core является политикой выбора, а не
жесткой связью: без preference выбирается установленный совместимый adapter.

## 5. Контракт core adapter

Core adapter владеет сборкой полного server config, native validation,
snapshot/rollback, atomic install, systemd lifecycle, health и listener checks.
Установка бинарного модуля отделена от активации: наличие `current` symlink не
означает, что unit должен работать. Неиспользуемое ядро остается выключенным.

Удаление runtime блокируется, если его ID присутствует в applied state или без
него enabled-профиль потеряет последнюю совместимую capability. Сначала
установите замену, переключите preference, дождитесь `Applied`, затем удаляйте.

## 6. Server secrets

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

## 7. Infrastructure ownership

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

## 8. Миграция существующего сервера

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

## 9. Crash recovery

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

## 9. Добавление нового адаптера

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
