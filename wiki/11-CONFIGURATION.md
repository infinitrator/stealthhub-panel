# Конфигурационные файлы

Infiproxy хранит состояние в трех разных местах, и смешивать их нельзя:

| Тип данных | Где хранится | Пример |
|---|---|---|
| Состояние control plane | SQLite панели | Администраторы, пользователи, Mihomo-профили, routing sets, настройки обновлений. |
| Конфигурация процессов | Файлы ОС | `infiproxy.env`, Xray JSON, Headscale YAML, Nginx и SSH. |
| Исполняемые версии | Versioned runtime directories | `/opt/infiproxy/cores/xray/<version>/xray` и symlink `current`. |

Изменение одного слоя не синхронизирует другие автоматически. Например,
изменение VLESS UUID в Xray не обновит `user.uuid` в SQLite, а изменение порта
во вкладке **Protocols** не перепишет Xray inbound.

## 1. Вкладка Configs

Веб-редактор открывает только файлы из compile-time allowlist и конфиги
зарегистрированных module manifests. Произвольный путь в форме указать нельзя.

### 1.1. Элементы каждой строки

| Элемент | Значение |
|---|---|
| Название | Человекочитаемая роль файла. |
| Badge состояния | `ready`, отсутствующий файл, слишком большой файл, symlink или ошибка чтения. |
| Category | `panel`, `edge`, `host`, `proxy-core` или `mesh-control`. |
| Syntax | Подсказка `dotenv`, `json`, `yaml`, `nginx`, `sshd_config` или `text`. |
| **Path** | Read-only реальный путь. |
| **Limits** | Текущий размер и максимальный размер web-editor. |
| **Content** | Содержимое UTF-8 файла. Встроенной подсветки и schema validation нет. |
| **Save with backup** | Проверяет поддерживаемый синтаксис, копирует существующий файл рядом и атомарно заменяет содержимое. Service не перезапускается. |

После сохранения result page показывает:

- исходный путь;
- `saved` или текст ошибки;
- путь созданного backup;
- команду validation;
- команду apply;
- кнопки **Back to Configs** и **Open System actions**.

### 1.2. Ограничения редактора

- URL выбирает только известный `slug`, а не путь пользователя.
- Если сам файл или любой компонент пути является symlink, чтение и запись
  отклоняются.
- Редактируются только regular files.
- Содержимое с NUL byte отклоняется.
- Файл больше лимита не загружается в браузер.
- Значение должно быть UTF-8, потому что используется `read_to_string`.
- Перед записью существующего файла обязателен sibling backup.
- Запись идет во временный regular file, вызывает `fsync`, наследует mode и
  завершается атомарным rename в том же каталоге.
- JSON, YAML, TOML и dotenv проходят parser-level проверку. Это не заменяет
  semantic configtest конкретного runtime.
- Nginx и SSH доступны только для просмотра; их native syntax проверяет root-TUI.
- Save не вызывает reload или restart.

Backup получает имя вида:

```text
config.json.infiproxy-bak-1786289123456
```

Число — Unix timestamp. Backup получает mode `0600`; для каждого исходного файла
редактор сохраняет не более 20 последних sibling backups. Это ограничивает рост,
но не заменяет off-host backup и контроль свободного места.

> [!CAUTION]
> Вкладка **Configs** и POST-сохранение доступны только первому owner-admin.
> Это узкая роль, а не полноценная RBAC-модель; не создавайте лишних
> администраторов и не передавайте owner session другим операторам.

### 1.3. Фиксированный allowlist

| Slug | Файл | Лимит | Web write |
|---|---|---:|---:|
| `panel-env` | `/etc/infiproxy/infiproxy.env` | 16 KiB | Да. |
| `nginx-site` | `/etc/nginx/sites-available/infiproxy.conf` | 64 KiB | Нет. |
| `ssh-daemon` | `/etc/ssh/sshd_config` | 64 KiB | Нет. |
| `xray-core` | `/etc/infiproxy-cores/xray/config.json` | 256 KiB | Да. |
| `sing-box-core` | `/etc/infiproxy-cores/sing-box/config.json` | 256 KiB | Да. |
| `hysteria-core` | `/etc/infiproxy-cores/hysteria/config.yaml` | 128 KiB | Да. |
| `tuic-core` | `/etc/infiproxy-cores/tuic/config.json` | 128 KiB | Да. |
| `mtproto-core` | `/etc/infiproxy-cores/mtproto/mtproto.env` | 16 KiB | Да. |
| `headscale-config` | `/etc/headscale/config.yaml` | 128 KiB | Да. |
| `headscale-nginx` | `/etc/nginx/sites-available/infiproxy-headscale.conf` | 64 KiB | Нет. |

Для динамического модуля добавляется `module-<id>`, если его `config_path` еще
не представлен фиксированным allowlist. Максимум динамического файла — 256 KiB;
syntax определяется по расширению. Web write разрешается только под
`/etc/infiproxy-cores/` и `/etc/headscale/`; остальные manifest paths read-only.

## 2. Универсальный безопасный цикл изменения

Применяйте его к каждому конфигу независимо от GUI или editor в SSH:

1. Зафиксируйте исходное состояние unit и активной версии binary.
2. Сделайте backup базы и изменяемого файла.
3. Измените минимально необходимый набор параметров.
4. Выполните parser/config validation родным инструментом.
5. Сравните diff и убедитесь, что secret не попал в журнал или shell history.
6. Используйте reload, если runtime его корректно поддерживает; иначе restart.
7. Проверьте `systemctl status` и последние строки journal.
8. Проверьте открытый listener через `ss`.
9. Выполните реальное подключение тестовым клиентом из другой сети.
10. Только после успеха удаляйте старый backup по retention policy.

Базовый шаблон:

```bash
sudo cp -a /path/config /path/config.pre-change-$(date +%Y%m%d%H%M%S)
sudo <program> <config-validation-options>
sudo systemctl restart <unit>
sudo systemctl --no-pager --full status <unit>
sudo journalctl -u <unit> -n 100 --no-pager
sudo ss -lntup
```

## 3. Окружение панели

Файл: `/etc/infiproxy/infiproxy.env`.

Штатные права: `root:infiproxy`, mode `0660`. Он читается systemd через
`EnvironmentFile=`. Текущий template содержит семь переменных.

### `INFIPROXY_BIND`

Адрес и TCP-порт Axum listener.

```dotenv
INFIPROXY_BIND=127.0.0.1:8080
```

Рекомендуется оставлять loopback. Nginx принимает публичный HTTPS и передает
запрос локально. Значение `0.0.0.0:8080` публикует панель напрямую на всех IPv4
интерфейсах, обходит TLS reverse proxy и не рекомендуется.

### `INFIPROXY_DB`

SQLx SQLite URL:

```dotenv
INFIPROXY_DB=sqlite:///var/lib/infiproxy/infiproxy.sqlite?mode=rwc
```

`mode=rwc` означает read/write/create. Каталог должен существовать и быть
доступен пользователю `infiproxy`; иначе запуск завершится ошибкой SQLite code
14 `unable to open database file`.

Не ставьте SQLite на NFS/SMB. Для одного экземпляра панели локальный диск проще
и надежнее. Одновременно запускать два процесса панели с одной БД не следует.

### `INFIPROXY_DB_MAX_CONNECTIONS`

Размер SQLx pool:

```dotenv
INFIPROXY_DB_MAX_CONNECTIONS=2
```

Допустимы `1..16`; невалидное значение заменяется на `2`. Для слабого VPS
оставьте `2`. Увеличение не ускоряет небольшой SQLite workload и может усилить
конкуренцию writers. Busy timeout равен 10 секундам, foreign keys включены.

### `INFIPROXY_COOKIE_SECURE`

```dotenv
INFIPROXY_COOKIE_SECURE=true
```

Значения `1`, `true`, `yes`, `on` включают Secure flag; остальные считаются
false. В production оставляйте `true`: браузер отправляет admin session cookie
только по HTTPS.

Для временного доступа через `http://127.0.0.1:8080` по SSH tunnel можно
установить `false`, перезапустить панель, закончить настройку HTTPS и немедленно
вернуть `true`.

### `INFIPROXY_SETUP_TOKEN`

```dotenv
INFIPROXY_SETUP_TOKEN=<64-hex-random-value>
```

Bootstrap генерирует token через CSPRNG и печатает его root-оператору. Пока
таблица `admins` пуста, startup требует не менее 32 символов, а
`POST /admin/setup` сравнивает значение constant-time. После атомарного создания
первого owner setup route больше не принимает регистрацию, поэтому token
становится неактивным по состоянию БД. Не публикуйте его и смените при подозрении
на утечку до первого входа.

### `INFIPROXY_CURRENT_COMMIT`

```dotenv
INFIPROXY_CURRENT_COMMIT=<40-hex-installed-sha>
```

Idempotent installer записывает exact Git commit установленного binary. Checker
использует его вместо неоднозначного состояния checkout, а root updater меняет
значение только после успешной сборки, установки и readiness-проверки.

### `RUST_LOG`

```dotenv
RUST_LOG=stealthhub_panel=info,tower_http=info
```

Управляет tracing filter. `info` подходит для обычной работы. `debug` повышает
объем journal и может раскрыть больше operational context; включайте временно.
Полные session/subscription secrets логировать нельзя.

### Legacy aliases

Код принимает старые `STEALTHHUB_BIND`, `STEALTHHUB_DB`,
`STEALTHHUB_DB_MAX_CONNECTIONS`, `STEALTHHUB_COOKIE_SECURE` и
`STEALTHHUB_SETUP_TOKEN`, если соответствующая `INFIPROXY_*` не задана.
Для новых установок используйте только новое имя, чтобы не создавать два
конфликтующих источника.

### Проверка после изменения env

```bash
sudo systemctl restart infiproxy.service
sudo systemctl --no-pager --full status infiproxy.service
sudo journalctl -u infiproxy.service -n 100 --no-pager
curl -fsS http://127.0.0.1:8080/ready
```

## 4. Nginx панели

Файл: `/etc/nginx/sites-available/infiproxy.conf`.

Guided HTTPS создает два server blocks:

- TCP `443` с TLS certificate/key;
- TCP `80` с redirect на HTTPS;
- `proxy_pass http://127.0.0.1:8080`;
- передача `Host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`;
- headers `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`.

Проверка и применение:

```bash
sudo nginx -t
sudo systemctl reload nginx.service
curl -I https://panel.example.com/health
```

Не направляйте Nginx обратно на публичный hostname: это создаст loop. Upstream
должен оставаться `127.0.0.1:8080`.

Сертификаты guided flow ожидает здесь:

```text
/etc/letsencrypt/live/<domain>/fullchain.pem
/etc/letsencrypt/live/<domain>/privkey.pem
```

## 5. SSH daemon

Файл: `/etc/ssh/sshd_config`.

Минимальные production-принципы:

- сначала настройте и проверьте вход по ключу;
- не отключайте рабочий способ входа до проверки новой сессии;
- ограничьте root login согласно своей модели управления;
- отключайте password authentication только после проверки ключей;
- firewall должен разрешать выбранный SSH-порт до reload;
- изменения применяйте через reload, не restart.

Проверка effective config:

```bash
sudo sshd -t
sudo sshd -T | less
sudo systemctl reload ssh.service
```

Infiproxy не создает SSH-ключи, не меняет автоматически порт SSH и не управляет
authorized_keys. Web-editor предоставляет доступ к файлу, но ответственность за
доступность recovery console остается у оператора.

## 6. Xray server config

Файл: `/etc/infiproxy-cores/xray/config.json`.

Starter template намеренно содержит:

- `log.loglevel: warning`;
- пустой массив `inbounds`;
- outbound `freedom` с tag `direct`;
- outbound `blackhole` с tag `blocked`.

Пустой `inbounds` означает, что сразу после установки Xray не принимает
клиентов. Для VLESS + REALITY/XHTTP нужно явно создать inbound, UUID/flow,
transport и REALITY keys в синтаксисе установленной версии Xray. Затем те же
клиентские значения внесите в Infiproxy/Mihomo.

Проверка:

```bash
sudo /opt/infiproxy/cores/xray/current/xray run -test \
  -config /etc/infiproxy-cores/xray/config.json
sudo systemctl restart infiproxy-xray.service
```

Опции Xray менялись между релизами. Перед production сверяйтесь с
[официальной документацией Xray](https://xtls.github.io/en/config/).

## 7. sing-box server config

Файл: `/etc/infiproxy-cores/sing-box/config.json`.

Starter template содержит log level `warn`, пустые `inbounds`, outbound
`direct` и `block`. Он безопасно не открывает proxy listener, но не готов
обслуживать Shadowsocks 2022, ShadowTLS или AnyTLS без ручного inbound.

Проверка:

```bash
sudo /opt/infiproxy/cores/sing-box/current/sing-box check \
  -c /etc/infiproxy-cores/sing-box/config.json
sudo systemctl restart infiproxy-sing-box.service
```

Не копируйте конфиг от другой major/minor версии без `sing-box check`: поля
могут быть deprecated или удалены. Ссылки на схемы протоколов есть в
[разделе 6](06-PROXY-PROTOCOLS.md).

## 8. Hysteria 2 server config

Файл: `/etc/infiproxy-cores/hysteria/config.yaml`.

Starter template:

```yaml
listen: :443
tls:
  cert: /etc/infiproxy-cores/tls/fullchain.pem
  key: /etc/infiproxy-cores/tls/privkey.pem
auth:
  type: password
  password: REPLACE_WITH_HYSTERIA2_PASSWORD
```

Что означает каждое поле:

| Поле | Смысл |
|---|---|
| `listen` | UDP listener. `:443` занимает UDP/443, но не TCP/443 Nginx. |
| `tls.cert` | Серверная certificate chain. |
| `tls.key` | Закрытый TLS key; не должен читаться посторонними. |
| `auth.type` | Механизм аутентификации Hysteria. |
| `auth.password` | Общий пароль starter-схемы; placeholder обязательно заменить. |

Проверка команды зависит от версии. Для текущего manifest сначала посмотрите
`hysteria server --help`, затем используйте поддерживаемый check mode. После
старта проверьте UDP listener:

```bash
sudo ss -lunp | grep ':443'
sudo journalctl -u infiproxy-hysteria.service -n 100 --no-pager
```

## 9. TUIC server config

Файл: `/etc/infiproxy-cores/tuic/config.json`.

| Starter field | Смысл |
|---|---|
| `server: "[::]:11443"` | QUIC/UDP listener на всех IPv6 и, в зависимости от sysctl, IPv4-mapped адресах. |
| `users: {}` | Пустой map UUID → password; без пользователя вход невозможен. |
| `certificate` | TLS certificate chain. |
| `private_key` | TLS private key. |
| `congestion_control: bbr` | Алгоритм congestion control внутри TUIC/QUIC. |
| `alpn: ["h3"]` | ALPN, который согласуется в TLS handshake. |

Добавленный UUID/password должен совпасть с данными Mihomo user/profile. Перед
рестартом изучите `tuic-server --help`: CLI конкретной версии является
источником истины для validation command.

```bash
sudo systemctl restart infiproxy-tuic.service
sudo journalctl -u infiproxy-tuic.service -n 100 --no-pager
sudo ss -lunp | grep ':11443'
```

## 10. Telegram MTProxy env

Файл: `/etc/infiproxy-cores/mtproto/mtproto.env`.

| Переменная | Назначение | Безопасное значение |
|---|---|---|
| `MTPROTO_PORT` | Публичный TCP-порт proxy. | `8444`; TCP `8443` зарезервирован стартовым профилем VLESS XHTTP. |
| `MTPROTO_STATS_PORT` | Локальный stats listener. | `8888`; не публиковать firewall. |
| `MTPROTO_SECRET` | 16 bytes в виде ровно 32 hex symbols. | Генерируется из CSPRNG в TUI. |
| `MTPROTO_WORKERS` | Число worker processes. | `2`, допустимо `1..16`; на слабом VPS начать с `1`. |
| `MTPROTO_AES_PWD` | Telegram `proxy-secret`. | `/etc/infiproxy-cores/mtproto/proxy-secret`. |
| `MTPROTO_PROXY_CONFIG` | Telegram upstream topology config. | `/etc/infiproxy-cores/mtproto/proxy-multi.conf`. |

Template secret из нулей является placeholder. Не запускайте публичный proxy с
ним. Используйте TUI **Guided initial setup**, который делает backup старого env,
скачивает оба upstream-файла и генерирует secret.

## 11. Headscale YAML

Файл: `/etc/headscale/config.yaml`.

Он подробно разобран в [разделе 9](09-HEADSCALE.md). Критичные группы:

| Группа | За что отвечает |
|---|---|
| `server_url` | Канонический HTTPS URL control server. |
| `listen_addr` | Локальный HTTP listener; Infiproxy использует `127.0.0.1:8088`. |
| `metrics_listen_addr` | Локальная метрика; `127.0.0.1:9098`. |
| `grpc_listen_addr` | gRPC listener; `127.0.0.1:50443`. |
| `prefixes` | Выделяемые mesh IPv4/IPv6 ranges. |
| `database.sqlite.path` | Отдельная Headscale SQLite database. |
| `dns` | MagicDNS и upstream resolvers. |
| `policy.path` | ACL policy; пустое значение не равно продуманной least-privilege policy. |

Проверка обязательна:

```bash
sudo headscale -c /etc/headscale/config.yaml configtest
sudo systemctl restart headscale.service
```

## 12. TLS-материалы proxy-runtime

Starter Hysteria и TUIC ожидают:

```text
/etc/infiproxy-cores/tls/fullchain.pem
/etc/infiproxy-cores/tls/privkey.pem
```

Это не те же пути, которые автоматически использует Certbot для Nginx. Нельзя
бездумно копировать private key в group-writable каталог. Выберите один из
подходов:

| Подход | Плюсы | Минусы |
|---|---|---|
| Deploy hook копирует cert/key с минимальными правами и рестартует runtime | Простая конфигурация runtime. | Нужно надежно поддерживать hook и permissions. |
| Runtime читает `/etc/letsencrypt/live/...` через ограниченные group/ACL | Нет второй копии ключа. | Сложнее права, возможны проблемы после renewal. |
| Отдельный сертификат для proxy hostname | Изоляция panel TLS от proxy TLS. | Больше сертификатов и renewal jobs. |

Предпочтителен отдельный proxy hostname и автоматический deploy hook, который
сначала проверяет новые файлы, выставляет `root:<runtime-group> 0640`, затем
рестартует только нужный unit.

## 13. Секреты в SQLite

Значения `secret_values` относятся к генерации Mihomo subscription и не
являются файлом env. Owner-only вкладка **Secrets** создает, ротирует и удаляет
значения, но после POST показывает только имена и никогда не возвращает value.

Примеры имен:

- `xray.reality.public_key`;
- `xray.reality.short_id`;
- `shadowsocks.2022.password`;
- `shadowtls.password`;
- `anytls.password`;
- `hysteria2.password`;
- `hysteria2.obfs_password`;
- `tuic.password`.

При отсутствии или пустом значении enabled profile делает generation
fail-closed с HTTP 503. Процедура внесения и сверки описана в
[профилях Mihomo](05-MIHOMO-PROFILES.md#как-безопасно-добавить-secret-value).

## 14. Права на файлы

Установщик создает основные каталоги так:

| Путь | Owner/group | Mode | Назначение |
|---|---|---:|---|
| `/etc/infiproxy` | `root:infiproxy` | `0770` | Env и control-plane config. |
| `/var/lib/infiproxy` | `infiproxy:infiproxy` | `0750` | SQLite и web request queues. |
| `/var/lib/infiproxy-maintenance` | `root:root` | `0751` | Root updater state. |
| `/etc/infiproxy-modules.d` | `root:root` | `0755` | Active module registry. |
| `/etc/infiproxy-modules.available.d` | `root:root` | `0755` | Module catalog. |
| `/opt/infiproxy/cores` | `root:root` | `0755` | Versioned binaries. |
| `/etc/infiproxy-cores` | `root:infiproxy` | `0770` | Runtime configs. |
| `/var/log/infiproxy-cores` | `infiproxy:infiproxy` | `0750` | Runtime logs, если unit их использует. |
| `/etc/headscale` | `root:infiproxy` | `0770` | Headscale config readable/editable panel group. |

Файлы runtime config обычно `root:infiproxy 0660`. Это позволяет веб-процессу
редактировать allowlisted configs, но расширяет последствия компрометации admin
session. Если web-editing не нужен, можно ужесточить права, приняв, что кнопка
**Save with backup** перестанет работать.

После ручного восстановления прав:

```bash
sudo chown root:infiproxy /etc/infiproxy/infiproxy.env
sudo chmod 0660 /etc/infiproxy/infiproxy.env
sudo chown infiproxy:infiproxy /var/lib/infiproxy/infiproxy.sqlite*
sudo chmod 0640 /var/lib/infiproxy/infiproxy.sqlite*
```

## 15. Конфигурация «идеально» и «сойдет для теста»

### Production-oriented

1. Panel bind остается `127.0.0.1:8080`, cookie Secure включен.
2. Panel, Headscale и proxy protocols получают отдельные hostnames/listeners.
3. Все placeholders заменены уникальными случайными credentials.
4. Server config и Mihomo profile сверены по полям в таблице до выдачи подписки.
5. Каждый config validation включен в change runbook.
6. Private keys доступны только конкретному runtime user/group.
7. Конфиги и обе SQLite базы регулярно копируются за пределы VPS.

### Приемлемый полевой тест

1. Панель доступна только через SSH tunnel.
2. Включен один runtime с одним тестовым inbound.
3. Используется отдельный временный пользователь без персональных данных.
4. Перед каждым изменением создается локальная копия файла и SQLite.
5. Проверка делается с мобильной сети, а не только с самого VPS.

## 16. Связанные разделы

- [Архитектура и основы сетей](02-ARCHITECTURE-AND-NETWORKING.md)
- [Профили Mihomo](05-MIHOMO-PROFILES.md)
- [Proxy-протоколы](06-PROXY-PROTOCOLS.md)
- [Система и TUI](10-SYSTEM-AND-TUI.md)
- [Backup и восстановление](12-BACKUP-RESTORE-UNINSTALL.md)
