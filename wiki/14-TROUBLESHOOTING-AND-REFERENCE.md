# Диагностика и справочник

Этот раздел предназначен для ситуации, когда установка, панель, updater или
runtime уже ведут себя не так, как ожидалось. Диагностика строится снизу вверх:
процесс → база/файл → listener → reverse proxy → DNS/TLS → внешний клиент.

> [!IMPORTANT]
> Не начинайте с переустановки или удаления. Сначала сохраните логи, состояние,
> commit, manifests и backup. Повторный idempotent installer часто помогает, но
> не должен скрывать первопричину.

## 1. Быстрый triage за пять минут

Выполните от `root`:

```bash
date -Is
uname -a
df -h /
free -h
systemctl --failed --no-pager --full
systemctl --no-pager --full status infiproxy.service
journalctl -u infiproxy.service -n 120 --no-pager
curl -i -H 'Accept: */*' http://127.0.0.1:8080/health
curl -i -H 'Accept: */*' http://127.0.0.1:8080/ready
ss -lntup
```

Затем зафиксируйте versions:

```bash
git -C /opt/infiproxy/source rev-parse HEAD
/usr/local/sbin/infiproxy-module-update --check-all
systemctl list-timers 'infiproxy-*' --all
```

Интерпретация:

| Наблюдение | Наиболее вероятный слой |
|---|---|
| Unit failed до появления listener | Env, права, SQLite или binary startup. |
| `/health` 200, `/ready` 503 | SQLite/storage. |
| Оба local probes 200, снаружи timeout | Firewall, Nginx, DNS или provider network. |
| HTTPS 502 | Nginx работает, backend panel/Headscale недоступен. |
| Runtime active, но клиент не подключается | Server config, protocol mismatch, TLS/SNI, UDP/firewall. |
| Module download прошел, symlink не изменился | Checksum, extraction или smoke test. |

## 2. Установка прервалась из-за SSH

Bootstrap и installer рассчитаны на повторный запуск. После reconnect не удаляйте
каталоги вслепую.

### 2.1. Проверка оставшегося состояния

```bash
sudo systemctl --no-pager --full status infiproxy.service
sudo journalctl -u infiproxy.service -n 100 --no-pager
sudo test -d /opt/infiproxy/source/.git && echo source-ok
sudo test -x /usr/local/sbin/infiproxy-manager && echo manager-ok
sudo test -x /usr/local/bin/infiproxy && echo binary-ok
```

Если source checkout цел и manager установлен:

```bash
sudo infiproxy-manager --guided
```

Если manager еще не установлен, повторите bootstrap в `tmux`:

```bash
tmux new -s infiproxy-install
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh \
  | sudo bash -s -- --guided --with-nginx
```

`tmux` сохраняет процесс при потере клиентского соединения. Отсоединение:
`Ctrl-b`, затем `d`; возврат:

```bash
tmux attach -t infiproxy-install
```

### 2.2. Очистка старых tmux sessions

Посмотреть sessions:

```bash
tmux list-sessions
```

Удалить одну после проверки ее имени:

```bash
tmux kill-session -t OLD_NAME
```

Удалить все sessions текущего пользователя:

```bash
tmux kill-server
```

Последняя команда завершает и процессы внутри tmux; применяйте только когда
убеждены, что там не выполняется updater/install/build.

## 3. `unable to open database file` / SQLite code 14

Сообщение:

```text
Failed to validate admin session: error returned from database:
(code: 14) unable to open database file
```

означает, что процесс не может открыть сам файл или один из parent directories,
создать sidecar/journal либо путь из `INFIPROXY_DB` неверен.

### 3.1. Проверка URL и прав

```bash
sudo systemctl show infiproxy.service -p EnvironmentFiles -p User -p Group
sudo grep '^INFIPROXY_DB=' /etc/infiproxy/infiproxy.env
sudo namei -l /var/lib/infiproxy/infiproxy.sqlite
sudo ls -la /var/lib/infiproxy
```

Штатный URL:

```dotenv
INFIPROXY_DB=sqlite:///var/lib/infiproxy/infiproxy.sqlite?mode=rwc
```

Безопасное исправление штатного layout:

```bash
sudo install -d -o infiproxy -g infiproxy -m 0750 /var/lib/infiproxy
sudo find /var/lib/infiproxy -maxdepth 1 -type f -name 'infiproxy.sqlite*' \
  -exec chown infiproxy:infiproxy {} + \
  -exec chmod 0640 {} +
sudo systemctl restart infiproxy.service
```

Если файла еще нет, не создавайте его командой `sudo sqlite3` от root: panel с
`mode=rwc` создаст файл с правильным owner. Если БД существует, сначала сделайте
backup и проверьте integrity.

### 3.2. Дополнительные причины

- filesystem read-only;
- диск или inode заполнен;
- путь находится на NFS/SMB;
- `ProtectSystem` не разрешает измененный custom path;
- AppArmor/SELinux policy блокирует путь;
- parent directory не имеет execute bit для service user;
- env содержит пробел/кавычки в неподдерживаемом формате.

Проверка записи от имени сервиса без изменения БД:

```bash
sudo -u infiproxy test -r /var/lib/infiproxy/infiproxy.sqlite
sudo -u infiproxy test -w /var/lib/infiproxy
```

## 4. Панель не запускается

### 4.1. `Address already in use`

```bash
sudo ss -ltnp 'sport = :8080'
sudo systemctl status infiproxy.service
```

Остановите только установленный конфликтующий процесс либо выберите другой
loopback port и одновременно исправьте Nginx `proxy_pass`. Не меняйте panel bind
на public address как обходное решение.

### 4.2. Ошибка env

```bash
sudo systemd-analyze verify /etc/systemd/system/infiproxy.service
sudo systemctl cat infiproxy.service
sudo sed -n '1,120p' /etc/infiproxy/infiproxy.env
```

Секретов в штатном panel env нет, но перед отправкой вывода третьей стороне все
равно просмотрите файл. Верните минимальный template из
[раздела конфигурации](11-CONFIGURATION.md#3-окружение-панели) и рестартуйте.

### 4.3. Binary не той архитектуры

```bash
uname -m
file /usr/local/bin/infiproxy
/usr/local/bin/infiproxy --version
```

Bootstrap собирает panel локально и обычно исключает mismatch. Ошибка чаще
означает ручную установку чужого artifact.

## 5. Login и browser session

### 5.1. После login снова открывается форма

Частая причина — `INFIPROXY_COOKIE_SECURE=true` при доступе по обычному HTTP.
Secure cookie browser по HTTP не отправляет.

Предпочтительное решение — завершить HTTPS. Для временного SSH tunnel:

```bash
sudo sed -i 's/^INFIPROXY_COOKIE_SECURE=.*/INFIPROXY_COOKIE_SECURE=false/' \
  /etc/infiproxy/infiproxy.env
sudo systemctl restart infiproxy.service
```

После выпуска certificate обязательно верните `true` и снова войдите.

### 5.2. `/admin/setup` перенаправляет на login

В БД уже есть admin. Проверьте count без вывода password hashes:

```bash
sudo sqlite3 /var/lib/infiproxy/infiproxy.sqlite \
  'SELECT id, username, created_at FROM admins ORDER BY id;'
```

Не удаляйте owner record без backup: foreign keys затрагивают sessions, а роль
owner привязана к минимальному существующему admin ID.

### 5.3. HTTP 403 `Security token is missing or invalid`

Форма была открыта в старой/истекшей сессии либо cookie изменился. Обновите
страницу, войдите снова и повторите действие один раз. Не отключайте CSRF.

### 5.4. HTTP 429

После пяти неудачных попыток username/source блокируется до конца 15-минутного
окна. Проверьте, что Nginx передает корректный `X-Real-IP`, и дождитесь
`Retry-After`. Restart панели сбрасывает in-memory limiter, но не должен
использоваться как штатный обход.

## 6. Panel updater failed

Сначала соберите три источника:

```bash
sudo systemctl --no-pager --full status infiproxy-panel-update.service
sudo journalctl -xeu infiproxy-panel-update.service --no-pager
sudo tail -n 200 /var/lib/infiproxy-maintenance/panel-update-run.log
```

Проверьте source и state:

```bash
sudo cat /etc/infiproxy-update.conf
sudo git -C /opt/infiproxy/source status --short
sudo git -C /opt/infiproxy/source rev-parse HEAD
sudo sed -n '1,160p' /var/lib/infiproxy/panel-update-state.env
sudo ls -la /var/lib/infiproxy-maintenance/update-backups
```

Не публикуйте state без просмотра: в нем нет ожидаемых proxy secrets, но любой
diagnostic artifact нужно проверять перед отправкой.

### 6.1. Installed и latest одинаковы, но Update now запущен

Текущий TUI создает immediate request даже при `status current`. Root updater
может повторно собрать тот же commit. Само совпадение SHA не является ошибкой;
failure ищите дальше в build, installer, Nginx validation или readiness.

Если новая версия не нужна, удалите только необработанный request после
остановки updater:

```bash
sudo systemctl stop infiproxy-panel-update.service
sudo rm -f /var/lib/infiproxy/panel-update-now.request
```

Не удаляйте `update-backups` и source checkout.

### 6.2. Безопасный повторный update из терминала

Если update действительно доступен:

```bash
sudo install -m 0640 -o root -g root /dev/null \
  /var/lib/infiproxy/panel-update-now.request
sudo systemctl start infiproxy-panel-update.service
sudo systemctl --no-pager --full status infiproxy-panel-update.service
```

Updater сам делает pre-update backup. Если service завершается ошибкой, не
запускайте его циклически: сначала изучите log и последний backup.

### 6.3. Source содержит локальные изменения

Panel updater переключает checkout принудительно и не предназначен для хранения
production edits. Сначала сохраните patch в отдельный private repository/branch:

```bash
sudo git -C /opt/infiproxy/source status --short
sudo git -C /opt/infiproxy/source diff > /root/infiproxy-local.patch
sudo chmod 0600 /root/infiproxy-local.patch
```

После этого используйте reviewed commit как update ref. Не полагайтесь на
uncommitted files внутри managed checkout.

### 6.4. Ручное восстановление из pre-update backup

Если automatic rollback неполон, следуйте
[процедуре восстановления](12-BACKUP-RESTORE-UNINSTALL.md#4-восстановление-панели).
Сначала остановите updater timers/path, чтобы они не начали новый цикл во время
restore.

## 7. Module helper сообщает `invalid type: null, expected a string`

Это означает несовместимость установленного Rust manifest helper со схемой
текущего GitHub release JSON, где digest/checksum field может быть `null`.
Обновлять runtime старым helper не следует.

Сверьте timestamps и hashes:

```bash
sudo ls -l /usr/local/libexec/infiproxy-module-manifest
git -C /opt/infiproxy/source rev-parse HEAD
```

Если source уже обновлен, а helper остался старым, пересоберите и повторно
запустите idempotent installer:

```bash
cd /opt/infiproxy/source
cargo build --release -p stealthhub-panel
sudo bash deploy/install.sh
```

Installer сохраняет существующий env и runtime configs без `--force-env`.
После этого:

```bash
sudo /usr/local/sbin/infiproxy-module-update --check-all
```

Не заменяйте `null` выдуманной checksum и не отключайте fail-closed проверку.

## 8. Module download или checksum failed

### 8.1. Сеть/GitHub

```bash
curl -I https://api.github.com/rate_limit
getent ahosts github.com
curl -4I https://github.com/
curl -6I https://github.com/
```

Если IPv6 route сломан, только для конкретного update:

```bash
sudo INFIPROXY_FORCE_IPV4=true \
  /usr/local/sbin/infiproxy-module-update --update hysteria
```

`INFIPROXY_FORCE_IPV4` влияет на download, а не исправляет checksum, smoke test
или server config.

### 8.2. Digest/checksum отсутствует

Updater намеренно прекращает установку, если GitHub asset digest и официальный
checksum sidecar не дают валидный SHA-256. Это безопасное поведение. Возможные
действия:

1. Обновить panel/helper до ревизии с актуальным parser.
2. Проверить официальный upstream release и manifest asset pattern.
3. Дождаться исправленного upstream release/checksum.
4. Для ручного import получить SHA-256 из отдельного доверенного канала.

Нельзя подставлять локально вычисленный hash только что скачанного файла как
доказательство подлинности: он проверяет целостность повторной копии, но не
происхождение первой.

## 9. `smoke test failed; current symlink was not changed`

Это fail-safe: новая version directory могла быть создана, но active `current`
остался прежним.

Проверьте:

```bash
uname -m
file /opt/infiproxy/cores/MODULE/VERSION/BINARY
mount | grep ' /opt '
readlink -f /opt/infiproxy/cores/MODULE/current
```

Запустите ровно тот version command, который ожидает installer:

| Module | Smoke command |
|---|---|
| sing-box | `sing-box version` |
| Hysteria | `hysteria version` |
| Xray | `xray version`, fallback `xray --version` |
| TUIC | `tuic-server --version` |
| MTProxy | `--help`/`-h` и поиск ожидаемой usage-строки |

Пример:

```bash
/opt/infiproxy/cores/sing-box/1.13.14/sing-box version
echo $?
```

Причины:

- asset не той архитектуры;
- upstream изменил CLI;
- filesystem смонтирован `noexec`;
- binary поврежден несмотря на ошибочно выбранный checksum asset;
- отсутствует dynamic loader/library у не-static binary;
- old installer использует устаревший smoke command.

Не переключайте `current` вручную до успешного запуска binary. Сначала обновите
installer или manifest, затем повторите module update.

## 10. Module status `installed=unknown`

Updater читает version marker:

```text
/var/lib/infiproxy-maintenance/module-versions/<id>.version
```

Binary может существовать после старого/manual install, но marker отсутствовать.
`unknown` не означает автоматически, что binary поврежден. Проверьте symlink и
version, затем запустите штатный `--update <id>`: если upstream trusted metadata
валидна, updater установит/признает версию и запишет marker.

Не создавайте marker вручную без проверки binary provenance.

## 11. Module request застрял

Проверьте watcher, queue и failed files:

```bash
sudo systemctl status infiproxy-module-update.path
sudo systemctl status infiproxy-module-update.service
sudo find /var/lib/infiproxy/module-requests -maxdepth 1 -type f -ls
sudo tail -n 200 /var/lib/infiproxy-maintenance/module-update.log
```

Файл `.failed` сохраняется намеренно для диагностики. После исправления причины
создайте новый запрос кнопкой/TUI; не переименовывайте неизвестный failed request
в active без проверки его содержимого.

Перезапуск watcher:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now infiproxy-module-update.timer \
  infiproxy-module-update.path
```

## 12. Runtime unit active, но proxy не работает

`active` означает только, что процесс не завершился. Проверяйте data plane:

```bash
sudo systemctl --no-pager --full status infiproxy-MODULE.service
sudo journalctl -u infiproxy-MODULE.service -n 150 --no-pager
sudo ss -lntup
```

Сверьте server и Mihomo:

| Поле | Должно совпасть |
|---|---|
| Protocol | VLESS/SS/Hysteria2/TUIC/AnyTLS и точная версия/вариант. |
| Address | Публичный DNS/IP, доступный клиенту. |
| Port | Listener runtime и profile port. |
| Credential | UUID/password/secret. |
| TLS name | Certificate SAN и client SNI. |
| Transport | TCP/XHTTP/QUIC и transport-specific path/host. |
| REALITY | Public key, short ID, server name и flow. |
| Network family | IPv4/IPv6 route и firewall. |

Тестируйте из другой сети. Подключение к public IP с самого VPS может проходить
или ломаться иначе из-за hairpin routing/provider firewall.

## 13. Hysteria/TUIC и UDP

### Симптомы

- TCP-панель работает, QUIC protocol timeout;
- unit active, но client handshake не начинается;
- работает в одной сети и не работает в другой.

Проверка:

```bash
sudo ss -lunp
sudo nft list ruleset
sudo ufw status verbose
```

Убедитесь, что cloud firewall/security group тоже разрешает UDP. `curl` проверяет
TCP/HTTP и не тестирует QUIC runtime.

Для Hysteria starter ожидается UDP/443. Для TUIC starter — UDP/11443. Эти порты
можно изменить, но обе стороны и firewall должны быть обновлены одновременно.

Плохой throughput может быть связан с MTU, packet loss, congestion control,
CPU saturation или provider UDP shaping. Не увеличивайте параметры вслепую;
сначала сравните packet capture/metrics и официальный performance guide.

## 14. Подписка Mihomo не импортируется

### 14.1. Проверка HTTP

```bash
curl -fsS -D /tmp/sub.headers \
  'https://panel.example.com/sub/TOKEN/mihomo.yaml' \
  -o /tmp/mihomo.yaml
sed -n '1,40p' /tmp/sub.headers
```

Не отправляйте `/tmp/mihomo.yaml` третьей стороне без удаления credentials.

### 14.2. Что искать

```bash
grep -n 'REPLACE_WITH\|xray\.reality\|hysteria2\.\|tuic\.password' \
  /tmp/mihomo.yaml
```

Любой placeholder или literal secret name означает незавершенную настройку.

Проверьте YAML parser самого Mihomo, если клиент предоставляет test command.
Версии Mihomo различаются по поддержке XHTTP/AnyTLS и полям transport, поэтому
обновите клиент до совместимой версии и сверяйтесь с
[официальной документацией](https://wiki.metacubex.one/en/).

### 14.3. HTTP 404/410/403

| Ответ | Возможная причина |
|---|---|
| 404 | Token не существует или rule set slug неизвестен. |
| 403 | User отключен. |
| 410 | User истек либо quota считается исчерпанной. |
| 500 | DB/generator error; смотреть panel journal. |

Reset token немедленно инвалидирует старый URL.

## 15. Routing provider возвращает 404

Endpoint `/rules/<slug>` публикует только enabled set. Если выключить все sets,
generator текущей ревизии может использовать default references, но endpoints
останутся disabled и ответят 404.

Исправление:

1. Включите минимум один корректный rule set.
2. Убедитесь, что `subscription_domain` указывает на доступный HTTPS hostname.
3. Откройте каждый generated provider URL вручную.
4. Проверьте payload validator и первую-match семантику.

Rule providers публичны и не требуют user token; секретов в payload быть не
должно.

## 16. Headscale

### 16.1. Config не проходит проверку

```bash
sudo headscale -c /etc/headscale/config.yaml configtest
sudo journalctl -u headscale.service -n 150 --no-pager
```

Не используйте TUI restart как substitute validation: в текущей реализации
некоторые пути продолжают restart после неуспешного `configtest`.

### 16.2. Client не регистрируется

Проверьте:

```bash
curl -I https://hs.example.com/
getent ahosts hs.example.com
sudo headscale -c /etc/headscale/config.yaml users list
sudo headscale -c /etc/headscale/config.yaml nodes list
```

Типовые причины:

- Headscale DNS record включен в orange-cloud proxy вместо DNS-only;
- `server_url` не совпадает с hostname certificate;
- Nginx не передает WebSocket upgrade;
- pre-auth key истек/уже использован;
- system time клиента или сервера неверно;
- client использует неправильный `--login-server`;
- ACL/routes запрещают ожидаемый доступ после регистрации.

### 16.3. Web request не выполняется

```bash
sudo systemctl status infiproxy-module-update.path
sudo find /var/lib/infiproxy/headscale-requests -maxdepth 1 -type f -ls
sudo ls -la /var/lib/infiproxy-maintenance/headscale-processing
sudo tail -n 200 /var/lib/infiproxy-maintenance/module-update.log
```

После получения pre-auth key нажмите **Clear displayed result**. Если worker
упал, не публикуйте state JSON целиком: он может содержать последний key.

## 17. Cloudflare, certificate и Nginx

### 17.1. Zone not found / API error

Проверьте:

- token относится к правильному Cloudflare account;
- scope ограничивает, но включает нужную zone;
- есть `Zone:Read` и `DNS:Edit`;
- zone input — apex `example.com`, record input — полный hostname;
- token не содержит случайного пробела/newline.

Не запускайте `set -x` при работе с token.

### 17.2. Certificate issuance failed

```bash
sudo certbot certificates
sudo journalctl -u certbot.timer -n 120 --no-pager
sudo ls -l /root/.secrets/certbot/cloudflare.ini
```

Credential file должен иметь mode `0600`. DNS-01 зависит от propagation;
повторный частый выпуск может попасть под Let’s Encrypt rate limit.

### 17.3. Nginx 502

```bash
sudo nginx -t
sudo systemctl status nginx.service infiproxy.service
curl -i http://127.0.0.1:8080/ready
sudo journalctl -u nginx.service -n 100 --no-pager
```

Если local readiness работает, проверьте `proxy_pass`, SELinux policy и Nginx
error log. Если не работает, проблема в panel/storage, а не certificate.

### 17.4. Headscale через Nginx

Headscale использует отдельный backend `127.0.0.1:8088` и отдельный hostname.
Не направляйте оба hostnames на один upstream. Проверьте WebSocket headers и
DNS-only Cloudflare mode.

## 18. Configs: Save with backup failed

| Сообщение | Причина |
|---|---|
| `unknown config target` | Устаревшая форма/slug или module удален. Обновить страницу. |
| `content is larger...` | Превышен per-file limit. Редактировать через root editor после backup. |
| `content contains NUL bytes` | Файл бинарный/поврежден, web-editor его не принимает. |
| `symlinked config paths are not allowed` | Путь или parent является symlink; защита от path redirection. |
| `path is not a regular file` | Directory/device/socket вместо файла. |
| `backup failed` | Permissions, read-only filesystem, no space или inode exhaustion. |
| `write failed` | Panel user/group не имеет записи либо systemd sandbox запрещает путь. |

После успешного save service не reload автоматически. Выполните validation и
apply через TUI/root shell.

## 19. Web System button failed

Страница честно показывает stdout/stderr фиксированной команды. Штатный panel
user обычно не имеет права `systemctl restart`. Это ожидаемая граница
привилегий, а не повод выдавать полный sudo.

Используйте:

```bash
sudo infiproxy-manager
```

Для Headscale вручную запускайте `configtest` до restart. Для Xray/sing-box/
Hysteria/TUIC валидируйте соответствующим binary.

## 20. IP Check показывает мало данных

Вкладка выполняет только локальные операции: validation literal IP, reverse DNS
и route lookup. Она не опрашивает автоматически репутационные базы и не запускает
speed test. Каждая внешняя ссылка передает выбранный IP соответствующему
провайдеру только после клика.

Результаты reputation-сервисов могут расходиться и устаревать. Проверяйте ASN,
PTR, BGP origin и конкретный blocklist; не сводите решение к одному score.

## 21. Нехватка памяти или медленная сборка

Runtime panel легкий, но Rust release build и MTProxy source build требуют
больше RAM/CPU, чем работа готового binary.

Проверьте:

```bash
free -h
swapon --show
journalctl -k -g 'Out of memory\|Killed process' --no-pager
```

На слабом VPS собирайте release на отдельной совместимой машине/CI либо временно
добавьте swap согласно политике хоста. Swap не заменяет RAM и может сильно
замедлить build. После установки уменьшите параллелизм source build при
необходимости; не ограничивайте память systemd до подтверждения реального peak.

## 22. Полный справочник путей

### 22.1. Control plane

| Путь | Назначение |
|---|---|
| `/usr/local/bin/infiproxy` | Panel binary. |
| `/etc/infiproxy/infiproxy.env` | Runtime environment. |
| `/var/lib/infiproxy/infiproxy.sqlite` | Panel SQLite. |
| `/var/lib/infiproxy/panel-update-state.env` | Checker state для root updater/UI. |
| `/var/lib/infiproxy/panel-update-now.request` | Immediate update trigger. |
| `/var/lib/infiproxy/module-requests` | Typed module queue. |
| `/var/lib/infiproxy/headscale-requests` | Typed Headscale queue. |
| `/opt/infiproxy/source` | Managed Git checkout. |

### 22.2. Root maintenance

| Путь | Назначение |
|---|---|
| `/usr/local/sbin/infiproxy-manager` | SSH-TUI. |
| `/usr/local/sbin/infiproxy-panel-update` | Panel root updater. |
| `/usr/local/sbin/infiproxy-module-update` | Module root updater. |
| `/usr/local/sbin/infiproxy-core-install` | Verified archive installer. |
| `/usr/local/libexec/infiproxy-module-manifest` | Rust manifest/GitHub JSON helper. |
| `/usr/local/libexec/infiproxy-headscale-control` | Typed Headscale worker. |
| `/etc/infiproxy-update.conf` | Root-owned GitHub repo/ref. |
| `/etc/infiproxy-modules.d` | Active manifests. |
| `/etc/infiproxy-modules.available.d` | Available catalog. |
| `/var/lib/infiproxy-maintenance` | Logs, versions, builds, locks metadata и backups. |
| `/var/lib/infiproxy-maintenance/headscale/state.json` | Root-owned snapshot/last result; иногда временно содержит pre-auth key. |

### 22.3. Runtime

| Путь | Назначение |
|---|---|
| `/opt/infiproxy/cores/<id>/<version>` | Versioned proxy binaries. |
| `/opt/infiproxy/cores/<id>/current` | Atomic active symlink. |
| `/opt/infiproxy/modules/headscale/<version>` | Versioned Headscale binary. |
| `/etc/infiproxy-cores/<id>` | Proxy configs. |
| `/etc/infiproxy-cores/tls` | Starter TLS location для Hysteria/TUIC. |
| `/var/log/infiproxy-cores` | Runtime log directory, если unit/config его использует. |
| `/etc/headscale/config.yaml` | Headscale config. |
| `/var/lib/headscale/db.sqlite` | Headscale state DB. |

## 23. systemd units

| Unit | Тип | Что запускает |
|---|---|---|
| `infiproxy.service` | long-running | Rust web panel. |
| `infiproxy-panel-update.service` | oneshot root | Panel update when due/requested. |
| `infiproxy-panel-update.timer` | timer | Проверка due каждые 15 минут. |
| `infiproxy-panel-update.path` | path | Immediate request watcher. |
| `infiproxy-module-update.service` | oneshot root | Queue + automatic module/Headscale work. |
| `infiproxy-module-update.timer` | timer | Due work каждые 15 минут. |
| `infiproxy-module-update.path` | path | Queue watcher. |
| `infiproxy-xray.service` | long-running | Xray current binary. |
| `infiproxy-sing-box.service` | long-running | sing-box current binary. |
| `infiproxy-hysteria.service` | long-running | Hysteria current binary. |
| `infiproxy-tuic.service` | long-running | TUIC current binary. |
| `infiproxy-mtproto.service` | long-running | Telegram MTProxy current binary. |
| `headscale.service` | long-running | Headscale current binary. |

Команды:

```bash
systemctl cat UNIT
systemctl is-enabled UNIT
systemctl is-active UNIT
systemctl --no-pager --full status UNIT
journalctl -u UNIT -n 120 --no-pager
```

## 24. Default port plan

| Protocol/address | Default consumer | Public? |
|---|---|---:|
| TCP `22` | SSH, если distro default не изменен | Ограниченно. |
| TCP `80` | Nginx redirect | Да, optional. |
| TCP `443` | Nginx panel/Headscale virtual hosts | Да. |
| UDP `443` | Hysteria starter | Только если настроен. |
| TCP `127.0.0.1:8080` | Infiproxy | Нет. |
| TCP `127.0.0.1:8088` | Headscale HTTP control | Нет. |
| TCP `127.0.0.1:9098` | Headscale metrics | Нет. |
| TCP `127.0.0.1:50443` | Headscale gRPC | Нет. |
| TCP `8443` | VLESS XHTTP starter profile | Да, после настройки Xray inbound. |
| TCP `8444` | MTProxy starter | Да, если настроен. |
| TCP `8888` | MTProxy stats согласно runtime args/unit | Нет. |
| UDP `11443` | TUIC starter | Да, если настроен. |
| Configurable | Xray/sing-box inbounds | По конфигу. |

Перед изменением:

```bash
sudo ss -lntup
```

## 25. HTTP endpoints

| Method/path | Доступ | Назначение |
|---|---|---|
| `GET /` | Public | Entry page. |
| `GET/POST /admin/setup` | Public только до первого admin | Owner creation. |
| `GET/POST /admin/login` | Public | Login. |
| `POST /admin/logout` | Admin + CSRF | Logout. |
| `GET /admin` | Admin | Dashboard. |
| `GET/POST /admin/account` | Admin + CSRF для POST | Password rotation и session revocation. |
| `/admin/users*` | Admin + CSRF для POST | User lifecycle. |
| `/admin/settings` | Admin; update controls owner-only | Panel/client/update settings. |
| `/admin/protocols*` | Admin + CSRF | Mihomo profile editor. |
| `/admin/secrets*` | Owner-only + CSRF для POST | Write-only secret value lifecycle. |
| `/admin/routing*` | Admin + CSRF | Rule sets. |
| `/admin/cores*` | View admin; actions owner-only | Runtime module catalog. |
| `/admin/headscale*` | Owner-only | Typed Headscale control. |
| `/admin/ip` | Admin | Local IP diagnosis/external links. |
| `/admin/system*` | View admin; preview owner-only + CSRF | Sensors, command map, uninstall preview. |
| `/admin/configs` | Owner-only + CSRF save | Allowlist config editor. |
| `/admin/health` | Admin | Detailed host/service diagnostics. |
| `/admin/credits` | Admin | Project/license credits. |
| `GET /health` | Public | Minimal plain-text liveness. |
| `GET /ready` | Public | SQLite readiness. |
| `GET /sub/<token>` | Bearer URL | User subscription page. |
| `GET /sub/<token>/mihomo.yaml` | Bearer URL | Generated Mihomo config. |
| `GET /rules/<slug>` | Public if enabled | Rule-provider YAML. |

## 26. Локальная разработка

Используйте отдельную временную БД и insecure cookie только на loopback:

```bash
INFIPROXY_BIND=127.0.0.1:8080 \
INFIPROXY_DB='sqlite:///tmp/infiproxy-dev.sqlite?mode=rwc' \
INFIPROXY_DB_MAX_CONNECTIONS=2 \
INFIPROXY_COOKIE_SECURE=false \
INFIPROXY_SETUP_TOKEN="$(openssl rand -hex 32)" \
RUST_LOG='stealthhub_panel=debug,tower_http=info' \
cargo run -p stealthhub-panel
```

Откройте:

```text
http://127.0.0.1:8080/admin/setup
```

Удаление временного state после остановки процесса:

```bash
rm -f /tmp/infiproxy-dev.sqlite \
  /tmp/infiproxy-dev.sqlite-shm \
  /tmp/infiproxy-dev.sqlite-wal
```

Никогда не направляйте dev process на production SQLite.

## 27. Проверки перед commit/release

Команды соответствуют GitHub Actions:

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
```

Deployment contracts:

```bash
shellcheck -x \
  deploy/bootstrap.sh \
  deploy/install.sh \
  deploy/panel-update.sh \
  deploy/module-update.sh \
  deploy/cores/install-core.sh \
  deploy/infiproxy-manager.sh \
  deploy/infiproxy-profile.sh \
  deploy/tests/updater-regression.sh \
  deploy/tests/http-smoke.sh \
  deploy/tests/wiki-check.sh

for file in deploy/*.sh deploy/cores/*.sh deploy/tests/*.sh; do
  bash -n "$file"
done

cargo build -p stealthhub-panel --bins
target/debug/infiproxy-module-manifest list deploy/modules.d
bash deploy/tests/wiki-check.sh
bash deploy/tests/updater-regression.sh
bash deploy/tests/http-smoke.sh
bash deploy/install.sh --check
bash deploy/bootstrap.sh --check --src-dir "$PWD"
```

Dependency audit, если `cargo-audit` установлен:

```bash
cargo audit
cargo deny check
```

Release smoke test дополнительно должен включать clean Ubuntu/Debian VPS,
first-owner setup, HTTPS, один TCP runtime, один UDP runtime, subscription import,
module update/rollback, Headscale enrollment, reboot/autostart и restore test.

## 28. Безопасный support bundle

Не архивируйте всю `/etc` или `/var/lib/infiproxy`. Сначала соберите только
нечувствительные метаданные во временный root-only каталог:

```bash
sudo install -d -m 0700 /root/infiproxy-support
sudo systemctl --no-pager --full status infiproxy.service \
  > /root/infiproxy-support/panel-status.txt 2>&1
sudo journalctl -u infiproxy.service -n 200 --no-pager \
  > /root/infiproxy-support/panel-journal.txt
sudo systemctl --failed --no-pager --full \
  > /root/infiproxy-support/failed-units.txt
sudo ss -lntup > /root/infiproxy-support/listeners.txt
sudo /usr/local/sbin/infiproxy-module-update --check-all \
  > /root/infiproxy-support/modules.txt 2>&1
```

Перед передачей вручную удалите:

- subscription tokens в URL;
- usernames/IP, если они чувствительны;
- cookies и authorization headers;
- UUID/password/REALITY data;
- Cloudflare/pre-auth/MTProto secrets;
- private keys;
- полный config и SQLite dumps.

## 29. Когда нужна provider console

Используйте web/VNC/serial console VPS-провайдера, если:

- firewall закрыл SSH;
- `sshd_config` не проходит parsing и daemon не стартует;
- network config потерян;
- root filesystem read-only или не монтируется;
- boot завис на failed mount/unit;
- SSH host keys/permissions повреждены.

Панель и tmux не могут восстановить соединение, если сам SSH/network stack
недоступен. Проверяйте provider console до рискованных изменений.

## 30. Связанные разделы

- [Быстрый старт](01-QUICK-START.md)
- [Веб-интерфейс](03-WEB-INTERFACE.md)
- [Модули и обновления](08-MODULES-AND-UPDATES.md)
- [System и TUI](10-SYSTEM-AND-TUI.md)
- [Конфигурация](11-CONFIGURATION.md)
- [Backup и restore](12-BACKUP-RESTORE-UNINSTALL.md)
- [Безопасная эксплуатация](13-SECURITY-OPERATIONS.md)
