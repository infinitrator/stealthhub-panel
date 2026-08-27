# Бэкапы, восстановление и удаление

Резервная копия Infiproxy должна защищать не только бинарник панели. На сервере
есть как минимум две независимые базы данных, runtime-конфиги, TLS-ключи,
module manifests, systemd units и DNS/certificate state.

> [!IMPORTANT]
> Автоматические pre-update backups являются локальной страховкой от неудачного
> обновления, но не защищают от потери VPS, диска, root-компрометации или ошибки
> удаления. Production backup должен регулярно уходить на другой хост в
> зашифрованном виде.

## 1. Что является ценными данными

| Данные | Основной путь | Что будет потеряно без них |
|---|---|---|
| База панели | `/var/lib/infiproxy/infiproxy.sqlite` | Администраторы, session records, пользователи, subscription tokens, UUID, профили, routes, settings, secret values. |
| База Headscale | `/var/lib/headscale/db.sqlite` | Узлы, users, routes, pre-auth state и координационные данные. |
| Panel env | `/etc/infiproxy/infiproxy.env` | Bind, DB URL, cookie flags и logging. |
| Private server secrets | `/etc/infiproxy/secrets.d` | Private keys/passwords, недоступные web-процессу. |
| Proxy configs | `/etc/infiproxy-cores` | Server inbounds, credentials, TLS paths и MTProto env/upstream files. |
| Headscale config | `/etc/headscale` | Public URL, prefixes, MagicDNS, ACL path и keys. |
| Module registry | `/etc/infiproxy-modules.d` | Какие модули зарегистрированы и как обновляются. |
| Module catalog | `/etc/infiproxy-modules.available.d` | Доступные manifests, включая импортированные. |
| Update source | `/etc/infiproxy-update.conf` | GitHub repository и ref панели. |
| Nginx sites | `/etc/nginx/sites-available/infiproxy*.conf` | HTTPS edge для панели и Headscale. |
| Certificates | `/etc/letsencrypt` и runtime TLS path | HTTPS identity и private keys. |
| Cloudflare token | `/root/.secrets/certbot/cloudflare.ini` | DNS-01 renewal; это особо чувствительный secret. |
| Custom systemd units | `/etc/systemd/system/infiproxy*.service`, `headscale.service*` | Условия запуска и hardening. |
| Active binaries | `/opt/infiproxy/{cores,modules}` | Быстрый offline rollback конкретной версии. |
| Source checkout | `/opt/infiproxy/source` | Installed commit и локальные изменения, если они были. |

Исходники и публичные бинарники можно скачать повторно, но точные конфиги,
пользовательские credentials и private keys восстановить из GitHub нельзя.

## 2. Встроенные типы backup

### 2.1. Config editor backup

Кнопка **Save with backup** копирует только один существующий файл рядом с ним:

```text
config.json.infiproxy-bak-<unix_timestamp>
```

Свойства:

- создается до записи;
- отсутствующий файл backup не получает;
- ошибка копирования отменяет save;
- retention и автоматического restore нет;
- SQLite, certificate и другие связанные файлы не входят.

Это undo для одной правки, а не disaster-recovery backup.

### 2.2. Backup при panel update

Перед каждым фактическим обновлением root updater создает:

```text
/var/lib/infiproxy-maintenance/update-backups/YYYYMMDD-HHMMSS/
```

Содержимое:

| Файл | Данные |
|---|---|
| `infiproxy` | Предыдущий `/usr/local/bin/infiproxy`, если существовал. |
| `control-binaries/` | Panel, manifest, Headscale и reconcile helpers либо маркеры их отсутствия. |
| `infiproxy.sqlite` | Online-consistent SQLite `.backup` базы панели. |
| `system-configs.tar.gz` | Panel env, proxy configs, Headscale config, updater config, active/available manifests, Nginx sites. |
| `metadata.env` | UTC creation time, previous Git commit и факт существования БД. |

Если `sqlite3` отсутствует или backup БД/конфигов не удался, update прекращается
до изменения control plane. Каталог имеет mode `0700`, файлы backup — `0600`.

Default retention — 30 дней через `INFIPROXY_BACKUP_RETENTION_DAYS`. Старые
каталоги удаляются во время следующего update, а не отдельным ежедневным job.

Если build/install/readiness завершается неуспешно, updater пытается:

1. Остановить панель.
2. Восстановить system configs из archive.
3. Удалить SQLite `-wal` и `-shm` sidecars.
4. Восстановить SQLite с владельцем `infiproxy` и mode `0640`.
5. Вернуть source checkout на предыдущий commit.
6. Установить предыдущий binary.
7. Вернуть privileged helper binaries, включая reconciler.
8. Повторно выполнить старый installer и запустить panel unit.

Автоматический rollback является best effort. Строка `warning: automatic ...
incomplete` требует ручного восстановления.

### 2.3. Backup при module update

Если `config_path` модуля существует, перед переключением версии создается:

```text
/var/lib/infiproxy-maintenance/module-backups/<module>/YYYYMMDD-HHMMSS/
```

| Файл | Данные |
|---|---|
| `config.tar.gz` | Только manifest-defined config path. |
| `metadata.env` | Config path, предыдущая target-директория `current`, enabled/active state и timestamp. |

Архив и metadata имеют mode `0600`; retention по умолчанию также 30 дней.
Binary устанавливается в новую version directory. Только после smoke test
symlink `current` переключается атомарно. Если восстановление service state
завершилось ошибкой, updater пытается вернуть symlink на предыдущую версию.

> [!NOTE]
> Module rollback возвращает binary symlink, но не выполняет автоматический
> downgrade преобразованного самим runtime конфига. Именно поэтому config archive
> сохраняется отдельно.

### 2.4. Backup в мастерах

- **Force env template rewrite** копирует старый env в
  `infiproxy.env.bak.YYYYMMDDHHMMSS`.
- MTProto setup копирует старый `mtproto.env` в `.bak.<timestamp>`.
- Headscale config writer копирует старый YAML в `.bak.<timestamp>`.

Эти backups локальные и не имеют retention.

## 3. Полный ручной backup

### 3.1. Подготовка

Проверьте диск и обе базы:

```bash
sudo df -h /
sudo sqlite3 /var/lib/infiproxy/infiproxy.sqlite 'PRAGMA quick_check;'
sudo sqlite3 /var/lib/headscale/db.sqlite 'PRAGMA quick_check;'
```

Результат каждой SQLite-проверки должен быть `ok`. Если Headscale еще не
настроен и файла нет, пропустите его.

Войдите в root shell, чтобы переменные и mode применялись ко всем следующим
командам:

```bash
sudo -i
umask 077
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup="/var/backups/infiproxy/${stamp}"
install -d -m 0700 "$backup"
```

### 3.2. Согласованные SQLite-копии

Не копируйте живую SQLite обычным `cp`, особенно при наличии `-wal`. Используйте
SQLite backup API:

```bash
sqlite3 /var/lib/infiproxy/infiproxy.sqlite ".backup '$backup/infiproxy.sqlite'"
chmod 0600 "$backup/infiproxy.sqlite"
```

Для Headscale:

```bash
if [ -f /var/lib/headscale/db.sqlite ]; then
  sqlite3 /var/lib/headscale/db.sqlite ".backup '$backup/headscale.sqlite'"
  chmod 0600 "$backup/headscale.sqlite"
fi
```

Проверьте копии, а не originals:

```bash
sqlite3 "$backup/infiproxy.sqlite" 'PRAGMA integrity_check;'
if [ -f "$backup/headscale.sqlite" ]; then
  sqlite3 "$backup/headscale.sqlite" 'PRAGMA integrity_check;'
fi
```

### 3.3. Конфиги и operational state

Создайте archive только из существующих путей:

```bash
paths=()
for path in \
  /etc/infiproxy \
  /etc/infiproxy-cores \
  /etc/headscale \
  /etc/infiproxy-modules.d \
  /etc/infiproxy-modules.available.d \
  /etc/infiproxy-update.conf \
  /etc/nginx/sites-available/infiproxy.conf \
  /etc/nginx/sites-available/infiproxy-subscription.conf \
  /etc/nginx/sites-available/infiproxy-headscale.conf \
  /etc/systemd/system/infiproxy.service \
  /etc/systemd/system/infiproxy-panel-update.service \
  /etc/systemd/system/infiproxy-panel-update.timer \
  /etc/systemd/system/infiproxy-panel-update.path \
  /etc/systemd/system/infiproxy-module-update.service \
  /etc/systemd/system/infiproxy-module-update.timer \
  /etc/systemd/system/infiproxy-module-update.path \
  /etc/systemd/system/infiproxy-reconcile.service \
  /etc/systemd/system/infiproxy-reconcile.timer \
  /etc/systemd/system/infiproxy-reconcile.path \
  /etc/systemd/system/infiproxy-xray.service \
  /etc/systemd/system/infiproxy-sing-box.service \
  /etc/systemd/system/infiproxy-hysteria.service \
  /etc/systemd/system/infiproxy-tuic.service \
  /etc/systemd/system/infiproxy-mtproto.service \
  /etc/systemd/system/headscale.service \
  /etc/systemd/system/headscale.service.d \
  /root/.secrets/certbot/cloudflare.ini
do
  [ -e "$path" ] || [ -L "$path" ] || continue
  paths+=("${path#/}")
done
tar -C / --acls --xattrs -czf "$backup/configs.tar.gz" -- "${paths[@]}"
chmod 0600 "$backup/configs.tar.gz"
```

Сертификаты можно включить отдельным archive, чтобы применять к нему более
строгую ротацию и доступ:

```bash
if [ -d /etc/letsencrypt ]; then
  tar -C / --acls --xattrs -czf "$backup/letsencrypt.tar.gz" -- etc/letsencrypt
  chmod 0600 "$backup/letsencrypt.tar.gz"
fi
```

### 3.4. Инвентарь версий

```bash
git -C /opt/infiproxy/source rev-parse HEAD >"$backup/panel-commit.txt"
/usr/local/bin/infiproxy --version >"$backup/panel-version.txt" 2>&1 || true
/usr/local/sbin/infiproxy-module-update --check-all >"$backup/modules.txt" 2>&1 || true
systemctl list-unit-files 'infiproxy*' headscale.service >"$backup/units.txt"
ss -lntup >"$backup/listeners.txt"
```

Если нужны offline rollback binaries, дополнительно архивируйте `/opt/infiproxy`
и `/usr/local/bin/infiproxy`. Это значительно увеличивает размер и обычно не
нужно, если upstream releases доступны и checksums известны.

### 3.5. Контрольная сумма и вывоз

```bash
cd "$backup"
sha256sum ./* > SHA256SUMS
chmod 0600 SHA256SUMS
```

Зашифруйте backup до отправки. Подходящий инструмент выбирает оператор: `age`,
GPG, restic или encrypted object storage. Проверка должна включать не только
наличие файла, но и периодическое test restore на отдельный VPS.

Не храните единственную копию внутри `/var/lib/infiproxy-maintenance`: full
uninstall удаляет этот каталог.

## 4. Восстановление панели

### 4.1. Перед началом

1. Разверните совместимый Linux host.
2. Установите Infiproxy той же ревизии или версии, что указана в inventory.
3. Не создавайте новых production users поверх пустой БД.
4. Скопируйте backup на host и проверьте `sha256sum -c SHA256SUMS`.
5. Остановите panel и maintenance units.

```bash
sudo systemctl stop infiproxy.service
sudo systemctl stop infiproxy-panel-update.timer infiproxy-panel-update.path
sudo systemctl stop infiproxy-module-update.timer infiproxy-module-update.path
```

### 4.2. Restore SQLite панели

```bash
sudo rm -f /var/lib/infiproxy/infiproxy.sqlite-wal \
  /var/lib/infiproxy/infiproxy.sqlite-shm
sudo install -d -o infiproxy -g infiproxy -m 0750 /var/lib/infiproxy
sudo install -o infiproxy -g infiproxy -m 0640 \
  BACKUP_DIR/infiproxy.sqlite /var/lib/infiproxy/infiproxy.sqlite
sudo sqlite3 /var/lib/infiproxy/infiproxy.sqlite 'PRAGMA integrity_check;'
```

Не запускайте SQLite migration новой версии до создания дополнительной копии
старой БД. Startup панели выполняет idempotent schema initialization, но
downgrade после будущей несовместимой migration может потребовать ручной работы.

### 4.3. Restore конфигов

Не распаковывайте archive вслепую. Сначала посмотрите список:

```bash
tar -tzf BACKUP_DIR/configs.tar.gz | less
```

На чистом replacement host можно восстановить выбранные пути:

```bash
sudo tar -C / --acls --xattrs -xzf BACKUP_DIR/configs.tar.gz
sudo systemctl daemon-reload
```

Проверьте owner/mode env и БД, затем:

```bash
sudo systemctl restart infiproxy.service
sudo systemctl --no-pager --full status infiproxy.service
curl -fsS http://127.0.0.1:8080/ready
```

На уже используемом host извлекайте archive во временный каталог и переносите
файлы выборочно, чтобы не затереть новый SSH/Nginx/systemd config.

## 5. Восстановление Headscale

Headscale database восстанавливается независимо:

```bash
sudo systemctl stop headscale.service
sudo rm -f /var/lib/headscale/db.sqlite-wal /var/lib/headscale/db.sqlite-shm
sudo install -d -o headscale -g headscale -m 0750 /var/lib/headscale
sudo install -o headscale -g headscale -m 0640 \
  BACKUP_DIR/headscale.sqlite /var/lib/headscale/db.sqlite
sudo headscale -c /etc/headscale/config.yaml configtest
sudo systemctl start headscale.service
sudo systemctl --no-pager --full status headscale.service
```

После restore проверьте users, nodes и routes. Старые pre-auth keys могли истечь;
не публикуйте их из backup logs.

## 6. Ручной rollback модуля

Сначала найдите metadata:

```bash
sudo find /var/lib/infiproxy-maintenance/module-backups/MODULE \
  -maxdepth 2 -type f -name metadata.env -print
```

Прочитайте `current_target`, `was_enabled` и `was_active`. Проверьте, что target
directory существует и binary запускает `version`/`--version`. Затем остановите
unit, переключите symlink через временную ссылку и восстановите config archive.

Пример структуры действий, где значения нужно взять из metadata:

```bash
sudo systemctl stop infiproxy-MODULE.service
sudo tar -C / -xzf /var/lib/infiproxy-maintenance/module-backups/MODULE/STAMP/config.tar.gz
sudo ln -sfn /opt/infiproxy/cores/MODULE/OLD_VERSION \
  /opt/infiproxy/cores/MODULE/.current.rollback
sudo mv -Tf /opt/infiproxy/cores/MODULE/.current.rollback \
  /opt/infiproxy/cores/MODULE/current
sudo systemctl start infiproxy-MODULE.service
```

Для Headscale runtime root находится в `/opt/infiproxy/modules/headscale`, а
service называется `headscale.service`. Не используйте пример буквально без
проверки manifest.

## 7. Проверка test restore

Минимальный quarterly drill:

1. Создайте новый временный VPS без production DNS.
2. Установите exact panel commit.
3. Восстановите panel DB и configs.
4. Подмените public hostnames тестовыми или держите services остановленными.
5. Проверьте login, список users, generated subscription и routes.
6. Восстановите Headscale DB и сравните users/nodes без подключения production clients.
7. Проверьте hashes архивов и время полного восстановления.
8. Удалите временный host и зафиксируйте найденные пробелы runbook.

Backup без успешного restore test считается непроверенным.

## 8. Удаление из веб-панели

Кнопки **Preview ... removal** только показывают команды. Они не выполняют shell
и не удаляют данные. Используйте preview для peer review перед SSH-TUI.

## 9. Удаление через SSH-TUI

Откройте:

```bash
sudo infiproxy-manager
```

Выберите **Danger zone**, режим, прочитайте весь plan и введите точную фразу:

```text
DELETE INFIPROXY
```

Также доступен прямой вызов:

```bash
sudo infiproxy-manager --uninstall panel
sudo infiproxy-manager --uninstall full
sudo infiproxy-manager --uninstall factory
```

Не запускайте прямой вызов до backup: после печати plan он также запросит
подтверждение и затем передаст утвержденные команды root shell.

### 9.1. Panel-only removal

Удаляет:

- panel service и только panel-updater units;
- binary панели, panel updater и update config;
- `/etc/infiproxy`;
- SQLite, panel update request/state и panel update backups/logs;
- source checkout и Nginx site панели.

Оставляет:

- пользователя/группу `infiproxy`, SSH-TUI, module updater и Rust helpers;
- active/available module manifests и module update state/backups;
- `/etc/infiproxy-cores`;
- `/opt/infiproxy/cores` и `/opt/infiproxy/modules`;
- core service unit files;
- `/etc/headscale`, `/var/lib/headscale` и Headscale binary;
- Headscale Nginx site;
- OS packages.

> [!CAUTION]
> Panel-only необратимо удаляет пользователей, admin-учетные записи,
> client-side secrets и routing settings вместе с SQLite. Runtime-процессы
> сохраняются, но подписки больше не выдаются. Сначала сделайте backup БД.

### 9.2. Full footprint removal

Дополнительно удаляет:

- зарегистрированные и встроенные core/headscale units;
- runtime binary/config/log directories;
- `/etc/headscale` и `/var/lib/headscale`;
- `/usr/local/bin/headscale`;
- source checkout `/opt/infiproxy/source`;
- Nginx sites панели и Headscale.

Системные пакеты `nginx`, `git`, Rust, Certbot, SQLite, build dependencies и
другие packages не удаляются.

### 9.3. Factory footprint cleanup

Отличается от full тем, что удаляет весь `/opt/infiproxy`, а не только известные
подкаталоги. Это может удалить вручную добавленные файлы внутри этого дерева.

Название **Factory** означает очистку известного Infiproxy footprint, но не
возврат к исходному snapshot дистрибутива.

### 9.4. Что не удаляет ни один режим

- Cloudflare DNS records, созданные через API;
- Let’s Encrypt account/certificates в `/etc/letsencrypt`;
- Cloudflare credential `/root/.secrets/certbot/cloudflare.ini`;
- firewall rules, если оператор менял их отдельно;
- OS packages и Rust toolchain;
- пользователь `headscale`, если он был создан;
- внешние backups и monitoring integrations;
- сторонние Nginx sites;
- изменения SSH config.

После full/factory вручную проверьте эти объекты и удаляйте только если они не
используются другими приложениями.

## 10. Проверка после удаления

```bash
systemctl list-unit-files | grep -E 'infiproxy|headscale'
systemctl --failed --no-pager
ss -lntup
find /etc /opt /var/lib /var/log /usr/local -maxdepth 4 \
  -iname '*infiproxy*' -o -iname '*stealthhub*' 2>/dev/null
nginx -t
```

Проверьте Cloudflare dashboard и DNS отдельно. Если Nginx остался, его reload
после удаления sites должен проходить успешно.

## 11. Рекомендуемая политика backup

| Среда | Частота | Retention | Копия вне VPS |
|---|---|---|---|
| Тест | Перед каждым изменением и раз в неделю | 2–4 недели | Желательна. |
| Небольшой production | Ежедневно + перед update | 30–90 дней | Обязательна. |
| Критичный production | Несколько раз в день для SQLite + config on change | По RPO/RTO и политике | Минимум одна immutable/offline копия. |

RPO — сколько данных допустимо потерять по времени. RTO — сколько времени
допустимо восстанавливать сервис. Эти числа нужно определить до аварии.

## 12. Связанные разделы

- [Модули и обновления](08-MODULES-AND-UPDATES)
- [Headscale](09-HEADSCALE)
- [Конфигурация](11-CONFIGURATION)
- [Безопасная эксплуатация](13-SECURITY-OPERATIONS)
- [Диагностика](14-TROUBLESHOOTING-AND-REFERENCE)
