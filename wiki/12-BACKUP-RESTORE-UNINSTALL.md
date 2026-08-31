# Backup, restore и uninstall

[Назад: конфигурация](11-CONFIGURATION) | [К оглавлению](Home) |
[Далее: безопасность](13-SECURITY-OPERATIONS)

## 1. Что нужно сохранять

Полный current-state backup состоит из согласованных частей:

| Данные | Путь | Почему важны |
|---|---|---|
| SQLite | /var/lib/infiproxy/infiproxy.sqlite | Admins, sessions, users, profiles, shared secrets, routing, generations |
| Panel env | /etc/infiproxy/infiproxy.env | Bind, DB URL, cookie/setup configuration |
| Root secrets | /etc/infiproxy/secrets.d | Server-only credentials |
| Runtime configs/TLS | /etc/infiproxy-cores | Server listeners, shared TLS pair |
| Active manifests | /etc/infiproxy-modules.d | Approved installed module contracts |
| Available catalog | /etc/infiproxy-modules.available.d | Approved installable contracts |
| Update source | /etc/infiproxy-update.conf | Root-pinned REPO/REF |
| Nginx sites | /etc/nginx/sites-available/infiproxy*.conf | Admin/subscription HTTPS edge |
| systemd units | /etc/systemd/system/infiproxy* | Service execution/hardening |
| Reconcile state | /var/lib/infiproxy-maintenance/reconcile | Last applied generation/journal |
| Version markers | /var/lib/infiproxy-maintenance/module-versions | Installed runtime versions |

Versioned runtime binaries можно восстановить повторной verified установкой, но
сохранение current target ускоряет rollback. Не считайте каталог backups на том
же VPS disaster recovery.

## 2. Почему нельзя просто копировать SQLite

SQLite использует WAL. Во время работы актуальные pages могут находиться в
infiproxy.sqlite-wal, поэтому копия только main file может быть
несогласованной. Используйте SQLite Online Backup API через команду .backup
либо полностью остановите writers и копируйте main/WAL/SHM как один набор.

Предпочтительный online backup:

    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    backup=/var/backups/infiproxy/$stamp
    sudo install -d -o root -g root -m 0700 "$backup"
    sudo -u infiproxy sqlite3 /var/lib/infiproxy/infiproxy.sqlite +      ".backup '$backup/infiproxy.sqlite'"
    sudo chmod 0600 "$backup/infiproxy.sqlite"
    sudo sqlite3 "$backup/infiproxy.sqlite" 'PRAGMA integrity_check;'

Ожидаемый результат integrity_check: ok.

## 3. Согласованный manual backup

Перед runtime/update/uninstall изменением:

    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    backup=/var/backups/infiproxy/$stamp
    sudo install -d -o root -g root -m 0700 "$backup"

Сохраните SQLite:

    sudo -u infiproxy sqlite3 /var/lib/infiproxy/infiproxy.sqlite +      ".backup '$backup/infiproxy.sqlite'"
    sudo chmod 0600 "$backup/infiproxy.sqlite"
    sudo sqlite3 "$backup/infiproxy.sqlite" 'PRAGMA integrity_check;'

Сохраните root-owned configs:

    sudo tar -C / -czf "$backup/system-configs.tar.gz" +      etc/infiproxy +      etc/infiproxy-cores +      etc/infiproxy-modules.d +      etc/infiproxy-modules.available.d +      etc/infiproxy-update.conf +      etc/systemd/system/infiproxy.service +      etc/systemd/system/infiproxy-panel-update.service +      etc/systemd/system/infiproxy-panel-update.timer +      etc/systemd/system/infiproxy-panel-update.path +      etc/systemd/system/infiproxy-module-update.service +      etc/systemd/system/infiproxy-module-update.timer +      etc/systemd/system/infiproxy-module-update.path +      etc/systemd/system/infiproxy-reconcile.service +      etc/systemd/system/infiproxy-reconcile.timer +      etc/systemd/system/infiproxy-reconcile.path
    sudo chmod 0600 "$backup/system-configs.tar.gz"

Если Nginx используется:

    sudo tar -C / -czf "$backup/nginx-sites.tar.gz" +      etc/nginx/sites-available/infiproxy.conf +      etc/nginx/sites-available/infiproxy-subscription.conf +      etc/nginx/sites-enabled/infiproxy.conf +      etc/nginx/sites-enabled/infiproxy-subscription.conf
    sudo chmod 0600 "$backup/nginx-sites.tar.gz"

Некоторые optional paths могут отсутствовать. Для универсального automation
используйте tar --ignore-failed-read только вместе с manifest отсутствующих
paths; иначе молчаливый неполный backup опасен.

Снимите диагностику без secrets:

    sudo git -C /opt/infiproxy/source rev-parse HEAD >"$backup/source.sha"
    sudo cat /var/lib/infiproxy-maintenance/panel-last-applied.sha +      >"$backup/applied.sha"
    sudo systemctl list-unit-files 'infiproxy*' >"$backup/units.txt"
    sudo systemctl list-timers 'infiproxy*' >"$backup/timers.txt"
    sudo ss -lntup >"$backup/listeners.txt"

Не сохраняйте environment, config или YAML в обычный support log.

## 4. Проверка backup

Минимальная проверка:

    sudo test -s "$backup/infiproxy.sqlite"
    sudo test -s "$backup/system-configs.tar.gz"
    sudo sqlite3 "$backup/infiproxy.sqlite" 'PRAGMA integrity_check;'
    sudo tar -tzf "$backup/system-configs.tar.gz" >/dev/null
    sudo sha256sum "$backup"/* >"$backup/SHA256SUMS"

Проверьте ownership root:root и modes 0700/0600. Затем зашифруйте и перенесите
копию off-host. Restore считается проверенным только после регулярной
репетиции на отдельном host.

## 5. Автоматические update backups

Panel updater перед checkout/build сохраняет:

- panel и privileged helper binaries;
- SQLite через .backup;
- panel/runtime configs;
- active/available manifests;
- Nginx sites;
- previous source commit и service metadata.

Root backups находятся в:

    /var/lib/infiproxy-maintenance/update-backups

Module updater сохраняет config и metadata в:

    /var/lib/infiproxy-maintenance/module-backups/<id>/<timestamp>

Default retention - 30 дней. Эти копии предназначены для локального rollback и
не заменяют off-host backup.

## 6. Restore SQLite

Сначала остановите все writers:

    sudo systemctl stop infiproxy.service
    sudo systemctl stop infiproxy-reconcile.path infiproxy-reconcile.timer
    sudo systemctl stop infiproxy-panel-update.path infiproxy-panel-update.timer
    sudo systemctl stop infiproxy-module-update.path infiproxy-module-update.timer

Проверьте backup:

    sudo sqlite3 BACKUP_DIR/infiproxy.sqlite 'PRAGMA integrity_check;'

Восстановите через SQLite:

    sudo rm -f /var/lib/infiproxy/infiproxy.sqlite-wal +      /var/lib/infiproxy/infiproxy.sqlite-shm
    sudo -u infiproxy sqlite3 /var/lib/infiproxy/infiproxy.sqlite +      ".restore 'BACKUP_DIR/infiproxy.sqlite'"
    sudo chown infiproxy:infiproxy /var/lib/infiproxy/infiproxy.sqlite
    sudo chmod 0640 /var/lib/infiproxy/infiproxy.sqlite
    sudo -u infiproxy sqlite3 /var/lib/infiproxy/infiproxy.sqlite +      'PRAGMA integrity_check;'

Не запускайте старую SQLite schema с новым binary без compatibility check.

## 7. Restore configs и services

Развертывайте archive только после просмотра списка:

    sudo tar -tzf BACKUP_DIR/system-configs.tar.gz
    sudo tar -C / -xzf BACKUP_DIR/system-configs.tar.gz
    sudo systemctl daemon-reload

Проверьте permissions:

- /etc/infiproxy/secrets.d - root-owned 0700;
- server-only files - root-owned 0600;
- /etc/infiproxy-cores/tls - root:infiproxy-runtime 0750;
- TLS certificate/key - root:infiproxy-runtime 0640;
- manifests/update config - root-owned и не group/world-writable.

Проверьте configs до старта:

    sudo nginx -t
    sudo /opt/infiproxy/cores/xray/current/xray run -test +      -config /etc/infiproxy-cores/xray/config.json
    sudo /opt/infiproxy/cores/sing-box/current/sing-box check +      -c /etc/infiproxy-cores/sing-box/config.json
    sudo /opt/infiproxy/cores/mihomo/current/mihomo -t +      -f /etc/infiproxy-cores/mihomo/config.yaml

Запускайте сначала panel, затем reconciler и только ожидаемые runtimes:

    sudo systemctl start infiproxy.service
    curl -fsS http://127.0.0.1:8080/ready
    sudo systemctl start infiproxy-reconcile.service

## 8. Проверка после restore

1. /health и /ready отвечают.
2. Login owner работает.
3. desired/applied generations и status ожидаемы.
4. Active manifests соответствуют установленным binaries.
5. TLS readiness не degraded.
6. PID-owned TCP/UDP listeners совпадают с profiles.
7. Subscription token тестового user выдает YAML.
8. Rule-provider URLs отдают ожидаемый payload.
9. Реальный client handshake проходит для каждого enabled profile.
10. Timers включены только после canary.

Если backup был сделан во время Failed/RecoveryRequired, restore этого backup
может вернуть то же состояние. Выбирайте known-good generation.

## 9. Uninstall modes

Web System показывает только plan. Исполнение:

    sudo infiproxy-manager --uninstall panel
    sudo infiproxy-manager --uninstall full
    sudo infiproxy-manager --uninstall factory

Перед подтверждением TUI печатает точный command list и требует повторное имя
mode.

| Mode | Удаляет | Сохраняет |
|---|---|---|
| panel | Panel binary/state, updater/reconciler, source, admin/subscription Nginx sites | Runtime binaries/services/configs и module updater |
| full | Panel, registered runtimes, configs/state, manifests, source, manager, service users | OS packages |
| factory | Весь известный /opt/infiproxy footprint и те же managed artifacts | OS packages и сторонние данные вне allowlist |

Full и factory намеренно не выполняют package purge. Installer не может доказать,
были ли Git, Rust, Nginx, Certbot или build dependencies установлены до
Infiproxy.

Uninstall не является secure erase. SSD/VPS snapshots, provider backups и
off-host archives могут сохранить secrets.

## 10. Безопасное удаление

1. Создайте и проверьте off-host backup.
2. Запишите текущий SHA, DNS и listeners.
3. Откройте вторую SSH/provider-console session.
4. Остановите client traffic или перенесите DNS.
5. Запустите нужный mode и внимательно просмотрите plan.
6. После удаления проверьте:

       sudo systemctl list-unit-files 'infiproxy*'
       sudo find /etc /opt /var/lib /var/log -maxdepth 4 -iname '*infiproxy*'
       sudo ss -lntup

7. Удалите оставшиеся данные только после классификации ownership.
8. Ротируйте credentials, которые когда-либо находились на host.

Не используйте rm -rf по широким системным каталогам и не удаляйте чужие
Nginx/systemd files по совпадению части имени.
