# Диагностика и справочник

[Назад: безопасность](13-SECURITY-OPERATIONS) | [К оглавлению](Home) |
[Далее: релиз](15-RELEASE-AND-COMPATIBILITY)

## 1. Порядок диагностики

Проверяйте слои сверху вниз:

1. Host: disk, memory, DNS, clock, network.
2. Panel process: infiproxy.service.
3. SQLite: /ready.
4. Root control workers: updater/reconciler path/timer/service.
5. Module binary/version/current symlink.
6. Generated runtime config и native validator.
7. systemd runtime service.
8. TCP/UDP listener.
9. Public DNS/firewall/TLS.
10. Subscription generation и реальный client handshake.

Не начинайте с переустановки: она может затереть evidence и не исправить
невалидный desired state.

## 2. Минимальная сводка

    date
    uptime
    df -h /
    free -h
    sudo systemctl --failed
    sudo systemctl status infiproxy.service --no-pager --full
    curl -i http://127.0.0.1:8080/health
    curl -i http://127.0.0.1:8080/ready
    sudo ss -lntup

/health=ok означает, что процесс отвечает. /ready=ok означает, что panel может
выполнить SQLite query. Ни один endpoint не проверяет все proxy runtimes.

## 3. Panel не запускается

    sudo systemctl status infiproxy.service --no-pager --full
    sudo journalctl -u infiproxy.service -n 200 --no-pager
    sudo systemctl cat infiproxy.service
    sudo sed -n '1,120p' /etc/infiproxy/infiproxy.env

Не публикуйте setup token или DB URL с credentials. Типичные причины:

| Симптом | Проверка |
|---|---|
| unable to open database file | Parent ownership/mode, DB URL, disk |
| setup token too short | Admins table пуста и token < 32 chars |
| address already in use | ss -ltnp sport=:8080 |
| permission denied | systemd sandbox + file ownership |
| SQLite migration error | Backup, integrity_check, exact binary SHA |

Production permissions:

    sudo namei -l /var/lib/infiproxy/infiproxy.sqlite
    sudo -u infiproxy test -r /var/lib/infiproxy/infiproxy.sqlite
    sudo -u infiproxy test -w /var/lib/infiproxy

Ожидается /var/lib/infiproxy owner infiproxy:infiproxy mode 0750, database
обычно 0640. Не делайте chmod 777.

## 4. Забыты login/password

Штатного password-reset CLI в текущем release нет. Если существует другая
рабочая admin session, откройте Account и используйте Change Password.

Если доступ потерян полностью, аварийный путь удаляет только admin accounts и
sessions, после чего first-owner setup открывается заново. Users/profiles/
subscriptions остаются, но операция требует root и verified backup.

1. Откройте provider console или устойчивую SSH/tmux session.
2. Сделайте SQLite .backup и integrity_check.
3. Остановите panel.
4. Удалите admin rows в одной transaction.
5. Убедитесь, что INFIPROXY_SETUP_TOKEN содержит минимум 32 символа.
6. Запустите panel и создайте нового owner через SSH tunnel.

    backup=/var/backups/infiproxy/admin-recovery-$(date -u +%Y%m%dT%H%M%SZ).sqlite
    sudo install -d -o root -g root -m 0700 /var/backups/infiproxy
    sudo -u infiproxy sqlite3 /var/lib/infiproxy/infiproxy.sqlite \
      ".backup '$backup'"
    sudo chmod 0600 "$backup"
    sudo sqlite3 "$backup" 'PRAGMA integrity_check;'
    sudo systemctl stop infiproxy.service
    sudo -u infiproxy sqlite3 /var/lib/infiproxy/infiproxy.sqlite <<'SQL'
    PRAGMA foreign_keys=ON;
    BEGIN IMMEDIATE;
    DELETE FROM admin_sessions;
    DELETE FROM admins;
    COMMIT;
    SQL
    sudo systemctl start infiproxy.service

Используйте tunnel:

    ssh -L 8080:127.0.0.1:8080 root@SERVER

Откройте http://127.0.0.1:8080/admin/setup. После восстановления проверьте
Settings, update source, profiles, manifests и active sessions. Считайте старые
admin credentials скомпрометированными.

## 5. Login отклоняется

- Проверьте точный username; сравнение case-sensitive.
- Подождите окно rate-limit после серии ошибок.
- Источник может определяться trusted forwarded header только в настроенной
  reverse-proxy модели.
- Argon2 worker pool ограничен двумя jobs; при перегрузке возможен 503/Retry.
- Cookie Secure не отправляется по HTTP. Для production используйте HTTPS; для
  loopback development COOKIE_SECURE=false.

Не отключайте throttling и Secure cookie как постоянное исправление.

## 6. Subscription 401/403/503

| Код | Причина |
|---:|---|
| 401 | Token не найден, старый после reset или user удален |
| 403 | User disabled, expired или stored quota condition блокирует |
| 503 | Profile/secret/policy/runtime capability incomplete |

Проверяйте без вывода token в shared terminal:

    curl --config <(printf 'url = "https://SUB_HOST/sub/%s/mihomo.yaml"\n' "$TOKEN")

503 требует проверки enabled profiles, present secret names, installed runtime
capabilities и routing policy. Server logs редактируют детали и не должны
печатать secret values.

## 7. Reconcile Pending/Failed/RolledBack

    sudo systemctl status infiproxy-reconcile.path \
      infiproxy-reconcile.timer infiproxy-reconcile.service --no-pager
    sudo journalctl -u infiproxy-reconcile.service -n 200 --no-pager
    sudo find /var/lib/infiproxy/reconcile-requests -maxdepth 1 -type f -ls
    sudo find /var/lib/infiproxy-maintenance/reconcile -maxdepth 2 -type f -ls

Проверьте:

- request regular/bounded/app-owned и safe mode;
- desired generation существует в SQLite;
- protocol/core adapter и capability доступны;
- exact runtime version совместима;
- root-only/shared secrets разрешаются;
- listener network+port уникален;
- TLS pair ready;
- native validator принимает candidate.

RolledBack означает, что previous state восстановлен. RecoveryRequired требует
ручного restore; не удаляйте journal. Полный contract:
[Desired state](09-RECONCILIATION-AND-DESIRED-STATE).

## 8. Runtime не установлен или inactive

    sudo infiproxy-module-update --check <id>
    sudo ls -la /opt/infiproxy/cores/<id>
    sudo readlink -f /opt/infiproxy/cores/<id>/current
    sudo systemctl status infiproxy-<id>.service --no-pager

Installed binary и active service - разные состояния. Reconciler активирует
runtime, только когда desired resources его требуют. Start из Modules создаст
typed lifecycle request, но пустой/invalid config может снова остановить unit.

## 9. Module update failed

    sudo systemctl status infiproxy-module-update.service --no-pager --full
    sudo journalctl -u infiproxy-module-update.service -n 200 --no-pager
    sudo tail -n 200 /var/lib/infiproxy-maintenance/module-update.log

Типичные причины:

- GitHub API/network/IPv6;
- asset отсутствует для architecture;
- digest/checksum отсутствует или не совпал;
- archive safety limit/path validation;
- binary smoke test;
- active service не прошел canary;
- module ID retired/unknown;
- active desired resource блокирует remove.

Updater не меняет current symlink при failed verification. Если service failed
после switch, он пытается вернуть previous target и state. Для хоста со
сломавшимся IPv6 допустим разовый:

    sudo INFIPROXY_FORCE_IPV4=true \
      /usr/local/sbin/infiproxy-module-update --update <id>

## 10. Panel update failed

    sudo cat /etc/infiproxy-update.conf
    sudo systemctl status infiproxy-panel-update.service --no-pager --full
    sudo journalctl -u infiproxy-panel-update.service -n 200 --no-pager
    sudo tail -n 200 /var/lib/infiproxy-maintenance/panel-update-run.log
    sudo sed -n '1,160p' /var/lib/infiproxy/panel-update-state.env
    sudo sed -n '1,160p' /var/lib/infiproxy-maintenance/panel-update-status.env

Ожидаемый production source:

    REPO=infinitrator/stealthhub-panel
    REF=main

Manual и scheduled paths используют этот файл. SQLite не должен заменять
REPO/REF. Возможные причины: non-fast-forward, build/test/install failure,
backup failure, DB compatibility failure, local /ready failure.

Failed update должен восстановить previous source/config/DB/control binaries.
Сравните:

    sudo git -C /opt/infiproxy/source rev-parse HEAD
    sudo cat /var/lib/infiproxy-maintenance/panel-last-applied.sha

Не меняйте marker вручную.

## 11. TLS runtime not ready

    sudo namei -l /etc/infiproxy-cores/tls/fullchain.pem
    sudo namei -l /etc/infiproxy-cores/tls/privkey.pem
    getent passwd infiproxy-runtime
    getent group infiproxy-runtime
    sudo -u infiproxy-runtime test -r /etc/infiproxy-cores/tls/fullchain.pem
    sudo -u infiproxy-runtime test -r /etc/infiproxy-cores/tls/privkey.pem
    openssl x509 -in /etc/infiproxy-cores/tls/fullchain.pem -noout \
      -subject -issuer -dates

Directory и files должны иметь actual runtime GID, а не просто одинаковую
случайную group. Каждый ancestor symlink target должен быть traversable.
Installer не изменяет ownership/mode symlink target.

Проверьте key match без вывода private key:

    openssl x509 -in /etc/infiproxy-cores/tls/fullchain.pem -pubkey -noout \
      | openssl pkey -pubin -outform DER | sha256sum
    openssl pkey -in /etc/infiproxy-cores/tls/privkey.pem -pubout -outform DER \
      | sha256sum

Hashes должны совпасть.

## 12. Nginx/HTTPS

    sudo nginx -t
    sudo systemctl status nginx.service infiproxy.service --no-pager
    sudo journalctl -u nginx.service -n 100 --no-pager
    curl -i http://127.0.0.1:8080/ready

Local ready + public 502 обычно означает proxy_pass/SELinux/Nginx problem.
Certificate mismatch проверяйте по hostname, SNI, chain и expiry.

Cloudflare DNS-01 token должен иметь только Zone:Read и DNS:Edit для нужной
zone. Не выводите credential file.

## 13. Port/listener problem

    sudo ss -lntup
    sudo systemctl status infiproxy-xray.service \
      infiproxy-sing-box.service infiproxy-hysteria.service \
      infiproxy-tuic.service infiproxy-mihomo.service --no-pager

Сравнивайте network:

- TCP 443 Nginx не конфликтует с UDP 443 Hysteria;
- одинаковый TCP+port или UDP+port конфликтует;
- disabled starter profile не обязан иметь listener;
- listener process должен соответствовать ожидаемому PID/service.

Firewall проверяйте отдельно для IPv4/IPv6 и TCP/UDP. Loopback backend 8080 не
открывайте публично.

## 14. Routing/rule source

YAML provider:

    curl -i https://SUB_HOST/rules/<slug>.yaml

MRS для mixed classical set не поддержан и возвращает 501. Remote source должен
использовать HTTPS public URL, допустимый format и bounded response. Проверяйте
last error/refresh metadata в Routing.

Если generated YAML не проходит Mihomo:

    mihomo -t -f downloaded.yaml

Не передавайте файл третьим лицам: он содержит credentials.

## 15. Configs page

Configs read-only. Отсутствие Save with backup - ожидаемый contract, а не
ошибка permissions. Если file показывает:

| Status | Причина |
|---|---|
| file does not exist yet | Optional config не создан |
| file is larger... | Превышен browser read limit |
| symlinked config paths... | Path traversal hardening |
| path is not a regular file | Directory/device/socket |
| read error | Panel sandbox/permissions |

Изменяйте file через SSH manager, выполняйте native validation и reload.

## 16. Справочник services

| Unit | Identity | Назначение |
|---|---|---|
| infiproxy.service | infiproxy | Web control plane |
| infiproxy-reconcile.service | root oneshot | Desired-state transaction |
| infiproxy-reconcile.path/timer | systemd | Request/recovery scheduling |
| infiproxy-panel-update.service | root oneshot | Panel update |
| infiproxy-panel-update.path/timer | systemd | Immediate/scheduled panel update |
| infiproxy-module-update.service | root oneshot | Runtime lifecycle |
| infiproxy-module-update.path/timer | systemd | Requests/daily auto update |
| infiproxy-{runtime}.service | infiproxy-runtime | Proxy data plane |

## 17. Справочник HTTP routes

| Route | Access | Contract |
|---|---|---|
| /health | Public | Plain liveness |
| /ready | Public | Plain SQLite readiness |
| /admin/setup | Public только до первого admin | Owner creation |
| /admin/login | Public | Login |
| /admin/account | Admin | Password rotation |
| /admin/users* | Admin mutations + CSRF | User lifecycle |
| /admin/settings | Admin; update fields owner | Settings |
| /admin/protocols* | View admin; mutations owner | Profiles |
| /admin/secrets* | Owner | Shared secrets |
| /admin/routing* | View admin; mutations owner | Routing |
| /admin/cores | View admin; lifecycle owner | Modules |
| /admin/system | Admin; uninstall preview owner | Host view |
| /admin/configs | Owner, read-only targets | Config inspection |
| /admin/health | Admin | Detailed health |
| /sub/{token} | Bearer URL | Account |
| /sub/{token}/mihomo.yaml | Bearer URL | Client config |
| /rules/{slug} | Public when enabled | YAML provider |

## 18. Локальная разработка

    export INFIPROXY_SETUP_TOKEN="$(openssl rand -hex 32)"
    INFIPROXY_BIND=127.0.0.1:8080 \
    INFIPROXY_DB='sqlite://./infiproxy.local.sqlite?mode=rwc' \
    INFIPROXY_COOKIE_SECURE=false \
    cargo run -p stealthhub-panel

Не указывайте production DB/config paths локальному process. Внутренние crate
names stealthhub-* остаются package identifiers и не являются именем продукта.

## 19. Безопасный support bundle

Можно передать:

- exact commit SHA;
- sanitized unit state;
- sanitized journal errors;
- OS/kernel/version;
- redacted listener list;
- test command + exit status.

Нельзя передавать:

- subscription URLs/tokens;
- session cookies/setup token;
- UUID/usernames без необходимости;
- shared/server-only secrets;
- TLS private key;
- Cloudflare token;
- generated Mihomo YAML;
- полный env/SQLite/config archive.
