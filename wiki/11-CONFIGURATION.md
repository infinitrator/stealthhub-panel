# Конфигурация

[Назад: System и TUI](10-SYSTEM-AND-TUI) | [К оглавлению](Home) |
[Далее: backup и uninstall](12-BACKUP-RESTORE-UNINSTALL)

## 1. Три источника состояния

| Слой | Источник истины | Примеры |
|---|---|---|
| Control plane | SQLite | admins, users, profiles, routing, settings, generations |
| Root policy | Root-owned files | update source, manifests, server-only secrets, systemd |
| Applied data plane | Generated configs + journal | runtime JSON/YAML, active services/listeners |

Ручное изменение generated runtime config не изменяет desired state и может
быть заменено следующим reconcile. Для поддерживаемых adapters изменяйте
profiles/secrets в соответствующем control surface, затем ждите Applied.

## 2. Web Configs

URL: /admin/configs, owner-only.

Страница читает только allowlisted regular UTF-8 files:

| Slug/type | Path | Limit | Web write |
|---|---|---:|---|
| panel-env | /etc/infiproxy/infiproxy.env | 16 KiB | Нет |
| nginx-site | /etc/nginx/sites-available/infiproxy.conf | 64 KiB | Нет |
| ssh-daemon | /etc/ssh/sshd_config | 64 KiB | Нет |
| active module config | manifest-declared path | 256 KiB | Нет |

В текущем release все ConfigFileSpec имеют editable=false. Content textarea
read-only, кнопка Save with backup не рендерится. POST route дополнительно
проверяет owner, CSRF, allowlist и editable flag, поэтому подстановка slug/path
не превращает его в editor.

Страница отклоняет:

- symlink в любом компоненте path;
- directory/device/socket вместо regular file;
- файл больше лимита;
- non-UTF-8 content;
- неизвестный slug.

Изменение root configs выполняйте через sudo infiproxy-manager или
контролируемый SSH editor с backup, native validation и rollback.

## 3. Panel environment

Путь:

    /etc/infiproxy/infiproxy.env

| Variable | Default | Значение |
|---|---|---|
| INFIPROXY_BIND | 127.0.0.1:8080 | Backend listener; оставляйте loopback за Nginx |
| INFIPROXY_DB | sqlite:///var/lib/infiproxy/infiproxy.sqlite?mode=rwc | SQLite URL |
| INFIPROXY_DB_MAX_CONNECTIONS | 2 | Небольшой pool для слабого VPS |
| INFIPROXY_COOKIE_SECURE | true | Secure flag admin cookie |
| INFIPROXY_SETUP_TOKEN | generated 64 hex | First-admin bootstrap secret |
| INFIPROXY_CURRENT_COMMIT | installer value | Diagnostic build/source value |
| RUST_LOG | stealthhub_panel=info,tower_http=info | Logging filter по internal crate name |

Authoritative deployed SHA - root marker:

    /var/lib/infiproxy-maintenance/panel-last-applied.sha

INFIPROXY_CURRENT_COMMIT не должен перекрывать marker при определении current
update status.

После изменения env:

    sudo systemctl restart infiproxy.service
    sudo systemctl status infiproxy.service --no-pager
    curl -fsS http://127.0.0.1:8080/ready

Не ставьте COOKIE_SECURE=false при доступе через публичную сеть. Для локальной
разработки это допустимо только на loopback.

## 4. SQLite

Путь production:

    /var/lib/infiproxy/infiproxy.sqlite

WAL и foreign_keys включены connection options. Не копируйте только main file
при работающем процессе. Используйте .backup:

    sudo -u infiproxy sqlite3 /var/lib/infiproxy/infiproxy.sqlite +      ".backup '/var/backups/infiproxy/manual.sqlite'"

Не храните SQL passwords/tokens в shell history. Не редактируйте generations,
adapter_state или schema_migrations вручную.

## 5. Panel settings в SQLite

UI Settings управляет:

| Key | Назначение |
|---|---|
| panel_name | Client metadata/UI name |
| subscription_domain | Public host для /sub и /rules |
| node_domain | Profile endpoint/infrastructure readiness |
| panel_update_enabled | Scheduled panel apply policy |
| panel_update_time | Local server HH:MM |
| panel_update_hour | Compatibility mirror derived from time |

Root update source не хранится здесь. REPO/REF берутся из:

    /etc/infiproxy-update.conf

Fresh install:

    REPO=infinitrator/stealthhub-panel
    REF=main

Non-main ref возможен только через explicit operator override. Manual и
automatic updater используют один файл.

## 6. Module manifests

    /etc/infiproxy-modules.d
    /etc/infiproxy-modules.available.d

Manifest - declarative key=value, не shell. Он задает stable ID, display
metadata, GitHub repo/tag, driver, root, binary, systemd service, config path и
architecture asset templates.

Installed manifests должны быть:

- root-owned regular files;
- не symlink;
- не group/world-writable;
- bounded;
- валидны native Rust helper.

Проверка:

    sudo /usr/local/libexec/infiproxy-module-manifest +      list /etc/infiproxy-modules.d --root-owned

Не редактируйте active manifest для обхода exact pin. Импорт нового generic
manifest - root supply-chain decision через SSH manager.

## 7. Runtime layout

| Runtime | Binary | Config | Unit |
|---|---|---|---|
| Xray | /opt/infiproxy/cores/xray/current/xray | /etc/infiproxy-cores/xray/config.json | infiproxy-xray.service |
| sing-box | /opt/infiproxy/cores/sing-box/current/sing-box | /etc/infiproxy-cores/sing-box/config.json | infiproxy-sing-box.service |
| Hysteria | /opt/infiproxy/cores/hysteria/current/hysteria | /etc/infiproxy-cores/hysteria/config.yaml | infiproxy-hysteria.service |
| TUIC | /opt/infiproxy/cores/tuic/current/tuic-server | /etc/infiproxy-cores/tuic/config.json | infiproxy-tuic.service |
| Mihomo | /opt/infiproxy/cores/mihomo/current/mihomo | /etc/infiproxy-cores/mihomo/config.yaml | infiproxy-mihomo.service |

Module updater меняет versioned binary/current symlink и сохраняет config.
Reconciler меняет complete config и управляет activation. Не смешивайте эти
transactions.

Native validation:

    sudo /opt/infiproxy/cores/xray/current/xray run -test +      -config /etc/infiproxy-cores/xray/config.json
    sudo /opt/infiproxy/cores/sing-box/current/sing-box check +      -c /etc/infiproxy-cores/sing-box/config.json
    sudo /opt/infiproxy/cores/mihomo/current/mihomo -t +      -f /etc/infiproxy-cores/mihomo/config.yaml

Hysteria/TUIC adapters выполняют structural validation и isolated startup
smoke tests в compatibility gate; production readiness дополнительно проверяет
service/listener и реальный canary.

## 8. TLS runtime pair

Fixed paths:

    /etc/infiproxy-cores/tls/fullchain.pem
    /etc/infiproxy-cores/tls/privkey.pem

Expected identity/modes:

| Object | Owner/group | Mode contract |
|---|---|---|
| tls directory | root:infiproxy-runtime | безопасный, group read+traverse, no writes/other |
| certificate | root:infiproxy-runtime | group read, no unsafe writes |
| private key | root:infiproxy-runtime | group read, no other access, no unsafe writes |

Readiness independently resolves actual infiproxy-runtime uid/gid. Совпадение
file/directory с одинаковой, но неверной group не принимается.

Symlink разрешен только к regular target. Installer не chown/chmod target
symlink, а readiness проверяет metadata resolved target и effective traversal
всех ancestors. Certificate проверяется openssl: parse, hostname, expiry и
public key match с private key.

## 9. Secret references

Shared values:

    SQLite table secret_values

Server-only values:

    /etc/infiproxy/secrets.d/<reference>

Root-only file должен быть regular, root-owned, максимум 8192 bytes и mode без
group/other access. Reconciler не пишет value в logs/journal.

Legacy server-only value можно однократно перенести через SSH manager:

    sudo /usr/local/libexec/infiproxy-reconcile +      --adopt-server-secret xray.reality.private_key

Helper принимает только reference, который protocol adapter классифицирует как
server-only, сверяет значения, пишет root file и удаляет SQLite copy.

## 10. Nginx

Panel backend остается HTTP на loopback. Nginx завершает TLS и проксирует к:

    http://127.0.0.1:8080

Проверка перед reload:

    sudo nginx -t
    sudo systemctl reload nginx.service

Admin и subscription hostnames могут иметь разные sites. Не направляйте proxy
TCP/UDP listeners через admin HTTP vhost, если protocol этого не поддерживает.

SSH manager может:

- создать/обновить Cloudflare A record;
- сохранить scoped API token mode 0600;
- выдать certificate Certbot DNS-01;
- записать panel HTTPS site;
- проверить nginx -t и восстановить previous file при failure.

## 11. Routing и rule providers

Routing state находится в normalized SQLite tables. Не редактируйте generated
Mihomo YAML вручную: он собирается на каждый subscription request.

Public provider:

    https://SUBSCRIPTION_HOST/rules/<slug>.yaml

MRS для mixed classical sets не реализован и возвращает 501. Используйте YAML.

Remote rule sources поддерживают bounded HTTPS fetch, allowlisted formats и
scheduled refresh. URL к private/loopback destination должен fail closed.

## 12. Ownership после install

| Path | Owner/group | Mode |
|---|---|---:|
| /etc/infiproxy | root:infiproxy | 0750 |
| /etc/infiproxy/infiproxy.env | root:infiproxy | 0660 |
| /etc/infiproxy/secrets.d | root:root | 0700 |
| /var/lib/infiproxy | infiproxy:infiproxy | 0750 |
| /var/lib/infiproxy-maintenance | root:root | 0751 |
| reconcile transaction dirs | root:root | 0700 |
| /etc/infiproxy-modules.d | root:root | 0755 |
| /opt/infiproxy/cores | root:root | 0755 |
| /etc/infiproxy-cores | root:infiproxy-runtime | 0750 |
| runtime config files | root:infiproxy-runtime | 0640 |
| /var/log/infiproxy-cores | infiproxy-runtime:infiproxy-runtime | 0750 |

Panel user не добавляется в runtime group. Ручной chown root configs на
infiproxy ломает privilege boundary.

## 13. Безопасный цикл изменения

1. Зафиксируйте SHA, generation, unit/listener state.
2. Сделайте SQLite и config backup.
3. Измените один логический параметр.
4. Выполните parser/native validation.
5. Примените через соответствующий control surface.
6. Дождитесь Applied или доказанного rollback.
7. Проверьте /ready, service и listener.
8. Выполните внешний client handshake.
9. Только после canary включайте следующий change.

Production-oriented настройка: loopback bind, valid HTTPS, exact runtime pins,
minimum enabled profiles, module auto-update opt-in после staging, encrypted
off-host backup.

Допустимый тест: SSH tunnel, один temporary user, один stable profile, manual
updates и отсутствие публичного admin port.
