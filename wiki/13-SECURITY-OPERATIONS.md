# Безопасная эксплуатация

Этот документ описывает реализованные механизмы и остаточные риски ревизии,
указанной в [индексе wiki](Home). Он не является сертификатом, результатом
внешнего penetration test или гарантией отсутствия уязвимостей.

## 1. Модель угроз

При эксплуатации нужно учитывать как минимум следующих противников и ошибки:

| Угроза | Что пытается получить или нарушить |
|---|---|
| Интернет-сканер | Найти публичную панель, health metadata, proxy listeners и слабые credentials. |
| Credential attacker | Подобрать пароль администратора или украсть session cookie. |
| Subscription thief | Получить bearer URL пользователя и использовать его конфигурацию. |
| Compromised admin browser | Отправить разрешенные state-changing запросы и прочитать доступные secrets/configs. |
| Supply-chain attacker | Подменить Git ref, GitHub account, release asset, manifest или build dependency. |
| Malicious/buggy update | Повредить schema, config, binary или unit. |
| Local unprivileged process | Прочитать файлы с избыточными правами или воздействовать на request queue. |
| Operator error | Закрыть SSH, открыть лишний порт, запустить placeholder config или удалить backup. |
| Host compromise | Получить root и все локальные БД, токены, private keys и backups. |

Infiproxy не может защитить данные после полного root-компрометации. Задача
hardening — уменьшить поверхность, ограничить последствия и обеспечить
обнаружение/восстановление.

## 2. Сетевые поверхности

### 2.1. Что публиковать

| Listener | Рекомендация |
|---|---|
| SSH TCP | Разрешить только административным адресам/VPN, использовать ключи. |
| Nginx TCP/443 | Публичный HTTPS панели. |
| Nginx TCP/80 | Только redirect/ACME, если нужен. |
| Proxy TCP/UDP ports | Открывать только реально настроенные protocols. |
| `127.0.0.1:8080` | Не публиковать; backend панели. |

TCP/443 и UDP/443 могут одновременно принадлежать разным процессам: TCP и UDP
— разные transport sockets. Поэтому Nginx TCP/443 и Hysteria UDP/443 не
конфликтуют. Два UDP listeners на одном address/port, напротив, конфликтуют.

Проверка фактической поверхности:

```bash
sudo ss -lntup
sudo nft list ruleset
sudo ufw status verbose
```

Выполняйте внешний scan со своей рабочей станции, а не только с VPS: loopback,
cloud firewall и host firewall дают разный результат.

### 2.2. IPv4 и IPv6

Firewall rule только для IPv4 не закрывает IPv6 listener `[::]`. Для каждого
публичного runtime проверьте обе семьи адресов. Если IPv6 не используется,
лучше явно bind runtime на нужный IPv4, чем полагаться на неочевидный sysctl.

## 3. Аутентификация администратора

### 3.1. Создание владельца

`/admin/setup` доступен только пока таблица admins пуста. Запуск без admin требует
installer-generated `INFIPROXY_SETUP_TOKEN` минимум из 32 символов; POST сравнивает
его constant-time. Username должен иметь 3–64 символа, пароль — минимум 12.
Пароль хешируется Argon2 со случайной salt в одном из двух bounded blocking
workers, чтобы CPU-intensive hashing не блокировал async runtime и не создавал
неограниченное число CPU jobs.

Первый существующий admin определяется как owner не отдельной ролью, а минимальным
`admins.id`.
Owner может менять update policy, запускать module operations и panel update.

> [!WARNING]
> Не публикуйте незавершенную установку в Интернет. Создание первого admin
> выполняется условной атомарной SQLite-вставкой, поэтому конкурентный второй
> запрос не создаст еще одного владельца. SSH tunnel все равно уменьшает
> доступную поверхность во время первичной настройки.

### 3.2. Login protection

Реализовано:

- одинаковая внешняя ошибка для неизвестного username и неверного password;
- dummy Argon2 verification для неизвестного username;
- задержка 500 ms после неуспешного login;
- in-memory rate limit: 5 failures за 15 минут;
- одновременно учитываются normalized username и source IP;
- максимум 2048 rate-limit keys;
- `Retry-After` при блокировке;
- forwarded source принимается только когда прямой peer — loopback reverse proxy.

Ограничения:

- счетчики исчезают при restart панели;
- это не distributed limiter;
- нет MFA/WebAuthn/TOTP;
- нет CAPTCHA и account lock notification;
- нет встроенной интеграции Fail2ban;
- нет UI списка устройств/сессий и выборочного отзыва одной сессии.

В **Account** каждый admin может сменить собственный пароль. Операция требует
текущий пароль и отзывает все его server-side sessions транзакционно.

Поэтому панель не должна быть защищена только формой login. Используйте Nginx
rate limiting, IP allowlist или административный VPN поверх TLS.

## 4. Сессии и CSRF

### 4.1. Session token

- Генерируется 32 случайных bytes из OS CSPRNG.
- В cookie хранится URL-safe Base64 без padding.
- В SQLite хранится SHA-256 token hash, а не сам token.
- Срок сессии — 7 дней.
- Cookie имеет `HttpOnly`, `SameSite=Lax`, `Path=/admin`.
- `Secure` определяется `INFIPROXY_COOKIE_SECURE`.
- Logout удаляет серверную session record и истекает cookie.

`touch_admin_session` обновляет activity metadata, но срок истечения задается при
создании; это не бесконечная sliding session.

Production значение:

```dotenv
INFIPROXY_COOKIE_SECURE=true
```

### 4.2. CSRF

Каждая реализованная authenticated POST form включает token, производный от
session token и domain-separation string. Сервер сравнивает его в constant time.
Неуспех дает HTTP 403.

CSRF защищает от cross-site отправки команды, но не от XSS или захваченной
admin-сессии. Поэтому CSP, отсутствие raw HTML из пользовательского ввода и
изоляция admin browser остаются важными.

## 5. HTTP security headers

Middleware добавляет ко всем ответам:

| Header | Текущее значение | Назначение |
|---|---|---|
| `X-Frame-Options` | `DENY` | Запрещает embedding и clickjacking через frame. |
| `X-Content-Type-Options` | `nosniff` | Отключает MIME sniffing. |
| `Referrer-Policy` | `no-referrer` | Не передает URL как Referer. Особенно важно для subscription tokens в path. |
| `Content-Security-Policy` | `default-src 'none'; style-src 'self'` и узкий allowlist | Нет inline CSS/scripts/connections, запрещены frame ancestors и base URI. |
| `Permissions-Policy` | Camera/mic/geolocation/payment disabled | Отключает ненужные browser capabilities. |
| `Cache-Control` | `no-store, max-age=0` на `/admin*` | Не дает кэшировать admin pages. |

CSP не содержит `'unsafe-inline'`: CSS отдается отдельным same-origin asset.
JavaScript в текущем UI не требуется.

HSTS приложение не добавляет, но generated Nginx template выставляет:

```nginx
add_header Strict-Transport-Security "max-age=31536000" always;
```

Не добавляйте `includeSubDomains`/preload, пока не уверены, что каждый subdomain
работает по HTTPS: ошибочный HSTS трудно быстро отменить в browser caches.

## 6. Авторизация и роли

Модель не является полноценной RBAC.

| Возможность | Owner (минимальный admin ID) | Другой admin record |
|---|---:|---:|
| Login/dashboard | Да | Да |
| Users | Да | Да |
| Protocols и routing mutations | Да | Нет |
| Account/password rotation | Да | Да |
| Secret editor | Да | Нет |
| Configs read-only inspector | Да | Нет |
| System read-only telemetry | Да | Да |
| Uninstall preview | Да | Нет |
| Общие settings | Да | Да |
| Panel update settings/now | Да | Нет |
| Module check/update/install/remove | Да | Нет |

UI штатно создает только первого admin, но дополнительные records могут
появиться через миграцию/ручное администрирование. Они могут управлять users,
общими Settings и собственной account session, но owner-only handlers повторно
проверяют protocol/routing/module/update/secret/config boundaries на сервере.

Остаточные риски:

- owner привязан к минимальному числовому ID, а не неизменяемой role;
- нет granular permissions;
- нет UI инвентаризации/выборочного отзыва sessions;
- нет immutable security audit log действий.

## 7. Публичные HTTP endpoints

| Endpoint | Аутентификация | Содержимое |
|---|---|---|
| `/health` | Нет | Только plain `ok` liveness. |
| `/ready` | Нет | Только plain SQLite readiness и HTTP 200/503. |
| `/sub/<token>` | Bearer token в URL | Страница подписки пользователя. |
| `/sub/<token>/mihomo.yaml` | Bearer token в URL | Полный клиентский config и credentials. |
| `/rules/<name>` | Нет | Enabled rule-provider payload. |
| `/admin/login` | Нет | Login form. |
| `/admin/setup` | Нет до первого admin | First-owner setup. |

### 7.1. Health metadata

Публичные `/health` и `/ready` не выполняют content negotiation и не раскрывают
OS, paths или service state. Подробный `/admin/health` требует admin session.

```bash
curl -H 'Accept: */*' https://panel.example.com/health
curl -H 'Accept: */*' https://panel.example.com/ready
```

Liveness проверяет process; readiness — SQLite. Ни один из них не доказывает
работоспособность proxy data plane.

### 7.2. Subscription URLs

Subscription token является bearer credential. Любой, кто получил URL, может
загрузить UUID/password/key material до reset/disable/expiry пользователя.

Риски утечки:

- browser history и clipboard;
- messenger preview и URL scanner;
- Nginx access log;
- reverse-proxy/CDN logs;
- monitoring traces;
- screenshot или support bundle.

`Referrer-Policy: no-referrer` уменьшает утечку в следующие сайты, но не убирает
URL из server logs. Не пересылайте subscription URL через открытые каналы.
После подозрения нажмите **Reset token** и при необходимости отключите user.

## 8. Secrets at rest

SQLite панели содержит subscription tokens и `secret_values` без прикладного
шифрования. Proxy configs также содержат passwords/UUID/private-key paths.
Защита основана на правах файловой системы и безопасности root host.

Минимальные меры:

1. Ограничьте SSH и root access.
2. Не давайте backup archives mode шире `0600`.
3. Шифруйте backup до вывоза.
4. Не помещайте production secrets в Git.
5. Не вставляйте secrets в issue, CI log или support output.
6. После компрометации ротируйте не только admin password, но и subscription
   tokens, proxy credentials, REALITY keys, TLS keys и
   Cloudflare token.

Cloudflare token сохраняется root-only mode `0600`, что правильно. Он должен
иметь доступ только к одной DNS-zone и только `Zone:Read`, `DNS:Edit`.

## 9. Разделение привилегий

### 9.1. Panel unit hardening

Панель работает как system user без login shell. Unit включает:

- `NoNewPrivileges=true`;
- `PrivateTmp=true`;
- `ProtectHome=true`;
- `ProtectSystem=strict`;
- `LockPersonality=true`;
- `MemoryDenyWriteExecute=true`;
- ограниченный `ReadWritePaths`.

Это заметно уменьшает последствия web-компрометации. Единственный
`ReadWritePaths` panel unit - `/var/lib/infiproxy`; каталоги runtime,
Nginx, SSH, root manifests и server-only secrets web-процессу недоступны для
записи. Страница Configs в текущем release является allowlisted read-only
inspector. Runtime configs меняет root reconciler или оператор через SSH.

Proxy units работают отдельной identity `infiproxy-runtime:infiproxy-runtime`.
Пользователь panel не входит в runtime group. Это не дает захваченной web
session читать TLS private key через group permissions.

### 9.2. Root workers

Web-процесс не выполняет module update напрямую. Он создает файл
строго заданного типа в request directory. systemd path unit запускает root
worker, который:

- заново валидирует module ID/request schema;
- отклоняет symlink, небезопасный owner/mode и oversized request;
- читает root-owned manifests;
- не принимает произвольную shell command из web form;
- использует lock от конкурентных updater instances;
- сохраняет status/result в ограниченном формате.

Сохраняйте ownership manifest directories `root:root`. Если пользователь
`infiproxy` сможет менять active manifest, граница доверия будет нарушена.

## 10. Supply-chain обновлений

### 10.1. Panel updater

Panel updater работает как root, делает `git fetch`, переключается на настроенный
`REPO@REF`, собирает Rust workspace и запускает installer. Это означает, что
компрометация GitHub repository/ref или dependency supply chain равна root code
execution на VPS.

Updater запрещает non-fast-forward переход от установленного commit по умолчанию,
но это защищает от случайного force-push, а не от компрометации разрешенной ветки.

Текущая реализация не проверяет:

- cryptographic signature Git commit/tag;
- release attestation/provenance;
- заранее утвержденный commit allowlist;
- reproducible-build digest установленного panel binary.

Production меры:

1. Защитите GitHub account hardware-backed MFA/passkey.
2. Включите branch protection и запрет force-push.
3. Используйте reviewed repository или собственный read-only mirror.
4. Сначала включайте только update notifications/checks.
5. Автоматическое применение разрешайте после CI и staging проверки.
6. Перед ручным update сравнивайте полный SHA, а не только первые 12 symbols.
7. Храните off-host backup, который updater не может удалить.

Установка `curl | sudo bash` удобна, но исполняет сетевой ответ как root. Более
строгий bootstrap: скачать script, проверить commit/signature из доверенного
канала, изучить его и только затем выполнить.

### 10.2. Runtime modules

Release modules используют manifest allowlist, platform asset selection,
upstream digest/checksum, HTTPS-only download, лимиты 512 MiB для download, 1 GiB
и 4096 entries для извлечения, smoke test и атомарный symlink.
Если обязательный digest отсутствует/null или не совпадает, установка должна
останавливаться fail closed.

Generic manifest import выполняйте только для официального проекта после review
manifest и systemd unit. Проверки unit уменьшают риск, но не делают неизвестный
binary доверенным.

## 11. Nginx, Cloudflare и TLS

### 11.1. TLS boundary

Panel backend говорит HTTP только на loopback. TLS завершается в Nginx. Поэтому:

- `X-Forwarded-Proto` должен быть `https`;
- backend port нельзя открыть firewall;
- certificate renewal нужно мониторить;
- Nginx validation должна предшествовать reload;
- административный и proxy hostnames лучше разделять.

### 11.2. Cloudflare modes

Panel hostname можно проксировать через Cloudflare, если это совместимо с вашей
моделью доверия. Proxy listeners не следует направлять через административный
HTTP virtual host.

DNS-01 позволяет выдать certificate без временного публичного HTTP challenge,
но API token становится ключом изменения DNS. Не показывайте его в terminal
recording и ротируйте после подозрения на утечку.

## 12. Proxy и mesh security

### 12.1. Клиентские и серверные значения

Перед выдачей subscription сверяйте:

- protocol и transport;
- host/port;
- UUID/password;
- SNI/server name;
- ALPN;
- REALITY public key/short ID;
- Hysteria/TUIC TLS hostname;
- certificate validity;
- firewall и UDP/TCP family.

Placeholder или имя secret, попавшее в YAML, является ошибкой конфигурации.

## 13. Logging и мониторинг

Минимально мониторьте:

| Сигнал | Условие тревоги |
|---|---|
| `/ready` | HTTP не 200 больше двух последовательных checks. |
| `infiproxy.service` | Restart loop или failed. |
| Updater services | Любой failed result. |
| Module services | Failed/inactive для ожидаемо enabled module. |
| Certificate | Менее 14–21 дней до expiry. |
| Disk | 80% warning, 90% critical с учетом вашей емкости. |
| Memory/load | Устойчивое давление, а не единичный spike. |
| SSH/login | Необычные source IP и серия failures. |
| Git/module version | Неожиданное изменение вне maintenance window. |

Встроенного append-only audit log административных кнопок нет. Journal и Nginx
access logs полезны, но не считаются tamper-proof после root compromise.

При сборе logs удаляйте:

- `/sub/<token>` paths;
- proxy passwords и UUID;
- Cloudflare token;
- TLS private keys;
- session cookie.

## 14. Incident response

### 14.1. Подозрение на admin-session compromise

1. Ограничьте Nginx/firewall административным IP или отключите public panel host.
2. Сохраните volatile evidence: time, connections, processes, journal, Nginx logs.
3. Остановите panel, если продолжаются state changes.
4. Сбросьте admin credentials и завершите все sessions через контролируемую DB-процедуру.
5. Сбросьте subscription tokens затронутых users.
6. Проверьте protocol profiles, routes, configs, manifests и updater source.
7. Сравните binaries/configs с доверенным backup и commit.
8. Возобновляйте сервис только после определения масштаба.

### 14.2. Подозрение на root compromise

Не пытайтесь считать host снова доверенным простой сменой пароля.

1. Изолируйте VPS в provider firewall.
2. Снимите forensic snapshot, если это разрешено вашей политикой.
3. Разверните чистый host из trusted image.
4. Восстановите только проверенные данные, не неизвестные binaries/scripts.
5. Ротируйте все credentials и private keys.
6. Замените Cloudflare token и проверьте DNS history.
7. Переключите DNS только после внешней проверки нового host.

## 15. Известные ограничения текущей ревизии

| Приоритет | Ограничение | Компенсация |
|---|---|---|
| Высокий | Root panel updater доверяет mutable Git ref без commit signature/attestation. | Protected branch, reviewed mirror, staging и manual approval. |
| Высокий | Нет MFA и полноценной RBAC; высокорисковые protocol/routing/module/update/secret actions ограничены owner, но обычные admins управляют users и общими Settings. | Один owner, network allowlist/VPN, сильный уникальный пароль. |
| Высокий | Secrets хранятся локально без application-level encryption. | Host hardening, строгие permissions, encrypted off-host backup. |
| Средний | Нет immutable admin audit trail и session management UI. | Central journal shipping, минимальное число admins. |
| Средний | Subscription URL — bearer secret в path. | TLS, log redaction, secure delivery, reset on leak. |
| Средний | Нет scheduled off-host backup. | Настроить restic/borg/другой внешний job. |
| Средний | Reconciler синхронизирует поддерживаемые server identities, но не доказывает реальный внешний handshake и не может индивидуально отозвать shared credentials. | Count-only drift checks, secret rotation и end-to-end canary. |
| Низкий/функциональный | Traffic quota хранится, но collector runtime usage отсутствует. | Внешний collector или ручной учет; не обещать enforcement. |

## 16. Hardening checklist перед production

- [ ] Первый owner создан через SSH tunnel до public exposure.
- [ ] Уникальный пароль длиннее минимальных 12 символов хранится в password manager.
- [ ] `INFIPROXY_BIND=127.0.0.1:8080`.
- [ ] `INFIPROXY_COOKIE_SECURE=true`.
- [ ] Панель доступна только по valid HTTPS.
- [ ] Monitoring использует публичные plain `/health` и `/ready`; detailed health требует login.
- [ ] SSH работает по ключам и ограничен firewall/VPN.
- [ ] IPv4 и IPv6 firewall проверены внешним scan.
- [ ] Открыты только фактически используемые runtime ports.
- [ ] Все starter placeholders заменены.
- [ ] Mihomo profile совпадает с server inbound.
- [ ] Cloudflare token ограничен одной zone и mode `0600`.
- [ ] Automatic panel update включен только после выбора trust policy.
- [ ] Module checksums/digests и smoke tests проходят.
- [ ] Daily encrypted off-host backup настроен и test restore выполнен.
- [ ] Certificate expiry, disk, readiness и failed units мониторятся.
- [ ] Recovery SSH/provider console проверена.

## 17. Первичные рекомендации

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [systemd.exec sandboxing](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [Cloudflare API token security](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)

## 18. Связанные разделы

- [Архитектура](02-ARCHITECTURE-AND-NETWORKING)
- [Модули и обновления](08-MODULES-AND-UPDATES)
- [System и TUI](10-SYSTEM-AND-TUI)
- [Backup и удаление](12-BACKUP-RESTORE-UNINSTALL)
- [Диагностика](14-TROUBLESHOOTING-AND-REFERENCE)
