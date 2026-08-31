# Пользователи и подписки

[Назад: веб-интерфейс](03-WEB-INTERFACE) | [К оглавлению](Home) |
[Далее: профили](05-PROTOCOL-PROFILES-AND-RUNTIMES)

## 1. Модель пользователя

Одна запись users содержит:

| Поле | Семантика |
|---|---|
| id | Внутренний SQLite ID |
| username | Уникальная operator label |
| uuid | Случайный UUID v4 для per-user protocols |
| subscription_token | Отдельный случайный bearer token для HTTP URL |
| enabled | Разрешена ли выдача subscription и участие в desired runtime |
| traffic_limit_bytes | Optional сохраненный limit |
| traffic_used_bytes | Сохраненное значение usage, default 0 |
| expires_at | Optional UTC expiry |
| created_at / updated_at | Audit metadata, не immutable audit log |

UUID и subscription token - разные credentials. Reset token не меняет UUID.
Удаление и повторное создание user дает новые значения.

## 2. Создание

На странице Users:

### Username

- trim перед записью;
- длина 3-64 символа;
- разрешены ASCII letters/digits, dot, underscore и hyphen;
- уникален.

Не помещайте email, phone или другие персональные данные без необходимости:
username попадает в operator UI и может участвовать в client labels.

### Traffic limit, GB

Пустое значение означает unlimited metadata. Число переводится в bytes.

**Ограничение beta:** Infiproxy не собирает live traffic из runtimes, не
увеличивает traffic_used_bytes и не блокирует data plane по quota. Effective
subscription check сравнивает stored used/limit, но при неизменяемом used=0 это
не является реальным enforcement. Используйте внешний collector только после
отдельного review его доверия и точности.

### Expires in days

Пустое значение означает отсутствие expiry. Число 0 также не создает expiry;
положительное значение до 3650 сохраняет UTC deadline.

Текущий UI не редактирует limit/expiry после create. Для изменения нужна
контролируемая schema-aware операция, которой web release пока не предоставляет.
Не правьте production SQLite без backup и согласованного transaction plan.

### Create

Create:

1. валидирует форму;
2. генерирует UUID v4 и 32-hex subscription token;
3. вставляет enabled row с used=0;
4. увеличивает desired generation;
5. будит reconciler.

Если enabled profiles используют PerUserUuid, server config должен получить
новую identity только после успешного apply.

## 3. Effective access

Account page и Mihomo YAML блокируются, если:

- enabled=false;
- expires_at уже наступил;
- stored traffic_used_bytes >= traffic_limit_bytes.

Проверка выполняется при каждом HTTP запросе. Она не отключает уже открытое
соединение и не доказывает runtime-side revoke.

HTTP contract:

| Endpoint | Успех | Ошибка |
|---|---|---|
| /sub/{token} | Account HTML | invalid page / blocked status |
| /sub/{token}/mihomo.yaml | YAML + Subscription-Userinfo | 401 invalid, 403 blocked, 503 incomplete config |

Responses используют no-store/no-cache и Referrer-Policy no-referrer, но bearer
token все равно может попасть в browser history, clipboard, reverse-proxy logs
или screenshot.

## 4. Кнопки Users

### open

Открывает account page. Она показывает status, traffic metadata, expiry,
subscription URL и Mihomo import link.

### download

Запрашивает свежий YAML. Generation включает только enabled profiles, которые:

- имеют установленный protocol adapter;
- имеют доступную core capability;
- проходят adapter config/secret validation;
- могут быть собраны с текущей routing/DNS policy.

Если обязательная конфигурация неполна, endpoint возвращает 503 вместо частично
опасного YAML.

### Disable

- enabled становится false;
- новые subscription requests дают 403;
- desired generation увеличивается;
- PerUserUuid adapters удаляют identity при успешном reconcile.

Disable не удаляет row/token/UUID и может быть отменен кнопкой Enable.

### Enable

Возвращает user в desired set и запускает reconcile. До Applied server
authorization может еще не совпадать с intent.

### Reset token

Открывает confirm page, затем атомарно меняет только subscription_token. Старый
URL перестает находить user немедленно. Generation не увеличивается, потому что
server identity и UUID не меняются.

Reset token не отзывает:

- уже импортированный YAML;
- UUID в active runtime;
- shared passwords;
- текущие proxy connections.

При утечке client credentials ротируйте соответствующие secrets/UUID через
поддерживаемый lifecycle, а не ограничивайтесь token reset.

### Delete

Confirm page показывает UUID, URL и traffic metadata. Delete:

- удаляет users row;
- инвалидирует subscription token;
- увеличивает desired generation;
- удаляет per-user identity после успешного reconcile.

SharedCredential protocol не умеет индивидуально удалить знание общего пароля.

## 5. User participation в protocol adapters

| Режим | Примеры | Revoke semantics |
|---|---|---|
| PerUserUuid | VLESS, TUIC, Trojan, Mieru | Identity должна исчезнуть из live config |
| SharedCredential | Hysteria2, SS2022/ShadowTLS, AnyTLS, Snell | Нужна общая ротация для server-side revoke |
| None | Infrastructure resources | Users не участвуют |

Core adapter после apply наблюдает поддерживаемые live user sets. В SQLite
runtime_user_sync сохраняются только counts, а не identities.

## 6. Mihomo subscription

Server собирает документ на каждый запрос:

1. ищет user по token;
2. проверяет effective access;
3. загружает Settings, profiles, secrets, rule sets, client и DNS policy;
4. собирает capabilities реально установленных runtimes;
5. protocol adapters создают proxy objects;
6. policy resolver создает groups/rules;
7. результат сериализуется в YAML.

Заголовок Subscription-Userinfo содержит upload=0, download=stored usage,
optional total и expire. Это compatibility metadata, а не подтвержденная
runtime статистика.

Generated YAML может содержать UUID и shared secrets. Считайте его секретом.

## 7. Cache и logging

Приложение выставляет:

- Content-Type application/yaml;
- Cache-Control no-cache, no-store, must-revalidate;
- Referrer-Policy no-referrer через middleware.

Оператор reverse proxy должен дополнительно:

- не логировать полный /sub/{token} path либо редактировать token;
- не кэшировать subscription responses;
- не отправлять path в внешнюю analytics;
- использовать valid HTTPS;
- ограничить доступ к admin host.

## 8. Рекомендуемая выдача

1. Создайте временного user.
2. Дождитесь Applied и InSync для per-user profile.
3. Откройте account page по HTTPS.
4. Передайте URL через защищенный канал.
5. Импортируйте Mihomo YAML.
6. Проверьте DNS, TCP/UDP handshake и routing.
7. После подозрения на URL leak нажмите Reset token.
8. После credential leak ротируйте protocol credential и повторно примените
   runtime state.

Не публикуйте token в issue, shell history или screenshots.

## 9. Backup и восстановление

Users, token, UUID, profiles и shared secrets находятся в panel SQLite:

    /var/lib/infiproxy/infiproxy.sqlite

Для online backup используйте SQLite .backup, а не копирование одного main file
при активном WAL:

    backup=/var/backups/infiproxy/manual-$(date -u +%Y%m%dT%H%M%SZ)
    sudo install -d -o root -g root -m 0700 "$backup"
    sudo -u infiproxy sqlite3 /var/lib/infiproxy/infiproxy.sqlite +      ".backup '$backup/infiproxy.sqlite'"
    sudo chmod 0600 "$backup/infiproxy.sqlite"
    sudo sqlite3 "$backup/infiproxy.sqlite" 'PRAGMA integrity_check;'

Результат integrity_check должен быть ok. Храните копию off-host в
зашифрованном виде. Полная процедура:
[Backup, restore и uninstall](12-BACKUP-RESTORE-UNINSTALL).

## 10. Текущие ограничения

- Нет UI edit для username, UUID, limit или expiry.
- Нет live traffic collector/quota enforcement.
- Нет массовой ротации subscription tokens.
- Нет отдельной pause-until даты.
- Нет API tokens/scopes для автоматизации user lifecycle.
- Нет per-user revoke у shared-credential protocols.
- Нет доказательства client usage или последнего успешного proxy handshake.
- Нет immutable admin audit trail.

Эти ограничения документируются явно и не должны маскироваться значениями,
которые просто присутствуют в SQLite.
