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
| created_at / updated_at | Временные метки user row; отдельная история находится в `audit_events` |

UUID и subscription token - разные credentials. **Reset subscription URL** не
меняет UUID. Удаление и повторное создание user дает новые значения.

`users` остается источником истины. Таблица `user_lifecycle_state` хранит только
производный checkpoint: какие blocking reasons уже наблюдались и какой
generation еще ожидает публикации bounded reconcile request. Ее строки
самовосстанавливаются из `users`, удаляются каскадно и входят в обычный SQLite
backup.

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

**Ограничение beta:** Infiproxy не собирает live traffic из runtimes и сам не
увеличивает traffic_used_bytes. Effective access сравнивает сохраненные
used/limit и исключает quota-blocked identity из per-user desired state, но без
доверенного collector это не является измеренным live quota enforcement.

### Expires in days

Пустое значение означает отсутствие expiry. Число 0 также не создает expiry;
положительное значение до 3650 сохраняет UTC deadline.

После создания кнопка **Edit** позволяет задать или очистить quota и deadline.
Редактор expiry принимает только RFC 3339 UTC (`Z` или `+00:00`) и ограничивает
дату диапазоном 3650 дней от текущего времени. `traffic_used_bytes` показывается
read-only и не принимается из web-формы.

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

Одна core-модель вычисляет три независимых blocking reason. Account page,
Mihomo YAML и per-user desired authorization блокируются, если:

- enabled=false;
- expires_at уже наступил;
- stored traffic_used_bytes >= traffic_limit_bytes.

`expires_at <= now` считается истекшим, то есть граница включительна. Несколько
причин отображаются одновременно, например Disabled + Expired. Проверка
выполняется при каждом HTTP запросе и поэтому не ждет background task.

При старте panel выполняет один self-heal lifecycle checkpoints. Затем каждые
30 секунд индексированный deadline scan обнаруживает crossing, атомарно
увеличивает desired generation один раз и сохраняет pending generation до
успешной публикации reconcile request. Restart и повторный tick не создают
generation storm. Задержка data-plane convergence может составить интервал
проверки плюс время reconcile; уже открытое соединение принудительно не
разрывается.

Автоматический deadline crossing является системным convergence event, а не
административной мутацией, поэтому отдельная запись от имени admin в
`audit_events` не создается. Само изменение generation и его результат видны в
reconcile state/journal.

HTTP contract:

| Endpoint | Успех | Ошибка |
|---|---|---|
| /sub/{token} | Account HTML | invalid page / blocked status |
| /sub/{token}/mihomo.yaml | YAML + Subscription-Userinfo | 401 invalid, 403 blocked, 503 incomplete config |

Responses используют no-store/no-cache и Referrer-Policy no-referrer, но bearer
token все равно может попасть в browser history, clipboard, reverse-proxy logs
или screenshot.

## 4. Кнопки Users

### Subscription access

Открывает отдельную authenticated no-store страницу выдачи. Только там
показываются account URL, Mihomo YAML URL и one-click import. Общий список Users
не содержит UUID, subscription token или bearer path.

### Edit

Редактирует username, quota и expiry одной SQLite transaction. Форма содержит
скрытый `updated_at`; если другой admin уже изменил user, stale submit получает
conflict вместо перезаписи новых данных. Пустые quota/expiry означают unlimited
и never. Username проходит тот же контракт 3-64 ASCII символа, что Create.

Изменение active username создает generation, потому что текущие PerUserUuid
composers используют его как runtime label/name. Если user уже blocked и
остается blocked, одно изменение label generation не создает. Изменение
quota/expiry создает generation только при немедленной смене effective access;
будущий expiry получает отдельную generation при crossing deadline.

### Download через страницу выдачи

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
- desired generation увеличивается, если user до операции был effectively allowed;
- PerUserUuid adapters удаляют identity при успешном reconcile.

Disable не удаляет row/token/UUID и может быть отменен кнопкой Enable.

### Enable

Снимает manual blocking reason. Если expiry/quota продолжают блокировать user,
generation не нужна; иначе user возвращается в desired set и запускается
reconcile. До Applied server authorization может еще не совпадать с intent.

### Reset subscription URL

Открывает confirm page, затем атомарно меняет только subscription_token. Старый
URL перестает находить user немедленно. Generation не увеличивается, потому что
server identity и UUID не меняются.

Reset subscription URL не отзывает:

- уже импортированный YAML;
- UUID в active runtime;
- shared passwords;
- текущие proxy connections.

При утечке client credentials ротируйте соответствующие secrets/UUID через
поддерживаемый lifecycle, а не ограничивайтесь token reset.

### Rotate runtime identity

Confirmation page отправляет только CSRF и ожидаемый `updated_at`. Новый UUID v4
генерируется сервером; браузер не может выбрать его. Операция сохраняет username,
subscription token, quota и expiry, увеличивает generation и пишет
`user.runtime-identity-rotated` без старого/нового UUID в metadata.

Новые subscription documents сразу используют новый UUID. Для PerUserUuid
старый runtime identity перестает быть авторизован только когда новое поколение
получит статус Applied. UUID rotation не влияет на SharedCredential protocols и
не отзывает ранее выданный общий пароль.

### Delete

Confirm page не показывает UUID или bearer URL. Delete:

- удаляет users row;
- инвалидирует subscription token;
- увеличивает desired generation, если user был effectively allowed;
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
3. Нажмите **Subscription access** и откройте account page по HTTPS.
4. Передайте URL через защищенный канал.
5. Импортируйте Mihomo YAML.
6. Проверьте DNS, TCP/UDP handshake и routing.
7. После подозрения на URL leak нажмите **Reset subscription URL**.
8. После утечки per-user UUID нажмите **Rotate runtime identity**, дождитесь
   Applied и выдайте обновленную subscription.
9. После утечки shared credential ротируйте protocol secret и повторно примените
   runtime state для всех затронутых пользователей.

Не публикуйте token в issue, shell history или screenshots.

## 9. Backup и восстановление

Users, token, UUID, lifecycle checkpoints, profiles и shared secrets находятся
в panel SQLite:

    /var/lib/infiproxy/infiproxy.sqlite

Для online backup используйте SQLite .backup, а не копирование одного main file
при активном WAL:

    backup=/var/backups/infiproxy/manual-$(date -u +%Y%m%dT%H%M%SZ)
    sudo install -d -o root -g root -m 0700 "$backup"
    sudo -u infiproxy sqlite3 /var/lib/infiproxy/infiproxy.sqlite \
      ".backup '$backup/infiproxy.sqlite'"
    sudo chmod 0600 "$backup/infiproxy.sqlite"
    sudo sqlite3 "$backup/infiproxy.sqlite" 'PRAGMA integrity_check;'

Результат integrity_check должен быть ok. Храните копию off-host в
зашифрованном виде. Полная процедура:
[Backup, restore и uninstall](12-BACKUP-RESTORE-UNINSTALL).

## 10. Текущие ограничения

- Нет live traffic collector; stored quota gate не доказывает фактический usage.
- Нет массовой ротации subscription tokens.
- Нет отдельной pause-until даты.
- Нет API tokens/scopes для автоматизации user lifecycle.
- Нет per-user revoke у shared-credential protocols.
- Нет доказательства client usage или последнего успешного proxy handshake.
- Owner видит append-only admin audit trail на `/admin/audit`; токены, UUID и
  другие credentials в события не записываются.

Эти ограничения документируются явно и не должны маскироваться значениями,
которые просто присутствуют в SQLite.
