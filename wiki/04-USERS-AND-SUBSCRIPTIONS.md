# Пользователи и подписки

[Назад: веб-интерфейс](03-WEB-INTERFACE) | [К оглавлению](Home) | [Далее: профили Mihomo](05-MIHOMO-PROFILES)

## Что означает пользователь Infiproxy

User — запись, определяющая доступ к общей генерируемой Mihomo-конфигурации.
Она содержит:

| Поле | Назначение |
|---|---|
| `id` | Внутренний SQLite identifier. |
| `username` | Уникальная operator label. |
| `uuid` | Уникальный client identifier, используемый там, где generator подставляет user UUID. |
| `subscription_token` | Секретная bearer-часть публичного URL. |
| `enabled` | Ручная блокировка/разблокировка. |
| `traffic_limit_bytes` | Опциональный лимит. |
| `traffic_used_bytes` | Сохраненный счетчик. |
| `expires_at` | Опциональный UTC timestamp окончания. |

Для adapters с индивидуальной identity (сейчас VLESS и TUIC) user входит в
generated server authorization и меняется атомарно вместе с runtime. Протоколы
с общим password не получают отдельную server identity на каждого user.

## Создание

В **Users -> Create user**:

### Username

Используйте техническое имя, не реальное ФИО:

```text
alice-phone
lab-laptop-01
test-24h
```

Одна запись удобнее на одно устройство: тогда reset/revoke не затрагивает все
устройства человека.

### Traffic limit, GB

- пусто — unlimited;
- `0` — unlimited;
- положительное число — переводится в bytes и сохраняется как limit.

> [!WARNING]
> В текущей ревизии нет встроенного collector, который опрашивает runtime и
> увеличивает `traffic_used_bytes`. Ограничение применяется к значению в БД, но
> само по себе не обеспечивает реальный accounting. Не продавайте quota как
> гарантированную до интеграции проверенного accounting source.

### Expires in days

- пусто/`0` — без expiration;
- `1..3650` — `expires_at = now UTC + days`.

Срок рассчитывается в момент создания. GUI не содержит изменения срока
существующего user.

### Create

Кнопка создает UUID и random subscription token криптографическим RNG, затем
возвращает в список. Token не выбирается оператором.

## Таблица пользователей

### Enabled

- `on` — ручная блокировка снята;
- `off` — subscription заблокирована;
- даже при `on` expiry или quota может блокировать выдачу.

### UUID

UUID стабилен при reset subscription token. Удаление user удаляет UUID из панели.
Нельзя считать UUID секретом уровня пароля, но он является credential для
VLESS/TUIC-схем, если сервер использует тот же UUID.

### Subscription

Есть два URL:

```text
/sub/<token>
/sub/<token>/mihomo.yaml
```

Первый — human-friendly account page, второй — raw client config.

### Traffic и Expires

Показывается сохраненное `used / limit` и formatted expiration. Это snapshot
SQLite, а не live counter ядра.

## Кнопки управления

### open

Открывает публичную account page. Это useful preview, но URL в browser history и
server access log может содержать token. Не демонстрируйте экран публично.

### download

Возвращает raw YAML. Ответ помечен `no-store`, содержит `Subscription-Userinfo`
и должен считаться секретным.

### Disable

Сразу ставит `enabled=false`. После этого:

- account page показывает block reason;
- import/download недоступен;
- уже загруженная конфигурация на клиенте не стирается;
- participating adapters удаляют user из нового runtime candidate; shared
  protocol password остается действительным для ранее скачанного клиента.

Для shared-password протокола полноценный revoke требует rotation общего
secret, что затронет всех использующих его клиентов.

### Enable

Ставит `enabled=true`. Если срок истек или `used >= limit`, subscription останется
заблокированной по соответствующей причине.

### Reset token

Первая кнопка открывает confirmation. Вторая генерирует новый bearer token.

Reset нужен при:

- утечке URL;
- потере устройства;
- попадании token в screenshot/chat/log;
- передаче подписки другому устройству по ошибке.

Reset не меняет UUID и server protocol secrets. Старый URL немедленно перестает
выдаваться панелью, но локально сохраненный YAML продолжает работать до revoke
server credentials.

### Delete

Удаляет SQLite user и token после confirmation. Действие необратимо через GUI.
Оно создает desired generation; participating adapters удаляют identity только
после успешного `Applied`. Shared password отдельно не вращается.

## Публичная account page

### Status

Возможные причины блокировки:

- account disabled;
- account expired;
- traffic limit reached.

При active доступны:

| Кнопка/поле | Назначение |
|---|---|
| **Import** | Открывает `clash://install-config?url=...`; результат зависит от client app/OS. |
| **Download YAML** | Загружает raw Mihomo config. |
| Subscription URL | Read-only URL для ручного добавления provider. |
| One-click import URL | Read-only Clash scheme. |

Если браузер не знает `clash://`, используйте Download или вставьте HTTPS URL в
Mihomo-compatible client вручную.

## HTTP contract подписки

### Успех

- status `200`;
- YAML с proxy objects, groups, providers и rules;
- `Cache-Control: no-store`;
- `Subscription-Userinfo` с upload/download/total/expire.

### Ошибки

| Условие | Результат |
|---|---|
| Неверный token | `401 Unauthorized`. |
| Disabled/expired/quota | subscription не выдается, account page показывает причину. |
| Database/generation error | server error, подробность в panel journal. |

## Mihomo import: рекомендуемый порядок

1. Откройте account page на доверенном устройстве.
2. Скачайте YAML и проверьте его текстом.
3. Убедитесь, что endpoint, ports, SNI, UUID и secrets совпадают с server config.
4. Импортируйте через HTTPS URL, чтобы клиент мог обновлять subscription.
5. Установите разумный update interval в самом client, если он это предлагает.
6. Проверьте группу `MANUAL`, затем `AUTO-SAFE` и `SPEED`.
7. Проверьте DNS, TCP и UDP отдельно.
8. Не пересылайте URL в незащищенном чате.

## Идеальная модель выдачи

- отдельный user/token на устройство;
- короткий expiry для временных тестов;
- отдельный server credential на user/device, если runtime поддерживает;
- disable + server revoke при потере;
- reset token после любой возможной утечки;
- accounting source атомарно обновляет `traffic_used_bytes`;
- audit log связывает выдачу и revoke с operator.

## Допустимая модель для личного теста

- один user на владельца;
- unlimited quota;
- HTTPS subscription;
- ручной revoke в server config при потере устройства;
- еженедельный просмотр списка и удаление тестовых записей.

## Проверка token без раскрытия в shell history

Предпочтительно нажать `download` в браузере. Если нужен curl, передайте URL
через защищенный prompt:

```bash
read -r -s -p 'Subscription URL: ' SUB_URL; echo
curl --fail --silent --show-error "$SUB_URL" -o /tmp/mihomo.yaml
unset SUB_URL
chmod 0600 /tmp/mihomo.yaml
```

Не помещайте полный tokenized URL в issue, Git commit, публичный monitoring
dashboard или shared shell history.

## Backup пользователей

Users, UUID, tokens, settings, routing и secret values находятся в SQLite:

```text
/var/lib/infiproxy/infiproxy.sqlite
```

Копируйте ее согласованно через SQLite `.backup`, а не обычным `cp` работающего
WAL-файла. Процедура приведена в
[Бэкапах и восстановлении](12-BACKUP-RESTORE-UNINSTALL).
