# Профили Mihomo

[Назад: пользователи](04-USERS-AND-SUBSCRIPTIONS.md) | [К оглавлению](Home.md) | [Далее: proxy-протоколы](06-PROXY-PROTOCOLS.md)

## Назначение вкладки Protocols

Вкладка хранит шаблоны `proxies:` для клиентского Mihomo YAML. Каждый profile
содержит kind, role, endpoint и ссылки на секреты. При запросе подписки generator
берет UUID конкретного Infiproxy user и подставляет нужные secret values.

Она **не** выполняет:

- создание inbound в Xray/sing-box/Hysteria/TUIC;
- добавление user в server config;
- выдачу TLS/REALITY private keys;
- проверку открытого порта;
- restart systemd unit;
- end-to-end test.

## Общая схема генерации

```text
Panel Settings
  subscription_domain + node_domain
             |
Protocol profiles + secret_values + routing sets + subscription user UUID
             |
             v
       Mihomo YAML document
             |
             v
        Mihomo client
```

Только profiles с `enabled=true` попадают в YAML.

> [!CAUTION]
> Если enabled profiles нет, generator завершает запрос статусом `503` и не
> выдает YAML. Точно так же он поступает при отсутствии обязательного секрета.
> Это намеренный fail-closed контракт: сначала согласуйте клиентский profile с
> реально работающим server inbound, затем включайте его.

## Глобальные поля YAML

При наличии enabled profiles generator устанавливает:

| Поле | Значение | Смысл |
|---|---|---|
| `mixed-port` | `7890` | Локальный mixed listener клиента. |
| `allow-lan` | `false` | Другие устройства LAN не могут использовать client listener. |
| `mode` | `rule` | Трафик идет через rule engine. |
| `log-level` | `info` | Клиентский уровень журнала. |
| `ipv6` | `false` | IPv6 отключен в generated config. |
| `external-controller` | `127.0.0.1:9090` | API Mihomo доступен только loopback клиента. |

Локальные приложения Mihomo могут переопределять/сливать эти поля в зависимости
от способа импорта. Проверяйте итоговый effective config в клиенте.

## Профили по умолчанию

| Name | Kind | Role | Default | Endpoint | Required secret names |
|---|---|---|---|---|---|
| `VLESS-XHTTP-SAFE` | VLESS + REALITY + XHTTP | AUTO-SAFE | disabled | `node.infiproxy.local:8443` | `xray.reality.public_key`, `xray.reality.short_id` |
| `VLESS-REALITY-TCP-FALLBACK` | VLESS + REALITY + TCP/RAW | COMPAT | disabled | `node.infiproxy.local:7443` | `xray.reality.public_key`, `xray.reality.short_id` |
| `SS2022-SHADOWTLS-FALLBACK` | SS2022 + ShadowTLS v3 | COMPAT | disabled | `node.infiproxy.local:9443` | `shadowsocks.2022.password`, `shadowtls.password` |
| `ANYTLS-EXPERIMENTAL` | AnyTLS | COMPAT | disabled | `node.infiproxy.local:10443` | `anytls.password` |
| `HYSTERIA2-SPEED` | Hysteria2 | SPEED | disabled | `node.infiproxy.local:443/udp` | `hysteria2.password`, optional `hysteria2.obfs_password` |
| `TUIC-SPEED` | TUIC | SPEED | disabled | `node.infiproxy.local:11443/udp` | `tuic.password` |

При первом запуске все шесть profiles выключены. Повторный запуск или обновление
добавляет отсутствующие встроенные records через `ON CONFLICT DO NOTHING` и не
перезаписывает уже измененные endpoint, параметры или switch. GUI редактирует
встроенные records, но в beta не создает произвольные новые виды profile.

## Общие поля редактора

### Enabled

Определяет только включение объекта в generated YAML. Switch не проверяет
secret badge, runtime или firewall.

### Server address

Публичный hostname или IP, к которому подключится Mihomo. Обычно это значение
должно совпадать с **Node host** и DNS A/AAAA, но profile можно направить на
другой узел.

Если используете hostname:

- A/AAAA должны вести к VPS;
- client должен уметь разрешить DNS до подключения;
- значение не обязано равняться SNI, но схема сервера должна это допускать.

### Server port

Remote port. Он должен совпасть с listening inbound и firewall. Для Hysteria2 и
TUIC нужен UDP; для VLESS/ShadowTLS/AnyTLS обычно TCP.

### Secret name

Поле содержит **ключ**, например `tuic.password`, а не пароль. Generator ищет
это имя в SQLite `secret_values`.

- badge `present/ready` — строка с таким именем существует;
- badge `missing` — значения нет;
- секретное значение GUI никогда не показывает.

Если lookup не найден или значение пустое, generator завершает subscription
request ошибкой `503`. Имя (`tuic.password`) и placeholder никогда не попадают в
выдаваемый YAML. Поэтому `missing` все равно нужно устранить до включения profile.

## Как безопасно добавить secret value

Откройте owner-only вкладку **Secrets**:

1. Введите ровно то имя, которое выбрано в Protocols.
2. Вставьте client-side credential. Не сохраняйте server private key или TLS
   private key, если клиенту нужен только public key/password.
3. Нажмите **Store secret**. Повторное сохранение имени выполняет rotation.
4. Вернитесь в Protocols и убедитесь, что badge стал `present`.
5. Скачайте subscription и проверьте ее отдельным тестовым клиентом.

Значение не возвращается браузеру после POST. Удаление требует набрать точное
имя; enabled profile без значения немедленно становится fail-closed.

### Аварийное восстановление через SQLite

Прямой доступ к БД нужен только если web owner-session недоступна. Сначала
остановите панель или сделайте согласованный SQLite backup.

#### 1. Сделайте согласованный backup

```bash
sudo -u infiproxy sqlite3 /var/lib/infiproxy/infiproxy.sqlite \
  ".backup '/var/lib/infiproxy/pre-secret-edit.sqlite'"
sudo chmod 0600 /var/lib/infiproxy/pre-secret-edit.sqlite
```

#### 2. Откройте SQLite без history

```bash
sudo -u infiproxy env SQLITE_HISTORY=/dev/null \
  sqlite3 /var/lib/infiproxy/infiproxy.sqlite
```

#### 3. Выполните parameterized upsert

В prompt `sqlite>`:

```sql
.parameter init
.parameter set @name 'xray.reality.public_key'
.parameter set @value 'ACTUAL_PUBLIC_KEY'
INSERT INTO secret_values(name, value, created_at, updated_at)
VALUES(
  @name,
  @value,
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
)
ON CONFLICT(name) DO UPDATE SET
  value = excluded.value,
  updated_at = excluded.updated_at;
.parameter clear
.quit
```

Повторите с каждым именем. Не вставляйте server private key или TLS private key:
клиенту нужны только соответствующие public/client credentials.

#### 4. Проверьте только имена

```bash
sudo -u infiproxy sqlite3 /var/lib/infiproxy/infiproxy.sqlite \
  'SELECT name, updated_at FROM secret_values ORDER BY name;'
```

Не выводите колонку `value` в shared terminal/log. Значения лежат в SQLite в
открытом виде и попадают в backups, поэтому права и шифрование backup обязательны.

## VLESS + REALITY + XHTTP

Generated object включает:

| Mihomo field | Источник |
|---|---|
| `server`, `port` | Profile endpoint. |
| `uuid` | UUID конкретного subscription user. |
| `tls: true` | Фиксировано generator. |
| `servername` | **TLS server name**. |
| `client-fingerprint: chrome` | Фиксировано. |
| `reality-opts.public-key` | Secret value public key. |
| `reality-opts.short-id` | Secret value short ID. |
| `network: xhttp` | Kind profile. |
| `xhttp-opts.path` | **XHTTP path**. |
| `xhttp-opts.host` | Массив с server name. |

Server Xray должен иметь совместимые user UUID, REALITY private/public pair,
short ID, target/serverNames и XHTTP path. Public key, переданный клиенту,
получается из server private key, но private key в панельный secret store не
кладется.

Официальные поля: [Mihomo VLESS](https://wiki.metacubex.one/en/config/proxies/vless/),
[Mihomo XHTTP](https://wiki.metacubex.one/en/config/proxies/transport/) и
[Xray REALITY](https://xtls.github.io/en/config/transports/reality.html).

## VLESS + REALITY + TCP

Generated object аналогичен, но без `network/xhttp-opts`; Mihomo использует
обычный TCP/RAW transport. Это проще по количеству параметров, но kind должен
существовать в SQLite до редактирования через GUI.

Не пытайтесь превратить XHTTP default в TCP удалением path: kind сериализован
отдельно и не меняется формой.

## SS2022 + ShadowTLS v3

Generated object:

- `type: ss`;
- cipher фиксирован `2022-blake3-aes-256-gcm`;
- SS password берется из `shadowsocks.2022.password`;
- plugin `shadow-tls`, version 3;
- plugin host из **ShadowTLS server name**;
- отдельный ShadowTLS password из `shadowtls.password`;
- `udp: true`.

Оба пароля должны совпасть с server chain. SS2022 key для AES-256-GCM должен
иметь формат/длину, требуемую installed sing-box; официальный generator:

```bash
/opt/infiproxy/cores/sing-box/current/sing-box generate rand --base64 32
```

ShadowTLS password независим от SS key. Подмена одного другим нарушает слои.

## Hysteria2

Generated object:

- `type: hysteria2`;
- endpoint по UDP;
- auth password из `hysteria2.password`;
- SNI;
- `alpn: [h3]`;
- при непустом optional secret name добавляется Salamander obfs.

Default profile содержит имя `hysteria2.obfs_password`, поэтому после включения
generator добавит obfs. Starter Hysteria server config obfs не содержит. Выберите
один согласованный вариант:

1. добавьте Salamander с тем же password в server config и secret store;
2. очистите **Salamander obfs secret** в profile и не используйте obfs.

Неверный obfs password обычно выглядит как timeout, а не явная auth error.

## AnyTLS

Generated object включает password, SNI, `client-fingerprint: chrome`, `udp:
true`. Server sing-box должен иметь AnyTLS inbound с тем же password и TLS
certificate. AnyTLS появился в sing-box 1.12, поэтому перед включением проверьте
installed version и поддержку client Mihomo.

`udp: true` на клиентском object не превращает underlying AnyTLS TCP listener в
QUIC; это разрешение проксировать UDP-сессии механизмом протокола.

## TUIC

Generated object:

- `type: tuic`;
- `uuid` конкретного subscription user;
- общий password из `tuic.password`;
- SNI и `alpn: [h3]`;
- endpoint по UDP.

Starter TUIC config содержит `"users": {}`. Для каждого Infiproxy user, которому
выдается profile, server map должен содержать его UUID и password. Автоматической
синхронизации нет.

## Roles и proxy groups

Role profile нельзя изменить в GUI. Он определяет, в какие группы попадает имя.

| Role | Группа |
|---|---|
| `AutoSafe` | `AUTO-SAFE`, `FAILOVER`, `BALANCE` |
| `Compatibility` | Те же auto-safe groups |
| `Speed` | `SPEED` |
| `RuAccess` | `RU-ACCESS` |
| `Manual` | Только общий `MANUAL` через список всех proxies |

Если специализированная role group пуста, generator подставляет все enabled
profiles как fallback.

### MANUAL

Ручной select: `AUTO-SAFE`, `FAILOVER`, `BALANCE`, `SPEED`, `RU-ACCESS`, все
profile names и `DIRECT`.

### AUTO-SAFE

`url-test` к `https://www.gstatic.com/generate_204`, interval 300 s, tolerance
50 ms. Выбирает доступный endpoint с учетом latency, но не доказывает корректную
маршрутизацию всех сайтов.

### FAILOVER

`fallback`, health interval 120 s. Переключается при недоступности текущего.

### BALANCE

`load-balance`, `round-robin`, interval 180 s. Разные connections могут выходить
с разных profiles; это нежелательно для stateful/banking sessions.

### SPEED

Ручной select profiles с role Speed и `DIRECT`. Если Speed-профилей нет,
использует auto-safe list плюс Direct.

### RU-ACCESS

Ручной select profiles с role RuAccess и `DIRECT`; default profiles этой role нет.

## Проверка generated YAML

```bash
read -r -s -p 'Subscription URL: ' SUB_URL; echo
curl -fsS "$SUB_URL" -o /tmp/infiproxy-mihomo.yaml
unset SUB_URL
chmod 0600 /tmp/infiproxy-mihomo.yaml
```

Проверьте placeholders и default hosts:

```bash
rg -n 'REPLACE_WITH_|infiproxy\.local|\.password|\.public_key|\.short_id' \
  /tmp/infiproxy-mihomo.yaml
```

Пустой вывод ожидаем только если реальные значения не совпадают случайно с
этими шаблонами. Затем выполните config test тем Mihomo binary/version, который
реально использует клиент.

## Рекомендуемый профиль

- один TCP profile `AutoSafe`;
- один UDP/QUIC profile `Speed`;
- оба проверены end-to-end;
- unused defaults disabled;
- `MANUAL` используется для диагностики;
- `BALANCE` не выбран для сервисов с session/IP binding;
- subscription проверена на отсутствие placeholders после каждого изменения.

## Изолированная приемочная проверка

- один enabled profile;
- остальные disabled;
- UUID одного временного пользователя внесен server-side;
- shared password хранится только в core config, SQLite и защищенном client;
- ручной connectivity test после restart.
