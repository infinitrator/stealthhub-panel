# Маршрутизация и DNS Mihomo

[Назад: proxy-протоколы](06-PROXY-PROTOCOLS) | [К оглавлению](Home) | [Далее: модули](08-MODULES-AND-UPDATES)

## 1. Модель принятия решения

Infiproxy формирует клиентскую политику Mihomo. Решение принимается на устройстве
клиента, а не в firewall VPS:

```text
запрос -> первое совпавшее правило -> stable pool/profile ID -> proxy или DIRECT
```

Правила Mihomo обрабатываются сверху вниз. Узкое `DOMAIN` должно находиться выше
широкого `DOMAIN-SUFFIX`, блокировка выше разрешающего правила, а `MATCH` всегда
должен завершать список. Server runtime только обслуживает transport, который
уже выбрал клиент.

## 2. Что хранится в SQLite

Начиная с миграции schema v3 policy хранится в нормализованных таблицах:

- transport pools и их упорядоченные member selectors;
- inline rules со стабильным ID, priority, condition и target;
- rule sets, опубликованные как удаленные providers.

Миграция добавляет bootstrap policy только при отсутствии строк. Повторный запуск
не перезаписывает операторские данные. Перед обновлением все эти таблицы входят
в штатный SQLite backup.

### Transport pools

Pool превращается в Mihomo `proxy-group`. Поддерживаются `select`, `url-test`,
`fallback` и `load-balance`. Members ссылаются на stable profile ID, role,
другой pool, все доступные profiles, `DIRECT` или `REJECT`.

Перед генерацией выполняется полная проверка: уникальность ID, существование
enabled profile/pool references, отсутствие циклов и непустой итоговый список.
Невалидная policy останавливает выдачу ошибочного YAML вместо тихого fallback.

Текущий экран показывает pools, kind, число selectors, probe URL, interval и
enabled state. Изменение состава pools и inline rules через web UI в этой
ревизии не реализовано; эти секции являются read-only представлением durable
policy. Не редактируйте SQLite вручную.

### Inline policy

Enabled rules сортируются по числовому `priority`, затем компилируются в
`<condition>,<target>`. Target может быть `DIRECT`, `REJECT` или ID enabled pool.
Bootstrap policy содержит direct private networks, `GEOIP,RU` и финальный
`MATCH,MANUAL`; это стартовые строки базы, а не protocol-specific branches в
generator.

## 3. Rule sets

Rule set хранит stable slug, название, описание эффекта, target, enabled flag и
classical payload. В текущем UI можно:

- включить или выключить существующий set;
- выбрать `DIRECT`, `REJECT` или любой enabled transport pool;
- заменить весь payload;
- сохранить изменение с CSRF и owner-проверкой.

Создание, удаление и reorder самих sets через браузер пока не реализованы.
Provider-level target применяется ко всем строкам одного set, поэтому правила с
разными желаемыми targets следует хранить раздельно.

Допустимые строки payload:

```text
# комментарий
DOMAIN,api.example.com
DOMAIN-SUFFIX,example.com
DOMAIN-KEYWORD,example
IP-CIDR,203.0.113.0/24,no-resolve
IP-CIDR6,2001:db8::/32,no-resolve
GEOIP,RU
DST-PORT,443
NETWORK,udp
```

Validator отбрасывает пустые строки и комментарии, запрещает вложенные
`RULE-SET`/`SUB-RULE`, пустой type/value и управляющие конструкции. Он не
заменяет полную семантическую проверку Mihomo: сверяйте типы с
[официальным справочником rules](https://wiki.metacubex.one/en/config/rules/).

## 4. Provider endpoint

Enabled set доступен по `/rules/<slug>.yaml`. Slug выбирается только среди строк
SQLite; произвольный filesystem path не используется. Ответ имеет
`application/yaml; charset=utf-8`, `Cache-Control: public, max-age=300` и
content-derived `ETag`; совпавший `If-None-Match` получает `304 Not Modified`.
Disabled или неизвестный set возвращает `404`.

Формат ответа:

```yaml
payload:
  - DOMAIN-SUFFIX,example.com
  - IP-CIDR,203.0.113.0/24,no-resolve
```

Subscription описывает provider как HTTP/classical/YAML, сохраняет его под
`./rules/<slug>.yaml` и устанавливает refresh interval 3600 секунд. После
изменения server payload существующий клиент применит его при следующем refresh
или после ручного обновления provider.

## 5. Итоговый порядок правил

Generator сначала добавляет enabled rule sets в их сохраненном порядке, затем
enabled inline rules по priority:

```text
RULE-SET,<slug>,<target>
...
GEOIP,RU,DIRECT
IP-CIDR,10.0.0.0/8,no-resolve,DIRECT
...
MATCH,MANUAL
```

Конкретный порядок следует проверять по фактически скачанной subscription, а не
по bootstrap-примеру: сохраненная policy может отличаться.

## 6. DNS policy

Schema v4 хранит DNS policy независимо от transport policy. В Routing доступны:

| Поле | Что делает |
|---|---|
| **Enabled** | Добавляет managed `dns:` block в Mihomo YAML. |
| **Respect routing rules** | Включает `respect-rules`; proxy server resolver разрывает цикл разрешения node hostname. |
| **IPv6 answers** | Разрешает AAAA-ответы в клиентском DNS. Включайте только при рабочем IPv6. |
| **Enhanced mode** | Выбирает `redir-host` или `fake-ip`. |
| **Bootstrap / node resolvers** | IP/URL resolvers для начального разрешения proxy endpoints. |
| **Secure remote resolvers** | Основные resolver endpoints для proxied policy. |
| **Direct resolvers** | Resolver group для rule sets с target `DIRECT`. |

Enabled policy требует непустые bootstrap, remote и direct lists. Разрешены
literal IP, `system` и URL со схемами `https`, `tls`, `quic`, `udp` или `tcp`;
управляющие символы и чрезмерно длинные значения отклоняются.

Generated config использует `default-nameserver`, `nameserver`,
`proxy-server-nameserver`, `direct-nameserver` и `nameserver-policy` для enabled
DIRECT rule sets. Это снижает риск отправить явно proxied lookup в direct DNS,
но отсутствие утечки подтверждается только capture/log проверкой на конкретном
клиенте и в конкретной сети.

Официальные поля: [Mihomo DNS](https://wiki.metacubex.one/en/config/dns/) и
[rule-providers](https://wiki.metacubex.one/en/config/rule-providers/).

## 7. Практический цикл изменения

1. Сделайте SQLite backup или убедитесь, что свежий backup уже проверен.
2. Измените один rule set либо DNS policy за раз.
3. Скачайте `/sub/<token>/mihomo.yaml` и проверьте YAML parser-ом клиента.
4. Откройте каждый referenced `/rules/<slug>.yaml` и убедитесь в HTTP 200.
5. Импортируйте конфиг на один test client и обновите providers.
6. По Mihomo log проверьте matched rule, выбранную group и DNS resolver.
7. Только после проверки раскатывайте subscription остальным пользователям.

Команды быстрой проверки:

```bash
curl -fsS https://panel.example.com/rules/proxy-ai.yaml
curl -fsS https://panel.example.com/sub/TOKEN/mihomo.yaml -o /tmp/infiproxy.yaml
rg -n 'dns:|proxy-groups:|rule-providers:|RULE-SET|MATCH' /tmp/infiproxy.yaml
```

Subscription token является bearer credential: не вставляйте реальный URL в
issue, общий журнал или публичную shell history.
