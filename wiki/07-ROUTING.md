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

Schema v8 выполняет bootstrap policy ровно один раз. Обновление и повторный
запуск не восстанавливают удаленные оператором profiles, pools, policies или
rule sets. Перед обновлением все эти таблицы входят в штатный SQLite backup.

### Transport pools

Pool превращается в Mihomo `proxy-group`. Поддерживаются `select`, `url-test`,
`fallback` и `load-balance`. Members ссылаются на stable profile ID, role,
другой pool, все доступные profiles, `DIRECT` или `REJECT`.

Перед генерацией выполняется полная проверка: уникальность ID, существование
enabled profile/pool references, отсутствие циклов и непустой итоговый список.
Невалидная policy останавливает выдачу ошибочного YAML вместо тихого fallback.

Экран позволяет создать, переименовать, включить, выключить и удалить pool,
изменить strategy, priority, selectors, probe URL, interval, timeout, tolerance,
max failures, lazy mode, minimum healthy count, fallback pool и load-balancing
algorithm. Stable ID меняется как rename: все ссылки обновляются транзакционно.
При удалении используйте replacement pool, если на объект ссылаются policies,
rule sets или другие pools; без replacement такое удаление блокируется.

### Inline policy

Enabled rules сортируются по числовому `priority`, затем компилируются в
`<condition>,<target>`. Target может быть `DIRECT`, `REJECT` или ID enabled pool.
Bootstrap policy содержит direct private networks, `GEOIP,RU` и финальный
`MATCH,MANUAL`; это стартовые строки базы, а не protocol-specific branches в
generator.

В блоке **Inline routing policies** доступны create, edit, enable/disable,
rename и delete. Числовой `priority` задает порядок без drag-and-drop. Condition
содержит полное classical-условие без target, например
`DOMAIN-SUFFIX,example.com`; target может быть `DIRECT`, `REJECT`, stable pool
ID, точным profile name или `capability:<protocol-id>`. Dangling references и
невалидные условия отклоняются до commit.

## 3. Rule sets

Rule set хранит stable slug, название, описание эффекта, target, enabled flag и
advanced classical payload. В текущем UI можно:

- создать, изменить, клонировать и удалить произвольный set;
- включить или выключить set;
- выбрать `DIRECT`, `REJECT` или любой enabled transport pool;
- оставить raw classical layer, если нужен неподдержанный GUI-сценарий;
- открыть скомпилированный YAML через **Export / preview YAML**;
- сохранить изменение с CSRF и owner-проверкой.

Provider-level target применяется ко всем строкам одного set, поэтому правила с
разными желаемыми targets следует хранить раздельно.

### Нормализованные entries

Основной режим не требует ручного YAML. Для каждой записи сохраняются stable ID,
enabled state, kind, value, comment, source tag и числовой priority. Поддержаны
`DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `IP-CIDR`, `IP-CIDR6`, `GEOIP`,
`GEOSITE`, `ASN`, `PROCESS-NAME`, `DST-PORT`, `SRC-PORT`, `NETWORK` и
`CLASSICAL`.

| Элемент | Результат |
|---|---|
| **Add normalized entry** | Создает одну проверенную запись. |
| **Edit / Save** | Меняет kind, value, comment, tag, priority и enabled state. |
| **Delete** | Удаляет запись по stable ID. |
| **Import entries** | Добавляет values построчно; в `CLASSICAL` принимает полные правила. |
| **Deduplicate entries** | Удаляет повторения в пределах set, сохраняя первый приоритетный экземпляр. |
| Filter / search | Фильтрует отображение по kind и тексту; для ограничения HTML выводятся первые 200 совпадений. |

Компиляция объединяет enabled normalized entries, локальный advanced layer и
последний успешный cache remote sources. Ошибка нового fetch не уничтожает
проверенный cache.

### Remote data sources

Источник имеет stable ID, HTTPS URL, format, enabled state и refresh interval от
300 до 604800 секунд. Поддержаны plain text, YAML payload и Mihomo classical
provider. **Refresh** запускает немедленную загрузку; background checker обновляет
enabled sources по расписанию и использует ETag/Last-Modified.

Fetcher ограничивает размер и redirects, запрещает credentials в URL, принимает
только HTTPS и отклоняет loopback/private/link-local destination после DNS
проверки. Native Mihomo `mrs` намеренно не генерируется: mixed classical rules
не имеют одного корректного MRS behavior, поэтому endpoint возвращает явный
`501 Unsupported` вместо файла с выдуманной семантикой.

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

Generator сначала добавляет enabled rule sets в стабильном порядке, затем
enabled inline policies по priority:

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
