# Маршрутизация Mihomo

[Назад: proxy-протоколы](06-PROXY-PROTOCOLS) | [К оглавлению](Home) | [Далее: модули](08-MODULES-AND-UPDATES)

## Что маршрутизируется

Routing в Infiproxy формирует клиентские правила Mihomo. Решение принимается на
клиентском устройстве до выбора outbound:

```text
request metadata -> first matching rule -> target group -> selected proxy/DIRECT
```

Server core затем только обслуживает уже выбранный transport. Эти rules не
являются firewall VPS, Xray routing или Headscale policy.

## Принцип first match wins

Mihomo читает rules сверху вниз. Первое совпадение завершает выбор. Поэтому:

- узкий `DOMAIN,api.example.com` ставят выше широкого
  `DOMAIN-SUFFIX,example.com`;
- `REJECT` выше общего proxy rule;
- `MATCH` всегда последний;
- изменение порядка rule sets меняет поведение.

В текущей панели порядок фиксирован порядком default sets в коде.

## Built-in rule sets

### banking-direct

Название: **Banking and government**. Default target `DIRECT`.

Содержит Sberbank, Gazprombank, T-Bank/Tinkoff, VTB, Alfa-Bank, Gosuslugi и
nalog.gov.ru. Цель — сохранять локальный client egress для сервисов, которые
могут реагировать на иностранный/VPS IP.

Список не является юридически/операционно полным и требует проверки перед
production. Банковские CDN/identity domains могут находиться вне него.

### direct-local

Название: **Local and RU**. Default target `DIRECT`.

Содержит `.local`, `.lan`, `.ru`, `.рф` и RFC1918 IPv4 ranges. В generated main
rules private ranges также добавляются отдельно, поэтому часть защиты
дублируется намеренно.

`DOMAIN-SUFFIX,ru` отправляет direct любой `.ru`, а не только российские банки.
Если нужна более строгая модель, удалите широкую строку и оставьте явный allowlist.

### proxy-ai

Название: **AI and development**. Default target `AUTO-SAFE`.

Содержит OpenAI/ChatGPT, Anthropic/Claude и GitHub domains. Некоторые приложения
используют дополнительные CDN/auth/telemetry hostnames; добавляйте их только
после наблюдаемого miss, а не списками неизвестного происхождения.

### streaming

Название: **Streaming**. Default target `SPEED`.

Содержит YouTube/GoogleVideo/YTImg, Netflix и Spotify. `SPEED` — ручная select
group, а не автоматическое измерение bandwidth.

## Элементы редактора

### Enabled

При включении:

1. provider добавляется в `rule-providers` generated YAML;
2. добавляется строка `RULE-SET,<slug>,<target>`;
3. `/rules/<slug>.yaml` начинает отдавать payload.

При выключении endpoint возвращает 404 и set не должен включаться в новую
subscription.

> [!WARNING]
> Не выключайте одновременно все sets в текущей ревизии. Generator fallback-ит
> к default sets, но HTTP endpoints ориентируются на disabled state в SQLite и
> могут вернуть 404. Оставьте хотя бы один enabled set.

### Target group

| Target | Поведение |
|---|---|
| `DIRECT` | Выход из сети client без proxy. |
| `AUTO-SAFE` | URL-test среди AutoSafe/Compatibility profiles. |
| `SPEED` | Ручной выбор speed profile либо fallback/direct. |
| `RU-ACCESS` | Ручной выбор RuAccess profile либо fallback/direct. |
| `MANUAL` | Главная ручная группа со всеми вариантами. |
| `REJECT` | Блокировка request клиентом. |

Target должен существовать в generated config. Эти шесть значений allowlisted.

### Classical payload

Одна rule без target на строку. Target задается целому provider формой.

Примеры:

```text
# Comment
DOMAIN,api.example.com
DOMAIN-SUFFIX,example.com
DOMAIN-KEYWORD,example
IP-CIDR,203.0.113.0/24,no-resolve
IP-CIDR6,2001:db8::/32,no-resolve
GEOIP,RU
DST-PORT,443
NETWORK,udp
```

Panel validation:

- игнорирует blank lines и строки, начинающиеся с `#`;
- требует хотя бы одну data line;
- требует `TYPE,value`;
- отвергает пустой type/value;
- отвергает `RULE-SET` и `SUB-RULE` внутри provider;
- не проверяет семантику каждого Mihomo rule type глубоко.

То есть опечатка `DOMAIN-SUFIX` может пройти простую panel validation, но быть
отвергнута/проигнорирована Mihomo. Сверяйтесь с
[официальным rule reference](https://wiki.metacubex.one/en/config/rules/).

### Save rule set

Сохраняет один set в SQLite после validation. Другие sets не меняются. Уже
скачанный client provider обновится только при следующем interval/manual refresh.

## Формат provider

Endpoint возвращает:

```yaml
payload:
  - DOMAIN-SUFFIX,example.com
  - IP-CIDR,203.0.113.0/24,no-resolve
```

Generated main config описывает provider так:

```yaml
type: http
behavior: classical
format: yaml
path: ./rules/<slug>.yaml
url: https://<subscription-host>/rules/<slug>.yaml
interval: 3600
```

Mihomo кеширует файл в своем home directory. `interval: 3600` означает проверку
раз в час, а не моментальное применение server edit.

Официальные поля: [Mihomo rule-providers](https://wiki.metacubex.one/en/config/rule-providers/).

## Финальный порядок generated rules

```text
RULE-SET,<enabled-set-1>,<target>
RULE-SET,<enabled-set-2>,<target>
...
GEOIP,RU,DIRECT
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
MATCH,MANUAL
```

Следствия:

- domain set может совпасть до GEOIP;
- весь оставшийся RU GeoIP идет Direct;
- private IPv4 идет Direct;
- все остальное попадает в `MANUAL` и зависит от выбора пользователя;
- IPv6 globally disabled generated setting, но IP-CIDR6 provider rules могут
  иметь смысл только после осознанного изменения client config.

## `no-resolve`

У IP rules `no-resolve` запрещает Mihomo инициировать DNS resolution только ради
этого rule. Это уменьшает лишние DNS lookup и риск неожиданного side effect.
Для domain request IP rule без resolution может не совпасть, если IP еще неизвестен.

## Практические сценарии

### Домен всегда Direct

Добавьте в ранний direct set:

```text
DOMAIN-SUFFIX,example.ru
```

Сохраните, скачайте provider вручную, refresh-ните его в client и проверьте
external IP на этом домене.

### Домен всегда через proxy

Добавьте в `proxy-ai` или другой set с `AUTO-SAFE`:

```text
DOMAIN,api.example.com
DOMAIN-SUFFIX,example-cdn.com
```

### Заблокировать tracker

Измените target подходящего set на `REJECT` либо используйте отдельный set, если
он появится в коде. Текущий GUI не создает новые set, поэтому изменение target
существующего set влияет на все его строки.

### UDP через speed profile

Classical rule может использовать `NETWORK,udp`, но provider-level target
применится ко всему set. Не смешивайте domain и network rules с разными
желаемыми targets в одном set.

## Проверка provider до rollout

```bash
curl -fsS https://panel.example.com/rules/proxy-ai.yaml
```

Проверьте HTTP status:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  https://panel.example.com/rules/proxy-ai.yaml
```

Затем в raw subscription проверьте URL и `RULE-SET`:

```bash
rg -n 'rule-providers|RULE-SET|GEOIP|MATCH' /tmp/infiproxy-mihomo.yaml
```

Финальная проверка проводится Mihomo client log: какой rule matched и какая
group выбрана.

## DNS leak и routing

Domain routing корректен только вместе с DNS policy client. Infiproxy generated
config не задает расширенный `dns:` block. Конкретный Mihomo app может добавлять
собственную DNS-конфигурацию.

Для строгой схемы отдельно решите:

- кто резолвит DNS: OS, Mihomo или upstream;
- идут ли DNS requests через proxy;
- нужен ли fake-ip/redir-host;
- как обрабатываются IPv6 и split DNS;
- какие domains должны резолвиться локально для Direct.

Не делайте вывод об отсутствии DNS leak только по совпадению HTTP egress IP.

## Рекомендуемая политика

- rules минимальны и объяснимы;
- broad suffixes используются только осознанно;
- banking и auth flows тестируются отдельно;
- provider changes сначала проверяются одним test client;
- `MATCH` остается `MANUAL`, пока default policy не утверждена;
- route set backup входит в SQLite backup;
- раз в месяц удаляются устаревшие domains.

## Допустимая политика

- default sets без изменений;
- один основной AutoSafe profile;
- ручной выбор `MANUAL`;
- проверка трех контрольных сайтов: Direct, AutoSafe, Speed;
- никакого REJECT до проверки false positives.
