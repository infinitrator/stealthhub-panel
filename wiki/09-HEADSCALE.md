# Headscale mesh hub

[Назад: модули](08-MODULES-AND-UPDATES.md) | [К оглавлению](Home.md) | [Далее: система и TUI](10-SYSTEM-AND-TUI.md)

## Что такое Headscale

Headscale — self-hosted реализация Tailscale coordination server. Он управляет
регистрацией устройств, public keys, policy, DNS и route metadata для одного
tailnet. Data plane остается на Tailscale clients и использует WireGuard.

Это не то же самое, что proxy core:

- Headscale не принимает произвольный browser traffic как VLESS/Hysteria;
- обычные mesh packets идут peer-to-peer, если NAT traversal удался;
- DERP relay используется, когда direct path невозможен;
- full Internet tunnel требует отдельно настроенного exit node;
- доступ к LAN требует subnet router.

Официальное описание: [Headscale](https://headscale.net/stable/) и
[control/data planes](https://tailscale.com/docs/concepts/control-data-planes).

## Infiproxy layout

```text
/opt/infiproxy/modules/headscale/current/headscale
/usr/local/bin/headscale -> current/headscale
/etc/headscale/config.yaml
/var/lib/headscale/db.sqlite
/etc/nginx/sites-available/infiproxy-headscale.conf
headscale.service
```

Local listeners TUI config:

| Endpoint | Bind | Публичность |
|---|---|---|
| Control HTTP | `127.0.0.1:8088` | через Nginx 443 |
| Metrics | `127.0.0.1:9098` | не публиковать |
| gRPC | `127.0.0.1:50443` | не публиковать в default model |
| Unix socket | `/var/run/headscale/headscale.sock` | local/group |

Порт 8088 выбран специально: upstream example 8080 конфликтовал бы с panel.

## Guided Headscale hub setup

TUI: **Advanced tools -> Headscale hub configuration -> Guided Headscale hub
setup** либо соответствующий шаг общего guided cycle.

### Запрашиваемые значения

| Prompt | Пример | Требование |
|---|---|---|
| Public hostname | `hs.example.com` | Отдельный FQDN. |
| MagicDNS base domain | `tailnet.example.com` | Не должен совпадать с public host буквально. |
| Cloudflare zone | `example.com` | Zone, содержащая hostname. |
| Let's Encrypt email | `admin@example.com` | Валидный email. |
| Public IPv4 | `203.0.113.10` | Можно auto-detect. |
| API token | secret | Можно использовать уже сохраненный. |

### Что делает flow

1. устанавливает Nginx/Certbot/Cloudflare plugin;
2. создает **DNS-only** A record;
3. сохраняет API token root-only;
4. получает Let's Encrypt certificate через DNS-01;
5. пишет dedicated Nginx config с upgrade forwarding;
6. ставит/обновляет verified Headscale module;
7. backup-ит и пишет `/etc/headscale/config.yaml`;
8. выполняет `headscale configtest`, если binary доступен;
9. enable/start-ит `headscale.service`;
10. печатает public URL и client command.

## Почему Cloudflare должен быть DNS-only

Headscale/Tailscale protocol требует POST-based WebSocket upgrade. Официальная
[reverse proxy documentation](https://headscale.net/stable/ref/integration/reverse-proxy/)
прямо указывает, что Cloudflare proxy/tunnel эту схему не поддерживает.

Используйте gray cloud. Cloudflare в этой схеме хранит DNS, но client TCP/TLS
соединяется прямо с Nginx VPS.

## Generated Headscale config

### Server URL и trusted proxy

- `server_url: https://hs.example.com`;
- trusted proxies только `127.0.0.1/32` и `::1/128`;
- Nginx передает real/forwarded headers.

Не добавляйте широкие trusted proxy ranges без понимания spoofing риска.

### Address allocation

- IPv4 pool `100.64.0.0/10`;
- IPv6 pool `fd7a:115c:a1e0::/48`;
- sequential allocation.

`100.64/10` — shared space, не public Internet route.

### Database

- SQLite `/var/lib/headscale/db.sqlite`;
- WAL enabled;
- service работает dedicated user `headscale`.

Эта DB не находится внутри panel SQLite и требует отдельного backup.

### DNS

- MagicDNS enabled;
- base domain из prompt;
- override local DNS enabled;
- global resolvers `1.1.1.1`, `1.0.0.1`.

Это стартовая policy, а не универсальный идеал. Для corporate/internal DNS
замените resolvers и split rules согласно вашей инфраструктуре.

### DERP

Embedded DERP server disabled. Config использует default Tailscale DERP map и
обновляет ее каждые 3 часа. Поэтому при неудачном direct path data может пройти
через внешний DERP relay, а не через ваш VPS.

Для полного self-hosted relay нужен отдельный осознанный DERP design, ports и
monitoring; текущий guided flow его не включает.

### Policy

Generated config имеет file policy path пустым. Без explicit restrictive policy
не считайте tailnet zero-trust сегментированным. Официальная документация
различает personal и tagged devices и рекомендует policy/grants.

## Headscale в SSH-TUI

Откройте **Advanced tools -> Headscale hub configuration**.

| Пункт | Что выполняется |
|---|---|
| **Guided Headscale hub setup** | Запрашивает hostname, MagicDNS domain, Cloudflare zone/email/public IPv4/token; устанавливает release, создает DNS-only A record, certificate, YAML и Nginx site, запускает service и предлагает enrollment key. |
| **Install/update verified release** | Передает `headscale` общему module updater. Updater не переписывает config намеренно, но перед version/config canary резервирует YAML и SQLite/state для автоматического rollback. |
| **Write Headscale config** | Запрашивает `https://` server URL и MagicDNS base domain, создает staged YAML и timestamped backup, останавливает active service перед `configtest`, атомарно публикует файл и возвращает старую конфигурацию/service при ошибке. DNS/Nginx/certificate этим пунктом не меняются. |
| **Create user and pre-auth key** | При отсутствии user создает его, запрашивает numeric ID и expiry, затем печатает key и client command. Секрет виден в терминале. |
| **List Headscale users** | Выполняет `headscale -c /etc/headscale/config.yaml users list`. |
| **Validate and restart Headscale** | Вызывает `configtest` и выполняет restart только при exit code 0; при ошибке показывает отказ и сохраняет работающий service. |
| **Headscale logs** | Показывает последние 120 строк `journalctl -u headscale.service`. |

Guided flow принудительно создает Cloudflare DNS-only record, потому что
Headscale не должен находиться за обычным CDN proxy. Он использует отдельные от
панели hostname и localhost backend.

## Web Headscale page

Все state-changing operations owner-only и идут через typed request files.

### Refresh users and nodes

Создает request. Root helper выполняет:

```text
headscale -c /etc/headscale/config.yaml users list
headscale -c /etc/headscale/config.yaml nodes list
```

Snapshot обновляется не синхронно с click. Обновите страницу после worker run.

### Create user

Допустимы ASCII letters/digits, `.`, `_`, `-`, длина 1–63, без `@` и пробела.

User — identity owner для personal nodes, не Linux user и не panel admin.

### Create pre-auth key

| Поле | Значение |
|---|---|
| User ID | Numeric ID из users list. |
| Expiration | `30m`, `24h`, `168h`; максимум четыре digits, unit m/h. |
| Reusable | Один key регистрирует несколько nodes. |
| Ephemeral | Node удаляется/считается временным по Headscale semantics. |

По умолчанию лучше одноразовый, короткоживущий, non-ephemeral key на одно
устройство. Reusable key удобен automation, но увеличивает blast radius утечки.

После создания key находится в `last_result` snapshot. Скопируйте один раз и
нажмите **Clear result**. Snapshot file имеет ограниченные права, но plaintext
secret существует до очистки.

Официальный flow:
[Headscale registration](https://headscale.net/stable/ref/registration/).

### Expire node

`nodes expire --identifier <id>` делает текущую machine identity недействительной
и требует повторной auth. Это не удаляет Tailscale client software и не очищает
его локальные данные.

### Open configuration

Переходит в allowlist Configs. Save не запускает `configtest`; после изменения
используйте root-TUI validate/restart.

## Root control bridge

Panel request dir:

```text
/var/lib/infiproxy/headscale-requests/*.request
```

Worker:

```text
/usr/local/libexec/infiproxy-headscale-control --process
```

Security contract:

- JSON enum с `deny_unknown_fields`;
- request не больше 8 КиБ;
- только regular non-group/world-writable file;
- rename в root-only processing dir перед чтением;
- fixed binary/config paths;
- argv без shell;
- timeout 20 секунд;
- output до 64 КиБ;
- state до 256 КиБ со стороны панели.

## Безопасное обновление версии

Headscale может изменять schema и SQLite во время `configtest`, поэтому обычной
проверки binary недостаточно. Встроенный updater:

1. игнорирует prerelease и выбирает стабильный release;
2. при отставании на несколько minor обновляет только на один minor за цикл;
3. создает root-only backup YAML и state, а SQLite копирует через online
   `.backup`;
4. останавливает ранее active service до canary новой версии;
5. запускает новый binary с текущим config;
6. публикует symlink и возвращает исходный enabled/active state только после
   успеха;
7. при любой ошибке восстанавливает предыдущую версию, config и state.

Контрольный аудит beta проверял generated config официальным Headscale `v0.29.3`.
Это evidence для конкретной версии, а не обещание совместимости с будущими
релизами; перед major update изучайте upstream changelog и делайте off-host copy.

## Регистрация первого client

1. Создайте Headscale user.
2. Получите numeric user ID через Refresh.
3. Создайте short-lived pre-auth key.
4. На client установите официальный Tailscale.
5. Выполните:

```bash
sudo tailscale up \
  --login-server https://hs.example.com \
  --authkey <ONE_TIME_KEY>
```

6. Нажмите Clear result в панели.
7. Refresh users/nodes.
8. С client проверьте `tailscale status` и `tailscale ping <peer>`.

Не помещайте authkey в shell history на shared host. Для automation передавайте
его через protected secret mechanism и уничтожайте после регистрации.

## Subnet router

Subnet router дает mesh доступ к сети, где Tailscale не стоит на каждом host.

На router node:

```bash
sudo tailscale set --advertise-routes=192.168.50.0/24
```

На Headscale server:

```bash
sudo headscale -c /etc/headscale/config.yaml nodes list-routes
sudo headscale -c /etc/headscale/config.yaml nodes approve-routes \
  --identifier <NODE_ID> --routes 192.168.50.0/24
```

На consuming client:

```bash
sudo tailscale set --accept-routes
```

Router OS требует IP forwarding и firewall policy. Маршрут одобряется отдельно:
advertise не равно approve. См.
[Headscale routes](https://headscale.net/latest/ref/routes/).

## Exit node

Exit node отправляет Internet traffic клиента через выбранный mesh node.

На exit node:

```bash
sudo tailscale set --advertise-exit-node
```

На Headscale server одобрите default route, затем на client:

```bash
sudo tailscale set --exit-node <NODE_NAME>
```

Нужны IP forwarding, NAT/firewall и restrictive policy. Exit node — не функция
одной web-кнопки Infiproxy.

## Диагностика

```bash
sudo headscale -c /etc/headscale/config.yaml configtest
sudo systemctl status headscale.service --no-pager
sudo journalctl -u headscale.service -n 160 --no-pager
sudo nginx -t
curl -I https://hs.example.com/
sudo headscale -c /etc/headscale/config.yaml users list
sudo headscale -c /etc/headscale/config.yaml nodes list
```

На client:

```bash
tailscale status
tailscale netcheck
tailscale ping <peer>
```

Если connection идет DERP, это не обязательно ошибка; netcheck объяснит NAT/UDP
conditions. Но постоянный DERP увеличивает latency и зависит от external relay.

## Рекомендуемая настройка

- dedicated DNS-only hostname и valid public certificate;
- one-time short-lived auth keys;
- user per human/ownership boundary;
- tags для service nodes;
- restrictive policy/grants;
- internal/split DNS вместо безусловного public override при необходимости;
- backup Headscale DB, config, noise/private keys;
- direct connectivity и DERP fallback мониторятся отдельно.

## Допустимая lab-настройка

- один user;
- один одноразовый key 24h;
- два nodes;
- default DERP map;
- MagicDNS default;
- без exit/subnet routes;
- ежедневный SQLite/config backup до экспериментов с policy.
