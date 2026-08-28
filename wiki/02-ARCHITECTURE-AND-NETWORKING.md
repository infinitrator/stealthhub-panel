# Архитектура и основы сетей

[Назад: быстрый старт](01-QUICK-START) | [К оглавлению](Home) | [Далее: веб-интерфейс](03-WEB-INTERFACE)

## Модель Infiproxy

Infiproxy состоит из трех слоев:

```text
Mihomo client
    |
    | HTTPS: subscription and rule-provider
    v
Nginx -> Infiproxy panel -> SQLite
                              |
                              | request files / state files
                              v
                         root maintenance workers
                              |
                              v
              registered proxy runtimes / MTProxy
```

- **Control plane**: панель, SQLite, TUI, manifests, updater и systemd. Он решает,
  что настроено и какой runtime должен работать.
- **Data plane**: отдельные proxy-процессы и клиент Mihomo. Здесь идут реальные
  пакеты пользователя.
- **Distribution plane**: HTTPS subscription URL и rule-provider. Он переносит
  клиентскую конфигурацию из панели в Mihomo.

Ошибка control plane не обязательно обрывает уже установленные соединения
runtime. И наоборот, зеленая панель не доказывает, что data plane настроен.

## Что происходит при открытии сайта через Mihomo

Упрощенный путь:

1. приложение просит ОС разрешить домен через DNS;
2. Mihomo перехватывает запрос локальным proxy/TUN-механизмом клиента;
3. правила выбирают `DIRECT`, `REJECT` или одну из proxy groups;
4. proxy group выбирает конкретный профиль;
5. Mihomo устанавливает TCP или QUIC/UDP-соединение с VPS;
6. внешний runtime аутентифицирует клиента;
7. runtime открывает соединение от VPS к целевому сайту;
8. ответ возвращается по тому же логическому пути.

`DIRECT` означает выход с сети клиентского устройства. Proxy-профиль означает
выход с IP VPS. `REJECT` прекращает запрос локально.

## IP-адреса, подсети и маршруты

### IPv4 и IPv6

IPv4 — 32-битный адрес, например `203.0.113.10`. IPv6 — 128-битный, например
`2001:db8::10`. DNS A содержит IPv4, AAAA — IPv6.

Если hostname имеет A и AAAA, клиент может выбрать IPv6. Поэтому сломанный IPv6
на VPS способен проявляться как нестабильные GitHub downloads или подключения,
хотя IPv4 работает. `INFIPROXY_FORCE_IPV4=true` предусмотрен только как обход
для module updater, а не как постоянная замена исправлению IPv6.

### CIDR

CIDR описывает сеть и длину префикса:

- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — private IPv4;
- `127.0.0.0/8` — loopback;
- `100.64.0.0/10` — shared address space, не являющийся обычной private-сетью;
- `::1/128` — IPv6 loopback;
- `fd00::/8` — IPv6 unique local.

Чем больше число после `/`, тем меньше сеть. Один IPv4-хост — `/32`, один
IPv6-хост — `/128`.

### Routing table

Таблица маршрутов ОС решает, через какой интерфейс и gateway отправить пакет.
IP Check запускает `ip route get <IP>` и показывает именно локальный выбор
сервера. Это не traceroute и не проверка маршрута со смартфона.

## Порты и сокеты

Порт — 16-битное число `1..65535`, но сокет задается как минимум транспортом,
локальным IP и портом:

```text
127.0.0.1:8080/tcp
0.0.0.0:443/tcp
0.0.0.0:443/udp
```

`0.0.0.0`/`[::]` означает listener на внешних интерфейсах. `127.0.0.1`/`::1`
доступен только на самом сервере. Поэтому backend панели безопасно держать на
loopback, а публиковать через Nginx.

Проверка:

```bash
sudo ss -lntup
```

- `-l` — listening;
- `-n` — числа без DNS;
- `-t` — TCP;
- `-u` — UDP;
- `-p` — процесс.

## TCP и UDP

### TCP

TCP устанавливает соединение, гарантирует порядок байтов, повторяет потерянные
сегменты и управляет потоком. Его удобно использовать для веба и большинства
proxy-транспортов. Потеря одного сегмента задерживает последующие данные этого
TCP-потока — явление часто называют head-of-line blocking.

### UDP

UDP передает независимые datagram без встроенной доставки и порядка. Это
уменьшает базовый overhead и позволяет приложению самому выбрать стратегию
потерь. QUIC работает поверх UDP, но добавляет шифрование, streams,
retransmission и congestion control в user space.

Firewall должен отдельно разрешать `443/tcp` и `443/udp`. Открытый TCP-порт не
помогает Hysteria2 на UDP.

## QUIC и HTTP/3

QUIC стандартизован в [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) и
использует TLS 1.3 внутри транспорта. HTTP/3 работает поверх QUIC
([RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)).

Практические свойства:

- несколько независимых streams в одном QUIC connection;
- потеря пакета одного stream не обязана блокировать другие streams;
- connection migration может пережить смену клиентского IP;
- congestion control реализован runtime, поэтому цена CPU выше TCP kernel path;
- некоторые сети режут UDP/QUIC целиком.

Hysteria2 и TUIC хороши как speed/fallback transport, но не должны быть
единственным вариантом там, где UDP часто блокируется.

## DNS

DNS переводит hostname в IP и участвует в маршрутизации сильнее, чем кажется.

- **A/AAAA** указывают адрес origin;
- **PTR** связывает IP с reverse hostname и настраивается владельцем IP;
- **TTL** определяет время кеширования записи;
- **split DNS** может давать разные ответы внутри и снаружи сети;
Subscription host должен резолвиться у клиента, а node host — приводить к
правильному proxy endpoint.

Проверка:

```bash
dig +short A panel.example.com
dig +short AAAA panel.example.com
dig +short -x 203.0.113.10
```

## TLS, сертификаты, SNI и ALPN

### TLS

TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) аутентифицирует
сервер сертификатом, согласует ключи и шифрует канал. Сертификат должен быть
действителен по времени, цепочке доверия и hostname.

### SNI

SNI передает имя виртуального хоста во время TLS handshake. Nginx по SNI
выбирает сертификат/site. В proxy-профилях поле `server` отвечает, куда
соединяться, а `SNI`/`servername` — какое имя предъявить TLS-слою. Эти значения
могут различаться, но должны соответствовать выбранной серверной схеме.

### ALPN

ALPN согласует application protocol внутри TLS/QUIC: например `h2`,
`http/1.1`, `h3`. Если клиент и сервер не имеют общего ALPN, handshake может
завершиться ошибкой. Infiproxy генерирует `h3` для Hysteria2 и TUIC.

### DNS-01

Let's Encrypt DNS-01 подтверждает контроль домена временной TXT-записью. Это
позволяет выдать сертификат, даже если port 80 недоступен. Root-TUI использует
Certbot Cloudflare plugin и scoped API token.

## Reverse proxy

Nginx принимает публичный HTTPS, завершает TLS и пересылает HTTP на loopback:

```text
Internet -> 443/tcp Nginx -> 127.0.0.1:8080 Infiproxy
```

Плюсы:

- Rust-панель не получает private key сертификата напрямую;
- один IP/443 обслуживает разные hostname;
- origin listener не доступен извне;
- конфиг можно проверить `nginx -t` перед reload.

## Firewall и NAT

### Firewall

Firewall решает, какие входящие/исходящие packets разрешить. Принцип:

1. разрешить established/related;
2. разрешить SSH с доверенных адресов, если возможно;
3. разрешить `80/tcp`, `443/tcp` для Nginx;
4. разрешить только порты включенных proxy-runtime;
5. не публиковать `8080` и MTProto stats;
6. запретить остальное входящее.

Веб-страница только показывает команды проверки firewall. Reload и изменение
ruleset выполняются через root SSH-TUI или вручную после peer review.

### NAT

NAT сопоставляет внутренние и внешние адреса/порты. Для VPS с прямым публичным
IP обычно достаточно firewall. Для домашнего сервера нужен port forwarding, а
CGNAT может исключить прямой входящий доступ.

## Подписка и rule-provider

Subscription — публичный tokenized URL, возвращающий полный Mihomo YAML.
Rule-provider — отдельный YAML с массивом правил. Mihomo периодически скачивает
их и применяет через `RULE-SET`.

Плюс этой схемы: правила можно поменять в панели без перевыдачи основной ссылки.
Риск: possession subscription token дает доступ к профилю. Поэтому URL нужно
считать credential, а после утечки использовать **Reset token**.

## Три разных вида секретов

Не смешивайте:

1. **Admin password** — только вход в панель, в БД хранится Argon2 hash.
2. **Subscription token** — bearer-ссылка пользователя; в текущей БД хранится
   как значение, потому что нужен URL.
3. **Protocol secret** — REALITY public key/short ID, UUID/password клиента;
   лежит в `secret_values` и подставляется в YAML.

Server private key, TLS private key и Cloudflare token не должны попадать в
Mihomo subscription. REALITY **public** key передается клиенту, private key
остается только в Xray server config.

## Модель отказов

| Симптом | Вероятный слой |
|---|---|
| `/health` недоступен | панель/listener/systemd |
| `/health` ok, `/ready` 503 | SQLite/permissions |
| панель работает, subscription 404 | token/user state |
| YAML скачан, profile не подключается | server config/secret/port/firewall |
| TCP profile работает, Hysteria/TUIC нет | UDP/QUIC/firewall/ALPN |
| update downloaded, service rolled back | new binary/config incompatibility |

Именно поэтому проверка должна идти слой за слоем, а не одной кнопкой Health.
