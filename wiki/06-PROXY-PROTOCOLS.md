# Proxy-протоколы и серверные ядра

[Назад: профили Mihomo](05-MIHOMO-PROFILES) | [К оглавлению](Home) | [Далее: маршрутизация](07-ROUTING)

## Перед настройкой

Runtime module — исполняемый файл и systemd unit. Protocol profile — desired
client/server resource. Между ними нет двустороннего импорта ручных файлов, но
поддержанный adapter однонаправленно и атомарно строит runtime config из SQLite.

Для каждого транспорта заполните таблицу соответствия:

| Параметр | Server config | Mihomo profile | Должен совпасть |
|---|---|---|---|
| Public address | listener/firewall/DNS | `server` | да |
| Port и TCP/UDP | listener | `port`/kind | да |
| User identity | clients/users/auth | generated UUID/password | да |
| TLS hostname | cert/REALITY serverNames | SNI/servername | да |
| Transport | inbound method/network | profile kind/path | да |
| Extra obfs | server obfs | client obfs | да |

## Общий production-порядок

```bash
sudo infiproxy-module-update --check <module>
sudo infiproxy-module-update --update <module>
sudo systemctl status <unit> --no-pager
```

После установки:

1. сохраните backup существующего config при миграции;
2. создайте client secrets в web и private server secrets в root-TUI;
3. настройте и включите protocol profile;
4. дождитесь совпадения desired/applied generation;
5. откройте firewall port;
6. прочитайте reconcile/runtime journals;
7. проверьте socket и внешний handshake;
8. проведите end-to-end test подписки.

```bash
sudo systemctl start infiproxy-reconcile.service
sudo journalctl -u infiproxy-reconcile.service -n 100 --no-pager
sudo journalctl -u infiproxy-<core>.service -n 100 --no-pager
sudo ss -lntup
```

> [!IMPORTANT]
> Module smoke test проверяет, что binary запускается и отвечает на
> `version/--version`. Он не доказывает, что ваш config валиден или proxy
> принимает клиентов.

## Xray, VLESS, REALITY и XHTTP

### Что делает каждый слой

| Слой | Роль |
|---|---|
| VLESS | Легкий stateless proxy protocol, user identity обычно UUID. |
| XHTTP | Способ переносить VLESS stream через HTTP-подобный transport. |
| REALITY | Модифицированный TLS handshake и server authentication/camouflage. |
| TCP/RAW | Базовый stream transport без XHTTP framing. |

VLESS сам по себе не является достаточной transport security для public link;
официальная документация требует внешний TLS/REALITY либо иной доверенный/
зашифрованный контекст. См. [VLESS](https://xtls.github.io/en/config/inbounds/vless.html).

REALITY использует server private key, клиентский public key, short ID и target.
Не путайте REALITY target с IP вашего VPS: target — сайт/endpoint, чей handshake
используется схемой. Не выбирайте target вслепую; Project X предупреждает, что
некоторые target могут превратить неаутентифицированный fallback в нежелательный
port forward. См. [REALITY](https://xtls.github.io/en/config/transports/reality.html).

### Файлы и unit

```text
/opt/infiproxy/cores/xray/current/xray
/etc/infiproxy-cores/xray/config.json
infiproxy-xray.service
```

Starter config имеет `inbounds: []`, поэтому безопасно ничего не слушает.

### Генерация identity

```bash
XRAY=/opt/infiproxy/cores/xray/current/xray
sudo "$XRAY" version
sudo "$XRAY" uuid
sudo "$XRAY" x25519
openssl rand -hex 8
```

Названия команды key generation могут меняться; проверьте `xray help` для
installed version. Сохраните private key только в root-readable server config.
Public key и short ID занесите в panel `secret_values`.

### Семантический server inbound

Независимо от JSON spelling конкретной Xray version inbound должен содержать:

- public listen/port, например TCP 8443;
- protocol VLESS;
- clients с UUID каждого разрешенного Infiproxy user;
- `decryption: none` либо актуальный VLESS encryption contract;
- transport `xhttp` или raw/TCP;
- security `reality`;
- REALITY private key, short IDs, target и server names;
- для XHTTP тот же path, что в profile.

Поля transport в новых Xray docs называются `method`, в старых configs часто
`network`. Не копируйте config между major versions без `xray run -test`.

### Проверка

```bash
sudo /opt/infiproxy/cores/xray/current/xray run \
  -test -config /etc/infiproxy-cores/xray/config.json
sudo systemctl restart infiproxy-xray.service
sudo journalctl -u infiproxy-xray.service -n 100 --no-pager
sudo ss -lntp | grep ':8443'
```

Для профилей с `PerUserUuid` root reconciler пересобирает server clients list
при создании, отключении и удалении user. После активации core adapter повторно
читает live config; несовпадение UUID-set вызывает rollback. В UI сохраняются
только counts, но не UUID.

### XHTTP или TCP/RAW

| Вариант | Плюсы | Минусы |
|---|---|---|
| XHTTP | Гибкий HTTP-like transport, отдельный path/modes. | Больше согласуемых параметров и version compatibility. |
| TCP/RAW | Меньше настроек, проще диагностика. | Нет XHTTP framing; traffic shape/возможности другие. |

Для первого полевого теста TCP/RAW проще, но штатный default GUI profile —
XHTTP. Выбирайте не по названию, а по client/server support конкретных versions.

## sing-box: Shadowsocks 2022 + ShadowTLS v3

### Слои

Shadowsocks AEAD 2022 шифрует proxy payload. ShadowTLS формирует внешний TLS-like
handshake и затем передает authenticated connection внутреннему proxy. Это два
разных authentication secrets.

Infiproxy Mihomo profile фиксирует cipher
`2022-blake3-aes-256-gcm`. По официальной документации sing-box этому методу
нужен 32-byte Base64 key:

```bash
/opt/infiproxy/cores/sing-box/current/sing-box generate rand --base64 32
```

См. [Shadowsocks inbound](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/)
и [ShadowTLS v3 inbound](https://sing-box.sagernet.org/configuration/inbound/shadowtls/).

### Файлы и unit

```text
/opt/infiproxy/cores/sing-box/current/sing-box
/etc/infiproxy-cores/sing-box/config.json
infiproxy-sing-box.service
```

Starter config имеет `inbounds: []`. Для working chain нужны совместимые
ShadowTLS и Shadowsocks inbounds/detour по документации installed sing-box.

### Что согласовать

- внешний ShadowTLS listener, обычно TCP 9443;
- version 3;
- ShadowTLS user/password;
- handshake server/port и SNI policy;
- внутренний Shadowsocks 2022 inbound;
- cipher и 32-byte Base64 key;
- порядок detour/chain;
- outbound direct/block;
- оба client secret names в SQLite.

### Проверка

```bash
sudo /opt/infiproxy/cores/sing-box/current/sing-box check \
  -c /etc/infiproxy-cores/sing-box/config.json
sudo systemctl restart infiproxy-sing-box.service
sudo journalctl -u infiproxy-sing-box.service -n 100 --no-pager
sudo ss -lntp | grep ':9443'
```

Не включайте `SS2022-SHADOWTLS-FALLBACK`, пока оба слоя не проходят test.

## sing-box: AnyTLS

AnyTLS — TLS-based proxy protocol с password users и padding scheme. В sing-box
он доступен с 1.12.0. Он работает поверх TCP/TLS, а не QUIC.

Официальный inbound содержит:

- type `anytls`;
- listen/listen_port;
- массив users с name/password;
- TLS certificate/key;
- optional padding scheme.

См. [AnyTLS inbound](https://sing-box.sagernet.org/configuration/inbound/anytls/).

Для Infiproxy profile согласуйте external port 10443, SNI/certificate и
`anytls.password`. Starter sing-box config AnyTLS inbound не создает.

Проверка использует тот же `sing-box check`. Убедитесь, что Mihomo client version
поддерживает AnyTLS до rollout.

## Hysteria2

### Как работает

Hysteria2 — TCP/UDP proxy поверх QUIC с unreliable datagram extension. До
успешной auth server ведет себя как HTTP/3 endpoint; после auth принимает proxy
requests. Optional Salamander меняет внешний вид UDP packets, но не заменяет
TLS/QUIC security.

Протокол и wire format описаны в
[официальной спецификации](https://v2.hysteria.network/docs/developers/Protocol/).

### Файлы и unit

```text
/opt/infiproxy/cores/hysteria/current/hysteria
/etc/infiproxy-cores/hysteria/config.yaml
infiproxy-hysteria.service
```

Starter config слушает `:443`, берет certificate/key из
`/etc/infiproxy-cores/tls/` и содержит placeholder password.

### Минимальные элементы server config

- `listen: :443` или другой UDP port;
- TLS certificate и private key;
- auth type/password либо userpass;
- optional masquerade/reverse proxy;
- optional Salamander/Gecko, согласованный с клиентом;
- optional bandwidth/congestion/ACL settings.

Сертификат должен покрывать SNI. Не используйте `insecure` на клиенте как
постоянное решение certificate error.

### Проверка

```bash
sudo /opt/infiproxy/cores/hysteria/current/hysteria version
sudo systemctl restart infiproxy-hysteria.service
sudo journalctl -u infiproxy-hysteria.service -n 100 --no-pager
sudo ss -lnup | grep ':443'
```

Если установленная Hysteria не предоставляет отдельный `--check`, панель проверяет YAML,
но семантическую проверку выполняйте контролируемым рестартом с готовым rollback;
для foreground-диагностики сначала остановите unit, чтобы не открыть второй
server на том же UDP-порту.

### Когда выбирать

- высокая RTT/packet loss;
- UDP не заблокирован;
- server имеет CPU headroom;
- нужен отдельный speed profile.

QUIC в user space потребляет больше CPU, чем kernel TCP; Hysteria сама отмечает
это в [performance guide](https://v2.hysteria.network/docs/advanced/Performance/).

## TUIC

### Как работает

TUIC стандартизует relay TCP и UDP поверх QUIC. Цели протокола включают 0-RTT,
stream multiplexing, connection migration и lossy/lossless UDP relay. См.
[TUIC protocol](https://github.com/tuic-protocol/tuic).

### Файлы и unit

```text
/opt/infiproxy/cores/tuic/current/tuic-server
/etc/infiproxy-cores/tuic/config.json
infiproxy-tuic.service
```

Starter config:

- слушает `[::]:11443` по UDP/QUIC;
- использует TLS files из `/etc/infiproxy-cores/tls`;
- выбирает congestion control `bbr`;
- ALPN `h3`;
- имеет пустой `users` map.

### Users map

Mihomo profile отправляет `uuid` Infiproxy user и shared `tuic.password`.
TUIC adapter строит users map из enabled desired users; live observation после
активации сравнивает ключи map и откатывает поколение при drift.

### Проверка

```bash
sudo /opt/infiproxy/cores/tuic/current/tuic-server --version
sudo systemctl restart infiproxy-tuic.service
sudo journalctl -u infiproxy-tuic.service -n 100 --no-pager
sudo ss -lnup | grep ':11443'
```

TUIC server `1.0.0` не предоставляет отдельную команду `check`. Панель проверяет
JSON; полная проверка — controlled restart, active UDP listener и реальный
client handshake. Пустой `users` starter map намеренно не запускается.

## Mihomo: Trojan, Snell и Mieru

Один `mihomo` runtime обслуживает три независимых TCP listener. Config строится
атомарно из enabled profiles, проверяется командой `mihomo -t -f`, а после
restart reconciler проверяет PID-owned listeners и user set.

```text
/opt/infiproxy/cores/mihomo/current/mihomo
/etc/infiproxy-cores/mihomo/config.yaml
infiproxy-mihomo.service
```

| Профиль | Auth | TLS | Starter port |
|---|---|---|---|
| `trojan-tls` | UUID пользователя как уникальный Trojan password | certificate/key, SNI, uTLS fingerprint клиента | TCP 12443 |
| `snell-v5` | общий `snell.psk` | не используется базовой композицией | TCP 13443, UDP передается внутри TCP |
| `mieru` | UUID как username и общий `mieru.password` | protocol-native transport | TCP 14443 |

Trojan и Mieru участвуют в user reconciliation: отключенный пользователь
исчезает из server config. Snell использует shared PSK и поэтому не даёт
индивидуального отзыва без смены ключа.

Перед включением Trojan положите certificate и private key в общий TLS tree и
задайте SNI, совпадающий с сертификатом. Для Snell и Mieru создайте secret refs
в панели. После установки runtime выполните:

```bash
sudo /opt/infiproxy/cores/mihomo/current/mihomo -t \
  -f /etc/infiproxy-cores/mihomo/config.yaml
sudo systemctl start infiproxy-reconcile.service
sudo systemctl status infiproxy-mihomo.service --no-pager
sudo ss -lntp | grep -E ':(12443|13443|14443)\b'
```

## Декларативные композиции и исследованные кандидаты

Каждый selectable adapter объявляет `protocol`, `transport`, `security`,
optional `flow` и maturity. GUI показывает только целые зарегистрированные
комбинации; произвольное смешивание несовместимых слоёв не предлагается.

| Selectable adapter | Композиция | Готовность |
|---|---|---|
| `vless-reality-xhttp` | VLESS + XHTTP + REALITY | Stable |
| `vless-reality-tcp` | VLESS + TCP + REALITY | Stable |
| `anytls-tls` | AnyTLS + TCP + TLS | Stable |
| `anytls-shadowtls-v3` | AnyTLS + TCP + ShadowTLS v3 | Stable |
| `anytls-restls` | AnyTLS + TCP + ResTLS | Experimental |
| `anytls-jls` | AnyTLS + TCP + JLS | Experimental |
| `shadowsocks2022-shadow-tls` | SS2022 + TCP + ShadowTLS v3 | Stable |
| `hysteria2` | Hysteria2 + QUIC + TLS/optional Salamander | Stable |
| `any-tls` | AnyTLS + TCP + TLS | Experimental |
| `tuic` | TUIC v5 + QUIC + TLS | Stable |
| `trojan-tls` | Trojan + TCP + TLS/uTLS | Stable |
| `trojan-shadowtls-v3` | Trojan + TCP + ShadowTLS v3 | Stable |
| `trojan-restls` | Trojan + TCP + ResTLS | Experimental |
| `trojan-jls` | Trojan + TCP + JLS | Experimental |
| `trojan-reality` | Trojan + TCP + REALITY | Stable |
| `snell-v5` | Snell v5 + TCP + PSK | Stable |
| `snell-v5-shadowtls-v3` | Snell v5 + ShadowTLS v3 | Stable |
| `snell-v5-restls` | Snell v5 + ResTLS | Experimental |
| `snell-v5-jls` | Snell v5 + JLS | Experimental |
| `mieru` | Mieru + TCP + protocol auth | Stable |

Таблица ниже фиксирует ecosystem support, а не обещает готовый Infiproxy
adapter. Baseline исследования — stable Mihomo `v1.19.30`. Если upstream не
указывает первую версию поля, minimum намеренно не угадывается: требуется
документация и config canary установленного binary.

| Кандидат | Client / server | Auth и ресурсы | Maturity | В Infiproxy |
|---|---|---|---|---|
| AnyTLS + JLS | Mihomo outbound + inbound | AnyTLS password, JLS user/password, fallback destination | Experimental | Реализован `anytls-jls`; exact parser/server canary пройден |
| AnyTLS + ResTLS | Mihomo outbound + inbound | AnyTLS password, ResTLS password/destination | Experimental | Реализован `anytls-restls`; exact parser/server canary пройден |
| VLESS + JLS | Mihomo outbound + inbound | UUID users, JLS user/password/destination | Experimental | Unsupported: JLS auth lifecycle и renderer не реализованы |
| VLESS + ResTLS | Mihomo outbound + inbound | UUID users, ResTLS password/destination | Experimental | Unsupported: ResTLS secret lifecycle и renderer не реализованы |
| Trojan TLS/ShadowTLS/ResTLS/JLS/REALITY | Mihomo outbound + inbound | UUID password и credential выбранной единственной wrapper | Stable/Experimental | Все пять явных capabilities реализованы и проверены `v1.19.30` |
| ShadowQUIC | Mihomo outbound + inbound; JLS всегда включён | username/password, QUIC/TLS/JLS, optional domain | Experimental | Unsupported: QUIC/JLS listener ownership и canary не реализованы |
| Snell v5 plain/ShadowTLS/ResTLS/JLS | Mihomo outbound + inbound | shared PSK и optional wrapper credential | Stable/Experimental | Все четыре capabilities реализованы и проверены `v1.19.30` |
| Mieru TCP | Mihomo outbound + inbound | username/password | Stable | Реализован `mieru` |
| MASQUE | Mihomo outbound; matching public inbound не подтверждён | ECDSA key pair, tunnel CIDR, optional SNI | Unsupported | Не предлагается |
| TrustTunnel | Mihomo outbound + inbound | username/password, domain, certificate/key, HTTP/2 и optional HTTP/3 | Experimental | Unsupported: runtime canary не реализован |

Первичные источники: [AnyTLS outbound](https://wiki.metacubex.one/en/config/proxies/anytls/),
[AnyTLS inbound](https://wiki.metacubex.one/en/config/inbound/listeners/anytls/),
[VLESS inbound](https://wiki.metacubex.one/en/config/inbound/listeners/vless/),
[TLS/uTLS](https://wiki.metacubex.one/en/config/proxies/tls/),
[ShadowQUIC](https://wiki.metacubex.one/en/config/proxies/shadowquic/),
[Snell](https://wiki.metacubex.one/en/config/proxies/snell/),
[Mieru](https://wiki.metacubex.one/en/config/proxies/mieru/),
[MASQUE](https://wiki.metacubex.one/en/config/proxies/masque/) и
[TrustTunnel](https://wiki.metacubex.one/en/config/proxies/trusttunnel/).

## Маскировка: практические оговорки

Ни SNI популярного сайта, ни Chrome fingerprint, ни obfs не дают математической
гарантии неразличимости. Ошибочный target, редкий port, постоянный packet shape,
certificate mismatch или активный probe могут выдать сервис.

Безопасный подход:

- использовать официально поддерживаемые combinations;
- не включать случайные experimental knobs;
- держать fallback/masquerade действительно рабочим, если protocol это требует;
- не выбирать чужой CDN target без оценки abuse риска;
- иметь альтернативный transport с другим TCP/UDP failure mode;
- тестировать из реальной сети, а не только с localhost.

## Идеальная комбинация

- VLESS REALITY XHTTP/RAW как основной TCP transport;
- Hysteria2 или TUIC как QUIC speed fallback, но не оба без необходимости;
- Trojan/Snell/Mieru через отдельный Mihomo runtime при необходимости TCP fallback;
- отдельные hostnames для административного HTTPS и proxy endpoints;
- server credentials per user там, где runtime поддерживает;
- inactive/unused units disabled и ports закрыты.

## Допустимая простая комбинация

- один Xray VLESS transport;
- UUID одного временного пользователя в Xray clients;
- один fallback только после стабильной основной схемы;
- никакого `BALANCE` до end-to-end тестов;
- manual updates с backup и rollback verification.
