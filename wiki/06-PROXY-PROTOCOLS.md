# Proxy-протоколы и серверные ядра

[Назад: профили Mihomo](05-MIHOMO-PROFILES) | [К оглавлению](Home) | [Далее: маршрутизация](07-ROUTING)

## Перед настройкой

Runtime module — исполняемый файл и systemd unit. Protocol profile — клиентская
конфигурация. Между ними нет автоматического двустороннего binding.

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

1. сохраните backup starter config;
2. сгенерируйте credentials локальным binary/openssl;
3. заполните server config;
4. проверьте синтаксис без restart, если core умеет;
5. откройте firewall port;
6. `enable --now` unit;
7. прочитайте journal;
8. проверьте socket;
9. настройте client profile и secret values;
10. проведите end-to-end test.

```bash
sudo cp -a /etc/infiproxy-cores/<core>/config.* \
  /etc/infiproxy-cores/<core>/config.pre-change
sudo systemctl enable --now infiproxy-<core>.service
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

Если generator использует UUID каждого subscription user, server clients list
нужно обновлять при создании/удалении user. Панель этого пока не делает.

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

Hysteria `2.12.1` не предоставляет отдельный `--check`. Панель проверяет YAML,
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
Добавьте каждый UUID в TUIC users map с тем же password. После создания нового
panel user его TUIC-доступ не заработает, пока server map не обновлен.

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

## Telegram MTProxy

### Чем отличается

MTProxy обслуживает только Telegram MTProto clients. Он не является generic
Mihomo proxy и не появляется в subscription YAML.

Official upstream использует:

- `proxy-secret` для связи с Telegram infrastructure;
- `proxy-multi.conf`, который Telegram рекомендует периодически обновлять;
- 16-byte/32-hex client secret;
- public client port;
- local stats port;
- число worker processes.

См. [TelegramMessenger/MTProxy](https://github.com/TelegramMessenger/MTProxy).

### Файлы и unit

```text
/opt/infiproxy/cores/mtproto/current/mtproto-proxy
/etc/infiproxy-cores/mtproto/mtproto.env
/etc/infiproxy-cores/mtproto/proxy-secret
/etc/infiproxy-cores/mtproto/proxy-multi.conf
infiproxy-mtproto.service
```

TUI **Guided initial setup**:

1. определяет/спрашивает public host;
2. предлагает public port `8444`, который не пересекается со встроенным
   профилем VLESS XHTTP на TCP `8443`;
3. предлагает stats port `8888`;
4. предлагает 2 workers (`1..16`);
5. генерирует secret или принимает ровно 32 hex;
6. скачивает два official upstream файла;
7. backup-ит env и пишет новый;
8. печатает `https://t.me/proxy?...`;
9. отдельно спрашивает, enable/start ли unit.

Stats listener не открывайте наружу. В текущем systemd argv secret находится в
process arguments после expansion env; ограничьте локальный доступ к process
metadata и не публикуйте diagnostic dumps.

### Refresh upstream config

Telegram upstream README рекомендует обновлять `proxy-multi.conf` примерно раз в
день. Используйте TUI **Refresh Telegram upstream config**, затем controlled
restart и проверку журнала.

### Секреты с prefix

Official upstream описывает prefix `dd` для random padding в client secret. TUI
генерирует базовые 32 hex и валидирует именно эту длину; advanced variants
требуют ручной проверки совместимости и не должны вводиться в это поле как
34+ символа без изменения manager contract.

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
- MTProto только для Telegram;
- отдельный Headscale hostname/mesh use case;
- server credentials per user там, где runtime поддерживает;
- inactive/unused units disabled и ports закрыты.

## Допустимая простая комбинация

- один Xray VLESS transport;
- UUID одного временного пользователя в Xray clients;
- один fallback только после стабильной основной схемы;
- никакого `BALANCE` до end-to-end тестов;
- manual updates с backup и rollback verification.
