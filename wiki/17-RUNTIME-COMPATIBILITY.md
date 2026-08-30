# Runtime compatibility

[Назад: адаптеры](16-ADAPTERS-AND-RECONCILIATION) | [К оглавлению](Home)

Контракт проверен **29 августа 2026 года**. Основной клиент — Clash Mi с
встроенным Mihomo; фиксируется версия parser/core, а не версия приложения.

## Проверенные версии

| Компонент | Точная версия | Политика |
|---|---|---|
| Mihomo client/server | `v1.19.30` | Основной client baseline и preferred modern TCP runtime. |
| Xray-core | `v26.3.27` | Только проверенный REALITY fallback; `v26.7.11+` несовместим с контрактом Mihomo. |
| sing-box | `v1.13.20` | Shadowsocks 2022 + ShadowTLS и ограниченные fallback-capabilities; XHTTP не заявляется. |
| Hysteria | `app/v2.12.2` | Native Hysteria 2 server. |
| TUIC server | `tuic-server-1.0.0` | Native TUIC v5 server. |

Все manifest используют `upstream=pinned-release`. Отсутствующая настройка
automatic runtime update означает `false`. Updater не переходит на новый tag,
не делает автоматический downgrade и сообщает, если установленная версия
находится вне проверенного контракта.

## Каталог Protocols

| Семейство | Stable | Experimental |
|---|---|---|
| VLESS | REALITY TCP + Vision + XUDP; REALITY XHTTP без Vision | ShadowTLS v3; ResTLS; JLS без Vision |
| AnyTLS | TLS; ShadowTLS v3 | ResTLS; JLS |
| Trojan | TLS; ShadowTLS v3; REALITY | ResTLS; JLS |
| Snell v5 | plain; ShadowTLS v3 | ResTLS; JLS |
| Shadowsocks | 2022 + ShadowTLS v3 | — |
| Speed | Hysteria 2 + optional Salamander; TUIC v5 | ShadowQUIC с intrinsic JLS и выключенным 0-RTT |
| Mieru | TCP, `HANDSHAKE_STANDARD`, `MULTIPLEXING_LOW` | — |
| HTTP-like | — | TrustTunnel H2; Sudoku legacy HTTPMask с ChaCha20-Poly1305 |

Новые профили создаются **выключенными**. Старый ID `any-tls` сохраняется для
миграционной совместимости; новые настройки используют `anytls-tls`.

## Жесткие запреты

- AnyTLS + REALITY не поддерживается Mihomo и не существует в GUI.
- XHTTP никогда не получает `xtls-rprx-vision`.
- sing-box не может быть выбран для XHTTP.
- одновременно формируется не более одной из REALITY, ShadowTLS, ResTLS и JLS.
- server-only REALITY/TLS private key не хранится и не показывается в SQLite,
  подписке или веб-интерфейсе.
- Xray с marker/probe version, отличным от `v26.3.27`, не выбирается reconciler.
- TrustTunnel H3 не выставляется: один profile пока не может атомарно заявить
  TCP и UDP socket ownership. H2 использует только TCP.
- ShadowQUIC не получает отдельный `jls-opts`, потому что JLS встроен в протокол.
- Sudoku никогда не генерирует `aead-method: none`.

Отсутствующий version marker больше не означает compatibility. Adapter запускает
только фиксированную version-команду своего binary и принимает исключительно
точный pin; ошибка, неразбираемый вывод и более новая версия дают `outside contract`.

## Что показывает GUI

В **Protocols** таблица показывает composition, maturity, preferred runtime,
установленную версию, validated version, fallback и sanitized compatibility
status. `outside contract` означает, что бинарник нельзя применять к этому
профилю до возврата на проверенный pin или повторной полной валидации.

## Как перепроверить pins

```bash
bash deploy/tests/runtime-compatibility.sh
```

Скрипт загружает точные официальные assets, проверяет stable metadata и
SHA-256, затем выполняет:

- `mihomo -t -f` для полного клиентского каталога и всех native listeners;
- `xray run -test -config` для TCP/XHTTP REALITY;
- `sing-box check -c` для каждой заявленной capability;
- bounded loopback startup Hysteria и TUIC на `127.0.0.1`.

Менять pin можно только вместе с успешным результатом этого suite и обновлением
[`docs/runtime-compatibility.md`](https://github.com/infinitrator/stealthhub-panel/blob/main/docs/runtime-compatibility.md).

Официальные источники: [Mihomo](https://wiki.metacubex.one/en/),
[Xray](https://xtls.github.io/en/), [sing-box](https://sing-box.sagernet.org/),
[Hysteria](https://v2.hysteria.network/docs/) и
[TUIC](https://github.com/tuic-protocol/tuic).
