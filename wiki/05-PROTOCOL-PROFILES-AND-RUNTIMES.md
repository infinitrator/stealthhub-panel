# Профили протоколов и выбор runtime

[Назад: пользователи](04-USERS-AND-SUBSCRIPTIONS) | [К оглавлению](Home) |
[Далее: proxy-протоколы](06-PROXY-PROTOCOLS)

## 1. Что такое профиль

Protocol profile - это версионированная запись желаемого endpoint. Она
содержит:

- стабильное имя профиля;
- protocol adapter ID и schema version;
- роль в клиентской routing policy;
- server hostname/IP и port;
- enabled flag;
- preferred core ID;
- stable managed resource ID;
- adapter-owned JSON configuration с именами secret references.

Профиль одновременно участвует в двух процессах:

1. Protocol adapter строит proxy object для Mihomo subscription.
2. Root reconciler строит server fragment и передает его совместимому core
   adapter.

Включенный профиль не считается работающим, пока desired generation не стал
Applied, выбранный runtime не прошел health/listener checks и реальный клиент
не выполнил handshake.

## 2. Lifecycle в текущем интерфейсе

Страница Protocols показывает встроенные profiles и inventory adapters. В
текущем beta release web UI:

- изменяет Enabled, Server address, Server port и adapter-specific fields;
- не создает произвольные новые profiles;
- не удаляет встроенные profiles;
- не меняет protocol adapter ID;
- не меняет preferred core ID существующей записи.

Save profile доступен только owner. Сервер валидирует hostname/IP, port,
ограничения строк, secret reference names и текущую adapter schema. Успешное
сохранение увеличивает desired generation и создает bounded reconcile request.

### Enabled

Enabled включает профиль в subscription и desired server state. Disable:

- исключает proxy object из новых YAML;
- запускает новое поколение server configuration;
- для per-user runtime удаляет соответствующий listener/users после reconcile.

Это не отзывает уже сохраненный shared password у клиента. Для shared-credential
protocol при компрометации нужна ротация секрета.

### Server address

Это адрес, который получает клиент. Он должен разрешаться с клиентской сети и
вести к тому же listener, который применяет reconciler. Значение node_domain в
Settings используется как starter default, но profile хранит собственное
значение.

### Server port

Это client-facing port конкретного профиля. TCP и UDP - разные пространства:
Nginx TCP 443 и Hysteria UDP 443 могут работать одновременно. Два enabled
profiles с одинаковыми network+port создают конфликт listener claims и должны
быть отклонены до live mutation.

### Adapter-specific fields

Text field хранит обычную конфигурацию: SNI, path или path root. Secret field
хранит только reference name. Метка present означает, что shared value найдено
в panel SQLite; она не подтверждает наличие root-only server secret.

REALITY private key относится к server-only references и должен находиться в:

    /etc/infiproxy/secrets.d/xray.reality.private_key

Создавайте и ротируйте root-only значения через:

    sudo infiproxy-manager

## 3. Как выбирается runtime

Generic CoreRegistry не содержит protocol-specific if/else. Protocol adapter
объявляет required capability. Core adapter объявляет capabilities и selection
priority. Выбор происходит так:

1. Если profile имеет preferred_core_id, требуется зарегистрированный core с
   этим ID и нужной capability.
2. Иначе registry ищет установленный совместимый core.
3. При нескольких кандидатах используется детерминированный priority.
4. Если совместимого установленного core нет, resource получает состояние
   CoreUnavailable/Unsupported и live state не меняется.

Starter profiles имеют явные preferred runtimes. UI текущей версии показывает
selection в inventory, но не предлагает переключатель core. Изменять persisted
preferred_core_id вручную через SQLite не рекомендуется: это обход schema и
reconcile validation.

## 4. Capability matrix runtime

| Runtime | Capabilities, объявленные кодом |
|---|---|
| Xray | vless-reality-tcp, vless-reality-xhttp |
| sing-box | vless-reality-tcp, shadowsocks2022-shadow-tls, hysteria2, any-tls, tuic |
| Hysteria | hysteria2 |
| TUIC | tuic |
| Mihomo | VLESS REALITY/wrappers, AnyTLS wrappers, Trojan variants, Snell v5 variants, Mieru, TrustTunnel H2, ShadowQUIC, Sudoku HTTPMask |

Mihomo не объявляет legacy any-tls, Hysteria2, TUIC или
shadowsocks2022-shadow-tls server capabilities. sing-box не объявляет
Trojan, Snell, Mieru или XHTTP. Inventory и CoreRegistry обязаны доверять
manifest truthfulness, а composer tests не дают capability расходиться с
реализацией.

## 5. Starter profiles и ports

Все starter profiles создаются disabled. Ports ниже берутся из
default_profiles() текущего кода, а не являются глобальным требованием.

| Profile | Capability | Network | Port | Preferred runtime | Maturity |
|---|---|---:|---:|---|---|
| VLESS-XHTTP-SAFE | vless-reality-xhttp | TCP | 8443 | Mihomo | Stable |
| VLESS-REALITY-TCP-FALLBACK | vless-reality-tcp | TCP | 7443 | Mihomo | Stable |
| VLESS-SHADOWTLS-V3-EXPERIMENTAL | vless-shadowtls-v3 | TCP | 7543 | Mihomo | Experimental |
| VLESS-RESTLS-EXPERIMENTAL | vless-restls | TCP | 7643 | Mihomo | Experimental |
| VLESS-JLS-EXPERIMENTAL | vless-jls | TCP | 7743 | Mihomo | Experimental |
| SS2022-SHADOWTLS-FALLBACK | shadowsocks2022-shadow-tls | TCP | 9443 | sing-box | Stable |
| ANYTLS-EXPERIMENTAL | any-tls | TCP | 10443 | sing-box | Experimental |
| ANYTLS-TLS | anytls-tls | TCP | 10543 | Mihomo | Stable |
| ANYTLS-SHADOWTLS-V3 | anytls-shadowtls-v3 | TCP | 10643 | Mihomo | Stable |
| ANYTLS-RESTLS-EXPERIMENTAL | anytls-restls | TCP | 10743 | Mihomo | Experimental |
| ANYTLS-JLS-EXPERIMENTAL | anytls-jls | TCP | 10843 | Mihomo | Experimental |
| HYSTERIA2-SPEED | hysteria2 | UDP | 443 | Hysteria | Stable |
| TUIC-SPEED | tuic | UDP | 11443 | TUIC | Stable |
| TROJAN-TLS-COMPATIBILITY | trojan-tls | TCP | 12443 | Mihomo | Stable |
| TROJAN-SHADOWTLS-V3 | trojan-shadowtls-v3 | TCP | 12543 | Mihomo | Stable |
| TROJAN-RESTLS-EXPERIMENTAL | trojan-restls | TCP | 12643 | Mihomo | Experimental |
| TROJAN-JLS-EXPERIMENTAL | trojan-jls | TCP | 12743 | Mihomo | Experimental |
| TROJAN-REALITY | trojan-reality | TCP | 12843 | Mihomo | Stable |
| SNELL-V5-COMPATIBILITY | snell-v5 | TCP | 13443 | Mihomo | Stable |
| SNELL-V5-SHADOWTLS-V3 | snell-v5-shadowtls-v3 | TCP | 13543 | Mihomo | Stable |
| SNELL-V5-RESTLS-EXPERIMENTAL | snell-v5-restls | TCP | 13643 | Mihomo | Experimental |
| SNELL-V5-JLS-EXPERIMENTAL | snell-v5-jls | TCP | 13743 | Mihomo | Experimental |
| MIERU-TCP-COMPATIBILITY | mieru | TCP | 14443 | Mihomo | Stable |
| TRUSTTUNNEL-H2-EXPERIMENTAL | trusttunnel-h2 | TCP | 15443 | Mihomo | Experimental |
| SHADOWQUIC-EXPERIMENTAL | shadowquic | UDP | 16443 | Mihomo | Experimental |
| SUDOKU-HTTPMASK-EXPERIMENTAL | sudoku-httpmask | TCP | 17443 | Mihomo | Experimental |

Legacy migration is отдельным контрактом: существующие VLESS REALITY profiles
могут сохранить Xray placement, чтобы schema lift не менял runtime молча.

## 6. User participation

Adapter объявляет один из трех режимов:

| Режим | Семантика |
|---|---|
| PerUserUuid | Каждый enabled user должен присутствовать в server state отдельным ID |
| SharedCredential | Все users получают один server credential |
| None | User list не участвует в runtime auth |

PerUserUuid позволяет reconciler сравнить desired и observed identities.
Diagnostics сохраняют только counts: desired, observed, missing и unexpected.
UUID/usernames не попадают в status record.

SharedCredential означает:

- Disable блокирует subscription endpoint конкретного user;
- generated YAML для него больше не выдается;
- известный общий пароль может продолжить работать напрямую;
- индивидуальный revoke требует сменить общий credential и обновить всех
  разрешенных клиентов.

## 7. Secret model

Есть три разных класса значений:

| Класс | Где хранится | Пример |
|---|---|---|
| Subscription bearer token | SQLite users | URL /sub/{token} |
| Shared client/server secret | SQLite secret_values | tuic.password |
| Server-only secret | root file | REALITY private key |

Web Secrets показывает имена и позволяет owner записывать shared values. Secret
value после сохранения не выводится обратно. Root-only values web-процесс
читать не должен.

Перед удалением secret проверьте все enabled profiles. Reconcile с отсутствующим
required value завершается fail closed до успешного publish.

## 8. Практический порядок включения

1. Установите точный runtime pin в Modules.
2. Создайте необходимые shared и root-only secrets.
3. Проверьте DNS server address и firewall для TCP/UDP profile.
4. Проверьте TLS pair, если capability его требует.
5. Включите один profile и нажмите Save profile.
6. Дождитесь Applied и равенства desired/applied generations.
7. Проверьте service, PID-owned listener и journal.
8. Создайте временного user, импортируйте YAML и выполните реальный handshake.
9. Только после canary включайте следующий profile.

Не включайте все 26 profiles одновременно. Простой production baseline обычно
содержит один стабильный TCP transport и один UDP fallback только при реальной
необходимости.

## 9. Диагностика

    sudo systemctl status infiproxy-reconcile.service --no-pager
    sudo journalctl -u infiproxy-reconcile.service -n 200 --no-pager
    sudo ss -lntup
    curl -fsS http://127.0.0.1:8080/ready

Если resource остается CoreUnavailable, проверьте:

- active manifest в /etc/infiproxy-modules.d;
- executable current symlink;
- exact installed version;
- capability выбранного core;
- profile preferred_core_id;
- service и TLS readiness.

Подробный transaction model:
[Desired state и reconciliation](09-RECONCILIATION-AND-DESIRED-STATE).
