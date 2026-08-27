# Модули и обновления

[Назад: маршрутизация](07-ROUTING) | [К оглавлению](Home) | [Далее: Headscale](09-HEADSCALE)

## Зачем runtime-модули отделены от панели

Панель, proxy cores и Headscale имеют разные upstream release cycles. Модульная
модель позволяет обновить один binary без пересборки панели и без замены config.

```text
root-owned manifest
      |
      +-> upstream/repo/asset contract
      +-> runtime path and systemd unit
      +-> config path
      |
module updater -> version directory -> atomic current symlink -> service restore
```

## Active registry и available catalog

| Каталог | Смысл |
|---|---|
| `/etc/infiproxy-modules.d` | Активные registered manifests. |
| `/etc/infiproxy-modules.available.d` | Одобренный root catalog. |
| `/var/lib/infiproxy-maintenance/module-disabled` | Marker, не позволяющий installer снова auto-activate удаленный module. |

Список не скомпилирован в Rust. Добавление root-approved manifest меняет GUI
без изменения enum/route, если module соответствует contract.

## Bundled manifests

| ID | Upstream | Driver | Runtime root | Unit |
|---|---|---|---|---|
| `xray` | `XTLS/Xray-core` latest release | release | cores | `infiproxy-xray.service` |
| `sing-box` | `SagerNet/sing-box` latest release | release | cores | `infiproxy-sing-box.service` |
| `hysteria` | `apernet/hysteria` latest release | release | cores | `infiproxy-hysteria.service` |
| `tuic` | `tuic-protocol/tuic` latest release | release | cores | `infiproxy-tuic.service` |
| `mtproto` | `TelegramMessenger/MTProxy` `master` commit | source build | cores | `infiproxy-mtproto.service` |
| `headscale` | `juanfont/headscale` latest release | dedicated | modules | `headscale.service` |

MTProto version — commit SHA, потому что updater компилирует source. Остальные
версии — GitHub release tags.

## Manifest contract

Manifest — простые `key=value`, не shell. Он задает:

```text
id, name, kind, role, repo, upstream, ref, driver, root,
binary, service, config, asset_amd64, asset_arm64
```

Parser:

- отвергает неизвестные/missing keys;
- валидирует безопасный ID и совпадение filename;
- ограничивает GitHub owner/repo;
- не выполняет substitutions как shell;
- требует root ownership и отсутствие group/world write для installed registry;
- для generic import ограничивает runtime собственным tree/unit/config.

## Web metadata и root updater

Это разные компоненты:

### Web metadata reader

- периодически и при открытии страницы перечитывает sanitized state;
- для module metadata может выполнять bounded GitHub API check;
- для обновления самой панели GitHub не вызывает;
- сохраняет безопасные latest/check fields в SQLite;
- зеркалирует безопасные state fields в `/var/lib/infiproxy/modules/<id>.env`;
- никогда не скачивает и не запускает binary.

### Root updater

- `/usr/local/sbin/infiproxy-module-update`;
- запускается вручную, path unit или timer;
- timer срабатывает каждые 15 минут;
- берет repo/asset только из validated root manifest;
- обрабатывает requests и scheduled auto update.

## Кнопки Modules

### Check all

В текущем web request последовательно проверяет все active manifests через
bounded HTTP client (15-second timeout). Обновляет metadata, но не binary.

GitHub API rate limit/error отобразится как check failure; installed runtime
продолжит работать.

### Auto On/Off и Save

Policy хранится в SQLite, default для module — `true`. Root auto-run берет только
module, у которого state одновременно:

```text
AUTO_ENABLED=true
INSTALLED=true
```

Scheduled module update запускается один раз в день после общего maintenance
time. Если хотя бы один update failed, day marker не ставится и scheduler может
повторить попытку при следующем 15-minute run.

### Check

Проверяет один upstream и обновляет latest state. Это безопасная подготовка перед
manual update.

### Install/Update latest

Создает `/var/lib/infiproxy/module-requests/<id>.request`. Path watcher запускает
root service. Кнопка не ждет download/build/restart.

Проверка результата:

```bash
sudo systemctl status infiproxy-module-update.service --no-pager
sudo tail -n 160 /var/lib/infiproxy-maintenance/module-update.log
sudo infiproxy-module-update --check <id>
```

### Remove

Требует точный ID. Root worker:

1. копирует manifest в available catalog, если его там нет;
2. disable/stop-ит unit;
3. удаляет versioned runtime tree;
4. удаляет active manifest/version/state;
5. ставит disabled marker;
6. **сохраняет config path**.

Это remove runtime, не secure erase secrets.

### Install latest из Available catalog

Создает `.register`. Worker повторно валидирует root manifest, активирует его,
создает config parent и сразу пытается установить latest. При fail request и
manifest получают `.failed` marker.

## Проверка release asset

Для release module updater:

1. вызывает GitHub latest release API;
2. строит точное asset name для `amd64`/`arm64`;
3. принимает SHA-256 digest asset metadata либо официальный checksum sidecar;
4. отвергает URL вне `github.com/<manifest-repo>/releases/download/`;
5. скачивает только по HTTPS с connect timeout 15 s, max time 600 s, тремя
   attempts и пределом 512 MiB;
6. проверяет SHA-256;
7. безопасно распаковывает archive;
8. запускает binary version smoke test;
9. только затем переключает `current` symlink.

Если upstream release не публикует digest и подходящий sidecar, updater
завершается fail-closed. Это не повод отключать checksum.

## Archive safety

Core installer отвергает path traversal, абсолютные paths, backslash paths,
symlink, hardlink и special entries. Архив ограничен 512 MiB, его объявленное
распакованное содержимое — 1 GiB и 4096 entries. Проверка выполняется до
извлечения. Binary копируется в новый version directory, после чего временная
`.current.<version>.next` ссылка атомарно переименовывается в `current`.

Runtime layouts:

```text
/opt/infiproxy/cores/<id>/<version>/<binary>
/opt/infiproxy/cores/<id>/current -> <version>
/opt/infiproxy/modules/headscale/<version>/headscale
/opt/infiproxy/modules/headscale/current -> <version>
```

## Service state и rollback

Перед update запоминаются `is-enabled` и `is-active`.

- inactive unit остается inactive;
- enabled state восстанавливается;
- active unit restart-ится новым binary и должен оставаться active после
  двухсекундного canary;
- если restart/canary failed, symlink возвращается к предыдущей версии и
  старый service restart-ится;
- config не заменяется.

Для обычных cores binary rollback не откатывает ручную config migration. Поэтому
не меняйте config под новую major version до успешного binary canary либо держите
отдельный backup. Headscale обрабатывается строже: updater делает backup config и
state/SQLite, останавливает active service перед потенциально мигрирующим
`configtest` и при ошибке восстанавливает binary link, config, DB и service state.

## Module config backup

Перед изменением установленного module updater создает:

```text
/var/lib/infiproxy-maintenance/module-backups/<id>/<timestamp>/
  config.tar.gz
  metadata.env
```

Metadata содержит previous version/current target и service state. Права root
`0700/0600`, default retention 30 дней.

Это local same-disk backup. При потере VPS он исчезнет вместе с системой.

## Manual CLI

```bash
sudo infiproxy-module-update --check-all
sudo infiproxy-module-update --check xray
sudo infiproxy-module-update --update xray
sudo systemctl start infiproxy-module-update.service
sudo systemctl list-timers infiproxy-module-update.timer
```

При сломанном IPv6 только для конкретного запуска:

```bash
sudo INFIPROXY_FORCE_IPV4=true \
  /usr/local/sbin/infiproxy-module-update --update hysteria
```

Не добавляйте этот workaround глобально, если можно исправить DNS/IPv6 route.

## TUI Runtime modules

Откройте `sudo infiproxy-manager` и выберите **Runtime modules**. Список
формируется из active registry, поэтому импортированный модуль появляется без
пересборки панели.

| Пункт | Фактическое действие |
|---|---|
| **Show installed/latest status** | Запускает `infiproxy-module-update --check-all`; для каждого active manifest обращается к GitHub и сравнивает version marker с latest release/commit. |
| **Check one module** | Предлагает динамический список и выполняет только `--check <id>`; binary/config не меняются. |
| **Install or update one module** | Сначала выполняет check, затем спрашивает подтверждение и запускает `--update <id>` от root. |
| **Restart module updater** | Выполняет `systemctl daemon-reload` и включает timer/path watcher; модули при этом не обновляются немедленно. |
| **Show module updater log** | Показывает последние 160 строк root-owned `module-update.log`. |
| **Import generic release manifest** | Валидирует operator-supplied `.module`, при необходимости проверяет hardening service unit, помещает manifest в available catalog и создает registration request. |
| **Remove registered module** | Требует точный ввод module ID, создает remove request; worker останавливает unit, удаляет runtime binary и active manifest, но сохраняет config и available manifest. |

Проверка версии использует сеть, но не устанавливает asset. Установка и удаление
асинхронны только когда создается request; прямой `--update` в TUI ждет
завершения root updater и показывает его output.

## Generic manifest import через TUI

**Advanced tools -> Manual verified archive import** импортирует archive для уже
registered core по URL и operator-provided SHA-256.

**Runtime modules -> Import generic release manifest** регистрирует новый
GitHub-release module. Если unit отсутствует, TUI принимает только unit, где:

- один `Exec*` и это expected versioned binary;
- `User=infiproxy`, `Group=infiproxy`;
- `NoNewPrivileges=true`;
- `ProtectSystem=strict`;
- нет elevated supplementary groups/hooks;
- capabilities отсутствуют либо ровно `CAP_NET_BIND_SERVICE`.

Это снижает риск, но сторонний binary все равно является supply-chain trust
decision root-оператора.

## Обновление панели

Панель обновляется отдельно от modules.

### Detection

- root timer каждые 15 минут fetch-ит pinned Git ref;
- repo/ref читаются из root-owned `/etc/infiproxy-update.conf`;
- applied SHA берется из root-written `panel-last-applied.sha`;
- root пишет bounded `panel-update-status.env`, а web только зеркалирует его в
  SQLite и публикует policy в `panel-update-state.env`.

### Schedule

`infiproxy-panel-update.timer` запускает root updater каждые 15 минут. Auto apply
требует enabled, update available, не примененный SHA и время не раньше
maintenance time.

### Update Now

Web owner button и TUI создают request file. Наличие request bypass-ит schedule.

Если current и latest совпадают, request удаляется до backup/build, поэтому
повторная сборка не выполняется.

### Pre-update backup

Root updater до checkout создает:

- копии panel binary и всех privileged Rust helpers, включая reconciler;
- SQLite `.backup`;
- tar panel/core/Headscale configs;
- manifests/catalog;
- admin, subscription/rules и Headscale Nginx sites;
- metadata с previous commit.

Если DB/config backup failed, update не начинается.

### Build, install, readiness, rollback

Updater разрешает только fast-forward переход от установленного commit; ручное
исключение `INFIPROXY_ALLOW_NON_FAST_FORWARD=true` предназначено только для
проверенного recovery. Затем он checkout-ит точный fetched commit, запускает
bootstrap/install и до 15 раз
проверяет local `/ready` с интервалом 2 s. Он отказывается проверять non-local
bind. При failure восстанавливает configs, DB, все control binaries и previous
source revision. Failed target SHA не публикуется: root marker изменяется одной
atomic replace только внутри successful readiness boundary.

Лог:

```bash
sudo tail -n 160 /var/lib/infiproxy-maintenance/panel-update-run.log
sudo journalctl -u infiproxy-panel-update.service -n 160 --no-pager
```

## Рекомендуемая update policy

- web detection включен;
- production auto apply только после внешнего backup;
- module auto update выключен для major-sensitive runtimes или проверяется на
  canary;
- окно 05:00 server local time подтверждено командой `date`;
- утром monitoring проверяет `/ready`, failed units и client probes;
- перед planned major update тестируется restore;
- никогда не удаляется последняя известная рабочая version directory вручную.

## Допустимая policy для теста

- все auto updates выключены;
- `--check-all` вручную;
- один module update за раз;
- config backup и journal после каждого;
- panel update только при наличии tmux/SSH recovery path.
