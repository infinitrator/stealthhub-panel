# Система и SSH-TUI

Infiproxy разделяет веб-панель и операции уровня ОС. Веб-процесс `infiproxy`
управляет SQLite, пользователями, профилями и desired state. Root-reconciler
применяет проверенное состояние. SSH-менеджер запускается от `root` и вызывает
только заранее описанные операции: произвольного shell в панели нет.

## 1. Запуск и совместимость

Основной запуск:

```bash
sudo infiproxy-manager
```

Установщик ставит оболочку `/usr/local/sbin/infiproxy-manager` и бинарник
`/usr/local/libexec/infiproxy-tui`. Оболочка передает интерактивный запуск в
полноэкранный Rust TUI. Для восстановления старого сценария доступен явный
режим `--legacy`; он не является основным интерфейсом и сохраняет старые
операции, которых нет в новом TUI.

Без интерактивного терминала TUI не запускается. Для автоматизации есть
ограниченные команды:

```bash
sudo infiproxy-manager status
sudo infiproxy-manager status --json
sudo infiproxy-manager diagnostics
sudo infiproxy-manager update check
```

`status --json` предназначен для локального мониторинга. Он содержит только
санитарно обработанные статусы и не читает пароли, токены, UUID или private key.

Минимальный размер терминала — 80x24. Поддерживаются truecolor, 256 цветов,
базовый ANSI, `NO_COLOR=1` и ASCII-режим `INFIPROXY_TUI_ASCII=1`.

## 2. Клавиатура

| Клавиша | Действие |
|---|---|
| `↑`/`↓`, `j`/`k` | Выбрать раздел или действие. |
| `Tab` / `Shift-Tab` | Перейти между навигацией, действиями и выводом. |
| `Enter` | Открыть раздел/форму или перейти к следующему полю. |
| `Esc` | Вернуться либо отменить форму без операции. |
| `R` | Повторно собрать локальное состояние. |
| `PgUp`/`PgDn`, `Home`/`End` | Прокрутить вывод. |
| `?` | Открыть справку. Любая клавиша закрывает её. |
| `Q`, `Ctrl-C` | Завершить TUI с восстановлением терминала. |

После запуска отображаются hostname, состояние панели, примененная ревизия,
reconcile state и доступные runtime-модули. Наблюдения обновляются по `R`;
пока идет операция, повторный запуск блокируется.

## 3. Разделы TUI

### Dashboard

Показывает состояние процесса панели, desired/applied generation, reconcile,
uptime, локальные `/health` и `/ready`, слушающие сокеты, SQLite и URL панели.
`active` или успешный listener-check не доказывает успешный proxy handshake.
Действие **Run reconciliation** публикует только ограниченный запрос
`reconcile` и требует подтверждения `APPLY`.

### System

Доступны только заранее заданные действия:

- **Restart panel** — `infiproxy.service`;
- **Validate / reload nginx** — сначала `nginx -t`, затем reload;
- **Validate / reload SSH** — сначала `sshd -t`, затем reload;
- **Restart enabled runtimes** — только зарегистрированные и enabled units.

Имена systemd не вводятся оператором. Веб-вкладка System остается read-only;
для изменения окружения и SSH-конфигурации используйте legacy recovery и
сохраните вторую SSH-сессию.

### Users и Profiles

Это read-only обзор SQLite, максимум 500 строк. Здесь намеренно не показываются
credential values, subscription tokens, runtime UUID и `config_json`. Изменения
делаются в авторизованной веб-панели, после чего TUI показывает новое состояние.

### Runtimes

Реестр модулей читается из root-owned manifest registry, поэтому список не
зашит в TUI. Для зарегистрированного модуля доступны **Check module release**,
**Install / update verified module**, **Start**, **Stop**, **Restart** и
**Remove runtime registration**. Update использует существующий проверяющий
updater, сохраняет конфигурацию и атомарно меняет версию. Stop требует `STOP`,
удаление — `REMOVE`, остальные изменяющие действия — `APPLY`.

### Updates

**Check pinned GitHub source** читает единый root-owned источник из
`/etc/infiproxy-update.conf`. **Request update now** создает request-файл для
того же updater, а не выбирает ветку из SQLite или из поля формы. **Enable timer
and path watcher** включает уже установленные systemd units. Результат `Requested`
не равен `Applied`: примененную ревизию нужно проверить после сборки и readiness.

### Logs и Diagnostics

Logs разрешает выбрать только известный unit из системных и зарегистрированных
модулей и читает не более 120 строк. Diagnostics предоставляет failed units,
disk capacity, listeners и DB/reconcile checks. Нет произвольного имени unit,
`journalctl -f`, сетевого адреса или команды.

### Secrets

TUI показывает только имена ссылок из `/etc/infiproxy/secrets.d`. **Store / rotate**
читает значение скрытым вводом через stdin root-helper; значение не попадает в
argv, вывод, журнал или снимок TUI. Файл публикуется атомарно как root `0600`.
**Delete** и **Adopt** требуют явного подтверждения. После изменения запускается
reconcile. Содержимое секрета восстановить через TUI нельзя.

### HTTPS

Встроенный bounded flow использует Cloudflare DNS-01 и Certbot:

1. **Install HTTPS dependencies** устанавливает необходимые пакеты средствами
   дистрибутива.
2. **Configure DNS + certificate + HTTPS** проверяет доменную область,
   hostname, email и IPv4, создает/обновляет DNS A-запись, сохраняет token
   root-only, выпускает сертификат и проверяет nginx.
3. **Renew existing certificates** вызывает `certbot renew`, затем `nginx -t`
   и reload.

Cloudflare token передается через stdin и не печатается. Используйте token с
минимальными правами DNS Edit и Zone Read для одной зоны, не Global API Key.
После успеха URL панели отображается в результате операции. Если DNS/HTTPS еще
не настроен, используйте SSH-туннель:

```bash
ssh -L 8080:127.0.0.1:8080 root@SERVER
```

### Deployment

Guided deployment — это набор ограниченных шагов, а не отдельный privileged
язык сценариев: readiness/repair, HTTPS, установка проверенного модуля и
финальная диагностика. Шаги можно выполнять повторно; завершение одного шага
помечается только в текущем сеансе TUI. Непрошедший шаг не маскируется как
успешный, а установка runtime не включает пользовательские профили автоматически.

### Danger

Доступны preview panel/full/factory, удаление и reboot. Перед удалением
показывается план. Удаление требует точного текста `DELETE INFIPROXY`, reboot —
`REBOOT`. `factory` удаляет известный footprint Infiproxy и checkout, но не
возвращает VPS побайтно к образу и не удаляет пакеты, если нельзя доказать, что
их установил Infiproxy.

## 4. Граница привилегий и восстановление

Операции TUI проходят через
`/usr/local/libexec/infiproxy-manager-operations.sh`. Rust формирует фиксированный
verb и bounded аргументы, а root-оболочка повторно проверяет module ID, service
allowlist, secret reference, подтверждение и арность. Пользовательские строки
никогда не выполняются как shell-программа. Команды запускаются с ограниченным
`PATH`, без `BASH_ENV`, с лимитом вывода и таймаутом. При timeout или отмене
завершается process group.

При обычном выходе, ошибке, `Ctrl-C` или panic TUI восстанавливает raw mode,
alternate screen и cursor. Обрыв SSH может прервать операцию после публикации
запроса; после повторного входа сначала нажмите `R` и проверьте systemd,
reconcile и updater state, а не запускайте действие вслепую.

Если новый бинарник недоступен после неполной установки:

```bash
sudo infiproxy-manager --legacy
sudo systemctl status infiproxy.service
sudo journalctl -u infiproxy.service -n 120 --no-pager
```

Не выдавайте веб-пользователю общий `sudo` и не заменяйте ограничения TUI на
web-shell.

## 5. Безопасный эксплуатационный порядок

1. До изменения SSH держите текущую root-сессию и откройте вторую.
2. Работайте в `tmux`, если установка или update длится долго.
3. Перед repair/update/danger проверьте backup и свободное место.
4. После операции проверьте `status --json`, unit journal, `/ready` и реальный
   клиентский handshake.
5. Для panel update помните: `Requested`, `Built` и `Applied` — разные состояния.

Подробности по модулям, резервным копиям и uninstall находятся в
[модулях и обновлениях](08-MODULES-AND-UPDATES),
[бэкапах](12-BACKUP-RESTORE-UNINSTALL) и
[операционной безопасности](13-SECURITY-OPERATIONS).
