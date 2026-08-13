# Система и SSH-TUI

Этот раздел описывает две разные плоскости управления сервером:

- веб-вкладку **System**, которая работает внутри непривилегированного процесса
  `infiproxy`;
- SSH-TUI `infiproxy-manager`, который запускается от `root` и предназначен для
  операций, действительно меняющих ОС.

> [!IMPORTANT]
> Наличие кнопки в **System** не выдает веб-процессу права `root`. Если действие
> вернуло `permission denied`, используйте `sudo infiproxy-manager`. Не следует
> исправлять это выдачей пользователю `infiproxy` неограниченного `sudo`.

## 1. Где находится граница ответственности

| Слой | Пользователь ОС | Назначение |
|---|---|---|
| Веб-панель | `infiproxy` | Пользователи, профили, маршруты, очередь модулей, просмотр состояния, allowlist-конфиги. |
| Panel updater | `root` | Получение исходников, сборка, backup, установка бинарника и rollback. |
| Module updater | `root` | Загрузка, проверка и атомарное переключение runtime-модулей. |
| SSH-TUI | `root` | Установка, HTTPS, systemd, модули, Headscale, MTProto и удаление. |
| Proxy-runtime | Обычно `infiproxy` | Передача proxy-трафика по своему серверному конфигу. |
| Headscale | `headscale` | Координация mesh-узлов и хранение собственного SQLite-состояния. |

Веб-панель намеренно не содержит произвольного терминала. Все команды в ней
сформированы кодом заранее; пользовательский ввод не подставляется в shell.

## 2. Вкладка System

Откройте **System** в левой навигации. Страница собирает информацию локально и
не обращается к внешним сервисам.

### 2.1. Верхняя строка состояния

| Поле | Источник | Как читать |
|---|---|---|
| **Deploy mode** | Константа сборки | В текущей версии — `systemd bare-metal`. |
| **Version** | Версия Cargo-пакета | Это версия приложения, а не Git commit и не версия модулей. |
| **Database** | Проверка SQLite | `ready` означает, что панель выполнила контрольный запрос. |
| **Cookie Secure** | `INFIPROXY_COOKIE_SECURE` | `enabled` требует HTTPS для отправки session cookie браузером. |

### 2.2. Host overview

| Карточка | Откуда берется значение | Ограничение |
|---|---|---|
| **OS** | `PRETTY_NAME` из `/etc/os-release` | Не подтверждает поддержку конкретного дистрибутива. |
| **Kernel** | `/proc/sys/kernel/osrelease` | Версия ядра Linux, не proxy-ядра. |
| **Uptime** | `/proc/uptime` | Время с последней загрузки VPS. |
| **Load** | `/proc/loadavg` | Среднее число выполняемых/ожидающих задач за 1, 5 и 15 минут. |
| **Memory** | `/proc/meminfo` | Панель показывает использованную память и процент. |
| **Root disk** | `df -k /` | Заполнение файловой системы, содержащей `/`. |

Load average нужно сопоставлять с числом vCPU. Например, длительный load `1.0`
на одном vCPU означает полную занятость, а на четырех vCPU оставляет запас.
Краткий пик не равен аварии; важна динамика вместе с памятью, диском и логами.

### 2.3. Runtime contract

Блок фиксирует ожидаемое расположение основных компонентов:

| Объект | Путь или unit |
|---|---|
| Бинарник панели | `/usr/local/bin/infiproxy` |
| Окружение | `/etc/infiproxy/infiproxy.env` |
| База панели | `/var/lib/infiproxy/infiproxy.sqlite` |
| Сервис | `infiproxy.service` |

Это диагностическая памятка, а не элементы управления.

### 2.4. Service control

HTTP-страница вызывает только read-only `systemctl is-active/is-failed` для
badge. Она не вызывает mutating `systemctl`, `sudo`, shell или произвольные
команды. Каждая строка показывает target, unit, config, рекомендуемый configtest
и точную root-команду применения. Их выполняет оператор через SSH-TUI.

Состояние определяется через `systemctl is-active`, затем `systemctl is-failed`:

| Badge | Значение |
|---|---|
| `active` | Unit запущен. Это еще не доказывает, что клиент может подключиться. |
| `inactive` | Unit известен systemd, но не работает. |
| `failed` | Последний запуск завершился ошибкой. |
| `unknown` | Unit отсутствует, systemd недоступен процессу или статус не распознан. |

> [!WARNING]
> Штатный `infiproxy.service` не имеет полномочий управлять systemd. Не добавляйте
> `infiproxy ALL=(ALL) NOPASSWD: ALL`.

### 2.5. Configuration workspace

Таблица на странице **System** только показывает пути и команды. Полный
allowlist-редактор находится во вкладке **Configs** и описан в
[разделе 11](11-CONFIGURATION.md).

### 2.6. Uninstall planner

Три красные кнопки не запускают удаление. Они открывают read-only runbook:

| Кнопка | Что показывает |
|---|---|
| **Preview panel-only removal** | План удаления control plane с сохранением runtime-конфигов и стороннего ПО. |
| **Preview full footprint removal** | План удаления панели, модулей, их конфигов, Headscale, Nginx-site и checkout. |
| **Preview factory footprint cleanup** | Более широкий план удаления каталога `/opt/infiproxy`; системные пакеты все равно не удаляются. |

Исполнение доступно только в **Danger zone** TUI. Перед ним обязательны backup и
проверка списка путей. Подробности приведены в
[разделе 12](12-BACKUP-RESTORE-UNINSTALL.md).

## 3. Запуск SSH-TUI

Выполните:

```bash
sudo infiproxy-manager
```

Если установлен `whiptail`, откроются диалоговые окна. Без него менеджер
использует быстрый текстовый fallback. Оба режима вызывают одни и те же функции.

### 3.1. Автозапуск после SSH-входа

Установщик размещает `/etc/profile.d/infiproxy-manager.sh`. Менеджер запускается
автоматически только когда одновременно выполнены условия:

- текущий UID равен `0`;
- присутствует `SSH_TTY`;
- stdin и stdout являются терминалом;
- `/usr/local/sbin/infiproxy-manager` исполняемый;
- `INFIPROXY_TUI_AUTO` не равен `0`;
- нет рекурсивного запуска через `INFIPROXY_TUI_ACTIVE`.

После выхода из TUI остается обычная shell-сессия. Чтобы пропустить TUI при
аварийной диагностике, подключитесь так:

```bash
ssh -t root@SERVER 'INFIPROXY_TUI_AUTO=0 bash -l'
```

Либо после обычного входа выберите **Exit to shell**.

## 4. Главное меню TUI

### 4.1. Overview and service status

Показывает `active` и `enabled` для панели и всех зарегистрированных модулей.
Модули читаются динамически из root-owned manifest registry, поэтому список не
ограничен встроенными именами.

Внизу печатаются локальные probes:

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
```

`health` проверяет жизнь процесса, `ready` — доступность SQLite. Обе проверки
нужны: живой процесс с недоступной БД не готов обслуживать панель.

### 4.2. Admin access and panel URL

Менеджер ищет первый `server_name` в Nginx-site панели.

- Если hostname найден, показывает `https://HOST/admin` и URL первого владельца
  `https://HOST/admin/setup`.
- Если hostname не найден, показывает команду SSH port forwarding и локальный
  URL `http://127.0.0.1:8080/admin`.
- Затем выполняет локальные `/health` и `/ready` с timeout 3 секунды.

Туннель с рабочей станции:

```bash
ssh -L 8080:127.0.0.1:8080 root@SERVER
```

После этого откройте `http://127.0.0.1:8080/admin`. При HTTP-тесте временно
потребуется `INFIPROXY_COOKIE_SECURE=false`; после появления HTTPS верните
`true`.

### 4.3. Runtime modules

Этот пункт управляет независимыми runtime-модулями. Все семь кнопок подробно
описаны в [разделе 8](08-MODULES-AND-UPDATES.md#tui-runtime-modules).

### 4.4. Restart and reload

| Пункт | Поведение |
|---|---|
| **Restart panel** | Перезапускает `infiproxy.service`. |
| **Validate and reload nginx** | Запускает `nginx -t`; reload выполняется только после успешной проверки. |
| **Validate and reload SSH** | Запускает `sshd -t`; reload выполняется только после успешной проверки. |
| **Restart all enabled modules** | Динамически перебирает manifest registry и рестартует только enabled units. |
| **Validate and restart Headscale** | Вызывает `headscale configtest`, затем рестарт. В текущей реализации ошибка `configtest` не останавливает рестарт из-за `|| true`; перед критичным изменением проверяйте вручную. |
| **Reboot server** | Выполняет `systemctl reboot` только после точного ввода `REBOOT`. |

Безопасный ручной порядок для Headscale:

```bash
sudo headscale -c /etc/headscale/config.yaml configtest
sudo systemctl restart headscale.service
sudo systemctl --no-pager --full status headscale.service
```

### 4.5. Logs and diagnostics

| Пункт | Команда и лимит |
|---|---|
| **Panel journal** | `journalctl -u infiproxy.service -n 120 --no-pager`. |
| **Module updater log** | Последние 160 строк `/var/lib/infiproxy-maintenance/module-update.log`. |
| **Panel updater log** | Последние 160 строк `/var/lib/infiproxy-maintenance/panel-update-run.log`. |
| **Nginx journal** | `journalctl -u nginx.service -n 120 --no-pager`. |
| **Failed systemd units** | `systemctl --failed --no-pager --full`. |

TUI намеренно не открывает бесконечный `journalctl -f`: bounded output быстрее и
не удерживает терминал. Для живой отладки используйте shell отдельно.

### 4.6. HTTPS and Cloudflare

| Пункт | Результат |
|---|---|
| **Install HTTPS dependencies** | Через `apt-get` или `dnf` устанавливает CA, Certbot, curl, Nginx, Python 3 и DNS-плагин Cloudflare; включает Nginx. Python здесь является зависимостью Certbot-плагина, а не runtime панели. |
| **Upsert Cloudflare A record** | Находит zone ID и создает либо обновляет A-record через Cloudflare API. |
| **Issue certificate with DNS-01** | Сохраняет API token с mode `0600` и вызывает Certbot DNS-01. |
| **Write nginx HTTPS config** | Создает HTTPS virtual host на `443`, redirect с `80`, проксирует к `127.0.0.1:8080`, затем проверяет и reload Nginx. |
| **Full guided setup** | Выполняет предыдущие шаги по порядку и выводит защищенный URL. |

Для токена Cloudflare достаточно доступа к одной зоне:

| Разрешение | Уровень |
|---|---|
| Zone / DNS / Edit | Выбранная DNS-зона. |
| Zone / Zone / Read | Выбранная DNS-зона. |

Не используйте Global API Key. Ограничьте token конкретной зоной и после
настройки проверьте `/root/.secrets/certbot/cloudflare.ini`: владелец `root`,
mode `0600`. Официальный порядок создания токена описан в
[Cloudflare API Tokens](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/).

Опция **Proxy through Cloudflare** относится только к hostname панели. Для
Headscale нужен отдельный DNS-only hostname: обычный Cloudflare HTTP proxy может
мешать протоколу координации и долгоживущим соединениям.

### 4.7. Panel updates

| Пункт | Поведение |
|---|---|
| **Check GitHub now** | Сравнивает локальный `git rev-parse HEAD` с `git ls-remote REPO REF`. Ничего не устанавливает. |
| **Update panel now** | Показывает сравнение, просит подтверждение, создает request-файл и запускает root updater. |
| **Show updater log** | Показывает последние 120 строк updater log. |
| **Restart timer and path watcher** | Перечитывает systemd и включает timer/path units. |

Если installed и latest commit совпадают, root updater завершает operation до
backup/build/install. Полная модель обновления описана в
[разделе 8](08-MODULES-AND-UPDATES.md#обновление-панели).

### 4.8. Panel environment

Открывает `/etc/infiproxy/infiproxy.env` в `$EDITOR`, `nano` или `vi`. Перед
открытием TUI нормализует каталог и права, а после выхода немедленно рестартует
панель.

> [!WARNING]
> В этом пункте нет автоматической проверки dotenv. Оставьте вторую SSH-сессию,
> после сохранения проверьте status и при ошибке исправьте файл из нее.

Поля перечислены в [разделе 11](11-CONFIGURATION.md#3-окружение-панели).

### 4.9. Guided deployment

Единый цикл предлагает в безопасном порядке:

1. Установить или восстановить панель из `/opt/infiproxy/source`.
2. При необходимости установить шаблон Nginx и заменить env с backup.
3. Настроить HTTPS через Cloudflare DNS-01.
4. Установить выбранные release-модули с проверкой целостности.
5. Собрать и настроить Telegram MTProxy.
6. Установить и настроить Headscale.
7. Показать URL и итоговое состояние units.

Отказ от необязательного шага не отменяет уже выполненные шаги. Мастер можно
запускать повторно; конфиги в большинстве путей сохраняются или предварительно
копируются.

Прямой запуск:

```bash
sudo infiproxy-manager --guided
```

### 4.10. Advanced tools

| Пункт | Назначение |
|---|---|
| **Install or repair panel** | Повторно запускает `deploy/install.sh --build`; можно добавить Nginx template либо принудительно заменить env с backup. |
| **Telegram MTProto configuration** | Первичная настройка, обновление upstream-файлов, import link и управление unit. |
| **Headscale hub configuration** | Установка release, конфиг, пользователи, pre-auth keys, проверка и logs. |
| **Manual verified archive import** | Запрашивает module, version, URL и SHA-256 и передает их безопасному core installer. |

#### Telegram MTProto configuration

| Кнопка | Что делает |
|---|---|
| **Guided initial setup** | Запрашивает публичный host, порт, локальный stats port, 1–16 workers и optional 32-hex secret; скачивает Telegram upstream-файлы, пишет env и печатает import URL. |
| **Refresh Telegram upstream config** | Обновляет `proxy-secret` и `proxy-multi.conf` с официальных Telegram endpoints. |
| **Show Telegram import link** | Читает порт и secret из env и формирует `https://t.me/proxy?...`. |
| **Enable and start service** | Выполняет `systemctl enable --now infiproxy-mtproto.service`. |
| **Restart service** | Перезапускает unit и показывает status. |

Если MTProxy binary еще не установлен, мастер сохраняет конфиг, но не запускает
service. Сначала обновите module `mtproto`, затем повторите запуск.

#### Headscale hub configuration

Все пункты этого подменю разобраны в
[разделе 9](09-HEADSCALE.md#headscale-в-ssh-tui).

### 4.11. Danger zone

| Пункт | Требуемое подтверждение |
|---|---|
| **Panel-only removal** | Точный ввод `DELETE INFIPROXY`. |
| **Full Infiproxy footprint removal** | Точный ввод `DELETE INFIPROXY`. |
| **Factory footprint cleanup** | Точный ввод `DELETE INFIPROXY`. |

До подтверждения TUI печатает полный набор команд. Режимы необратимы без
backup. **Factory** не означает побайтовое возвращение VPS к исходному образу и
не удаляет пакеты ОС, потому что установщик не знает, какие из них существовали
раньше.

## 5. systemd и автоматический запуск

### 5.1. Панель

`infiproxy.service` стартует после `network-online.target`, работает как
`infiproxy:infiproxy` и имеет `Restart=on-failure` с задержкой 3 секунды.

Hardening unit:

- `NoNewPrivileges=true` блокирует получение новых привилегий;
- `PrivateTmp=true` изолирует временный каталог;
- `ProtectHome=true` закрывает домашние каталоги;
- `ProtectSystem=strict` делает систему read-only, кроме `ReadWritePaths`;
- `MemoryDenyWriteExecute=true` затрудняет выполнение записываемой памяти;
- записывать разрешено только в state/config-каталоги панели и Headscale.

### 5.2. Maintenance timers

Оба timer запускаются каждые 15 минут, но worker внутри решает, наступил ли срок
проверки или maintenance window.

| Unit | Назначение |
|---|---|
| `infiproxy-panel-update.timer` | Плановая проверка/установка панели. |
| `infiproxy-panel-update.path` | Мгновенно реагирует на `panel-update-now.request`. |
| `infiproxy-module-update.timer` | Плановые проверки runtime-модулей. |
| `infiproxy-module-update.path` | Реагирует на `.request`, `.register`, `.remove` и Headscale requests. |

Проверка:

```bash
systemctl list-timers 'infiproxy-*'
systemctl status infiproxy-panel-update.path infiproxy-module-update.path
```

`Persistent=true` означает, что пропущенный timer запускается после следующей
загрузки. Панель и включенные runtime units также поднимаются systemd без ручной
инициализации.

## 6. Безопасное изменение SSH

Ошибочный `sshd_config` может закрыть единственный канал восстановления.
Используйте такой порядок:

1. Не закрывайте текущую root-сессию.
2. Откройте вторую SSH-сессию и убедитесь, что она работает.
3. Сделайте backup `/etc/ssh/sshd_config`.
4. Измените только один логический блок.
5. Выполните `sudo sshd -t`.
6. Используйте reload, а не restart.
7. Проверьте третий новый вход и только затем закройте старые сессии.

```bash
sudo cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.pre-infiproxy-change
sudo sshd -t
sudo systemctl reload ssh.service
```

Для длительной установки используйте `tmux`; он сохраняет процесс при обрыве
клиента, но не исправляет сетевую или server-side проблему SSH:

```bash
tmux new -s infiproxy-install
sudo infiproxy-manager --guided
```

Отсоединение: `Ctrl-b`, затем `d`. Возврат: `tmux attach -t infiproxy-install`.

## 7. Рекомендуемый эксплуатационный порядок

### Надежный вариант

1. Держите панель на loopback и публикуйте только через отдельный HTTPS virtual host.
2. Ограничьте SSH ключами, firewall и известными административными адресами.
3. Выполняйте privileged-операции только из TUI в `tmux` и при открытой резервной SSH-сессии.
4. Перед обновлением или конфигом проверяйте backup и свободное место.
5. Валидируйте конфиг родным бинарником до reload/restart.
6. После действия проверяйте unit, journal, `/ready` и реальное клиентское подключение.

### Допустимый тестовый вариант

1. Не публикуйте панель, используйте SSH tunnel.
2. Настройте один runtime и одного тестового пользователя.
3. Оставьте автоматическую установку обновлений выключенной, но выполняйте проверки.
4. Сохраняйте ручной backup SQLite и изменяемого конфига перед каждым тестом.

## 8. Связанные разделы

- [Конфигурационные файлы](11-CONFIGURATION.md)
- [Модули и обновления](08-MODULES-AND-UPDATES.md)
- [Headscale](09-HEADSCALE.md)
- [Бэкапы и удаление](12-BACKUP-RESTORE-UNINSTALL.md)
- [Диагностика](14-TROUBLESHOOTING-AND-REFERENCE.md)
