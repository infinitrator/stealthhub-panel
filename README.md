# Infiproxy

Infiproxy — односерверная Rust-панель для управления пользователями,
Mihomo/Clash-compatible подписками, правилами маршрутизации, профилями
протоколов и системными proxy-ядрами.

Основной способ развертывания: **VPS + bare metal + systemd**. Панель не
реализует proxy-протоколы сама: она управляет пользователями, настройками и
конфигами, а сетевую работу выполняют внешние ядра.

## Установка

Поддерживаемый основной путь: Ubuntu 22.04/24.04 или Debian 12 на чистом VPS.
Fedora/RHEL-like серверы с `dnf` также поддержаны bootstrap-скриптом для
установки зависимостей.

Одна команда для установки на сервер:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash
```

Проверить план установки без изменений на сервере:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash -s -- --check
```

Установка конкретной ветки, тега или коммита:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash -s -- --ref main
```

Установка из своего fork:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash -s -- \
  --repo https://github.com/<user>/<repo>.git \
  --ref main
```

Установка сразу с Nginx:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash -s -- --with-nginx
```

Принудительно пересоздать env-файл при обновлении:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash -s -- --force-env
```

Bootstrap делает весь базовый серверный цикл:

- ставит системные зависимости для сборки;
- ставит Rust stable через `rustup`, если `cargo` не найден;
- клонирует или обновляет исходники в `/opt/infiproxy/source`;
- собирает release-бинарник;
- устанавливает панель в `/usr/local/bin/infiproxy`;
- создает системного пользователя `infiproxy`;
- создает SQLite базу и runtime-каталоги;
- устанавливает `infiproxy.service`;
- устанавливает systemd-шаблоны для proxy-ядер;
- раскладывает стартовые config-файлы ядер;
- при `--with-nginx` устанавливает шаблон сайта в `/etc/nginx/sites-available/infiproxy.conf`;
- запускает только саму панель.

После установки проверить сервис:

```bash
systemctl status infiproxy.service
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
sudo infiproxy-manager
```

Пути на сервере:

```text
/opt/infiproxy/source
/usr/local/bin/infiproxy
/etc/infiproxy/infiproxy.env
/var/lib/infiproxy/infiproxy.sqlite
/etc/systemd/system/infiproxy.service
/etc/systemd/system/infiproxy-*.service
/opt/infiproxy/cores
/etc/infiproxy-cores
/var/log/infiproxy-cores
```

Панель по умолчанию слушает только localhost:

```env
INFIPROXY_BIND=127.0.0.1:8080
INFIPROXY_DB=sqlite:///var/lib/infiproxy/infiproxy.sqlite?mode=rwc
INFIPROXY_DB_MAX_CONNECTIONS=2
INFIPROXY_COOKIE_SECURE=true
INFIPROXY_ENABLE_DEMO_USER=false
INFIPROXY_ENABLE_DANGER_SHELL=true
```

Настройки окружения:

```bash
sudo nano /etc/infiproxy/infiproxy.env
sudo systemctl restart infiproxy.service
```

`INFIPROXY_ENABLE_DANGER_SHELL=true` включает owner-only break-glass shell во
вкладке System Danger Zone. Доступ есть только у первого админа, созданного при
первичной настройке.

SSH TUI:

```bash
sudo infiproxy-manager
```

Через TUI можно пройти установку/repair, открыть env, переключить danger shell,
перезапустить сервисы, посмотреть логи, открыть helper установки ядер и выполнить
root-level удаление: `panel`, `full` или `factory`.

Первый вход:

```text
https://<your-domain>/admin/setup
```

Если HTTPS ещё не настроен, открой панель через SSH-туннель:

```bash
ssh -L 8080:127.0.0.1:8080 root@<server>
```

После этого локально открой:

```text
http://127.0.0.1:8080/admin/setup
```

Для HTTPS поставь Nginx или Caddy перед панелью. Готовый пример Nginx лежит в:

```text
deploy/nginx-infiproxy.conf.example
```

## Обновление Панели

На сервере можно снова выполнить ту же одну команду:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash
```

Или обновить из уже установленного checkout:

```bash
cd /opt/infiproxy/source
sudo bash deploy/bootstrap.sh
```

Файл `/etc/infiproxy/infiproxy.env` не перезаписывается. Если
нужно принудительно вернуть env к шаблону:

```bash
sudo bash /opt/infiproxy/source/deploy/bootstrap.sh --force-env
```

## Установка Ядер

Панель готовит systemd-сервисы и каталоги для ядер, но не включает proxy-сервисы
автоматически. Сначала нужно установить бинарник ядра, проверить checksum и
подготовить финальный конфиг.

Поддержанные каталоги:

```text
/opt/infiproxy/cores/xray/current/xray
/opt/infiproxy/cores/sing-box/current/sing-box
/opt/infiproxy/cores/hysteria/current/hysteria
/opt/infiproxy/cores/tuic/current/tuic-server
```

Systemd-сервисы:

```text
infiproxy-xray.service
infiproxy-sing-box.service
infiproxy-hysteria.service
infiproxy-tuic.service
```

Установить или обновить ядро через проверенный архив:

```bash
sudo /opt/infiproxy/source/deploy/cores/install-core.sh \
  --core xray \
  --version 26.3.27 \
  --url 'https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip' \
  --sha256 '<sha256-from-release>' \
  --binary xray
```

Актуальные версии по официальным GitHub Releases на 2026-07-13:

```text
Xray stable:     v26.3.27
sing-box stable: v1.13.14
Hysteria stable: app/v2.10.0
TUIC stable:     tuic-server-1.0.0
```

Для Xray upstream также публикует более свежую prerelease-ветку. Для основной
установки оставлен stable release; prerelease лучше проверять на тестовом
пользователе перед переключением production.

Импортировать заранее скачанный архив:

```bash
sudo /opt/infiproxy/source/deploy/cores/install-core.sh \
  --core sing-box \
  --version 1.13.14 \
  --archive ./sing-box.tar.gz \
  --sha256 '<sha256>' \
  --binary sing-box
```

После настройки конфига ядра:

```bash
sudo systemctl enable --now infiproxy-xray.service
sudo systemctl status infiproxy-xray.service
```

Логика установки ядра:

```text
download/import archive
verify SHA256
extract to staging
run binary --version
install into /opt/infiproxy/cores/{core}/{version}
atomically switch current symlink
restart service only when --restart is passed
```

Скрипт не перезаписывает активный бинарник на месте. Новая версия кладется в
отдельный каталог, а `current` переключается атомарно.

## Локальный Запуск

```bash
INFIPROXY_BIND=127.0.0.1:8080 \
INFIPROXY_DB='sqlite://./infiproxy.local.sqlite?mode=rwc' \
INFIPROXY_ENABLE_DEMO_USER=true \
cargo run -p stealthhub-panel
```

Открыть:

```text
http://127.0.0.1:8080/admin/setup
http://127.0.0.1:8080/admin
http://127.0.0.1:8080/admin/users
http://127.0.0.1:8080/admin/settings
http://127.0.0.1:8080/admin/protocols
http://127.0.0.1:8080/admin/routing
http://127.0.0.1:8080/admin/cores
http://127.0.0.1:8080/admin/system
```

Создать тестового пользователя:

```bash
cargo run -p stealthhub-cli -- create-user --username test-local --traffic-limit-gb 10
cargo run -p stealthhub-cli -- list-users
```

## Проверка Проекта

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
bash -n deploy/bootstrap.sh
bash -n deploy/install.sh
bash -n deploy/cores/install-core.sh
```

## Основные Routes

```text
GET  /
GET  /admin/setup
POST /admin/setup
GET  /admin/login
POST /admin/login
POST /admin/logout
GET  /admin
GET  /admin/users
GET  /admin/settings
POST /admin/settings
GET  /admin/protocols
POST /admin/protocols/{name}/update
GET  /admin/routing
POST /admin/routing
GET  /admin/system
GET  /admin/cores
POST /admin/users/create
POST /admin/users/{id}/toggle
POST /admin/users/{id}/reset-token
POST /admin/users/{id}/delete
GET  /health
GET  /ready
GET  /sub/{token}/mihomo.yaml
GET  /rules/{name}
```

## Структура

```text
infiproxy/
├── Cargo.toml
├── Cargo.lock
├── crates/
│   ├── stealthhub-core/
│   ├── stealthhub-panel/
│   └── stealthhub-cli/
├── deploy/
│   ├── bootstrap.sh
│   ├── install.sh
│   ├── nginx-infiproxy.conf.example
│   ├── infiproxy.env.example
│   ├── infiproxy.service
│   └── cores/
└── .github/
```

## License

Infiproxy is licensed under the **GNU Affero General Public License v3.0 or later**.

```text
AGPL-3.0-or-later
```

See:

- [`LICENSE`](./LICENSE)
- [`LICENSE.ru.md`](./LICENSE.ru.md)
- [`NOTICE`](./NOTICE)
