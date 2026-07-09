# StealthHub Panel

StealthHub Panel — односерверная Rust-панель для управления пользователями,
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

Bootstrap делает весь базовый серверный цикл:

- ставит системные зависимости для сборки;
- ставит Rust stable через `rustup`, если `cargo` не найден;
- клонирует или обновляет исходники в `/opt/stealthhub-panel/source`;
- собирает release-бинарник;
- устанавливает панель в `/usr/local/bin/stealthhub-panel`;
- создает системного пользователя `stealthhub`;
- создает SQLite базу и runtime-каталоги;
- устанавливает `stealthhub-panel.service`;
- устанавливает systemd-шаблоны для proxy-ядер;
- раскладывает стартовые config-файлы ядер;
- запускает только саму панель.

После установки проверить сервис:

```bash
systemctl status stealthhub-panel.service
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
```

Пути на сервере:

```text
/opt/stealthhub-panel/source
/usr/local/bin/stealthhub-panel
/etc/stealthhub-panel/stealthhub-panel.env
/var/lib/stealthhub-panel/stealthhub.sqlite
/etc/systemd/system/stealthhub-panel.service
/etc/systemd/system/stealthhub-*.service
/opt/stealthhub/cores
/etc/stealthhub-cores
/var/log/stealthhub-cores
```

Панель по умолчанию слушает только localhost:

```env
STEALTHHUB_BIND=127.0.0.1:8080
STEALTHHUB_DB=sqlite:///var/lib/stealthhub-panel/stealthhub.sqlite?mode=rwc
STEALTHHUB_COOKIE_SECURE=true
STEALTHHUB_ENABLE_DEMO_USER=false
```

Настройки окружения:

```bash
sudo nano /etc/stealthhub-panel/stealthhub-panel.env
sudo systemctl restart stealthhub-panel.service
```

Первый вход:

```text
https://<your-domain>/admin/setup
```

Для HTTPS поставь Nginx или Caddy перед панелью. Готовый пример Nginx лежит в:

```text
deploy/nginx-stealthhub-panel.conf.example
```

## Обновление Панели

На сервере можно снова выполнить ту же одну команду:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash
```

Или обновить из уже установленного checkout:

```bash
cd /opt/stealthhub-panel/source
sudo bash deploy/bootstrap.sh
```

Файл `/etc/stealthhub-panel/stealthhub-panel.env` не перезаписывается. Если
нужно принудительно вернуть env к шаблону:

```bash
sudo bash /opt/stealthhub-panel/source/deploy/bootstrap.sh --force-env
```

## Установка Ядер

Панель готовит systemd-сервисы и каталоги для ядер, но не включает proxy-сервисы
автоматически. Сначала нужно установить бинарник ядра, проверить checksum и
подготовить финальный конфиг.

Поддержанные каталоги:

```text
/opt/stealthhub/cores/xray/current/xray
/opt/stealthhub/cores/sing-box/current/sing-box
/opt/stealthhub/cores/hysteria/current/hysteria
/opt/stealthhub/cores/tuic/current/tuic-server
```

Systemd-сервисы:

```text
stealthhub-xray.service
stealthhub-sing-box.service
stealthhub-hysteria.service
stealthhub-tuic.service
```

Установить или обновить ядро через проверенный архив:

```bash
sudo /opt/stealthhub-panel/source/deploy/cores/install-core.sh \
  --core xray \
  --version 26.3.27 \
  --url 'https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip' \
  --sha256 '<sha256-from-release>' \
  --binary xray
```

Импортировать заранее скачанный архив:

```bash
sudo /opt/stealthhub-panel/source/deploy/cores/install-core.sh \
  --core sing-box \
  --version 1.13.14 \
  --archive ./sing-box.tar.gz \
  --sha256 '<sha256>' \
  --binary sing-box
```

После настройки конфига ядра:

```bash
sudo systemctl enable --now stealthhub-xray.service
sudo systemctl status stealthhub-xray.service
```

Логика установки ядра:

```text
download/import archive
verify SHA256
extract to staging
run binary --version
install into /opt/stealthhub/cores/{core}/{version}
atomically switch current symlink
restart service only when --restart is passed
```

Скрипт не перезаписывает активный бинарник на месте. Новая версия кладется в
отдельный каталог, а `current` переключается атомарно.

## Локальный Запуск

```bash
STEALTHHUB_BIND=127.0.0.1:8080 \
STEALTHHUB_DB='sqlite://./stealthhub.local.sqlite?mode=rwc' \
STEALTHHUB_ENABLE_DEMO_USER=true \
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
stealthhub-panel/
├── Cargo.toml
├── Cargo.lock
├── crates/
│   ├── stealthhub-core/
│   ├── stealthhub-panel/
│   └── stealthhub-cli/
├── deploy/
│   ├── bootstrap.sh
│   ├── install.sh
│   ├── nginx-stealthhub-panel.conf.example
│   ├── stealthhub-panel.env.example
│   ├── stealthhub-panel.service
│   └── cores/
└── .github/
```

## License

StealthHub Panel is licensed under the **GNU Affero General Public License v3.0 or later**.

```text
AGPL-3.0-or-later
```

See:

- [`LICENSE`](./LICENSE)
- [`LICENSE.ru.md`](./LICENSE.ru.md)
- [`NOTICE`](./NOTICE)
