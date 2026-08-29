# Быстрый старт и первая настройка

[К оглавлению](Home) | [Далее: архитектура и сети](02-ARCHITECTURE-AND-NETWORKING)

## Цель первого запуска

После прохождения этого раздела должны выполняться четыре независимые проверки:

1. `infiproxy.service` активен и `/ready` отвечает `ready`.
2. создан первый admin-owner, панель доступна по защищенному каналу;
3. установлен и вручную доведен до рабочего состояния хотя бы один proxy-runtime;
4. тестовый пользователь получает Mihomo YAML без `REPLACE_WITH_*` и без
   отсутствующих секретов.

Успех только первого пункта означает, что работает control plane, но еще не
означает, что прокси-трафик проходит.

## 1. Подготовьте VPS

### Рекомендуемые ОС

- Ubuntu Server 24.04 LTS — основной рекомендуемый вариант;
- Ubuntu Server 22.04 LTS — поддерживаемый консервативный вариант;
- Debian 12 — минимальный и стабильный вариант;
- Fedora/RHEL-подобная система с `dnf` — bootstrap поддерживает, но путь
  установки тестировался менее широко, чем Debian/Ubuntu.

Нужны `root`/`sudo`, systemd, публичный IPv4, доступ к GitHub и достаточно места
для Rust-сборки. Для слабого VPS разумно иметь не менее 1 ГиБ RAM и swap на
время компиляции. После сборки сама панель легкая; QUIC-runtime могут требовать
больше CPU и памяти под нагрузкой.

### Перед установкой соберите данные

| Данные | Пример | Зачем |
|---|---|---|
| IP VPS | `203.0.113.10` | DNS A-записи и firewall. |
| Панельный hostname | `panel.example.com` | HTTPS панели. |
| Email Let's Encrypt | `admin@example.com` | Уведомления сертификата. |
| Cloudflare zone | `example.com` | Поиск зоны через API. |
| API token | scoped token | Создание DNS и DNS-01 challenge. |

Для Cloudflare создайте отдельный token только для нужной зоны. Минимально
понадобятся чтение зоны и изменение DNS. Не используйте Global API Key. Token
будет записан root-TUI в `/etc/letsencrypt/cloudflare.ini` с режимом `0600`.

### Спланируйте порты

Значения по умолчанию:

| Протокол | Адрес/порт | Публичный |
|---|---|---|
| Панель | `127.0.0.1:8080/tcp` | нет |
| Nginx | `80/tcp`, `443/tcp` | да |
| Hysteria2 starter | `443/udp` | после настройки |
| TUIC starter | `11443/udp` | после настройки |
| Trojan TLS starter | `12443/tcp` | после настройки |
| Snell v5 starter | `13443/tcp` | после настройки |
| Mieru TCP starter | `14443/tcp` | после настройки |

`443/tcp` Nginx и `443/udp` Hysteria не конфликтуют: протокол транспорта входит
в идентификатор сокета. Два процесса конфликтуют только при совпадении IP,
порта **и** TCP/UDP.

## 2. Защитите SSH-сеанс

Установка компилирует Rust и может пережить короткий сетевой разрыв лучше внутри
`tmux`:

```bash
sudo apt-get update
sudo apt-get install -y tmux
tmux new -s infiproxy-install
```

Отсоединиться без остановки процесса: `Ctrl-b`, затем `d`.

Вернуться:

```bash
tmux attach -t infiproxy-install
```

Проверить сеансы:

```bash
tmux list-sessions
```

`tmux` сохраняет процесс при обрыве SSH, но не при перезагрузке VPS. После
возврата сначала прочитайте оставшийся вывод, не запускайте bootstrap второй раз
вслепую.

## 3. Запустите установку одной командой

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh | sudo bash -s -- --guided --with-nginx
```

Bootstrap выполняет следующее:

1. определяет `apt-get` или `dnf`;
2. ставит build tools, Git, curl, OpenSSL headers, SQLite, архиваторы и TUI;
3. при отсутствии Cargo загружает rustup и ставит stable minimal toolchain;
4. клонирует/синхронизирует репозиторий в `/opt/infiproxy/source`;
5. checkout-ит `main` либо заданный `--ref`;
6. собирает `stealthhub-panel` и служебные Rust-helper в release mode;
7. запускает идемпотентный `deploy/install.sh`;
8. создает пользователя `infiproxy`, каталоги, конфиги и systemd units;
9. запускает панель, panel updater, module updater и path watchers;
10. открывает guided TUI через `/dev/tty`.

> [!CAUTION]
> Команда `curl | sudo bash` исполняет текущий код ветки `main` с root-правами.
> Для контролируемого production-развертывания сначала скачайте скрипт,
> проверьте его и укажите immutable tag/commit через `--ref`.

Пример с собственной ревизией:

```bash
curl -fsSL https://raw.githubusercontent.com/infinitrator/stealthhub-panel/main/deploy/bootstrap.sh -o /tmp/infiproxy-bootstrap.sh
less /tmp/infiproxy-bootstrap.sh
sudo bash /tmp/infiproxy-bootstrap.sh --ref <commit-or-tag> --guided --with-nginx
```

## 4. Пройдите Guided deployment

TUI предлагает один цикл, но каждый необязательный этап можно пропустить и
запустить позднее командой `sudo infiproxy-manager --guided`.

### Install or repair panel

- **Yes** — повторно использует единый `deploy/install.sh` из локального source;
- **Install nginx template** — выбирайте Yes на новом VPS;
- **Overwrite panel env template** — обычно No; Yes делает backup существующего
  env и заменяет его шаблоном.

Повторная обычная установка сохраняет существующие env, core configs, SQLite и
выключенные оператором модули.

### HTTPS with Cloudflare DNS-01

Введите zone, hostname панели, email, публичный IPv4 и API token.

- **Proxy panel traffic through Cloudflare?** — допустимы оба варианта. Для
  простого origin HTTPS можно оставить No; при Yes Cloudflare становится
  дополнительным reverse proxy перед Nginx.
- TUI создает/обновляет A-запись, сохраняет token, получает сертификат DNS-01,
  пишет Nginx site и делает `nginx -t` перед reload.
- Панель должна оставаться на `127.0.0.1:8080`; наружу смотрит только Nginx.

### Install verified proxy modules

Установка бинарника не равна настройке сервера. Для первого теста лучше выбрать
**один** runtime, затем согласовать его server config и Mihomo profile.

Рекомендуемый порядок:

1. Mihomo `v1.19.30` для новых VLESS + REALITY + XHTTP/TCP профилей;
2. Hysteria2 как отдельный UDP/QUIC fallback;
3. TUIC как второй QUIC fallback;
4. sing-box `v1.13.20` для SS2022 + ShadowTLS и проверенных fallback-профилей;
5. Xray `v26.3.27` как фиксированный VLESS REALITY compatibility fallback;
6. Mihomo для AnyTLS, Trojan, Snell v5 и Mieru TCP.

Не включайте systemd unit, пока placeholder-конфиг не заменен и не прошел
валидатор конкретного ядра.

## 5. Проверьте control plane

```bash
sudo systemctl --no-pager --full status infiproxy.service
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/ready
sudo journalctl -u infiproxy.service -n 100 --no-pager
```

Ожидается:

```text
ok
ready
```

`/health` проверяет жив ли HTTP-процесс. `/ready` дополнительно выполняет
`SELECT 1` через SQLite. Рабочий `/health` при ошибке `/ready` означает проблему
с БД, правами или путем, а не с listener.

Если видите `unable to open database file`, проверьте:

```bash
sudo install -d -o infiproxy -g infiproxy -m 0750 /var/lib/infiproxy
sudo find /var/lib/infiproxy -maxdepth 1 -name 'infiproxy.sqlite*' \
  -exec chown infiproxy:infiproxy {} + \
  -exec chmod 0640 {} +
sudo systemctl restart infiproxy.service
```

## 6. Создайте первого владельца

С HTTPS откройте:

```text
https://panel.example.com/admin/setup
```

Без HTTPS создайте tunnel на своем компьютере:

```bash
ssh -L 8080:127.0.0.1:8080 root@203.0.113.10
```

Откройте `http://127.0.0.1:8080/admin/setup`.

Поля:

- **Setup token**: случайное значение, напечатанное installer/TUI;
- **Username**: 3–64 символа;
- **Password**: минимум 12 символов;
- **Confirm password**: точное повторение;
- **Create admin**: атомарно создает первую admin-запись — владельца.

Именно owner может управлять panel update и runtime-модулями через
веб. Не удаляйте и не изменяйте первую admin-запись напрямую в SQLite без
проверенного recovery-плана.

## 7. Заполните Settings

В `/admin/settings`:

- **Panel name** — отображаемое имя;
- **Subscription host** — публичный HTTPS hostname, откуда Mihomo скачивает YAML
  и rule-provider; указывается host, без path;
- **Node host** — hostname/IP proxy endpoint, подставляемый в профили;
- **Panel automatic updates** — на первом production-развертывании разумно
  выключить до создания внешнего backup;
- **Maintenance time** — локальное время VPS, по умолчанию `05:00`.

Нажмите **Save Settings**. Проверьте, что subscription URL использует внешний
hostname и доступен клиентскому устройству.

## 8. Настройте первый runtime и профиль

Полный порядок описан в [Proxy-протоколах](06-PROXY-PROTOCOLS), но контрольный
алгоритм всегда одинаков:

1. установить модуль;
2. получить/создать серверные ключи, UUID, пароли и сертификаты;
3. записать server config в `/etc/infiproxy-cores/<core>/`;
4. выполнить валидатор бинарника;
5. запустить и включить systemd unit;
6. проверить listening socket и journal;
7. внести те же endpoint/публичные параметры в Mihomo profile;
8. добавить значения его secret names в `secret_values`;
9. включить профиль;
10. скачать YAML и проверить на клиенте.

Никогда не начинайте с шага 9: включенный профиль с отсутствующими secret values
генерируется с непригодными placeholder-значениями.

## 9. Создайте тестового пользователя

В `/admin/users`:

- **Username**: например `test-phone`;
- **Traffic limit, GB**: пусто или `0` для unlimited;
- **Expires in days**: `1` для короткого теста либо пусто/`0` без срока;
- **Create**: создает UUID и случайный subscription token.

Нажмите `open`, затем **Download YAML**. Перед импортом откройте YAML текстом и
убедитесь, что в нем нет:

```text
REPLACE_WITH_
node.infiproxy.local
xray.reality.public_key
singbox.ss2022.password
```

Наличие имени секрета вместо его значения означает, что секрет не сохранен.

## 10. Финальная проверка

```bash
sudo infiproxy-manager
sudo infiproxy-module-update --check-all
sudo systemctl --failed --no-pager --full
sudo ss -lntup
```

Проверьте с клиентского устройства:

1. HTTPS панели без certificate warning;
2. загрузку subscription YAML;
3. загрузку каждого включенного `/rules/<slug>`;
4. TCP и UDP через выбранный proxy-runtime;
5. DNS resolution и отсутствие утечки маршрутов согласно правилам;
6. повторное подключение после `systemctl restart <unit>`;
7. сохранность подключения после перезагрузки VPS.

## Минимально допустимая настройка

- панель только через SSH tunnel;
- один пользователь без quota;
- один полностью настроенный и проверенный runtime;
- automatic updates выключены;
- локальный SQLite backup перед каждым изменением.

## Рекомендуемая настройка

- отдельный HTTPS hostname панели;
- owner с длинной уникальной passphrase;
- минимум два транспорта с разными отказными характеристиками: один TCP и один
  UDP/QUIC;
- rule sets протестированы на контрольных доменах;
- automatic updates в ночном окне, внешний backup и мониторинг `/ready`;
- firewall открывает только SSH, Nginx и реально используемые proxy-порты;
- ежемесячная проверка восстановления на отдельном VPS.
