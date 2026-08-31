# Архитектура адаптеров

[Назад: релиз и совместимость](15-RELEASE-AND-COMPATIBILITY) | [К оглавлению](Home) | [Далее: runtime compatibility](17-RUNTIME-COMPATIBILITY)

Эта страница объясняет границу расширения Infiproxy. Она нужна разработчикам и
операторам, которые хотят понять, почему профиль, runtime-модуль и системный
ресурс являются разными сущностями.

## Три типа адаптеров

| Тип | За что отвечает | Чего не делает |
|---|---|---|
| Protocol adapter | Схема полей, проверка профиля, ссылки на секреты, участие пользователей, клиентский proxy object и server fragment | Не запускает сервис и не выбирает команды |
| Core adapter | Способности runtime, сборка полного конфига, native validation, атомарная установка, управление сервисом, health/listener checks и rollback | Не знает HTTP-запросов и страниц панели |
| Infrastructure adapter | Отдельный инфраструктурный ресурс, например subscription frontend или DNS readiness | Не подменяет protocol/core adapter |

Generic storage, subscription assembly и reconciler работают со стабильными
интерфейсами и capabilities. Они не содержат ветвлений по конкретным именам
протоколов.

## Идентичность и версии схем

Adapter ID является стабильной lowercase-строкой. Конфигурация профиля хранится
как JSON вместе с положительной schema version. Manifest объявляет API version,
ID, отображаемое имя и контракт адаптера. Смена смысла существующего поля без
миграции schema version нарушает совместимость.

Protocol ID одновременно является требуемой core capability. Core может быть
выбран только если он явно объявляет эту capability. Объявление должно совпадать
с тем, что composer действительно принимает; regression tests проверяют этот
контракт для встроенных runtime.

## Реестры

`protocol_registry()` и `core_registry()` собираются из доверенного кода текущего
бинарника. Встроенные protocol/core/infrastructure adapters регистрируются при
старте процесса. Повторяющийся ID, несовместимая API version или некорректный
manifest отклоняются.

Файлы `deploy/modules.d/*.module` описывают установку и обновление runtime-
бинарников. Они не загружают Rust-код, не являются plugin ABI и сами по себе не
добавляют capability в `CoreRegistry`. Для нового типа core нужны реализация
`CoreAdapter`, регистрация в бинарнике, тесты и новый выпуск панели.

## ProtocolAdapter

Встроенный protocol adapter владеет:

- manifest и набором configuration fields;
- проверкой типов, обязательных значений и допустимых диапазонов;
- обнаружением SecretRef без раскрытия значения;
- декларацией user participation и типа listener;
- построением client proxy object для Mihomo subscription;
- построением server fragment для выбранного совместимого core;
- composition metadata: protocol, transport, security, maturity и проверенный
  runtime baseline.

Секреты передаются через redacted resolver на минимально необходимой границе.
Они не должны попадать в manifest, desired snapshot, operation summary или
логи.

## CoreAdapter

Core adapter объявляет capabilities, service unit, selection priority и точную
проверенную версию. Он отвечает за:

1. сборку server fragments в полный candidate config;
2. структурную и, когда runtime поддерживает это, native validation;
3. snapshot текущего состояния;
4. атомарную замену файла с безопасными owner/mode;
5. enable/disable/reload/restart только фиксированного service unit;
6. проверку health и ожидаемых/запрещённых listeners;
7. восстановление snapshot при ошибке.

HTTP-поля не могут задавать executable, путь или shell-команду. Все такие
значения зафиксированы в доверенном adapter package.

## Infrastructure adapters

`subscription-frontend` владеет только выделенным Nginx vhost подписки. Он
проверяет уже выданный сертификат, конфликты `server_name`, синтаксис Nginx,
HTTPS readiness и listener. Выдача сертификата остаётся отдельной root-
операцией установщика/TUI.

`node-readiness` проверяет DNS узла без захвата чужого cover vhost. Protocol
adapters не содержат Nginx- или certificate-логики.

## Inventory и состояние

Панель показывает два разных слоя:

- module inventory: установлен ли runtime-бинарник и какая версия записана
  root updater;
- adapter/reconciliation state: существует ли adapter в текущем бинарнике,
  выбран ли он desired graph и применён ли соответствующий ресурс.

Наличие скачанного бинарника не означает, что core зарегистрирован или активен.
И наоборот, adapter может присутствовать в бинарнике, но быть unavailable из-за
отсутствующей или несовместимой runtime version.

## Добавление адаптера

Минимальный безопасный процесс:

1. определить стабильный ID, schema и capability;
2. реализовать protocol или core trait без ветвления в generic registry;
3. добавить точный runtime pin и проверяемый module manifest, если нужен бинарник;
4. зарегистрировать adapter в trusted bootstrap;
5. добавить unit tests для schema, renderer/composer, secrets и capability drift;
6. добавить runtime compatibility test точной версии;
7. обновить таблицы совместимости и операторскую документацию;
8. пройти полный CI и контролируемый canary до production rollout.

Транзакционный цикл, статусы и crash recovery описаны на странице
[Reconciliation и desired state](09-RECONCILIATION-AND-DESIRED-STATE). Подробный
разработческий контракт находится в
[`docs/adapter-contract.md`](../docs/adapter-contract.md).
