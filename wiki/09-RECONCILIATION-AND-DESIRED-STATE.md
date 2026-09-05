# Desired state и reconciliation

[Назад: модули](08-MODULES-AND-UPDATES) | [К оглавлению](Home) |
[Далее: System и SSH manager](10-SYSTEM-AND-TUI)

## 1. Зачем нужен reconciler

SQLite хранит намерение control plane, а runtime config и systemd отражают
фактический data plane. Простая запись формы прямо в live config могла бы
оставить часть runtimes обновленной, а часть - старой. Infiproxy поэтому
использует поколения и отдельный root worker.

Схема:

    web mutation
      -> SQLite transaction + desired_generation
      -> bounded reconcile.request
      -> root worker
      -> adapters build complete candidates
      -> validate all
      -> snapshot all
      -> atomic install and activation
      -> health/listener/user checks
      -> applied_generation

Request file только будит worker и содержит api_version + generation. В нем нет
commands, paths, executable names или secret values.

## 2. Desired и applied generation

- desired_generation - последнее принятое runtime-affecting намерение.
- applied_generation - последнее поколение, полностью подтвержденное worker.
- Равенство означает convergence только для проверок, реализованных adapters.
- desired > applied означает pending, applying, failure или recovery condition.

Runtime-affecting операции:

- create user и rotate runtime identity;
- active username change;
- enable/disable/delete или quota/expiry edit, если меняется effective access;
- автоматический crossing UTC expiry deadline;
- изменение enabled profile, endpoint или adapter config;
- изменение panel settings, участвующих в infrastructure resources;
- изменение routing state, если оно входит в generated client state.

Будущий expiry сам по себе не создает generation при сохранении: она возникает
один раз в момент crossing. Reset subscription token меняет только bearer URL и
не создает runtime generation.

## 3. Статусы

| Статус | Значение | Действие оператора |
|---|---|---|
| Pending | Desired state записан, worker еще не завершил | Подождать path/timer, проверить request |
| Applying | Идет привилегированная transaction | Не запускать параллельные ручные изменения |
| Applied | Все candidates опубликованы и проверки прошли | Выполнить внешний client canary |
| Failed | Ошибка до live mutation или безопасный отказ | Исправить config/secret/runtime и повторить |
| RolledBack | Live mutation началась, но previous state восстановлен | Найти первичную ошибку до нового apply |
| Unsupported | Adapter/capability/schema отсутствует | Установить совместимый adapter/runtime |
| RecoveryRequired | Автоматическая компенсация не доказала known-good state | Остановить изменения и восстановить вручную |

Названия в SQLite хранятся в kebab-case, например rolled-back и
recovery-required.

## 4. Планирование

Worker загружает полный DesiredState:

- profiles;
- effectively allowed users;
- settings;
- infrastructure resources.

Protocol registry проверяет schema и строит client/server semantics. Core
registry выбирает runtime только по capabilities, installation state и
deterministic priority. Infrastructure adapters добавляют subscription
frontend и node DNS readiness.

До изменения live state проверяются:

- adapter API/schema versions;
- наличие protocol/core adapters;
- required capabilities;
- уникальность listener network+port;
- dependency graph infrastructure resources;
- secret references;
- runtime compatibility pin/readiness.

Unknown profile или future schema сохраняется в inventory как historical/
unsupported; данные не удаляются автоматически.

### Lifecycle-driven generation

`users` является authoritative state. `user_lifecycle_state` хранит только
derived access checkpoint и optional pending generation. При старте panel один
repair scan восстанавливает missing/stale checkpoints и замечает пропущенный
expiry. После него 30-секундный цикл проверяет deadline crossings через partial
index `users(expires_at)` вместо полного сканирования таблицы.

Crossing и увеличение generation фиксируются одной SQLite transaction. Pending
generation очищается только после атомарной публикации bounded request, поэтому
ошибка filesystem не теряет intent, а restart не увеличивает generation заново.
HTTP subscription endpoint вычисляет состояние прямо из `users` с текущим UTC и
блокирует expired user даже до следующего background tick.

Для `PerUserUuid` только allowed users попадают в server fragment. Для
`SharedCredential` adapter не получает индивидуальный authorization set, а для
`None` users не участвуют. Generic reconciler не содержит protocol-specific
ветвей. Уже выданный shared credential остается рабочим до общей ротации.

## 5. Candidate transaction

Для поколения G reconciler:

1. Берет process-wide lock.
2. Сравнивает G с уже applied generation.
3. Создает private transaction directory.
4. Рендерит complete candidate для каждого затронутого runtime/resource.
5. Проверяет структуру всех candidates.
6. Запускает native validators там, где runtime их предоставляет.
7. Создает snapshots live configs и enabled/active service state.
8. Повторно проверяет, что desired generation не изменился.
9. Атомарно заменяет configs.
10. Активирует/останавливает services в deterministic order.
11. Проверяет service health, required и forbidden listeners.
12. Для поддерживаемых runtimes сравнивает expected/observed user IDs.
13. Compare-and-swap публикует applied_generation=G.

Полная validation всех candidates выполняется до первой live mutation. Поэтому
ошибка одного JSON/YAML не должна оставлять частично примененный набор.

## 6. Journal phases

Root state хранится в:

    /var/lib/infiproxy-maintenance/reconcile

Journal не содержит candidate payloads и secrets. Основные phases:

| Phase | Live mutation возможна |
|---|---|
| Prepared | нет |
| Staged | нет |
| Validated | нет |
| Snapshotted | еще нет; previous state уже сохранен |
| Installed | да |
| Activated | да |
| Healthy | да, verification пройдена |
| Publishing | publish generation начат |
| Published | transaction завершена |
| RollbackStarted | идет compensation |
| RolledBack | previous state восстановлен |
| RecoveryRequired | восстановление не доказано |

Operation ID, core IDs, timestamps и sanitized error доступны diagnostics.
Secret values, UUID lists и subscription tokens в journal не пишутся.

## 7. Rollback

Если ошибка произошла после mutation, worker:

1. останавливает дальнейшее применение;
2. восстанавливает snapshots всех уже измененных resources в обратном порядке;
3. возвращает previous enabled/active service state;
4. проверяет восстановленные configs/services/listeners;
5. оставляет applied_generation на предыдущем значении.

Успешная компенсация дает RolledBack. Если хотя бы один previous resource нельзя
проверить, статус становится RecoveryRequired. Это fail-closed состояние:
автоматически считать новый или старый data plane рабочим нельзя.

## 8. Crash recovery

При следующем запуске worker читает durable journal:

- pre-mutation phases безопасно помечаются failed, staging удаляется;
- mutated, но не published transaction откатывается;
- published generation принимается только если publish и verified resources
  доказаны journal/applied state;
- неизвестное состояние не принимается молча.

Не удаляйте transaction directory при RecoveryRequired до сохранения evidence и
backup. Ручное удаление journal не восстанавливает runtime.

## 9. User synchronization

Per-user adapters объявляют expected identity set. После activation core adapter
читает собственный live config и возвращает:

- InSync с user count;
- Drift с desired/observed/missing/unexpected counts;
- Unsupported, если надежное наблюдение для runtime отсутствует.

Панель хранит только counts. Совпадение count не заменяет сравнение set: adapter
делает set comparison внутри privileged flow, а наружу отдает redacted result.

Shared-credential adapters не обещают per-user runtime revoke и не должны
создавать ложный InSync.

## 10. Inventory

Один AdapterInventory используется Dashboard, Protocols, Modules, Configs и
Health. Он объединяет:

- зарегистрированные manifests;
- persisted adapter_state;
- profiles/resources;
- installed/active/healthy runtime probes;
- desired/applied generations.

Типичные resource states:

| State | Причина |
|---|---|
| Disabled | profile/resource выключен |
| ConfiguredPending | desired новее applied |
| AppliedHealthy | generation совпадает, runtime healthy |
| AppliedDegraded | applied, но probe degraded |
| CoreUnavailable | protocol adapter есть, compatible runtime не установлен |
| Unsupported | adapter отсутствует или schema новее |

Adapter state сохраняется даже при временном отсутствии package. Возвращенный
adapter может мигрировать собственную opaque schema.

## 11. Диагностика Pending/Failed

    sudo systemctl status infiproxy-reconcile.path infiproxy-reconcile.timer
    sudo systemctl status infiproxy-reconcile.service --no-pager --full
    sudo journalctl -u infiproxy-reconcile.service -n 200 --no-pager
    sudo find /var/lib/infiproxy/reconcile-requests -maxdepth 1 -type f -ls
    sudo find /var/lib/infiproxy-maintenance/reconcile -maxdepth 2 -type f -ls

Проверьте последовательно:

1. request directory принадлежит app user и не writable для group/world;
2. request - bounded regular file, не symlink;
3. required root-only/shared secrets существуют;
4. выбранный runtime установлен точной совместимой версии;
5. TLS pair доступна infiproxy-runtime;
6. ports свободны для соответствующего TCP/UDP;
7. native config validator принимает candidate;
8. systemd unit может запуститься в sandbox.

## 12. Безопасное повторение

После исправления причины не редактируйте applied.json или generation вручную.
Создайте новую корректную mutation в UI либо запустите root worker для уже
существующего request:

    sudo systemctl start infiproxy-reconcile.service

Успех:

    curl -fsS http://127.0.0.1:8080/ready
    sudo systemctl is-active infiproxy-reconcile.timer

Затем проверьте Dashboard: desired и applied равны, status Applied. Финальный
критерий data plane - внешний handshake для каждого enabled adapter/runtime
pair, а не только зеленый control-plane status.

Developer contract:
[architecture-reconciler.md](https://github.com/infinitrator/stealthhub-panel/blob/main/docs/architecture-reconciler.md).
