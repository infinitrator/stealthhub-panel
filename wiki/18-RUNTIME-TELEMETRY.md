# Runtime telemetry and accounting foundation

[Назад: runtime compatibility](17-RUNTIME-COMPATIBILITY) | [К оглавлению](Home)

Phase 3 добавляет наблюдаемый слой состояния и не меняет desired/applied state:

```text
desired != applied != observed
```

Adapter observation фиксирует runtime ID, источник, время, capability state и,
когда источник реально доступен, cumulative RX/TX/total и active connections.
Состояния `supported`, `unsupported`, `unavailable`, `stale` и `error`
различаются. В частности, `unsupported` никогда не отображается как `0 B`.

## Текущий контракт сбора

Collector запускается после старта панели и затем раз в 5 минут. Один цикл
ограничен 20 секундами; version probe каждого core использует только
adapter-owned binary/argv, ограничен 3 секундами и 64 KiB вывода. Никаких URL,
service names, socket paths или команд из SQLite/HTTP collector не принимает.

SQLite хранит latest observation каждого runtime и не более 4096 history rows
на узел. JSON одной записи ограничен 16 KiB. Эти записи не содержат config,
password, token, certificate или private key. Phase 3 не изменяет
`users.traffic_used_bytes` и не блокирует пользователя по наблюдаемому трафику.

## Матрица pinned runtimes

| Runtime | Process/version/listener | Aggregate traffic | Per-user traffic | Причина |
|---|---|---|---|---|
| Mihomo `v1.19.30` | supported/unavailable по факту probe | unsupported | unsupported | `/connections` требует включенного local controller; он не добавлен в generated server config. |
| Xray `v26.3.27` | supported/unavailable по факту probe | unsupported | unsupported | Stats и policy counters требуют отдельной конфигурации/API. |
| sing-box `v1.13.20` | supported/unavailable по факту probe | unsupported | unsupported | Clash API отключен, когда `external_controller` пуст. |
| Hysteria `app/v2.12.2` | supported/unavailable по факту probe | unsupported | unsupported | Traffic Stats HTTP API требует отдельного listener и secret. |
| TUIC `1.0.0` | supported/unavailable по факту probe | unsupported | unsupported | Проверенного native accounting interface в pinned contract нет. |

API намеренно не включаются автоматически: даже loopback listener создает
новую административную поверхность, credential lifecycle и требования к
runtime sandbox. Это отдельная будущая работа, а не повод показывать выдуманные
значения.

Официальные источники: [Mihomo API](https://wiki.metacubex.one/en/api/),
[Mihomo controller](https://wiki.metacubex.one/en/config/general/),
[Xray statistics](https://xtls.github.io/en/config/stats.html),
[Xray policy](https://xtls.github.io/en/config/policy.html),
[sing-box Clash API](https://sing-box.sagernet.org/configuration/experimental/clash-api/),
[Hysteria Traffic Stats API](https://v2.hysteria.network/docs/advanced/Traffic-Stats-API/),
[TUIC source/releases](https://github.com/tuic-protocol/tuic).

## Counter continuity

Cumulative samples сравниваются только при одинаковом continuity marker. При
смене процесса, уменьшении любого счетчика или новом epoch текущий sample
начинает новую continuity series. Delta никогда не бывает отрицательной.
Временно отсутствующий sample не превращает старое значение в свежее.

## Интерфейсы и диагностика

- **Health / Active runtimes** показывает installed и validated versions,
  version mismatch, capability states и timestamp наблюдения.
- **Users** честно сообщает, что runtime accounting unsupported; сохраненное
  quota metadata остается отдельным access gate.
- **SSH TUI / Runtimes** читает ту же SQLite latest table в read-only режиме.
- После миграции до первого collector cycle состояние может быть unavailable,
  но не zero.

Если `installed` отличается от `validated`, runtime нельзя выбирать для
reconcile. Проверьте `sudo infiproxy-module-update --check sing-box` и выполните
явное reviewed update к pinned release. Автоматический updater не делает
downgrade более новой локальной версии и потому не создает downgrade loop.

## Что не входит в Phase 3

Phase 4 quota enforcement не реализован: telemetry не выключает users, не
создает reconcile generations, не сбрасывает quota и не меняет доступ при
пересечении лимита.
