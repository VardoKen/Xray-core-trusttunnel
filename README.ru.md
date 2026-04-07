# Форк Xray-core с TrustTunnel

English version: [README.md](README.md)

Этот репозиторий является downstream-форком [XTLS/Xray-core](https://github.com/XTLS/Xray-core), в котором ведётся рабочая интеграция TrustTunnel в Xray-core.

Форк нужен не для хранения разрозненных экспериментов, а для поддерживаемой runtime-реализации TrustTunnel внутри Xray: с кодом протокола, binding конфигов, validator-ограничениями, live-traffic проверками и канонической документацией по фактически подтверждённому состоянию.

## Что Добавляет Этот Форк

- inbound и outbound `trusttunnel` внутри Xray-core
- подтверждённые HTTP/2 и HTTP/3 TCP path
- подтверждённые HTTP/2 и HTTP/3 UDP mux path
- подтверждённый HTTP/2 + REALITY path для TCP и UDP
- обработку `_check`, `_udp2` и `_icmp`
- validator и compatibility guards для TrustTunnel-конфигов
- runtime-поддержку `clientRandom`, `postQuantumGroupEnabled` и policy-guard для `hasIpv6`
- регулярную синхронизацию с upstream и regression-аудит по не-TrustTunnel путям

## Текущий Подтверждённый Scope

Каноническое состояние описано в [docs/current/current-state.md](docs/current/current-state.md). На текущем этапе у форка подтверждены:

- H2 TCP
- H3 TCP
- H2 UDP mux
- H3 UDP mux
- H2 TCP + REALITY
- H2 UDP + REALITY
- official interop для `_check`, `_udp2`, `_icmp`
- runtime-path для outbound `clientRandom`
- Linux TUN product path для `_icmp`
- общая интеграция Xray с `proxySettings`, `mux`, `sendThrough=origin`, `targetStrategy useipv4/forceipv4`, `sniffing + routeOnly` и inbound `rejectUnknownSni`

## Важные Ограничения

Этот форк не объявляет все исторические или official поля TrustTunnel автоматически рабочими.

Текущие жёсткие ограничения:

- `http3 + reality` явно не поддерживается и режется validator/runtime.
- `antiDpi=true` явно не поддерживается и режется validator/runtime.
- UDP domain targets не считаются подтверждённым product path.
- inbound `hosts[]` и `transports[]` сами по себе не являются универсальным virtual-host/router layer.
- lab-only secrets и deployment keys не должны попадать в tracked tree репозитория.

## Документация

Начать лучше отсюда:

- индекс документации: [docs/README.ru.md](docs/README.ru.md)
- руководство по конфигам: [docs/configuration.ru.md](docs/configuration.ru.md)
- English config guide: [docs/configuration.md](docs/configuration.md)

Канонический current-слой:

- состояние: [docs/current/current-state.md](docs/current/current-state.md)
- архитектура: [docs/current/architecture.md](docs/current/architecture.md)
- эксплуатация: [docs/current/operations.md](docs/current/operations.md)
- проверки: [docs/current/validation.md](docs/current/validation.md)
- roadmap: [docs/current/roadmap.md](docs/current/roadmap.md)

Исторические слои:

- в [docs/README.ru.md](docs/README.ru.md) описано, чем отличаются `current`, `history`, `migration` и `archive`

## Примеры Конфигов

Tracked templates лежат в [testing/trusttunnel](testing/trusttunnel):

- [testing/trusttunnel/client_h2.json](testing/trusttunnel/client_h2.json)
- [testing/trusttunnel/server_h2.json](testing/trusttunnel/server_h2.json)
- [testing/trusttunnel/server_h3.json](testing/trusttunnel/server_h3.json)
- [testing/trusttunnel/our_client_to_remote_server_h2_reality.json](testing/trusttunnel/our_client_to_remote_server_h2_reality.json)
- [testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json](testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json)
- [testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json](testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json)
- [testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json](testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json)

Их нужно трактовать как tracked templates, а не как место для deployment-секретов.

## Сборка

Windows PowerShell:

```powershell
$env:CGO_ENABLED = 0
go build -buildvcs=false -o .\tmp\xray-tt-current.exe .\main
```

Linux:

```bash
CGO_ENABLED=0 go build -buildvcs=false -o ./tmp/xray-tt-current ./main
```

## Политика Синхронизации С Upstream

Этот форк следует за upstream Xray-core, но не подаётся как готовый upstream patch stack. Рабочее правило такое:

1. догонять upstream `main`
2. после каждого merge/rebase повторять regression-проверки
3. считать `docs/current/*` единственным слоем текущей истины для форка
4. выделять upstreamable изменения позже, только после стабилизации поведения форка

## Лицензия

Репозиторий остаётся под той же лицензией, что и Xray-core: [Mozilla Public License Version 2.0](LICENSE).
