# Форк Xray-core с TrustTunnel

English version: [README.md](README.md)

Этот репозиторий является downstream-форком [XTLS/Xray-core](https://github.com/XTLS/Xray-core) с интеграцией TrustTunnel в Xray-core.

Форк нужен для поддерживаемой runtime-реализации TrustTunnel внутри Xray, а не для хранения внешних временных патчей.

## Что Есть В Форке

- inbound и outbound `trusttunnel`
- HTTP/2 и HTTP/3 TCP path
- HTTP/2 и HTTP/3 UDP mux path
- поддержка HTTP/2 + REALITY
- обработка `_check`, `_udp2` и `_icmp`
- validator для неподдержанных TrustTunnel-комбинаций

## Текущий Scope Возможностей

Публично документированные и целевые возможности форка:

- TrustTunnel поверх HTTP/2 + TLS
- TrustTunnel поверх HTTP/2 + REALITY
- TrustTunnel поверх HTTP/3 + TLS
- TrustTunnel для TCP, UDP mux и ICMP
- совместимость с общими routing и transport-настройками Xray

## Известные Ограничения

- `http3 + reality` не поддерживается
- `antiDpi=true` не поддерживается
- UDP domain targets не описываются как поддержанный product path

## Документация

- индекс документации: [docs/README.ru.md](docs/README.ru.md)
- руководство по конфигам: [docs/configuration.ru.md](docs/configuration.ru.md)
- English configuration guide: [docs/configuration.md](docs/configuration.md)

## Примеры

Санитизированные шаблоны конфигов лежат в [testing/trusttunnel](testing/trusttunnel).

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

## Лицензия

Репозиторий остаётся под той же лицензией, что и Xray-core: [Mozilla Public License Version 2.0](LICENSE).
