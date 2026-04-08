# Форк Xray-core с TrustTunnel

English version: [README.md](README.md)

Этот репозиторий является downstream-форком [XTLS/Xray-core](https://github.com/XTLS/Xray-core) с интеграцией TrustTunnel прямо в Xray-core.

Цель форка простая: держать TrustTunnel в виде поддерживаемого runtime внутри Xray, а не в виде частного набора патчей или отдельного прототипа.

## Поддержанные конфигурации

- HTTP/2 over TLS
- HTTP/2 over REALITY
- HTTP/3 over TLS
- `transport: "auto"` с выбором HTTP/3-first и fallback на HTTP/2
- упорядоченные outbound-списки `servers[]` с последовательным fallback по endpoint
- лимиты входящих соединений по клиентам с отдельными счётчиками для H1/H2 и H3
- TCP-туннелирование
- UDP-мультиплексирование через `_udp2`
- ICMP-туннелирование через `_icmp`
- Путь health-check через `_check`

## `clientRandom`

`clientRandom` не обязателен для того, чтобы вообще установить каждое TrustTunnel-соединение, но для реальных deployment-сценариев это рекомендуемый вариант по умолчанию.

Если сервер использует `client_random` rules и завершает список правил запасным deny-правилом, клиент без подходящего `clientRandom` будет отклонён. Если сервер не требует совпадения по `client_random`, туннель может работать и без явно заданного `clientRandom`.

В руководстве по конфигам есть:

- минимальные примеры, которые показывают кратчайшую валидную форму конфига
- рекомендуемые примеры, которые показывают более безопасный вариант для реального использования
- точное объяснение того, что такое `client_random` rules и как их писать
- примеры политики лимитов для входящих соединений по клиентам

## Неподдержанные комбинации

- `HTTP/3 over REALITY` не поддерживается, потому что текущий REALITY runtime в Xray построен вокруг TCP stream layer, а TrustTunnel H3 работает поверх QUIC.
- `antiDpi=true` поддерживается на `HTTP/2 over TLS` и `HTTP/2 over REALITY`. При `transport: "auto"` этот флаг заставляет клиент сразу идти в HTTP/2 path, без попытки HTTP/3. Для явного `HTTP/3` поле остаётся неподдержанным, потому что текущая реализация умеет делать split только первой TCP-based записи ClientHello.
- UDP domain targets не описываются как поддержанный product path. Подтверждённый UDP path использует IP-назначения.

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
