# TrustTunnel / Xray-Core — текущее состояние проекта

Статус: current
Дата фиксации: 2026-04-05
Коммит состояния: `6fcb3a28`
Ветка: `feat/trusttunnel-v1-sync-upstream-2026-03-30`
Область истины: фактическое состояние проекта после сессии, закрывшей H3 rules, ложный `H3_NO_ERROR` и legacy H3-path
Не использовать для: исторической хронологии, описания старых тупиковых веток и промежуточных решений

## 1. Краткий факт состояния

TrustTunnel в текущем дереве подтверждённо находится в рабочем состоянии по следующим направлениям:
- H2 TCP;
- H3 TCP;
- H2 UDP mux;
- H3 UDP mux;
- полный UDP interop matrix в направлениях official client → our server и our client → official endpoint для H2/H3, IPv4/IPv6, multi-flow и reopen после idle timeout;
- H2 rules по `client_random`;
- H3 rules по `client_random`;
- outbound `clientRandom` как реальная runtime-функция для H2 и H3;
- H2 `_check` special path с корректными `200` / `407` / `403`;
- H2 auth recovery после `407`: failed session не отравляет следующую session, и тот же server process принимает subsequent clean auth от official client;
- server-side H2/H3 `_icmp` mux по official wire-format с representable raw ICMP reply path;
- official client → our server H2/H3 `_icmp` interop через TUN-mode и raw ICMP echo-reply;
- client-side/outbound `_icmp` packet contract поверх `transport.Link` для H2/H3 echo-request и representable reply path;
- server-side `_icmp` config surface wired к runtime через `allowPrivateNetworkConnections`, `icmp.interfaceName`, `icmp.requestTimeoutSecs`, `icmp.recvMessageQueueCapacity` и observable `ipv6Available`;
- representable `_icmp` error-type parity подтверждена для echo-reply, destination-unreachable и time-exceeded; extra MTU/pointer fields остаются ограничением fixed-size reply frame;
- core network model распознаёт `icmp` в `common/net`, config parsing и routing/API semantics;
- server-side auth semantics на обычном CONNECT, `_check`, `_udp2` и `_icmp` выровнены;
- server-side inbound/outbound/user traffic counters и `onlineMap` sanity-check;
- базовая межоперабельность в направлениях official client → our server и our client → official endpoint.

## 2. Что закрыто на текущем состоянии

### 2.1. Рабочий H3 runtime-path

Актуальный H3 path расположен в транспортном слое и серверном TrustTunnel-обработчике:
- `transport/internet/tcp/hub.go`
- `transport/internet/tcp/http3_clienthello.go`
- `transport/internet/tcp/http3_conn.go`
- `proxy/trusttunnel/server.go`

Удалённый legacy H3-обработчик первой попытки реализации не является текущим runtime-path и не должен использоваться как точка дальнейшей разработки.

### 2.2. H3 rules по `client_random`

Искусственная блокировка H3 при наличии `client_random` rules снята.

На состоянии `99e59352` подтверждено:
- H3 получает `client_random` из QUIC Initial / TLS ClientHello;
- H3 path реально передаёт `client_random` в server-side rule-matching;
- allow/deny по H3 определяется фактическим совпадением rules, а не глобальным запретом.

### 2.3. Ложный `H3_NO_ERROR`

Штатное завершение H3 TCP-сессии больше не поднимается как прикладная ошибка.

Нормализованы завершения чтения с кодом `http3.ErrCodeNoError`, поэтому хвост вида:

```text
proxy/freedom: connection ends > proxy/freedom: failed to process request > H3_NO_ERROR
```

не является нормальным признаком текущего runtime-path и не должен использоваться как текущая трактовка поведения.

### 2.4. Базовый H3 interop

Подтверждено:
- official TrustTunnel client корректно работает с нашим H3 server;
- наш Xray client корректно работает с official TrustTunnel endpoint по H3;
- H3 UDP mux и stats-path подтверждены рабочими smoke-тестами.

### 2.5. H2 `_check` special path

Подтверждено runtime-retest на 2026-04-04 / `9f18af9d`:
- success-case для official client возвращает `200`, а `_check` не уходит в обычный dispatch path;
- auth-fail остаётся observable как `407` в рамках `authFailureStatusCode`;
- rule-deny остаётся observable как `403`;
- старые сигнатуры `failed to open connection to tcp:_check:443` и `lookup _check: no such host` отсутствуют.

### 2.6. Server-side auth semantics на pseudo-host path

Подтверждено локальными regression-тестами на 2026-04-05:
- auth и rules проверяются раньше special-path handling как для обычного CONNECT, так и для `_check`, `_udp2` и `_icmp`;
- H1 path больше не уводит `_check`, `_udp2` и `_icmp` в обычный target parsing и dispatch;
- H1 `_check` отвечает явным `200`, H1 `_udp2` отвечает явной HTTP-ошибкой вместо dispatch, а `_icmp` отвечает явным `501 Not Implemented` после auth/rules;
- H2/H3 `_icmp` больше не уходит в обычный dispatch path: при доступном raw ICMP открывается отдельный mux path, а при недоступном raw socket сервер отвечает `503 Service Unavailable`.

### 2.7. Outbound `clientRandom`

Подтверждено clean-HEAD runtime-retest на 2026-04-05 / `fc276340`:
- outbound `settings.clientRandom` реально участвует в формировании исходящего TLS ClientHello random;
- H2 allow-case с `clientRandom = "deadbeef"` проходит через server-side rules и логирует `matched rule[0] action=allow clientRandom=deadbeef`;
- H3 allow-case с `clientRandom = "deadbeef"` проходит через server-side rules и логирует тот же allow-match;
- deny-case с несовпадающим `clientRandom` на H2 и H3 возвращает `403` и уходит в catch-all deny-rule.

### 2.8. Official H2/H3 `_icmp` interop

Подтверждено clean-HEAD runtime-retest на 2026-04-05 / `5a21fd31` и `6c46922c`:
- official client в TUN-mode проходит certificate verification и открывает H2/H3 `_check` / `_icmp` против нашего server-side path;
- сервер логирует `trusttunnel H2 health-check accepted` / `trusttunnel H2 ICMP mux accepted` и `trusttunnel H3 health-check accepted` / `trusttunnel H3 ICMP mux accepted`;
- client log содержит `ICMP register_request` и `ICMP register_reply`, а `ping 1.1.1.1` из namespace `tun` проходит с `3/3 received` как на H2, так и на H3;
- сигнатура `fatal error: concurrent map writes` больше не воспроизводится на H2 parallel stream `_check` + `_icmp`, а H3 clean-HEAD retest проходит без transport-level регрессии.

### 2.9. `Network_ICMP` в core model

Подтверждено локальными test/build-проверками и lab runtime-retest на 2026-04-05 / `b1c14eb3`:
- `common/net.Network` теперь содержит отдельный `Network_ICMP`;
- `common/net.ParseDestination(...)` и `DestinationFromAddr(...)` распознают `icmp:` и `net.IPAddr`;
- `infra/conf.Network` / `NetworkList` принимают `icmp`;
- routing/API/webhook layer получает `icmp` через общий `SystemString()` и `net.Network` plumbing.
- TrustTunnel outbound больше не пытается молча увести `Network_ICMP` в обычный CONNECT path: он открывает `_icmp:0`, кодирует fixed-size request frames и локально восстанавливает echo-reply packet по сохранённому payload.
- server-side config model подключает `_icmp` runtime-surface: `allowPrivateNetworkConnections` по умолчанию ограничивает назначения глобальными адресами, `icmp.interfaceName` задаёт raw-socket `IfIndex`, `icmp.requestTimeoutSecs` переопределяет timeout ожидания reply, а `icmp.recvMessageQueueCapacity` задаёт bounded per-stream reply queue с official-style default `256` и drop-on-overflow semantics;
- H2 lab runtime-retest против `192.168.1.19` подтверждает, что `allowPrivateNetworkConnections = false` режет private target до raw-send path, а `true` возвращает `1/1 received`; отдельный retest с `icmp.interfaceName = "definitely-missing-if0"` даёт `trusttunnel H2 ICMP unavailable > route ip+net: no such network interface`;
- dedicated H2 lab runtime-retest с `settings.icmp.requestTimeoutSecs = 1` подтверждает timeout-ветку через bundle `/opt/lab/xray-tt/logs/h2-icmp-timeout-1s-tc-20260405-183916`: server log содержит `trusttunnel icmp raw send v4 dst=1.1.1.1` и через ~1s `trusttunnel icmp request timed out ...`, а client-side ping даёт `0 received`;
- direct H2 `_icmp` probe подтверждает observable `ipv6Available`: bundle `/opt/lab/xray-tt/logs/h2-icmp-ipv6-available-probe-20260405-190025` даёт `failed to handle trusttunnel icmp request > IPv6 ICMP is unavailable` при `false` и полноценный IPv6 echo-reply при `true`;
- representable error-type parity теперь покрывает echo-reply, destination-unreachable и time-exceeded; отдельный H2 runtime bundle `/opt/lab/xray-tt/logs/h2-icmp-timeexceeded-rawping-20260405-185429` подтверждает `ICMP time exceeded in-transit`, а server log содержит `trusttunnel H2 icmp reply ... type=11 code=0`;
- reply types, которым нужны дополнительные поля вне fixed-size reply frame, не считаются открытым runtime-дефектом текущей ветки: `PacketTooBig`/`ParameterProblem` server-side распознаются и матчятся по quoted echo-request, но MTU/pointer не могут быть переданы обратно без расширения протокола;
- Этот outbound path на текущем wire-format покрывает echo-request и representable reply types, а на Linux уже образует рабочий Xray product path через `proxy/tun`, если TUN interface управляется ОС с явной адресацией и routing. Clean-HEAD H2/H3 retest на 2026-04-05 / `96a9d053` подтверждён через выделенные namespace `tunxrayh2` / `tunxrayh3`, адрес `192.0.2.10/32` и маршрут `1.1.1.1/32 dev xraytunh*`.

### 2.10. Полный UDP interop matrix

Подтверждено clean-HEAD runtime-retest на 2026-04-05 / `6fcb3a28`:
- bundle `/opt/lab/xray-tt/logs/udp-matrix-20260405-222820` закрывает обе половины матрицы: official client → our server и our client → official endpoint;
- official client → our server на H2 и H3 проходит для IPv4 `1.1.1.1:53`, `8.8.8.8:53` и IPv6 `2606:4700:4700::1111:53`, а server log фиксирует `trusttunnel H2 UDP mux accepted` и `trusttunnel H3 UDP mux accepted`;
- отдельные reopen-case на `server_h2_udp_official_cert_timeout_1.json` и `server_h3_udp_timeout_1.json` подтверждают reopen после `udpConnectionsTimeoutSecs = 1`;
- our client → official endpoint на H2 и H3 проходит для IPv4 и IPv6 targets через runtime ports `5304/5305/5306/5307`, а прежний H2 outbound fail `trusttunnel CONNECT failed with status 502` больше не воспроизводится;
- practically significant interop-fix: outbound UDP CONNECT теперь использует official authority `_udp2`, при этом server-side matcher сохраняет backward-compat и принимает как `_udp2`, так и legacy `_udp2:0`.

## 3. Что считается текущей истиной

Текущую истину по проекту определяют:
- этот документ;
- `docs/current/architecture.md`;
- `docs/current/operations.md`;
- `docs/current/validation.md`;
- `docs/current/roadmap.md`.

Исторические и миграционные документы могут объяснять, почему раньше было иначе, но не могут переопределять этот current-слой.

## 4. Что остаётся открытым после этой фиксации

Открытыми задачами текущего этапа считаются не H3-баги, а следующие блоки:
- observable server behavior вне уже подтверждённого `_icmp` surface: bundle `/opt/lab/xray-tt/logs/timeout-retest-20260405-210405` и `/opt/lab/xray-tt/logs/timeout-retest-20260405-214512` пока дают downstream-observable подтверждение только для `udp_connections_timeout_secs`; `tls_handshake_timeout_secs`, `client_listener_timeout_secs`, `connection_establishment_timeout_secs` и `tcp_connections_timeout_secs` остаются частично подтверждёнными;
- REALITY;
- нормализация TrustTunnel вокруг `streamSettings` и общей модели Xray.

## 5. Антирегрессионное правило

Чтобы снова объявить открытой любую из уже закрытых H3-проблем, нужны более новые доказательства, чем текущая фиксация 2026-04-02 / `99e59352`:
- новый код;
- новый runtime-fail;
- новый interop-fail;
- новые подтверждённые логи или тесты.

Недостаточно:
- ссылаться на документы 2026-04-01;
- переносить старые тезисы из history/migration;
- повторять ранние ограничения без нового retest.

## 6. Практическая граница документа

Этот документ отвечает на вопрос: «что реально закрыто и что считать текущим фактом проекта».

Для истории разработки использовать `docs/history/development-history.md`.
Для того, что ещё осталось сделать, использовать `docs/current/roadmap.md`.
