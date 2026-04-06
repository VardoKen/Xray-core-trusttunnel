# TrustTunnel / Xray-Core — текущее состояние проекта

Статус: current
Дата фиксации: 2026-04-06
Коммит состояния: `55c97b16`
Ветка: `feat/trusttunnel-v1-sync-upstream-2026-03-30`
Область истины: фактическое состояние проекта после сессии, закрывшей H3 rules, ложный `H3_NO_ERROR` и legacy H3-path
Не использовать для: исторической хронологии, описания старых тупиковых веток и промежуточных решений

## 1. Краткий факт состояния

TrustTunnel в текущем дереве подтверждённо находится в рабочем состоянии по следующим направлениям:
- H2 TCP;
- H3 TCP;
- H2 UDP mux;
- H3 UDP mux;
- H2/TCP + REALITY через живой traffic path lab → remote server → internet;
- H2/UDP + REALITY через живой DNS traffic path lab → remote server → internet;
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
- server-side observable timeout surface подтверждён downstream-observable runtime-retest для `tlsHandshakeTimeoutSecs`, `clientListenerTimeoutSecs`, `connectionEstablishmentTimeoutSecs`, `tcpConnectionsTimeoutSecs` и `udpConnectionsTimeoutSecs`;
- core network model распознаёт `icmp` в `common/net`, config parsing и routing/API semantics;
- server-side auth semantics на обычном CONNECT, `_check`, `_udp2` и `_icmp` выровнены;
- H3 + REALITY больше не остаётся silent-misconfig: current runtime явно отклоняет эту комбинацию на client и server сторонах с marker `trusttunnel http3 with REALITY is unsupported: current Xray REALITY transport is TCP-only`;
- server-side inbound/outbound/user traffic counters и `onlineMap` sanity-check;
- полный `testing/scenarios` проходит как локально, так и на Debian lab; текущие full-tree ограничения остаются только внешними для `app/dns` QUIC probe и asset-зависимыми для `geoip.dat`, а не branch-регрессиями TrustTunnel;
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

### 2.11. Observable timeout surface

Подтверждено clean-HEAD runtime-retest на 2026-04-06 / `57d8d5e1`:
- `tls_handshake_timeout_secs = 3` теперь реально обрывает silent TLS peer на downstream probe `first_read_bytes=0`, `closed_after=3.00`; прошлый gap был закрыт transport-fix, который распространил timeout и на pre-handshake ClientHello extraction path;
- `client_listener_timeout_secs = 3` на H2 подтверждён двумя downstream markers: общий probe даёт `alpn=h2`, `initial_bytes=45`, `closed_after=4.00`, а raw H2 trace показывает GOAWAY frame ровно через `3.00s` idle и финальное закрытие transport примерно через секунду;
- `connection_establishment_timeout_secs = 4` даёт downstream `Empty reply from server` с `elapsed_ms=4064`, а server log завершает CONNECT примерно через четыре секунды после `trusttunnel H2 CONNECT accepted`;
- `tcp_connections_timeout_secs = 3` даёт downstream `Empty reply from server` с `elapsed_ms=3026`, а server log фиксирует close примерно через `3.00s` после `trusttunnel H2 CONNECT accepted`;
- `udp_connections_timeout_secs` остаётся подтверждённым через reopen marker: два последовательных UDP probe после `udpConnectionsTimeoutSecs = 1` проходят в одном и том же сценарии, а reopen-count остаётся `2`.

### 2.12. H2 REALITY production path

Подтверждено real-traffic runtime-retest на 2026-04-06 / `ae621d24`, затем повторно подтверждено current-head smoke на 2026-04-06 / `c6ff745b`:
- outbound H2 path теперь корректно работает поверх общего Xray `streamSettings.security = "reality"` и не падает в ложный HTTP/1.1 fallback, если REALITY transport не экспонирует negotiated ALPN обратно в TrustTunnel layer;
- practically significant fix заключается в том, что H2 path больше не требует буквального `NegotiatedProtocol == "h2"` для REALITY-wrapper: при `UsesReality=true` и пустом negotiated ALPN client пишет `trusttunnel transport=http2 requested with REALITY and empty negotiated ALPN; using HTTP/2 preface path` и продолжает по HTTP/2 preface path;
- живой H2/TCP current-head smoke через lab client `/opt/lab/xray-tt/configs/our_client_to_remote_server_h2_reality.json`, runtime binary `/opt/lab/xray-tt/tmp/xray-tt-regress-linux`, remote runtime binary `/opt/trusttunnel-dev/tmp/xray-tt-regress-linux`, lab bundle `/opt/lab/xray-tt/logs/workerfix-h2-reality-lab-20260406-153646` и remote bundle `/opt/trusttunnel-dev/logs/workerfix-h2-reality-remote-20260406-153646` повторно подтверждает `trusttunnel transport=http2 requested with REALITY and empty negotiated ALPN; using HTTP/2 preface path`, `trusttunnel H2 CONNECT accepted for tcp:www.cloudflare.com:443`, `trusttunnel H2 CONNECT accepted for tcp:api.ipify.org:443`, а downstream probe через SOCKS даёт `ip=37.252.0.130`, `http=http/2` и `{\"ip\":\"37.252.0.130\"}`;
- живой H2/UDP current-head smoke через lab client `/opt/lab/xray-tt/configs/our_client_udp_to_remote_server_h2_reality.json`, runtime binary `/opt/lab/xray-tt/tmp/xray-tt-regress-linux`, remote runtime binary `/opt/trusttunnel-dev/tmp/xray-tt-regress-linux`, lab bundle `/opt/lab/xray-tt/logs/workerfix-h2-reality-udp-lab-20260406-153758` и remote bundle `/opt/trusttunnel-dev/logs/workerfix-h2-reality-udp-remote-20260406-153758` повторно подтверждает `trusttunnel H2 UDP mux accepted`, `dispatch request to: udp:1.1.1.1:53`, `proxy/freedom: connection opened to udp:1.1.1.1:53` и real DNS answer для `cloudflare.com`.
- controlled load-test через lab client `/opt/lab/xray-tt/configs/our_client_to_remote_server_h2_reality_iperf_tcp.json`, remote iperf target `127.0.0.1:5201` и bundle `load-h2-reality-20260406-111027` подтверждает, что H2/REALITY path переносит большой TCP traffic без функционального срыва: на `iperf3 -P 4 -t 20` uplink receiver получает ~`166 Mbit/s`, reverse/downlink receiver получает ~`88 Mbit/s`, а на stress-case `iperf3 -P 8 -t 20` uplink receiver получает ~`238 Mbit/s`, reverse/downlink receiver получает ~`148 Mbit/s`;
- practically significant CPU verdict по этому load-test: lab-side Xray client на stress uplink (`-P 8`) держит в среднем ~`92.9%` process CPU с пиками до `117%`, а remote-side Xray server ~`69.7%` с пиками до `87%`; на stress reverse/downlink lab-side client остаётся основным горячим участком со средним ~`90.0%` и пиками до `119.8%`, тогда как remote-side server остаётся заметно ниже, ~`23.4%` среднего и `39%` peak.

## 3. Что считается текущей истиной

Текущую истину по проекту определяют:
- этот документ;
- `docs/current/architecture.md`;
- `docs/current/operations.md`;
- `docs/current/validation.md`;
- `docs/current/roadmap.md`.

Исторические и миграционные документы могут объяснять, почему раньше было иначе, но не могут переопределять этот current-слой.

## 4. Что остаётся открытым после этой фиксации

Открытыми задачами текущего этапа считаются не H3-баги и не уже закрытый H2 REALITY production path, а следующие блоки:
- client-side parity fields после закрытия H2 REALITY production path;
- нормализация TrustTunnel вокруг `streamSettings` и общей модели Xray.

H3 + REALITY на текущем этапе больше не считается обычным parity-gap: R&D завершён stop-factor verdict'ом. Любая будущая реализация потребует нового QUIC-capable REALITY transport в Xray core, а не локального патча в TrustTunnel.

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
