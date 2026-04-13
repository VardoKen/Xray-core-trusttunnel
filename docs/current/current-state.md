# TrustTunnel / Xray-Core — текущее состояние проекта

Статус: current
Дата фиксации: 2026-04-13
Коммит состояния: `69ea1a44`
Ветка: `feat/trusttunnel-multipath`
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
- `postQuantumGroupEnabled` больше не является декларативным outbound-полем: H2/TLS, H2/REALITY и H3/TLS client-side runtime переключает effective TLS/REALITY fingerprint и curve preferences через per-request `streamSettings` override или direct H3 TLS config;
- `hasIpv6=false` больше не ограничен literal-IP gate: client-side runtime режет явные IPv6 literal targets marker'ом `trusttunnel IPv6 target is disabled by hasIpv6=false`, а domain targets требует вести через outbound `targetStrategy useipv4/forceipv4` marker'ом `trusttunnel hasIpv6=false requires outbound targetStrategy useipv4/forceipv4 for domain targets`;
- `antiDpi=true` больше не остаётся silent no-op: current outbound runtime поддерживает его на `HTTP/2 over TLS` и `HTTP/2 over REALITY` через split первой TCP-based записи ClientHello, а `transport="auto"` при этом сразу выбирает HTTP/2 path; явный `HTTP/3` по-прежнему режется как unsupported;
- `transport="auto"` больше не остаётся декларативным transport hint: current runtime предпочитает H3 при совместимом QUIC path, уходит в H2 на transport-level H3 fail и сразу выбирает H2 для `antiDpi=true` и REALITY-path;
- config-build validator больше не оставляет unsupported combinations как silent misconfig: current `infra/conf` stage режет `http3 + reality`, `antiDpi=true` без совместимого `HTTP/2 + TLS/REALITY` security-path, H2 `postQuantumGroupEnabled` без TLS/REALITY `streamSettings`, а на non-HTTP3 + generic `streamSettings.tlsSettings` дополнительно режет `hostname` mismatch, `skipVerification` поверх explicit generic verify surface и `skipVerification` вместе с `certificatePem/certificatePemFile`;
- H2/TLS outbound подтверждает совместимость с generic Xray `streamSettings.tlsSettings` по `serverName`, authority-verify через custom CA, `VerifyPeerCertByName`, `PinnedPeerCertSha256` и `Fingerprint`; non-HTTP3 compatibility fields больше не образуют второй TrustTunnel-local verify path поверх generic TLS: `hostname` и `skipVerification` только дополняют missing `serverName` / `allowInsecure`, а на Windows custom-CA verify path по-прежнему требует `disableSystemRoot=true` как общее ограничение transport TLS, а не как TrustTunnel-specific исключение;
- общий outbound layer Xray теперь принимает per-request `streamSettings` override и не заставляет TrustTunnel мутировать handler-level transport config;
- common outbound integration с механизмами Xray подтверждена scenario-тестами: `proxySettings`, `mux`, `sendThrough=origin` и `targetStrategy useipv4`;
- common inbound integration подтверждена для `sniffing + routeOnly` и generic inbound TLS `rejectUnknownSni`; `metadataOnly` для TLS SNI не считается TrustTunnel-bug surface и остаётся обычной семантикой общего dispatcher path;
- dynamic user management на TrustTunnel inbound подтверждён через `HandlerService` `AddUser` / `RemoveUser` и `GetInboundUsersCount`;
- outbound endpoint-policy больше не ограничен literal server-list: client runtime поддерживает ordered multi-endpoint fallback, delayed race между первыми двумя ready endpoint, preference последнего успешно established endpoint, короткий cooldown после pre-establishment fail и active probing охлаждённых endpoint через реальный TrustTunnel `_check`; если `address` или `servers[].address` задан доменом, client на старте разворачивает его во все resolved IP и включает их в тот же policy; этот endpoint-policy подтверждён unit/scenario тестами и четырьмя remote-live sequence между lab и реальными remote endpoint;
- H3 TCP/TLS current-head path снова держит live tunnel traffic после `CONNECT 200`: client и server используют raw HTTP/3 stream вместо zero-length response-body модели;
- current-head live matrix lab → remote server → internet на `4bfd8ac9` повторно проходит по H2 TLS, H2 REALITY и H3 TLS с functional `15/15` через bundle `full-live-20260407-153034`; для затронутого non-H3 TLS path дополнительный representative load smoke `h2_tls_auto_load_tcp` проходит через bundle `full-live-20260407-153909-h2_tls_auto_load_tcp` с ~`61.97 Mbit/s`, lab/client CPU avg/max `9.14 / 21` и remote/server `23.23 / 47`; авторитетным полным load verdict по матрице всё ещё остаётся clean rerun `full-live-20260407-140912`, где fastest TCP case — `h2_reality_pq_off_load_tcp` ~`373.45 Mbit/s` при lab/client CPU avg/max `45.62 / 99` и remote/server `64.38 / 112`, тогда как H3 paths остаются заметно дороже по lab/client CPU;
- server-side inbound/outbound/user traffic counters и `onlineMap` sanity-check;
- полный `testing/scenarios` проходит как локально, так и на Debian lab; compile-only sweep `GOFLAGS=-buildvcs=false go test -run '^$' ./...` проходит по всему дереву, а текущие full-tree ограничения остаются только внешними для `app/dns` QUIC probe и asset-зависимыми для `geoip.dat`, а не branch-регрессиями TrustTunnel;
- базовая межоперабельность в направлениях official client → our server и our client → official endpoint.

На ветке `feat/trusttunnel-multipath` открыта новая experimental-R&D линия TrustTunnel Multipath Transport. На текущем этапе она всё ещё не изменила это подтверждённое runtime-состояние stable TrustTunnel path, но уже вышла из phase 4 scheduler/quorum hardening в phase 5 recovery/rejoin:
- `proxy/trusttunnel/config.proto`, `infra/conf/trusttunnel.go` и `infra/conf/trusttunnel_lint.go` уже дают experimental `multipath.*` config surface и fail-fast guardrails для phase-1 scope: только `HTTP/2 over TLS`, без `transport=auto/http3`, без `udp=true`, с обязательным multi-endpoint pool и с проверкой `minChannels/maxChannels`;
- `proxy/trusttunnel/multipath_session.go` уже содержит не только `MultipathSession` / `MultipathChannel`, attach-secret, attach-deadline, replay-guard и channel-limit validation, но и ready/close lifecycle, live stream handles, reorder window, gap-timeout, per-channel accounting counters, explicit strict quorum-loss semantics и recovery/rejoin state;
- `proxy/trusttunnel/multipath_control.go`, `proxy/trusttunnel/multipath_server.go` и `proxy/trusttunnel/multipath_server_runtime.go` уже реализуют `_mptcp_open` / `_mptcp_attach`, attach-proof, primary session creation, secondary channel attach, server-side quorum wait, payload dispatch после готовности session и detached session runtime без привязки к request-scoped context одного attach-канала;
- `proxy/trusttunnel/multipath_client.go` и `proxy/trusttunnel/multipath_frame.go` уже дают H2/TLS multipath payload runtime с dynamic channel set: writer переживает write-fail канала и продолжает на surviving channels, reorder path вместо мгновенного overflow-fail использует bounded backpressure до закрытия gap или timeout, а peer channel-loss может быть surfaced control-frame `channel_closed`;
- authoritative Linux multi-IP positive live validation подтверждена на второй VM `192.168.1.25` через bundle `/root/tt-multipath-phase3/logs/multipath-phase3-live-20260413-092248`: `_mptcp_open` проходит на `192.168.1.50:9443`, `_mptcp_attach` проходит на `192.168.1.51:9443`, `4 MiB` download и `4 MiB` upload дают совпадающие SHA-256, а `ss-9443.txt` фиксирует одновременные established TCP connections на обоих alias IP внутри одной logical session;
- separate negative Linux live validation через bundle `/root/tt-multipath-phase3/logs/multipath-phase3-gap-20260413-092142` уже подтверждает channel-loss path: второй VM хватает `nft reject with tcp reset` на server-side канале `192.168.1.51:9443`, downstream long download рвётся с `curl: (18) end of response ... missing`, но explicit outer-layer marker `trusttunnel multipath channel quorum lost` в live bundle пока ещё не surfaced и остаётся отдельным follow-up;
- authoritative Linux multi-IP recovery/rejoin validation подтверждена на той же VM через bundle `/root/tt-multipath-phase3/logs/multipath-phase5-rejoin-20260413-194749`: после forced channel-loss quorum сначала деградирует до `1/2`, затем восстанавливается через rejoin `channel=3`, `ss-after-rejoin.txt` снова фиксирует два `ESTAB` канала на `192.168.1.50/51`, а `sha256sum download.bin` совпадает с ожидаемым `79cf58c41ad3d94d7b41c668dfb378899d2cc70b6a28736122c1331626476731`;
- H1 и H3 pseudo-host path для multipath по-прежнему честно режутся как unsupported;
- следующими открытыми фазами остаются более явный outer-layer/runtime marker для strict quorum-loss в negative live bundle и отдельная external multi-IP validation вне локальной Linux VM.

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

Подтверждено real-traffic runtime-retest на 2026-04-06 / `ae621d24`, затем повторно подтверждено current-head smoke на 2026-04-06 / `c6ff745b`, расширенным current-head matrix на 2026-04-07 / `d350388e` и post-normalization current-head rerun на 2026-04-07 / `4bfd8ac9`:
- outbound H2 path теперь корректно работает поверх общего Xray `streamSettings.security = "reality"` и не падает в ложный HTTP/1.1 fallback, если REALITY transport не экспонирует negotiated ALPN обратно в TrustTunnel layer;
- practically significant fix заключается в том, что H2 path больше не требует буквального `NegotiatedProtocol == "h2"` для REALITY-wrapper: при `UsesReality=true` и пустом negotiated ALPN client пишет `trusttunnel transport=http2 requested with REALITY and empty negotiated ALPN; using HTTP/2 preface path` и продолжает по HTTP/2 preface path;
- живой H2/TCP current-head smoke через lab client `/opt/lab/xray-tt/configs/our_client_to_remote_server_h2_reality.json`, runtime binary `/opt/lab/xray-tt/tmp/xray-tt-regress-linux`, remote runtime binary `/opt/trusttunnel-dev/tmp/xray-tt-regress-linux`, lab bundle `/opt/lab/xray-tt/logs/workerfix-h2-reality-lab-20260406-153646` и remote bundle `/opt/trusttunnel-dev/logs/workerfix-h2-reality-remote-20260406-153646` повторно подтверждает `trusttunnel transport=http2 requested with REALITY and empty negotiated ALPN; using HTTP/2 preface path`, `trusttunnel H2 CONNECT accepted for tcp:www.cloudflare.com:443`, `trusttunnel H2 CONNECT accepted for tcp:api.ipify.org:443`, а downstream probe через SOCKS даёт `ip=37.252.0.130`, `http=http/2` и `{\"ip\":\"37.252.0.130\"}`;
- живой H2/UDP current-head smoke через lab client `/opt/lab/xray-tt/configs/our_client_udp_to_remote_server_h2_reality.json`, runtime binary `/opt/lab/xray-tt/tmp/xray-tt-regress-linux`, remote runtime binary `/opt/trusttunnel-dev/tmp/xray-tt-regress-linux`, lab bundle `/opt/lab/xray-tt/logs/workerfix-h2-reality-udp-lab-20260406-153758` и remote bundle `/opt/trusttunnel-dev/logs/workerfix-h2-reality-udp-remote-20260406-153758` повторно подтверждает `trusttunnel H2 UDP mux accepted`, `dispatch request to: udp:1.1.1.1:53`, `proxy/freedom: connection opened to udp:1.1.1.1:53` и real DNS answer для `cloudflare.com`.
- clean-HEAD full live functional matrix на `4bfd8ac9` через lab bundle `/opt/lab/xray-tt/logs/full-live-20260407-153034` и remote bundle `/opt/trusttunnel-dev/logs/full-live-20260407-153034` повторно закрывает не только H2/REALITY success-path, но и H2 TLS, H3 TLS, UDP DNS, `hasIpv6=false` domain-target fail и `http3 + reality` explicit reject;
- clean-HEAD full live load matrix на `d350388e` через lab bundle `/opt/lab/xray-tt/logs/full-live-20260407-140912` и remote bundle `/opt/trusttunnel-dev/logs/full-live-20260407-140912` подтверждает sustained TCP/UDP traffic и CPU-профиль по всем поддержанным комбинациям; fastest TCP case авторитетного rerun — `h2_reality_pq_off_load_tcp` ~`373.45 Mbit/s` при lab/client CPU avg/max `45.62 / 99` и remote/server `64.38 / 112`.

### 2.13. Multi-endpoint outbound policy

Подтверждено локальными regression-тестами и remote-live sequence на 2026-04-09:
- outbound `servers[]` больше не режется до одного endpoint на config-build/runtime path: client реально держит упорядоченный список `ServerEndpoint`;
- stream / UDP / ICMP path используют один и тот же ordered fallback по endpoint до установления tunnel;
- после успешного establish последующие соединения предпочитают последний успешно established endpoint, а не каждый раз начинают заново с первого адреса списка;
- pre-establishment fail больше не приводит к немедленному повторному удару в тот же endpoint на следующем соединении: проблемный endpoint уходит в короткий cooldown и временно переставляется в конец порядка попыток;
- remote-live sequence `/opt/lab/xray-tt/logs/endpoint-policy-live-20260409-005720` / `/opt/trusttunnel-dev/logs/endpoint-policy-live-20260409-005720` подтверждает ordered fallback, last-success preference и cooldown на одном long-lived client-process через четыре последовательных real-traffic шага: `A -> fallback to B -> cooldown skips A and uses C -> cooldown expiry returns to A`;
- отдельный remote-live sequence `/opt/lab/xray-tt/logs/endpoint-active-probe-live-20260409-051636` / `/opt/trusttunnel-dev/logs/endpoint-active-probe-live-20260409-051636` подтверждает active recovery probing: после fallback `A -> B` и последующего восстановления `A` client сам делает `_check` probe в cooling endpoint, логирует `trusttunnel active probe restored endpoint 1/2`, а следующий real-traffic CONNECT возвращается на `A` уже через `903ms`, то есть заметно раньше полного `5s` cooldown;
- отдельный remote-live sequence `/opt/lab/xray-tt/logs/endpoint-resolve-live-20260409-053846` / `/opt/trusttunnel-dev/logs/endpoint-resolve-live-20260409-053846` подтверждает address-expansion domain-entry: при single configured `address = "ttmulti.lab"` client log фиксирует `trusttunnel server 1/2 failed...`, downstream probe даёт `{"ip":"37.252.0.130"}`, а remote `tcpdump` фиксирует трафик на `37.252.0.130:9443`, то есть один доменный server-entry реально разворачивается в два runtime endpoint и проходит через тот же fallback policy.
- это поведение не является скрытой live-session migration: после установления tunnel runtime-ошибка уже работающей сессии не переключает её на другой endpoint автоматически.

## 3. Что считается текущей истиной

Текущую истину по проекту определяют:
- этот документ;
- `docs/current/architecture.md`;
- `docs/current/operations.md`;
- `docs/current/validation.md`;
- `docs/current/roadmap.md`.

Исторические и миграционные документы могут объяснять, почему раньше было иначе, но не могут переопределять этот current-слой.

На `2026-04-07` current baseline дополнительно включает merge `e83795ab`, который догоняет ветку до `upstream/main` `e5a9fb75`. Отдельный live A/B audit fork vs upstream по не-TrustTunnel path (`direct`, `tun`, `vless + tls`, `vless + reality`, `hysteria`) не дал подтверждённого поведенческого расхождения вне TrustTunnel: authoritative result root — `/opt/lab/xray-compare/results/non-tt-live-20260407-210442`, детали и метрики зафиксированы в `docs/current/validation.md`.

## 4. Что остаётся открытым после этой фиксации

Client-side parity surface для поддержанных H2/H3 + TLS и H2 + REALITY path на текущем этапе больше не считается открытым блоком: `post_quantum_group_enabled` wired в runtime, `hasIpv6=false` получил domain-target policy guard, `antiDpi=true` доведён до runtime на `HTTP/2 over TLS` и `HTTP/2 over REALITY`, а non-HTTP3 TLS compatibility surface доведён до текущей границы между compatibility fields и generic `streamSettings.tlsSettings`.

Открытыми задачами текущего этапа считаются уже не runtime-gaps внутри текущего validated protocol surface, а maintenance-блоки:
- держать non-HTTP3 compatibility boundary синхронной с upstream-изменениями generic TLS/REALITY и `streamSettings` layer Xray;
- поддерживать compatibility matrix и validator hardening синхронно с новыми generic integration-комбинациями Xray;
- добирать dedicated `metadataOnly` или иные generic inbound transport scenarios только если они реально понадобятся как product path сверх уже подтверждённых `sniffing + routeOnly` и `rejectUnknownSni`.

H3 + REALITY на текущем этапе больше не считается обычным parity-gap: R&D завершён stop-factor verdict'ом. Любая будущая реализация потребует нового QUIC-capable REALITY transport в Xray core, а не локального патча в TrustTunnel.

Ближайший открытый блок после фиксации multi-endpoint policy:
- довести outbound transport resilience до более близкой к original client модели поверх уже готовых `transport=auto`, `servers[]` fallback, delayed race, endpoint cooldown и active probing;
- следующая практическая цель — решать, нужен ли ещё один уровень endpoint model поверх уже работающего active probe и resolved-address expansion, например более близкое к original relay/address-selection поведение, а не возвращаться к уже закрытым H2/H3/REALITY/ICMP gaps.

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
