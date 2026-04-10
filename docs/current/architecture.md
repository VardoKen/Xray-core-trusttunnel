# TrustTunnel / Xray-Core — архитектура и runtime-path

Статус: current
Дата фиксации: 2026-04-10
Коммит состояния: `d2249887`
Ветка: `feat/trusttunnel-multipath`
Область истины: карта кода, реальные runtime-path, активные и декларативные поля конфигурации
Не использовать для: исторического описания этапов и промежуточных тупиковых веток

## 1. Назначение

Документ нужен для:
- дальнейшей разработки;
- отладки;
- сопровождения;
- изменения конфигов и тестовых артефактов;
- понимания реальных точек интеграции TrustTunnel в fork Xray-Core.

## 2. Лаборатория и воспроизводимые артефакты

### 2.1. Окружение

- ОС: Debian 13 (trixie), amd64
- Основное рабочее дерево: `/opt/lab/xray-tt/src/xray-core-trusttunnel`
- Upstream-дерево: `/opt/lab/xray-tt/src/xray-core-upstream`
- Reference endpoint: `/opt/lab/xray-tt/src/trusttunnel-ref`
- Reference client: `/opt/lab/xray-tt/src/trusttunnel-client-ref`
- Лабораторные каталоги: `/opt/lab/xray-tt/bin`, `/opt/lab/xray-tt/configs`, `/opt/lab/xray-tt/certs`, `/opt/lab/xray-tt/logs`, `/opt/lab/xray-tt/tmp`, `/opt/lab/xray-tt/pcap`

### 2.2. Базовые версии

- Xray-core: ранняя база `v26.2.6`, далее post-merge база от `upstream/main`
- merge-base текущей ветки с upstream: `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`
- TrustTunnel endpoint: `v1.0.17`
- TrustTunnel client: `v1.0.23`
- Go: `1.26.1`
- protoc: `3.21.12`
- protoc-gen-go: `v1.36.11`

### 2.3. Ключевые артефакты кода

- `proxy/trusttunnel/*`
- `infra/conf/trusttunnel.go`
- `infra/conf/trusttunnel_lint.go`
- `proxy/trusttunnel/post_quantum.go`
- `proxy/trusttunnel/endpoint_policy.go`
- `proxy/trusttunnel/stream_settings_compat.go`
- `app/proxyman/outbound/handler.go`
- `transport/internet/stream_settings_override.go`
- `transport/internet/tcp/trusttunnel_clienthello.go`
- `transport/internet/tcp/http3_conn.go`
- `transport/internet/tcp/http3_clienthello.go`
- `transport/internet/tcp/hub.go`
- `app/proxyman/inbound/always.go`
- `app/proxyman/inbound/worker.go`
- `testing/scenarios/trusttunnel_test.go`

### 2.4. Ключевые тестовые конфиги

- `testing/trusttunnel/*` — tracked test artifacts и примеры конфигов; они не попадают в обычный `go build ./main`, пока их отдельно не использует runtime или packaging tooling.
- `testing/trusttunnel/server_stub.json`
- `testing/trusttunnel/client_stub.json`
- `testing/trusttunnel/server_h2.json`
- `testing/trusttunnel/server_h2_official_cert.json`
- `testing/trusttunnel/client_h2.json`
- `testing/trusttunnel/server_h2_rules.json`
- `testing/trusttunnel/server_h2_udp.json`
- `testing/trusttunnel/server_h3.json`
- `testing/trusttunnel/server_h3_udp.json`
- `testing/trusttunnel/our_client_to_official_endpoint.json`
- `testing/trusttunnel/our_client_to_our_server.json`
- `testing/trusttunnel/our_client_udp_to_our_server_h2.json`
- `testing/trusttunnel/our_client_udp_to_our_server_h3.json`
- `testing/trusttunnel/official_client_to_our_server_h2_check_ok.toml`
- `testing/trusttunnel/official_client_to_our_server_h2_check_authfail.toml`
- `testing/trusttunnel/official_client_rules_allow.toml`
- `testing/trusttunnel/official_client_rules_deny.toml`
- `testing/trusttunnel/server_h3_rules.json`
- `testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json`
- `testing/trusttunnel/our_client_to_our_server_h2_clientrandom_deny.json`
- `testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json`
- `testing/trusttunnel/our_client_to_our_server_h3_clientrandom_deny.json`

Для live-traffic REALITY против remote host `37.252.0.130` в tracked tree уже лежат шаблоны under `testing/trusttunnel/*`, а runtime deployment может использовать их lab-local copies:
- tracked templates: `testing/trusttunnel/our_client_to_remote_server_h2_reality.json`, `testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json`, `testing/trusttunnel/server_h2_reality_remote.json`, `testing/trusttunnel/server_h2_udp_reality_remote.json`;
- deployment-specific overrides и любые non-test keys/coordinates должны оставаться lab-local runtime artifacts вне tracked history.

## 3. Config binding и модель протокола

### 3.1. JSON → protobuf

Файл:
- `infra/conf/trusttunnel.go`

Функция:
- регистрация inbound loader `trusttunnel`;
- регистрация outbound loader `trusttunnel`;
- преобразование JSON в `trusttunnel.ClientConfig` и `trusttunnel.ServerConfig`;
- чтение `certificatePemFile` в строковый PEM.

Это единственная точка binding между JSON-конфигом и protobuf-моделью TrustTunnel.

### 3.2. Протокольная модель

Файл:
- `proxy/trusttunnel/config.proto`

Сущности:
- `Account`
- `TransportProtocol`
- `MultipathScheduler`
- `Rule`
- `ServerHost`
- `MultipathConfig`
- `ClientConfig`
- `ServerConfig`

Практический вывод:
- config model шире, чем фактически используемый runtime;
- часть полей существует как compatibility surface, но не как подтверждённая активная функция.

### 3.3. Config-build validator

Файл:
- `infra/conf/trusttunnel_lint.go`

Реализовано:
- post-processing stage `TrustTunnel` проверяет TrustTunnel inbound/outbound после JSON build;
- validator fail-fast режет `antiDpi=true`, если outbound не даёт совместимый `HTTP/2 + TLS/REALITY` security-path;
- validator fail-fast режет `antiDpi=true` при explicit `transport=http3`;
- validator fail-fast режет outbound `transport=http3` + `streamSettings.security = "reality"`;
- validator fail-fast режет inbound `transports` содержащий `http3` + `streamSettings.security = "reality"`;
- validator fail-fast режет H2 outbound `postQuantumGroupEnabled`, если общий `streamSettings` не даёт TLS/REALITY security surface;
- validator fail-fast режет non-HTTP3 outbound `hostname` conflict с generic `tlsSettings.serverName`;
- validator fail-fast режет non-HTTP3 outbound `skipVerification=true` поверх explicit generic TLS verify surface;
- validator fail-fast режет non-HTTP3 outbound `skipVerification=true` вместе с `certificatePem` / `certificatePemFile`;
- validator fail-fast режет non-HTTP3 outbound `certificatePem` / `certificatePemFile` поверх explicit generic TLS verify surface;
- validator fail-fast режет experimental `multipath.enabled=true` вне phase-1 scope: не `transport=http2`, не `streamSettings.security=tls`, `udp=true`, отсутствие multi-endpoint pool, `multipath.minChannels < 2` и `multipath.maxChannels < minChannels`;
- H3 `postQuantumGroupEnabled` без outbound TLS `streamSettings` не режется этим guard, потому что H3 использует собственный TLS path.

## 4. Карта клиентского path

### 4.1. Основные файлы

- `proxy/trusttunnel/client.go`
- `proxy/trusttunnel/h3_client.go`
- `proxy/trusttunnel/udp_client.go`
- `proxy/trusttunnel/icmp_client.go`
- `proxy/trusttunnel/endpoint_policy.go`
- `proxy/trusttunnel/endpoint_probe.go`
- `proxy/trusttunnel/multipath_session.go`

### 4.2. Реализованные направления

- H1 CONNECT
- H2 CONNECT через `http2.Transport.NewClientConn`
- H3 CONNECT через `quic-go` / `http3.ClientConn` с raw request-stream tunnel semantics
- `transport="auto"` с H3-first выбором и H3→H2 fallback на transport-level ошибках
- H2 CONNECT / `_udp2` / `_icmp` поверх общего Xray `streamSettings.security = "reality"` без ложного HTTP/1.1 fallback при пустом negotiated ALPN у REALITY-wrapper
- ordered `servers[]` fallback, delayed race между первыми двумя ready endpoint, preference последнего успешно established endpoint, короткий cooldown после pre-establishment fail и active probing охлаждённых endpoint через реальный `_check`
- один domain-valued `address` / `servers[].address` на client init разворачивается в несколько resolved IP, и каждый из них становится отдельным runtime endpoint в том же policy order
- per-request `streamSettings` override через общий outbound layer Xray
- TrustTunnel-local `verifyTrustTunnelTLS()` только как fallback для path без authoritative generic `tlsSettings`; non-HTTP3 generic TLS path больше не строит второй verify-layer поверх transport TLS
- совместимость H2/TLS outbound с generic Xray `streamSettings.tlsSettings` по `ServerName`, authority-verify через custom CA, `VerifyPeerCertByName`, `PinnedPeerCertSha256` и `Fingerprint`
- UDP CONNECT на official authority `_udp2`; server-side reserved-host matcher сохраняет backward-compat на `_udp2` и legacy `_udp2:0`
- ICMP CONNECT на `_icmp:0` для H2 и H3
- common outbound features `proxySettings`, `mux`, `sendThrough=origin` и `targetStrategy useipv4` проходят через тот же generic Xray outbound layer и не требуют TrustTunnel-specific routing surface
- experimental `multipath.*` config surface уже существует вместе с `_mptcp_open` / `_mptcp_attach` control path, причём этот control path уже подтверждён Linux-to-Linux H2/TLS live open/attach между `192.168.1.19` и `192.168.1.25`; при этом payload data-plane он пока всё ещё не меняет и working multipath path не образует

### 4.3. Поля outbound, реально участвующие в runtime

Активны:
- `Transport`
- `Hostname`
- `SkipVerification`
- `CertificatePem`
- `EnableUdp`
- outbound `ClientRandom`
- `PostQuantumGroupEnabled` как client-side toggle для effective TLS/REALITY fingerprint и H3 TLS curve preferences
- `HasIpv6` как client-side gate для явных IPv6 literal targets и domain targets без `targetStrategy useipv4/forceipv4`
- `AntiDpi` как split первой TCP-based записи ClientHello на `HTTP/2 over TLS` и `HTTP/2 over REALITY`

Experimental multipath surface:
- `Multipath`

Практическая граница:
- `multipath.*` на текущем этапе уже является phase-2 control surface: config/validator, session registry, `_mptcp_open`, `_mptcp_attach`, attach-proof и server-side channel attach существуют, а live bundle `/opt/lab/xray-tt/logs/multipath-phase2-live-20260410-194957` дополнительно подтверждает real H2/TLS open/attach на разных IP (`192.168.1.50` / `192.168.1.51`) внутри одной multipath session;
- client-side payload path пока deliberately fail-fast режется, потому что framed multipath data layer, scheduler/reassembly и реальное multi-channel traffic distribution ещё не существуют в working runtime.

### 4.3.1. Generic TLS surface на поддержанном H2/TLS path

Подтверждено scenario-тестами в `testing/scenarios/trusttunnel_test.go`:
- `streamSettings.tlsSettings.serverName` реально участвует в verify path для TrustTunnel H2/TLS outbound;
- authority-verify через custom CA работает на том же path;
- `VerifyPeerCertByName` реально матчит peer certificate names;
- `PinnedPeerCertSha256` и `Fingerprint` не остаются декларативными полями и совместимы с TrustTunnel H2/TLS.

Текущее practically significant уточнение на `4bfd8ac9`:
- non-HTTP3 generic `tlsSettings` являются authoritative TLS surface;
- compatibility fields `hostname` и `skipVerification` только дополняют missing `serverName` / `allowInsecure`, а не создают второй TrustTunnel-local verify router;
- если generic TLS уже задаёт explicit verify surface (`VerifyPeerCertByName`, `PinnedPeerCertSha256`, authority-verify cert), compatibility fields не переписывают его, а validator режет двусмысленные конфигурации ещё на config-build этапе.

Практическая граница:
- на Windows current generic TLS transport требует `DisableSystemRoot=true` для воспроизводимого custom-CA verify path; это поведение относится к общему TLS transport layer Xray, а не к TrustTunnel-specific verify logic.

### 4.4. H2 REALITY runtime-path

Файлы:
- `proxy/trusttunnel/security_state.go`
- `proxy/trusttunnel/client.go`
- `proxy/trusttunnel/post_quantum.go`
- `proxy/trusttunnel/udp_client.go`
- `proxy/trusttunnel/icmp_client.go`
- `app/proxyman/outbound/handler.go`
- `transport/internet/stream_settings_override.go`

Реализовано:
- выбор H2 path больше не завязан только на буквальный `NegotiatedProtocol == "h2"`;
- helper `trustTunnelShouldUseHTTP2(...)` учитывает requested TrustTunnel transport и security state соединения;
- если outbound использует `settings.transport = "http2"` и общий Xray `streamSettings.security = "reality"`, то пустой negotiated ALPN у REALITY-wrapper больше не переводит client в ложный HTTP/1.1 fallback;
- тот же helper покрывает TCP CONNECT, `_udp2` и `_icmp`, потому что все три path используют один и тот же выбор H2 transport branch;
- common outbound handler теперь уважает per-request `streamSettings` override из context вместо жёсткого handler-level `streamSettings`;
- `postQuantumGroupEnabled` для H2/TLS и H2/REALITY реализован именно через этот override path и не мутирует shared handler config;
- practically significant marker: client log `trusttunnel transport=http2 requested with REALITY and empty negotiated ALPN; using HTTP/2 preface path`.

Подтверждено real-traffic retest на `ae621d24`, затем повторно подтверждено current-head smoke на `c6ff745b`:
- lab client `/opt/lab/xray-tt/configs/our_client_to_remote_server_h2_reality.json` и remote runtime binary `/opt/trusttunnel-dev/tmp/xray-tt-regress-linux` дают живой H2/TCP path до internet;
- lab client `/opt/lab/xray-tt/configs/our_client_udp_to_remote_server_h2_reality.json` и remote runtime binary `/opt/trusttunnel-dev/tmp/xray-tt-regress-linux` дают живой H2/UDP DNS path;
- controlled load bundle `/opt/lab/xray-tt/logs/load-h2-reality-20260406-111027` показывает, что тот же H2/REALITY path переносит sustained TCP traffic без функционального срыва.

### 4.5. H3 + REALITY explicit unsupported path

Файлы:
- `proxy/trusttunnel/h3_client.go`
- `proxy/trusttunnel/client.go`
- `proxy/trusttunnel/udp_client.go`
- `proxy/trusttunnel/icmp_client.go`
- `app/proxyman/outbound/handler.go`
- `transport/internet/tcp/hub.go`
- `transport/internet/reality/reality.go`

Архитектурный verdict:
- outbound H3 path не идёт через общий Xray `internet.Dial(..., streamSettings)` и сейчас сам строит QUIC/TLS handshake в `proxy/trusttunnel/h3_client.go`;
- current REALITY surface в Xray оборачивает только TCP `net.Conn` через `reality.UClient(...)` / `reality.Server(...)`, а не QUIC `PacketConn`;
- inbound H3 listener в `transport/internet/tcp/hub.go` поднимается только через TLS-based QUIC listener и не имеет QUIC-capable REALITY wrapper.
- При этом сам H3/TLS path уже не является проблемным tunnel-слоем: client и server используют raw HTTP/3 stream и clean-head live matrix подтверждает sustained TCP traffic; unsupported verdict относится именно к `http3 + reality`, а не к H3 transport вообще.

Следствие:
- H3 + REALITY в текущем дереве не является “ещё не допиленным fallback”, а отдельной unsupported combination;
- current runtime теперь явно режет её marker'ом `trusttunnel http3 with REALITY is unsupported: current Xray REALITY transport is TCP-only`;
- для будущей реализации нужен новый transport/security layer для QUIC + REALITY, а не локальный фикс внутри TrustTunnel handler.

### 4.6. Client-Side IPv6 / AntiDpi / Post-Quantum policy

Файлы:
- `proxy/trusttunnel/client.go`
- `proxy/trusttunnel/client_test.go`
- `proxy/trusttunnel/post_quantum.go`

Реализовано:
- `hasIpv6=false` теперь реально участвует в client-side policy layer и режет явные IPv6 literal targets до dial marker'ом `trusttunnel IPv6 target is disabled by hasIpv6=false`;
- тот же guard для domain targets требует outbound `targetStrategy useipv4/forceipv4` и иначе режет запрос marker'ом `trusttunnel hasIpv6=false requires outbound targetStrategy useipv4/forceipv4 for domain targets`;
- тот же guard не затрагивает явные IPv4 literal targets: live H2/REALITY retest подтверждает, что `tcp:1.1.1.1:443` продолжает идти через тот же working path;
- `antiDpi=true` на `HTTP/2 over TLS` и `HTTP/2 over REALITY` больше не остаётся декларативным no-op: transport layer оборачивает соединение и split'ит первую TCP-based запись ClientHello; `transport="auto"` при этом сразу выбирает HTTP/2 path, а explicit `http3` режется validator/runtime guard'ами;
- `postQuantumGroupEnabled` для H2/TLS и H2/REALITY переключает effective TLS/REALITY fingerprint между Chrome-family PQ/non-PQ вариантами через per-request override, а для H3/TLS переключает `CurvePreferences` между `X25519MLKEM768 + X25519` и `X25519`.

Граница текущего состояния:
- `antiDpi` остаётся открытым parity-вопросом только для `HTTP/3` и для более глубокого original-style anti-DPI behavior beyond split первого ClientHello write.
- `postQuantumGroupEnabled` пока сознательно ограничен default Chrome-family TLS/REALITY fingerprint surface и H3 TLS curve preferences; arbitrary uTLS/fingerprint families не переключаются автоматически.

### 4.6.1. Common inbound integration

Подтверждено:
- TrustTunnel inbound совместим с общими `sniffing + routeOnly`;
- generic inbound TLS setting `RejectUnknownSni` подтверждён отдельным scenario-тестом и не ломает TrustTunnel inbound path;
- `HandlerService` `AddUser` / `RemoveUser` и `GetInboundUsersCount` работают на TrustTunnel inbound без отдельного protocol-local management layer.

Граница текущего состояния:
- `metadataOnly` следует общей семантике `app/dispatcher`: в режиме `metadataOnly=true` выполняются только metadata sniffers, поэтому TLS SNI route override не образует отдельный TrustTunnel positive path.

### 4.7. Outbound `clientRandom` runtime-path

Файлы:
- `transport/internet/tls/client_random.go`
- `transport/internet/tcp/dialer.go`
- `proxy/trusttunnel/client.go`
- `proxy/trusttunnel/h3_client.go`
- `proxy/trusttunnel/udp_client.go`

Реализовано:
- `settings.clientRandom` нормализуется как TrustTunnel-style `prefix[/mask]`;
- для H2 path spec прокидывается через context в TLS dialer;
- для H3 path spec применяется напрямую к `tls.Config.Rand` перед QUIC/TLS handshake;
- первые 32 байта случайного источника подменяются так, чтобы outgoing ClientHello random удовлетворял configured spec.

Подтверждено clean-HEAD runtime-retest на `fc276340`:
- H2 и H3 allow-case с `clientRandom = "deadbeef"` проходят server-side rules;
- H2 и H3 deny-case с несовпадающим `clientRandom` получают `403`.

### 4.8. Outbound `_icmp` runtime-path

Файлы:
- `proxy/trusttunnel/client.go`
- `proxy/trusttunnel/icmp_client.go`
- `proxy/trusttunnel/icmp_codec.go`
- `proxy/tun/icmp.go`
- `proxy/tun/stack_gvisor.go`

Реализовано:
- `common/net.Network_ICMP` на outbound стороне переводит `Client.Process(...)` в отдельный `_icmp:0` path вместо обычного CONNECT target;
- request-side contract читает raw ICMP echo-request packet из `transport.Link`, извлекает `id`, `sequence`, `destination`, `ttl/hop_limit` и `data_size`, после чего пишет fixed-size TrustTunnel request frame;
- response-side contract читает fixed-size TrustTunnel reply frame и локально восстанавливает representable raw ICMP replies: echo-reply, destination-unreachable и time-exceeded по сохранённому исходному payload и quoted request context;
- path работает для H2 и H3 и использует те же transport-specific CONNECT routines, что и TCP/UDP path;
- `proxy/tun` поднимает `gicmp.NewProtocol4/NewProtocol6`, принимает echo-request traffic в `icmpConnectionHandler` и инжектит echo-reply обратно в link endpoint;
- clean-HEAD Linux retest на 2026-04-05 / `96a9d053` подтверждает, что этот path уже образует product-level source path через `proxy/tun`, если TUN interface вынесен в отдельный network namespace или иным образом получает явную OS-managed адресацию и routing.

Ограничения текущего состояния:
- client-side contract ограничен representable fixed-size reply frame: он покрывает echo-reply, destination-unreachable и time-exceeded, но не может перенести MTU/pointer-специфику `PacketTooBig` / `ParameterProblem` без расширения протокола;
- validated product path пока относится к Linux TUN deployment с внешним OS-managed routing; host-namespace схема вида `ip addr add 192.0.2.10/32 dev xraytunh2` + `ip route add 1.1.1.1/32 dev xraytunh2` воспроизводит request storm и считается unsafe wiring pattern;
- server-side config surface для `_icmp` now covers `allowPrivateNetworkConnections`, `icmp.interfaceName`, `icmp.requestTimeoutSecs`, `icmp.recvMessageQueueCapacity` и observable `ipv6Available`; `ipv6Available` при этом не должен трактоваться как общий server transport selector вне `_icmp`.

## 5. Карта серверного path

### 5.1. Основной серверный модуль

Файл:
- `proxy/trusttunnel/server.go`
- `proxy/trusttunnel/icmp_codec.go`
- `proxy/trusttunnel/icmp_server.go`

### 5.2. H1 path

- `Process()` читает TCP conn;
- через `bufio.Reader` проверяет H2 preface;
- при отсутствии preface уходит в `processHTTP1()`;
- там выполняются auth, извлечение `client_random`, rule-matching, а затем:
- reserved pseudo-hosts `_check`, `_udp2` и `_icmp` обрабатываются до обычного target parsing;
- только обычный CONNECT target уходит в `dispatcher.DispatchLink()` и `appdispatcher.WrapLink()`.

### 5.3. H2 path

- при H2 preface вызывается `processHTTP2()`;
- `http2.Server.ServeConn()` обслуживает stream;
- каждый CONNECT stream уходит в `serveHTTPConnectRequest("H2", ...)`.

Подтверждено runtime-проверкой 2026-04-04:
- pseudo-host `_check` на H2/H3 обрабатывается в `serveHTTPConnectRequest(...)` после auth/rules;
- health-check special-case срабатывает до UDP mux и до обычного target parsing;
- H2 `_check` больше не падает обратно в обычный dispatch path.

Подтверждено локальными regression-тестами, Linux root loopback-тестом и lab runtime-retest на 2026-04-05 / `b1c14eb3`:
- reserved pseudo-host `_icmp` на H2/H3 перехватывается до обычного target parsing;
- H2/H3 `_icmp` использует отдельный fixed-size codec по official wire-format;
- серверный path создаёт per-stream raw ICMP session и пишет обратно reply-frames без участия обычного Xray dispatcher;
- на подтверждённом состоянии echo-reply path работает для IPv4 loopback; clean-HEAD official H2/H3 interop подтверждён на 2026-04-05 / `5a21fd31` и `6c46922c`;
- representable reply types echo-reply, destination-unreachable и time-exceeded подтверждены server/client-side unit-path, а `time exceeded` дополнительно подтверждён H2 runtime bundle `/opt/lab/xray-tt/logs/h2-icmp-timeexceeded-rawping-20260405-185429`.

### 5.3.1. H2/H3 `_icmp` runtime-path

Файлы:
- `proxy/trusttunnel/icmp_codec.go`
- `proxy/trusttunnel/icmp_server.go`
- `proxy/trusttunnel/client_random.go`

Реализовано:
- CONNECT на `_icmp:0` после auth/rules переводится в отдельный H2/H3 mux path;
- входящий stream разбирается как последовательность fixed-size request frames:
  `id(2) + destination(16) + sequence(2) + ttl/hop_limit(1) + data_size(2)`;
- сервер создаёт echo-request в raw ICMP socket и ждёт reply в пределах фиксированного timeout;
- `settings.allowPrivateNetworkConnections`, `settings.icmp.interfaceName`, `settings.icmp.requestTimeoutSecs` и `settings.icmp.recvMessageQueueCapacity` уже подключены к server-side `_icmp` runtime;
- по текущей реализации private-network destinations по умолчанию режутся до raw-send path, `icmp.interfaceName` задаёт `IfIndex` для raw ICMP socket, `icmp.requestTimeoutSecs` переопределяет timeout ожидания reply, а `icmp.recvMessageQueueCapacity` задаёт bounded per-stream reply queue с default `256` и drop-on-overflow semantics;
- исходящий stream пишет fixed-size reply frames:
  `id(2) + source(16) + type(1) + code(1) + sequence(2)`;
- server-side reply parser и client-side reconstruction покрывают representable reply types echo-reply, destination-unreachable и time-exceeded; H2 runtime с raw ping `-e 0 -t 1` подтверждает `type=11 code=0`;
- attachment `trusttunnel.client_random` перед special-path dispatch клонирует `session.Content`, чтобы параллельные H2/H3 streams не делили один mutable `Attributes` map;
- `ipv6Available` для `_icmp` observable: при `false` H2 direct probe получает `IPv6 ICMP is unavailable`, при `true` path открывает IPv6 raw socket и возвращает echo-reply;
- если raw ICMP недоступен, H2/H3 path отвечает `503 Service Unavailable`.

Ограничения текущего состояния:
- H1 `_icmp` остаётся не transport path и отвечает `501 Not Implemented`;
- `PacketTooBig` / `ParameterProblem` server-side распознаются и матчатся по quoted echo-request, но fixed-size reply frame не может передать назад MTU/pointer-specific данные;
- clean-HEAD H2/H3 retest подтверждает product-level `_icmp` source path через `proxy/tun` на Linux с OS-managed routing; host-namespace `/32` wiring остаётся unsafe pattern и не считается рекомендуемым product deployment.

### 5.4. H3 path

- если входящее соединение реализует `tcp.HTTP3RequestConn`, вызывается `processHTTP3()`;
- H3 request оборачивается в совместимый request/response wrapper;
- дальше используется тот же `serveHTTPConnectRequest("H3", ...)`.

Ключевой вывод текущего состояния:
- H3 path является рабочим transport-layer path;
- дальнейшая разработка H3 должна вестись здесь, а не через удалённый legacy-обработчик первой попытки реализации.

## 6. Извлечение `client_random`

### 6.1. H1/H2 через TCP ClientHello

Файл:
- `transport/internet/tcp/trusttunnel_clienthello.go`

Реализовано:
- чтение TLS record header;
- сбор ClientHello;
- извлечение 32-byte random;
- возврат считанного префикса в поток чтения.

Использование:
- `transport/internet/tcp/hub.go`
- перед TLS server wrapping вызывается `wrapTrustTunnelClientRandomConnWithTimeout(conn, tls_handshake_timeout_secs)`, чтобы pre-handshake ClientHello extraction не обходил configured TLS handshake timeout;
- после этого уже выполняется TLS server wrapping и `trustTunnelServerHandshake(...)`.

### 6.2. H3 через QUIC Initial / TLS ClientHello

Файлы:
- `transport/internet/tcp/http3_clienthello.go`
- `transport/internet/tcp/http3_conn.go`
- `transport/internet/tcp/hub.go`

Реализовано:
- tracker по remote UDP source;
- разбор QUIC Initial;
- снятие header protection;
- decrypt Initial payload;
- сбор CRYPTO frames;
- извлечение ClientHello random;
- прокидывание `clientRandom` в `http3RequestConn`.

Итог:
- H3 `client_random` является реальным runtime-атрибутом;
- на состоянии `99e59352` он участвует в rule-matching.

## 7. Rules path

Файл:
- `proxy/trusttunnel/rules.go`

Поддержано:
- CIDR
- exact/prefix `client_random`
- masked `client_random`
- catch-all allow/deny

Текущее состояние:
- H1/H2 rules работают;
- H3 rules работают после снятия искусственной блокировки и retest на состоянии `99e59352`.

## 8. UDP mux

Файлы:
- `proxy/trusttunnel/udp_codec.go`
- `proxy/trusttunnel/udp_client.go`
- `proxy/trusttunnel/udp_server.go`

Признаки реализации:
- outbound pseudo-host `_udp2`;
- server-side reserved-host matcher принимает `_udp2` и legacy `_udp2:0`;
- отдельный request/response frame format;
- IPv4 кодируется как zero-padded 16-byte address;
- IPv6 передаётся в 16-byte raw form;
- клиент передаёт `AppName`;
- сервер держит flow table по `(client source, target)`;
- на каждый flow поднимается `udp_transport.NewDispatcher(...)`.

Подтверждённое состояние:
- clean-HEAD bundle `/opt/lab/xray-tt/logs/udp-matrix-20260405-222820` закрывает official client → our server и our client → official endpoint на H2/H3, IPv4/IPv6, multi-flow per session и reopen после `udpConnectionsTimeoutSecs = 1`;
- current `AppName`, который наш client пишет в UDP frame, принимается official endpoint в подтверждённой H2/H3 matrix и не остаётся interop-blocker.

Подтверждённое ограничение:
- H1 path не реализует UDP mux и явно отклоняет `_udp2` до обычного dispatch;
- destination должен быть IP-адресом;
- доменные UDP targets не подтверждены как рабочий path.

## 9. Stats path

Ключевые файлы:
- `proxy/trusttunnel/server.go`
- `proxy/trusttunnel/users.go`
- `app/proxyman/inbound/always.go`
- `app/proxyman/inbound/worker.go`

Ключевые правила:
- inbound counters создаются на worker layer;
- TCP path на сервере оборачивается через `appdispatcher.WrapLink(...)`;
- H3 request/response bytes учитываются через серверные wrappers;
- если `user.Email == ""`, runtime подставляет `Username` как user-key.

Практический вывод:
- `user>>>...>>>traffic>>>*` — обычные counters;
- `inbound>>>...>>>traffic>>>*` — обычные counters;
- `outbound>>>...>>>traffic>>>*` — обычные counters;
- `user>>>...>>>online` — `onlineMap`, а не counter;
- `NotFound` по `user>>>...>>>online` не равен поломке user stats.
- clean-HEAD bundle `/opt/lab/xray-tt/logs/auth-stats-sanity-20260405-231514` подтверждает H2 auth recovery, H2 TCP counters и H3 UDP `onlineMap`/user stats на текущем code-state `6fcb3a28`;
- `app/stats/online_map.go` намеренно игнорирует `127.0.0.1` и `[::1]`, поэтому localhost-only lab probes не могут подтверждать `onlineMap` как ненулевой;
- `api statsonlineiplist` возвращает IP/time map для `onlineMap`, а `api statsgetallonlineusers` возвращает полные onlineMap keys вида `user>>>u1>>>online`, а не bare usernames.

## 10. Observable timeout runtime

Ключевые файлы:
- `transport/internet/tcp/hub.go`
- `transport/internet/tcp/trusttunnel_handshake.go`
- `transport/internet/tcp/trusttunnel_listener_context.go`
- `proxy/trusttunnel/server.go`
- `proxy/trusttunnel/client.go`

Подтверждённое состояние на clean-HEAD runtime-retest `57d8d5e1`:
- `tlsHandshakeTimeoutSecs` распространяется не только на `tls.Server(...).HandshakeContext(...)`, но и на pre-handshake `client_random` extraction path; silent peer downstream-observable закрывается через `3.00s`;
- `clientListenerTimeoutSecs` на H2 работает через preface/read deadline и `http2.Server.IdleTimeout`; downstream raw trace получает GOAWAY через `3.00s` idle, а transport-close примерно через секунду;
- `connectionEstablishmentTimeoutSecs` downstream-observable на H2 CONNECT path и завершает зависший establishment примерно через configured deadline;
- `tcpConnectionsTimeoutSecs` downstream-observable как close inactive TCP tunnel после configured idle interval;
- `udpConnectionsTimeoutSecs` downstream-observable через reopen marker на H2/H3 UDP mux.

## 11. Активные и декларативные поля

### 11.1. Реально активные

Client side:
- `Hostname`
- `SkipVerification`
- `CertificatePem`
- `EnableUdp`
- `Transport`
- общий Xray `streamSettings.security = "reality"` для H2 outbound path
- outbound `ClientRandom`

Server side:
- `Users`
- `Rules`
- `AuthFailureStatusCode`
- `EnableUdp`
- `AllowPrivateNetworkConnections` для `_icmp`
- `IcmpInterfaceName`
- `IcmpRequestTimeoutSecs`
- `IcmpRecvMessageQueueCapacity`
- `TlsHandshakeTimeoutSecs`
- `ClientListenerTimeoutSecs`
- `ConnectionEstablishmentTimeoutSecs`
- `TcpConnectionsTimeoutSecs`
- `UdpConnectionsTimeoutSecs`
- `Ipv6Available` для `_icmp`

### 11.2. Пока не образуют полный product surface

Client side:
- `AntiDpi` за пределами текущего H2/TLS и H2/REALITY split-ClientHello runtime, прежде всего для explicit `http3` и более глубокого original-style anti-DPI behavior
- дальнейшая нормализация вокруг common `streamSettings` surface вместо protocol-local compatibility toggles

Server side:
- `Hosts`
- `Transports`

Следствие:
- эти поля нельзя описывать как завершённый самостоятельный функциональный блок без отдельной доработки или подтверждения runtime-поведением.

## 12. Практически важный interop по сертификатам

Для H2 interop с official TrustTunnel client нельзя ограничиваться фразой «сертификат проходит проверку».

Исторически и practically significant было установлено:
- ранний лабораторный self-signed сертификат не был достаточен;
- рабочий interop был получен после перехода на certificate chain формата official endpoint;
- значимы SAN и формат certificate chain;
- в successful case официальный клиент логировал `Certificate verified successfully`.

Следствие:
- H2 interop следует описывать вместе с certificate/trust-chain условием, а не как абстрактную transport-проверку.

## 13. Диагностические сигнатуры, которые нельзя терять

Ниже перечислены сигнатуры, которые должны оставаться в технической документации для будущей отладки регрессий.

### 12.1. H3 lifecycle failure

Симптом:
- `failed to read trusttunnel request > H3_NO_ERROR (local)`

Историческая причина:
- request handler завершал H3 stream раньше завершения tunnel copy.

### 12.2. Неправильная попытка идти TCP на H3 UDP/QUIC listener

Симптом:
- `connect: connection refused`

### 12.3. Неправильный порядок TLS verification в H3

Симптом:
- `peer certificate is missing`

### 12.4. Отсутствие регистрации transport protocol в тупиковой H3-ветке

Симптом:
- `unknown transport protocol: trusttunnelh3`

### 12.5. Попытка перенести stats wrapping в UDP transport

Симптом:
- import cycle с участием `transport/internet/udp`, `app/dispatcher`, `core`

## 14. Граница применения документа

Этот документ отвечает на вопросы:
- где проходит реальный runtime path;
- какие поля действительно активны;
- где находятся transport, rules, UDP и stats точки интеграции.

Для подтверждённых тестов использовать `docs/current/validation.md`.
Для рабочей конфигурации и эксплуатационных ограничений использовать `docs/current/operations.md`.
