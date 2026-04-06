# TrustTunnel / Xray-Core — эксплуатационная база

Статус: current
Дата фиксации: 2026-04-06
Коммит состояния: `ae621d24`
Область истины: рабочие сценарии, правила написания конфигов, эксплуатационные ограничения
Не использовать для: исторической хронологии и глубокой карты кода

## 1. Что реально считается рабочим эксплуатационным состоянием

Подтверждено:
- `protocol: "trusttunnel"` доступен как inbound и outbound;
- outbound работает для `transport="http2"` и `transport="http3"`;
- inbound обслуживает HTTP/1.1 CONNECT, HTTP/2 CONNECT и HTTP/3 CONNECT;
- outbound UDP mux использует official host `_udp2` для H2 и H3, а inbound compatibility matcher принимает `_udp2` и legacy `_udp2:0`;
- TCP и UDP используют штатный `dispatcher` Xray;
- server-side user stats, inbound stats и outbound stats работают на текущей архитектуре;
- H3 listener поднят внутри `transport/internet/tcp`;
- server-side `client_random` извлекается для H1/H2 и H3;
- базовый H3 interop подтверждён в обоих направлениях;
- целевые тесты и сборка на текущем рабочем дереве проходят.

## 2. Подтверждённые рабочие сценарии

### 2.1. Наш Xray client → наш Xray server по H2/TCP

Основные примеры:
- `testing/trusttunnel/server_h2.json`
- `testing/trusttunnel/client_h2.json`
- `testing/trusttunnel/our_client_to_our_server.json`

### 2.2. Наш Xray client → official TrustTunnel endpoint по H2/TCP

Основной пример:
- `testing/trusttunnel/our_client_to_official_endpoint.json`

### 2.3. Official TrustTunnel client → наш Xray server по H2/TCP

Основные примеры:
- `testing/trusttunnel/server_h2.json`
- `testing/trusttunnel/server_h2_rules.json`
- `testing/trusttunnel/official_client_to_our_server_h2_check_ok.toml`
- `testing/trusttunnel/official_client_to_our_server_h2_check_authfail.toml`

Критичная деталь:
- для воспроизводимого H2 interop нужно использовать сертификат и trust chain, совместимые с official client behavior;
- лабораторный self-signed сертификат не является достаточной гарантией межоперабельности;
- practically significant признаками были корректный SAN, совпадение имени `vpn.lab.local` и успешная верификация certificate chain на стороне official client.

Практически подтверждённый pair для H2 `_check` retest:
- `testing/trusttunnel/server_h2_official_cert.json` как tracked test config для official-client H2 interop; в lab он копируется в `/opt/lab/xray-tt/configs/server_h2_official_cert.json`
- `testing/trusttunnel/official_client_to_our_server_h2_check_ok.toml`
- `testing/trusttunnel/official_client_to_our_server_h2_check_authfail.toml`

### 2.4. Наш Xray client → наш Xray server по H3/TCP

Основной пример:
- `testing/trusttunnel/server_h3.json`

### 2.5. Official TrustTunnel client → наш Xray server по H3/TCP

На состоянии `99e59352` базовая H3 совместимость подтверждена фактическим retest.

### 2.6. Наш Xray client → official TrustTunnel endpoint по H3/TCP

На состоянии `99e59352` базовая H3 совместимость подтверждена фактическим retest.

### 2.7. Наш Xray client → наш Xray server по H2/UDP

Основные примеры:
- `testing/trusttunnel/server_h2_udp.json`
- `testing/trusttunnel/our_client_udp_to_our_server_h2.json`

### 2.8. Наш Xray client → наш Xray server по H3/UDP

Основные примеры:
- `testing/trusttunnel/server_h3_udp.json`
- `testing/trusttunnel/our_client_udp_to_our_server_h3.json`

### 2.9. Official TrustTunnel client → наш Xray server по H2/H3 UDP

Подтверждено clean-HEAD matrix bundle `/opt/lab/xray-tt/logs/udp-matrix-20260405-222820`:
- H2 server config: `testing/trusttunnel/server_h2_udp_official_cert.json`, runtime-copy `/opt/lab/xray-tt/configs/server_h2_udp_official_cert.json`;
- H3 server config: `testing/trusttunnel/server_h3_udp.json`, runtime-copy `/opt/lab/xray-tt/configs/server_h3_udp.json`;
- official client configs: `testing/trusttunnel/official_client_to_our_server_h2_udp.toml` и `testing/trusttunnel/official_client_to_our_server_h3_udp.toml`;
- IPv4 probes к `1.1.1.1:53` и `8.8.8.8:53` и IPv6 probe к `2606:4700:4700::1111:53` проходят как на H2, так и на H3;
- server logs содержат `trusttunnel H2 UDP mux accepted` и `trusttunnel H3 UDP mux accepted`.

### 2.10. Наш Xray client → official TrustTunnel endpoint по H2/H3 UDP

Подтверждено clean-HEAD matrix bundle `/opt/lab/xray-tt/logs/udp-matrix-20260405-222820`:
- official endpoint config: `/opt/lab/xray-tt/official-endpoint-lab/vpn.toml`;
- H2 client config: `testing/trusttunnel/our_client_udp_to_official_endpoint_h2.json`, runtime-copy `/opt/lab/xray-tt/configs/our_client_udp_to_official_endpoint_h2.json`, IPv6 runtime-copy `/opt/lab/xray-tt/configs/our_client_udp_to_official_endpoint_h2_ipv6.json`;
- H3 client config: `testing/trusttunnel/our_client_udp_to_official_endpoint_h3.json`, runtime-copy `/opt/lab/xray-tt/configs/our_client_udp_to_official_endpoint_h3.json`, IPv6 runtime-copy `/opt/lab/xray-tt/configs/our_client_udp_to_official_endpoint_h3_ipv6.json`;
- локальные DNS probes через `127.0.0.1:5304/5305/5306/5307` дают `answers=2`;
- после перехода outbound UDP CONNECT на `_udp2` прежний H2 fail `trusttunnel CONNECT failed with status 502` больше не воспроизводится.

### 2.11. Наш Xray client → remote server → internet по H2/TCP + REALITY

Подтверждено live-traffic retest на 2026-04-06 / `ae621d24`:
- lab client runtime config: `/opt/lab/xray-tt/configs/our_client_to_remote_server_h2_reality.json`;
- remote server runtime config: `/opt/trusttunnel-dev/configs/server_h2_reality_remote.json`;
- lab bundle: `/opt/lab/xray-tt/logs/h2-reality-lab-20260406-102306`;
- remote bundle: `/opt/trusttunnel-dev/logs/h2-reality-remote-20260406-102306`;
- client log содержит `trusttunnel transport=http2 requested with REALITY and empty negotiated ALPN; using HTTP/2 preface path`;
- remote server log содержит `trusttunnel H2 CONNECT accepted for tcp:www.cloudflare.com:443` и `trusttunnel H2 CONNECT accepted for tcp:api.ipify.org:443`;
- downstream SOCKS probes дают `ip=37.252.0.130`, `http=http/2` и `{"ip":"37.252.0.130"}`.

Практическая граница:
- remote server config остаётся lab-only runtime artifact, потому что содержит REALITY `privateKey` и не должен становиться tracked test config.

### 2.12. Наш Xray client → remote server → internet по H2/UDP + REALITY

Подтверждено live DNS retest на 2026-04-06 / `ae621d24`:
- lab client runtime config: `/opt/lab/xray-tt/configs/our_client_udp_to_remote_server_h2_reality.json`;
- remote server runtime config: `/opt/trusttunnel-dev/configs/server_h2_udp_reality_remote.json`;
- lab bundle: `/opt/lab/xray-tt/logs/h2-reality-udp-lab-20260406-102306`;
- remote bundle: `/opt/trusttunnel-dev/logs/h2-reality-udp-remote-20260406-102306`;
- remote server log содержит `trusttunnel H2 UDP mux accepted`, `dispatch request to: udp:1.1.1.1:53`, `proxy/freedom: connection opened to udp:1.1.1.1:53`;
- downstream DNS probe для `cloudflare.com` возвращает `104.16.132.229` и `104.16.133.229`.

Практическая граница:
- remote UDP server config тоже остаётся lab-only runtime artifact, потому что содержит REALITY `privateKey`.

### 2.13. Controlled load-test для H2/REALITY

Подтверждено bundle `load-h2-reality-20260406-111027`:
- lab Xray client binary: `/opt/lab/xray-tt/tmp/xray-tt-reality-linux`;
- remote Xray server binary: `/opt/trusttunnel-dev/tmp/xray-tt-reality-linux`;
- lab client runtime config: `/opt/lab/xray-tt/configs/our_client_to_remote_server_h2_reality_iperf_tcp.json`;
- remote controlled target: `127.0.0.1:5201` через `iperf3`;
- baseline `iperf3 -P 4 -t 20` даёт примерно `166 Mbit/s` receiver на uplink и `88 Mbit/s` receiver на reverse/downlink;
- stress `iperf3 -P 8 -t 20` даёт примерно `238 Mbit/s` receiver на uplink и `148 Mbit/s` receiver на reverse/downlink;
- на stress uplink lab-side Xray client держит в среднем около `92.9%` process CPU с пиками до `117%`, remote-side Xray server около `69.7%` с пиками до `87%`;
- на stress reverse/downlink lab-side Xray client держит около `90.0%` среднего process CPU с пиками до `119.8%`, тогда как remote-side server остаётся около `23.4%` среднего и `39%` peak.

Практический вывод:
- текущий bottleneck для большого H2/REALITY traffic находится скорее на lab/client side, а не на remote server CPU;
- process CPU выше `100%` в этих измерениях означает использование более чем одного ядра.

## 3. Как писать рабочие outbound-конфиги

### 3.1. Поддерживаемые поля

Подтверждённо используются:
- `address`
- `port`
- `username`
- `password`
- `hostname`
- `transport`
- `skipVerification`
- `certificatePem`
- `certificatePemFile`
- `udp`

Присутствуют в модели, но не подтверждены как самостоятельная активная функция:
- `hasIpv6`
- `antiDpi`

Подтверждённо активная runtime-функция:
- `clientRandom` для H2 и H3 outbound

### 3.2. Минимальные правила для H2 outbound

Нужны одновременно:
- `settings.transport = "http2"`
- `streamSettings.network = "tcp"`
- для TLS-path: `streamSettings.security = "tls"`
- для TLS-path: `streamSettings.tlsSettings.alpn = ["h2"]`
- для TLS-path: `streamSettings.tlsSettings.serverName == settings.hostname`
- для TLS-path: сертификат сервера соответствует `hostname`
- для REALITY-path: `streamSettings.security = "reality"`
- для REALITY-path: `streamSettings.realitySettings.serverName == settings.hostname`
- для REALITY-path: `publicKey`, `shortId` и `fingerprint` соответствуют серверу
- если используется `certificatePemFile`, PEM должен читаться в runtime verify path
- если используется REALITY-wrapper, пустой negotiated ALPN внутри TrustTunnel layer больше не должен трактоваться как причина падения в HTTP/1.1 fallback; авторитетным остаётся `settings.transport = "http2"`
- если нужен deterministic allow/deny через server-side rules, `settings.clientRandom` должен совпадать с `client_random` rule-spec

### 3.3. Минимальные правила для H3 outbound

Нужны:
- `settings.transport = "http3"`
- `hostname`
- согласованный certificate PEM или `skipVerification=true`
- отдельный TCP listener на server data-port для H3 не требуется
- если нужен deterministic allow/deny через server-side rules, `settings.clientRandom` должен совпадать с `client_random` rule-spec

## 4. Как писать рабочие inbound-конфиги

### 4.1. Серверные поля

Поддерживаются моделью:
- `users`
- `hosts`
- `transports`
- `rules`
- `ipv6Available`
- `authFailureStatusCode`
- `udp`

### 4.2. Практически активные поля сервера

Реально влияют на runtime:
- `users`
- `rules`
- `authFailureStatusCode`
- `udp`
- `allowPrivateNetworkConnections` для `_icmp`
- `icmp.interfaceName`
- `icmp.requestTimeoutSecs`
- `icmp.recvMessageQueueCapacity`
- `tlsHandshakeTimeoutSecs`
- `clientListenerTimeoutSecs`
- `connectionEstablishmentTimeoutSecs`
- `tcpConnectionsTimeoutSecs`
- `udpConnectionsTimeoutSecs`
- `ipv6Available` для `_icmp`

Пока не образуют самостоятельный server runtime-path:
- `hosts`
- `transports`

Следствие:
- серверный режим H2/H3 задаётся через transport listener, TLS ALPN и `streamSettings`;
- сертификаты listener задаются через `streamSettings.tlsSettings.certificates`;
- `settings.hosts[]` и `settings.transports[]` нельзя описывать как завершённый product-level механизм.

### 4.2.1. Практическая семантика timeout-полей

- `tlsHandshakeTimeoutSecs` теперь ограничивает и pre-handshake `client_random` extraction, и сам TLS handshake; silent TLS peer downstream-observable закрывается в пределах configured timeout.
- `clientListenerTimeoutSecs` на H2 нужно трактовать как idle timeout до server-side GOAWAY; итоговый transport-close происходит примерно через секунду после GOAWAY из-за `http2` shutdown timer.
- `connectionEstablishmentTimeoutSecs` закрывает зависший upstream establishment на CONNECT path; downstream marker на текущем lab retest — `Empty reply from server` примерно через configured timeout.
- `tcpConnectionsTimeoutSecs` закрывает inactive TCP tunnel после configured idle interval и даёт downstream close примерно в тот же срок.
- `udpConnectionsTimeoutSecs` проявляется не через TCP EOF, а через reopen semantics: новый UDP flow после idle timeout должен снова проходить в том же сценарии.

### 4.3. Правила по user stats

- `users[].username` и `users[].password` обязательны;
- `users[].email` не обязателен;
- если `email` пустой, runtime подставляет `username` как user-key;
- `user>>>...>>>online` — это `onlineMap`, а не counter;
- `api statsgetallonlineusers` возвращает полные onlineMap keys вида `user>>>u1>>>online`, а не bare usernames;
- `app/stats/online_map.go` намеренно игнорирует `127.0.0.1` и `[::1]`, поэтому `onlineMap` нужно валидировать через non-loopback source IP, а не через localhost-only client config;
- traffic counters и online-state нельзя диагностировать одним и тем же способом.

## 5. Rules и `client_random`

### 5.1. H1/H2

Поддержаны:
- CIDR
- exact/prefix `client_random`
- masked `client_random`
- catch-all allow/deny

### 5.2. H3

На состоянии `99e59352` server-side H3 rules считаются рабочими:
- `client_random` извлекается server-side;
- allow/deny определяется реальным rule match;
- H3 path больше не рассматривается как отдельный fail-closed special-case для rules.

Важно:
- этот пункт относится к server-side rules;
- outbound `clientRandom` на стороне Xray-client подтверждён как рабочая runtime-функция для H2 и H3 на нашем server-side rules path.

### 5.2.1. Outbound `clientRandom` на H2/H3

Подтверждено clean-HEAD runtime-retest на 2026-04-05 / `fc276340`:
- `settings.clientRandom = "deadbeef"` на нашем Xray client приводит к allow-match на server-side rules как для H2, так и для H3;
- несовпадающий `clientRandom` приводит к deny через `403` как для H2, так и для H3;
- practically significant конфиги для такого retest:
- `testing/trusttunnel/server_h2_rules.json`
- `testing/trusttunnel/server_h3_rules.json`
- `testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json`
- `testing/trusttunnel/our_client_to_our_server_h2_clientrandom_deny.json`
- `testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json`
- `testing/trusttunnel/our_client_to_our_server_h3_clientrandom_deny.json`

### 5.3. `_check` на H2/H3

На состоянии 2026-04-04 `_check` на H2/H3 подтверждён runtime-проверкой:
- auth проверяется раньше health-check ответа;
- rules проверяются раньше health-check ответа;
- при успешных auth/rules сервер отвечает `200` и не должен уходить в обычный dispatch path;
- при auth failure используется `authFailureStatusCode` и practically significant значением остаётся `407`.

Для H2 дополнительно подтверждено:
- deny-rule блокирует `_check` через `403`;
- официальный client видит `407` и `403` как observable HTTP/2 responses;
- старые `_check`-сигнатуры отсутствуют.

На состоянии 2026-04-05 этот блок больше не считается отдельной открытой проблемой:
- reserved pseudo-hosts больше не падают из H1/H2/H3 в обычный dispatch path;
- H2/H3 `_icmp` больше не является заглушкой `501`: при доступном raw ICMP сервер открывает отдельный mux path и отвечает `200`, а при недоступном raw socket отвечает `503`.

### 5.3.1. Official H2/H3 `_icmp` interop

Подтверждено clean-HEAD runtime-retest на 2026-04-05 / `5a21fd31` и `6c46922c`:
- server config: `testing/trusttunnel/server_h2_official_cert.json`, который в lab копируется в `/opt/lab/xray-tt/configs/server_h2_official_cert.json`;
- repo-local template official client: `testing/trusttunnel/official_client_to_our_server_h2_icmp.toml`, в clean-head retest использовалась runtime-copy `/opt/lab/xray-tt/configs/official_client_to_our_server_h2_icmp_test.toml`;
- H3 server config: `testing/trusttunnel/server_h3.json`, который в lab копируется в `/opt/lab/xray-tt/configs/server_h3.json`;
- repo-local template official client для H3: `testing/trusttunnel/official_client_to_our_server_h3_icmp.toml`, в clean-head retest использовалась runtime-copy `/opt/lab/xray-tt/configs/official_client_to_our_server_h3_icmp_test.toml`;
- official client поднимает `[listener.tun]` с `netns = "tun"` и проходит certificate verification для `vpn.lab.local`;
- сервер логирует `trusttunnel H2 health-check accepted` / `trusttunnel H2 ICMP mux accepted` и `trusttunnel H3 health-check accepted` / `trusttunnel H3 ICMP mux accepted`;
- `ping 1.1.1.1` из namespace `tun` проходит с `3/3 received` как на H2, так и на H3.

### 5.3.2. `icmp` в core config/routing layer

Подтверждено локальными test/build-проверками на 2026-04-05 / `1810939f`, `81dfc323` и `0fbc2ed5`:
- `common/net` содержит `Network_ICMP` и строковую форму `icmp`;
- `common/net.ParseDestination(...)` принимает `icmp:1.2.3.4` и `icmp:[2001:4860:4860::8888]`;
- `infra/conf.Network` и `NetworkList` принимают `icmp` в JSON-конфигах;
- routing/API/webhook layer видит `icmp` как отдельное network-значение.
- TrustTunnel outbound для такого target больше не возвращает ранний reject: H2/H3 path открывает `_icmp:0`, кодирует fixed-size request frames и локально восстанавливает echo-reply packet из reply-frame и сохранённого payload.
- Практически подтверждённый client-side contract покрывает echo-request и representable reply types текущего fixed-size reply frame.
- server-side JSON config теперь подаёт `_icmp` runtime-settings: `allowPrivateNetworkConnections`, `icmp.interfaceName`, `icmp.requestTimeoutSecs`, `icmp.recvMessageQueueCapacity`, а `ipv6Available` observable на попытке открыть IPv6 raw socket;
- по текущей реализации `allowPrivateNetworkConnections = false` ограничивает `_icmp` global-unicast destination-адресами, `icmp.interfaceName` задаёт raw-socket `IfIndex`, `icmp.requestTimeoutSecs` переопределяет timeout ожидания reply, а `icmp.recvMessageQueueCapacity` задаёт bounded per-stream reply queue с default `256`;
- отдельный H2 lab runtime-retest против `192.168.1.19` подтверждает, что `allowPrivateNetworkConnections = false` даёт `0 received` и лог `private network connections are disabled`, а `true` возвращает `1 received`;
- отдельный H2 lab runtime-retest с `icmp.interfaceName = "definitely-missing-if0"` подтверждает, что `_icmp` path доходит до `trusttunnel H2 ICMP unavailable > route ip+net: no such network interface`;
- dedicated H2 lab runtime-retest подтверждает `icmp.requestTimeoutSecs = 1` через bundle `/opt/lab/xray-tt/logs/h2-icmp-timeout-1s-tc-20260405-183916`;
- direct H2 `_icmp` probe подтверждает observable `ipv6Available` через bundle `/opt/lab/xray-tt/logs/h2-icmp-ipv6-available-probe-20260405-190025`;
- representable reply types echo-reply, destination-unreachable и time-exceeded подтверждены; types с extra MTU/pointer fields ограничены fixed-size reply frame и не образуют отдельного runtime toggled feature;
- На Linux это уже образует рабочий Xray product path через `proxy/tun`, если TUN interface управляется ОС с явной адресацией и routing. Подтверждённый clean-HEAD шаблон: выделенный namespace `tunxrayh2` / `tunxrayh3`, адрес `192.0.2.10/32` на `xraytunh*` и маршрут `1.1.1.1/32 dev xraytunh*`.
- Host-namespace схема вида `ip addr add 192.0.2.10/32 dev xraytunh2` + `ip route add 1.1.1.1/32 dev xraytunh2` считается unsafe wiring pattern: в диагностическом retest она воспроизвела ICMP request storm без egress.

## 6. UDP path

Реализовано:
- outbound UDP CONNECT использует `_udp2`, а inbound compatibility matcher принимает `_udp2` и legacy `_udp2:0`;
- клиентский и серверный codec;
- H2 и H3 path;
- multiplex нескольких UDP flows поверх одного HTTP stream.

Подтверждённое ограничение:
- H1 `CONNECT _udp2` и legacy `CONNECT _udp2:0` не являются рабочим UDP path и явно отклоняются до обычного dispatch;
- destination должен быть IP-адресом;
- доменные UDP targets не подтверждены как рабочая функция.

## 7. Практические ограничения текущего режима

На текущем состоянии нельзя объявлять как завершённые функции:
- `antiDpi` как рабочий product path;
- `hasIpv6` как активную готовую функцию;
- TrustTunnel + H3 + REALITY как закрытый production path;
- `ipv6Available` как общий server transport selector вне `_icmp` raw-socket surface;
- server runtime host/cert selection через `settings.hosts[]`;
- server runtime routing H2/H3 только через `settings.transports[]` без корректных `streamSettings`;
- `_icmp` за пределами Linux path с OS-managed TUN routing или за пределами fixed-size official reply frame, если нужны MTU/pointer-specific поля;
- доменные UDP targets;
- lab-only REALITY server configs с `privateKey` внутри tracked tree репозитория.

## 8. Как использовать старые документы

Если в репозитории рядом существуют:
- старые `docs/test-matrix/*`;
- старый `docs/trusttunnel-v1.md`;
- ранние рабочие заметки или импортированные черновики,

их можно использовать только как исторический или диагностический материал.

Для текущих утверждений о рабочем H3 path, H3 rules, official H3 interop и закрытых H3-дефектах использовать только `docs/current/*`.

## 9. Практическое правило перед interop-запуском

Перед любым retest использовать preflight из `docs/current/validation.md`:
- зафиксировать текущий commit и worktree state;
- зафиксировать путь к реально запускаемому бинарю;
- зафиксировать exact config paths;
- зафиксировать certificate/trust chain текущего запуска.

Это защищает от повторения исторической ошибки со старым бинарём и от ложной трактовки сертификатных проблем как transport-проблем.
