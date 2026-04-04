# TrustTunnel / Xray-Core — эксплуатационная база

Статус: current
Дата фиксации: 2026-04-05
Коммит состояния: `worktree after auth semantics fix`
Область истины: рабочие сценарии, правила написания конфигов, эксплуатационные ограничения
Не использовать для: исторической хронологии и глубокой карты кода

## 1. Что реально считается рабочим эксплуатационным состоянием

Подтверждено:
- `protocol: "trusttunnel"` доступен как inbound и outbound;
- outbound работает для `transport="http2"` и `transport="http3"`;
- inbound обслуживает HTTP/1.1 CONNECT, HTTP/2 CONNECT и HTTP/3 CONNECT;
- UDP mux реализован через `_udp2:0` для H2 и H3;
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
- `clientRandom`
- `antiDpi`

### 3.2. Минимальные правила для H2 outbound

Нужны одновременно:
- `settings.transport = "http2"`
- `streamSettings.security = "tls"`
- `streamSettings.tlsSettings.alpn = ["h2"]`
- `streamSettings.tlsSettings.serverName == settings.hostname`
- сертификат сервера соответствует `hostname`
- если используется `certificatePemFile`, PEM должен читаться в runtime verify path

### 3.3. Минимальные правила для H3 outbound

Нужны:
- `settings.transport = "http3"`
- `hostname`
- согласованный certificate PEM или `skipVerification=true`
- отдельный TCP listener на server data-port для H3 не требуется

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

Пока не образуют самостоятельный server runtime-path:
- `hosts`
- `transports`
- `ipv6Available`

Следствие:
- серверный режим H2/H3 задаётся через transport listener, TLS ALPN и `streamSettings`;
- сертификаты listener задаются через `streamSettings.tlsSettings.certificates`;
- `settings.hosts[]` и `settings.transports[]` нельзя описывать как завершённый product-level механизм.

### 4.3. Правила по user stats

- `users[].username` и `users[].password` обязательны;
- `users[].email` не обязателен;
- если `email` пустой, runtime подставляет `username` как user-key;
- `user>>>...>>>online` — это `onlineMap`, а не counter;
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
- outbound `clientRandom` на стороне Xray-client всё ещё не считается закрытой runtime-функцией.

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
- `_icmp` пока остаётся не реализованным transport path, но теперь отвечает явным `501 Not Implemented` после auth/rules.

## 6. UDP path

Реализовано:
- отдельный UDP CONNECT host `_udp2:0`;
- клиентский и серверный codec;
- H2 и H3 path;
- multiplex нескольких UDP flows поверх одного HTTP stream.

Подтверждённое ограничение:
- H1 `CONNECT _udp2:0` не является рабочим UDP path и явно отклоняется до обычного dispatch;
- destination должен быть IP-адресом;
- доменные UDP targets не подтверждены как рабочая функция.

## 7. Практические ограничения текущего режима

На текущем состоянии нельзя объявлять как завершённые функции:
- outbound `clientRandom` как активную runtime-функцию;
- `antiDpi` как рабочий product path;
- `hasIpv6` / `ipv6Available` как активную готовую функцию;
- server runtime host/cert selection через `settings.hosts[]`;
- server runtime routing H2/H3 только через `settings.transports[]` без корректных `streamSettings`;
- `_icmp` как реализованный эксплуатационный path;
- доменные UDP targets.

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
