# TrustTunnel Multipath Transport — план R&D

Статус: draft R&D plan  
Дата фиксации: 2026-04-10  
Ветка: `feat/trusttunnel-multipath`  
Область истины: план новой экспериментальной линии разработки, а не описание уже подтверждённого runtime  
Не использовать для: утверждений вида «multipath уже реализован» или «multipath уже interoperable»

## 1. Цель

Цель этой ветки — исследовать и, при успехе, реализовать transport-level multipath режим для TrustTunnel, в котором:
- один логический серверный endpoint представлен несколькими IP;
- один логический клиентский session context использует несколько IP одновременно;
- трафик в рамках одной логической сессии распределяется по нескольким transport-каналам;
- идентичность сессии определяется не IP-адресом, а session-level криптографическим контекстом.

Это следующий слой поверх уже реализованного outbound endpoint policy:
- `servers[]`;
- resolved-address expansion;
- fallback;
- delayed race;
- preference последнего успешного endpoint;
- cooldown;
- active `_check` probe.

Текущий endpoint policy выбирает один лучший transport path на данный момент. Multipath должен пойти дальше и удерживать несколько transport path одновременно в рамках одной логической сессии.

## 2. Ключевые технические ограничения

### 2.1. Главное ограничение TCP

Фраза «сервер обязан отвечать со случайного IP из пула» в прямом виде непригодна для TCP-реализации на обычных сокетах.

Причина:
- установленное TCP-соединение жёстко привязано к 4-tuple;
- kernel не позволит безопасно отправлять данные установленного соединения с произвольного другого local IP;
- попытка «перекинуть» ответы уже существующего TCP-сокета на другой IP фактически ломает сам TCP-сеанс.

Следствие для реализации:
- multipath для TCP должен строиться не на «переезде одного TCP-сокета между IP», а на множестве одновременных TCP-соединений;
- каждое отдельное TCP-соединение отвечает со своего local IP;
- multipath-свойство достигается распределением framed session-data по нескольким TCP-каналам, а не spoofing/rewire одного сокета.

### 2.2. Ограничение текущего TrustTunnel runtime

Current TrustTunnel runtime умеет:
- открыть transport path;
- открыть tunnel stream;
- передавать payload по одному transport path.

Он не умеет:
- связывать несколько transport-соединений в одну session-level byte-stream модель;
- reassemble/reorder один логический TCP поток из чанков, пришедших по разным transport-соединениям;
- держать channel membership как отдельный объект протокола.

Следствие:
- multipath — не «маленький patch к endpoint policy»;
- это новый session/channel/frame layer поверх существующего TrustTunnel path.

### 2.3. Ограничение по порядку внедрения

Нельзя пытаться внедрить всё сразу в H2, H3, UDP, REALITY и `_icmp`.

Правильный порядок:
1. сперва спроектировать multipath session model;
2. затем реализовать TCP multipath на `HTTP/2 over TLS`;
3. потом расширять на `HTTP/2 over REALITY`;
4. только после стабилизации TCP-path переходить к UDP;
5. H3 рассматривать отдельным этапом, а не стартовой целью.

## 3. Базовые решения для этой ветки

### 3.1. Scope первой реализации

Первая реализация должна покрыть только:
- client outbound;
- server inbound;
- `HTTP/2 over TLS`;
- TCP payload path;
- несколько IP одного сервера в рамках одной логической multipath-сессии.

Не включать в первую фазу:
- H3;
- UDP;
- `_icmp`;
- spoof-like ответ «с любого IP» для TCP;
- silent fallback обратно к single-path.

### 3.2. Failure policy

Multipath в этой ветке должен быть explicit opt-in и explicit fail-fast.

Если multipath включён, runtime не должен тихо деградировать в single-path режим без отдельной политики.

Для первой фазы принять strict-model:
- клиент обязан открыть не меньше `minChannels` активных каналов;
- если после grace-period активных каналов меньше `minChannels`, session считается невалидной;
- single-path fallback возможен только как отдельный явно заданный режим, но не как скрытое поведение по умолчанию.

### 3.3. Принцип идентификации

Session identity должна держаться на:
- `session_id`;
- `session_secret` / attach-secret;
- channel-level proof;
- sequence/reassembly state.

IP не должен участвовать:
- ни в auth;
- ни в session lookup;
- ни в channel attach verification.

## 4. Целевая модель протокола

### 4.1. Логическая multipath-сессия

Новый объект:
- `MultipathSession`

Содержит:
- `session_id`;
- `created_at`;
- `client user / auth context`;
- `target destination`;
- `mode` (`tcp` на первой фазе);
- `session secret` для attach proof;
- `channel table`;
- `scheduler state`;
- `rx reorder state`;
- `tx sequence state`;
- lifecycle state (`opening`, `active`, `degraded`, `closing`).

### 4.2. Канал

Новый объект:
- `MultipathChannel`

Содержит:
- `channel_id`;
- `server IP`, к которому подключён transport;
- transport connection handle;
- last-seen timestamps;
- health / drain / closing flags;
- accounting counters.

### 4.3. Primary и secondary channels

Первая transport-связь:
- создаёт multipath session;
- получает `session_id`;
- получает attach secret / proof material.

Каждый secondary channel:
- идёт на другой server IP;
- выполняет attach к уже существующей session;
- после successful attach включается в scheduler.

### 4.4. Session framing для TCP

Текущий raw CONNECT-туннель недостаточен для multipath-TCP, потому что один логический byte stream надо резать на чанки и собирать обратно.

Для этого нужен отдельный framed layer.

Минимальный состав frame:
- `session_id`;
- `channel_id`;
- `direction`;
- `stream_seq`;
- `payload_len`;
- `flags`;
- `payload`;
- `auth tag`.

Сервер должен:
- принимать чанки с разных channels;
- собирать их в один ordered byte stream;
- передавать дальше в обычный outbound dispatch.

Клиент должен:
- резать локальный TCP stream на chunk frames;
- распределять chunk frames по нескольким channels;
- принимать обратные frames;
- reassemble их в ordered downstream stream.

## 5. Предлагаемое протокольное расширение

### 5.1. Новые control-path

Для первой реализации нужны отдельные control-semantics, а не попытка впихнуть multipath attach в обычный CONNECT без явного различения.

Предлагаемый набор:
- primary open path: `_mptcp_open`
- secondary attach path: `_mptcp_attach`

Возможный вариант для H2:
- обычный CONNECT на pseudo-host path;
- после auth/rules special handler создаёт / находит multipath session;
- дальше transport stream переходит в framed multipath mode.

### 5.2. Attach proof

Secondary attach не должен доверять одному `session_id`.

Нужен proof:
- `attach_mac = HMAC(session_secret, session_id || channel_nonce || timestamp || target_hash)`

Сервер проверяет:
- session существует;
- attach не replay;
- proof валиден;
- target / mode совпадают;
- лимиты channels не превышены.

### 5.3. Session open response

Primary open должен вернуть клиенту:
- `session_id`;
- `attach secret` или derived attach token seed;
- negotiated `minChannels/maxChannels`;
- negotiated frame parameters;
- negotiated scheduler mode.

### 5.4. Sequence and reorder

Для TCP multipath нельзя полагаться на transport-level порядок.

Нужны:
- глобальный sequence counter для outbound direction;
- reorder buffer на receiver;
- window / memory cap;
- fail policy для gap timeout.

## 6. Реализация в кодовой базе Xray / TrustTunnel

### 6.1. Client-side

Основные точки:
- `proxy/trusttunnel/client.go`
- новые файлы:
  - `proxy/trusttunnel/multipath_client.go`
  - `proxy/trusttunnel/multipath_scheduler.go`
  - `proxy/trusttunnel/multipath_frame.go`
  - `proxy/trusttunnel/multipath_session.go`

Что нужно сделать:
- multipath-aware client config build;
- session bootstrap через primary channel;
- secondary channel fan-out на разные IP;
- channel registry;
- chunk scheduler;
- reassembly для обратного направления;
- strict enforcement `minChannels`.

### 6.2. Server-side

Основные точки:
- `proxy/trusttunnel/server.go`
- новые файлы:
  - `proxy/trusttunnel/multipath_server.go`
  - `proxy/trusttunnel/multipath_registry.go`
  - `proxy/trusttunnel/multipath_attach.go`
  - `proxy/trusttunnel/multipath_reassembly.go`

Что нужно сделать:
- session registry;
- session lookup по `session_id`;
- attach verification;
- channel registration/removal;
- per-session reorder/forward;
- reverse-direction scheduler обратно в client channels.

### 6.3. Config / validator

Новые точки:
- `proxy/trusttunnel/config.proto`
- `proxy/trusttunnel/config.pb.go`
- `infra/conf/trusttunnel.go`
- `infra/conf/trusttunnel_lint.go`

Предлагаемая config surface:
- `multipath.enabled`
- `multipath.minChannels`
- `multipath.maxChannels`
- `multipath.scheduler`
- `multipath.attachTimeoutSecs`
- `multipath.reorderWindowBytes`
- `multipath.reorderGapTimeoutMs`
- `multipath.strict`

Validator первой фазы должен fail-fast резать:
- `multipath.enabled=true` без `servers[]` или без multi-IP resolved pool;
- `multipath.enabled=true` вместе с `transport=http3`;
- `multipath.enabled=true` вместе с UDP-only path;
- `multipath.minChannels < 2`;
- `multipath.maxChannels < minChannels`.

### 6.4. Reuse уже реализованного кода

Из текущего branch-state нужно переиспользовать, а не выкидывать:
- `servers[]` fallback;
- resolved-address expansion;
- delayed race;
- cooldown;
- active `_check` probe;
- last-success preference.

Их роль меняется:
- раньше они выбирали один лучший endpoint;
- теперь они должны стать bootstrap-механикой для набора активных channels.

## 7. Пошаговый план реализации

### Фаза 0. Архитектурное сужение задачи

Цель:
- зафиксировать реалистичную модель multipath для TCP;
- явно отказаться от невыполнимой literal-семантики «один TCP-канал, ответы случайно с любого IP».

Результат:
- этот документ;
- validator-level guardrails;
- branch policy: first target = H2/TLS TCP only.

### Фаза 1. Session model и config surface

Сделать:
- config model `multipath.*`;
- runtime data structures `MultipathSession` и `MultipathChannel`;
- server session registry;
- client session manager;
- unit tests на config/validator/session lifecycle.

Критерий готовности:
- multipath session objects живут в runtime;
- unsupported combinations режутся на config-build этапе;
- ничего ещё не заявляется как product-ready data path.

### Фаза 2. Primary open + secondary attach

Сделать:
- `_mptcp_open`;
- `_mptcp_attach`;
- attach proof;
- primary session creation;
- attach handshake;
- channel registration на server.

Критерий готовности:
- клиент поднимает минимум 2 transport channels на разные IP;
- сервер видит их как одну logical session;
- IP не участвует в auth/session identity.

### Фаза 3. TCP multipath frame layer

Сделать:
- framed payload format;
- chunking;
- sequence numbering;
- reorder buffer;
- reverse-direction framing.

Критерий готовности:
- один downstream TCP stream реально проходит через несколько outer TCP channels;
- server reassembles byte stream без corruption;
- data path больше не single-channel.

### Фаза 4. Scheduler и strict enforcement

Сделать:
- round-robin scheduler как baseline;
- fairness counters;
- per-channel backpressure;
- strict policy при падении количества active channels ниже `minChannels`.

Критерий готовности:
- runtime не липнет к одному IP;
- трафик действительно распределяется;
- single-channel degeneration не проходит незамеченной.

### Фаза 5. Recovery

Сделать:
- reopen channels через existing endpoint policy;
- active probe для rejoin;
- graceful drain broken channels;
- optional rebalance после возврата endpoint.

Критерий готовности:
- multipath session переживает потерю одного канала без silent collapse в single-path, если можно быстро восстановить channel quorum;
- иначе session закрывается по strict policy.

### Фаза 6. Live validation для TCP

Нужны реальные тесты:
- server с несколькими IP;
- минимум 2 simultaneous active channels;
- forced traffic distribution;
- kill one channel;
- restore one channel;
- long-lived transfer;
- hash/ordering verification;
- CPU / throughput measurement.

Критерий готовности:
- подтверждённый real-traffic path lab → remote multipath endpoint → internet;
- подтверждённое распределение трафика между IP;
- отсутствие silent fallback в один IP.

### Фаза 7. `HTTP/2 over REALITY`

Только после стабильного H2/TLS multipath.

Сделать:
- проверить совместимость multipath open/attach с current REALITY path;
- отдельный validator;
- отдельный live matrix.

Критерий готовности:
- H2/REALITY multipath не ломает existing H2/REALITY single-path runtime.

### Фаза 8. UDP multipath

Это отдельный протокол-слой, не побочный patch к TCP multipath.

Сделать:
- datagram session framing;
- session_id + AEAD protection;
- packet scheduler по нескольким IP;
- reply acceptance без жёсткой привязки к одному source IP;
- NAT/firewall validation.

Критерий готовности:
- UDP path не залипает на одном IP;
- packet integrity и session integrity подтверждены.

### Фаза 9. H3 и дальнейшая экспансия

Не стартовая задача.

Рассматривать только после:
- TCP multipath на H2/TLS;
- recovery;
- live validation;
- понятной validator story.

## 8. Тестовый план

### 8.1. Unit

Нужны тесты на:
- config validation;
- session registry;
- attach proof;
- duplicate/nonced attach rejection;
- reorder buffer;
- scheduler fairness;
- strict min-channel enforcement.

### 8.2. Scenario

Нужны сценарии:
- 2 IP active from start;
- third IP joins later;
- primary dies;
- secondary dies;
- reorder out-of-order chunks;
- attach replay attempt;
- invalid attach proof.

### 8.3. Remote-live

Нужны обязательные live кейсы:
- `2 active IP / upload`;
- `2 active IP / download`;
- `kill IP1`;
- `restore IP1`;
- `long file transfer with hash check`;
- `iperf-like load`;
- CPU / throughput per side;
- packet/tcpdump proof, что реально используются разные IP.

### 8.4. Regression вне TrustTunnel

После каждой существенной фазы multipath:
- `go test ./...`
- `go test ./testing/scenarios`
- отдельный non-TrustTunnel live audit минимум по:
  - `direct`
  - `tun`
  - `vless + tls`
  - `vless + reality`
  - `hysteria`

Причина:
- multipath полезет в shared transport/client/session logic;
- regression должен ловиться не только unit-тестами.

## 9. Основные риски

### 9.1. Сложность TCP reassembly

Это главный технический риск.

Если framed multipath TCP окажется слишком дорогим или слишком сложным по reorder/backpressure, проект может потребовать:
- жёсткого ограничения на размер reorder window;
- более простой scheduler;
- либо пересмотра scope.

### 9.2. Resource pressure

Multipath увеличит:
- количество transport connections;
- memory на reorder buffers;
- CPU на framing и crypto;
- количество concurrent server sessions.

Нужны:
- per-session caps;
- per-user caps;
- observability counters;
- защитные лимиты на channels и buffers.

### 9.3. Совместимость с existing runtime

Нельзя ломать:
- existing single-path TrustTunnel;
- H2/H3 validated paths;
- REALITY;
- common Xray transports.

Multipath должен быть:
- explicit opt-in;
- validator-guarded;
- отделён от current stable path.

## 10. Решение о старте разработки

Для этой ветки принять следующий рабочий порядок:
1. реализовать только `HTTP/2 over TLS` multipath-TCP;
2. не трогать H3 и UDP до завершения TCP-path;
3. использовать существующий multi-endpoint policy как bootstrap layer;
4. ввести новый explicit session/channel/frame layer;
5. не пытаться реализовать literal random-source-IP для TCP;
6. не считать успехом локальные зелёные тесты без remote-live доказательства multi-IP traffic distribution.

## 11. Ближайшие шаги

1. Добавить `multipath.*` в config model и validator.
2. Ввести server/client session registry и channel objects.
3. Спроектировать `_mptcp_open` / `_mptcp_attach`.
4. Сделать минимальный framed TCP data path для двух channels.
5. Поднять первый remote-live стенд с двумя IP и доказать одновременную передачу по обоим IP.
