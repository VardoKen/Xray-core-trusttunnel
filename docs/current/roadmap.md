# TrustTunnel / Xray-Core — roadmap

Статус: current
Дата фиксации: 2026-04-10
База roadmap: состояние проекта после закрытия `_icmp` protocol/runtime gap, H2/H3 official `_icmp` interop, product-level Linux TUN path, auth semantics на pseudo-host path, outbound clientRandom, полного UDP interop matrix, auth/stats sanity-check, observable timeout surface, client-side `postQuantumGroupEnabled`, `hasIpv6` domain-target guard, `antiDpi` runtime для `HTTP/2 over TLS` и `HTTP/2 over REALITY`, config-build validator, common outbound/inbound Xray integration scenarios, dynamic user management, `transport=auto` / H3→H2 fallback и clean-head live traffic matrix
Область истины: только открытые задачи после закрытия H3 rules, ложного `H3_NO_ERROR`, legacy H3-path, H2 `_check`, auth semantics на pseudo-host path, outbound clientRandom, `_icmp` protocol/runtime surface, полного UDP interop matrix, auth/stats sanity-check, observable timeout surface, common outbound integration coverage, inbound `sniffing + routeOnly`, `_icmp` routing/policy/stats plumbing и dynamic user management
Не использовать для: фиксации уже закрытых багов и исторической хронологии

## 1. Принцип чтения roadmap

Этот документ не повторяет уже закрытые H3-дефекты, не переоткрывает закрытый H2 `_check` и не возвращает auth/stats sanity-check или observable timeout surface в список открытых проблем без новых доказательств.

Текущее направление разработки:
1. не переоткрывать уже закрытый H2 production path по REALITY без новых доказательств;
2. довести TrustTunnel до корректной интеграции с общими механизмами Xray-Core;
3. не переоткрывать H3 + REALITY как “просто ещё один parity-gap”: current R&D уже упёрся в stop-factor текущего Xray transport layer.
4. для новой R&D-ветки `feat/trusttunnel-multipath` multipath transport вести как отдельный experimental block; канонический план зафиксирован в `docs/current/multipath-transport-plan.md`.

Уже закрытые integration-блоки не возвращаются в roadmap без новых доказательств:
- common outbound features `sendThrough`, `proxySettings`, `mux`, `targetStrategy`;
- common inbound `sniffing + routeOnly`;
- generic H2/TLS transport settings `serverName`, custom-CA verify, `VerifyPeerCertByName`, `PinnedPeerCertSha256`, `Fingerprint`;
- generic inbound TLS `rejectUnknownSni`;
- `_icmp` в routing/policy/stats модели;
- dynamic user management через `HandlerService`;
- initial config-build validator для unsupported TrustTunnel combinations.

Переоткрывать закрытую H3-тройку можно только при появлении более новых доказательств, чем фиксация `99e59352`.

## 2. REALITY после базовой совместимости

### 2.1. Архитектурная точка внедрения

REALITY должен внедряться через общий Xray `streamSettings.security`, а не через trusttunnel-specific `settings`.

### 2.2. Закрытый production-path

Закрыто real-traffic retest на 2026-04-06 / `ae621d24`, затем повторно подтверждено current-head smoke на 2026-04-06 / `c6ff745b`:
- TrustTunnel + H2/TCP + REALITY;
- TrustTunnel + H2/UDP + REALITY.

Практически значимый итог:
- REALITY на H2 больше не является открытым production-gap;
- текущий runtime идёт через общий Xray `streamSettings.security = "reality"`, а не через trusttunnel-specific поле;
- отдельным post-fix verdict зафиксировано, что H2 path не должен падать в HTTP/1.1 fallback только из-за пустого negotiated ALPN у REALITY-wrapper.

### 2.3. H3 + REALITY stop-factor

R&D по TrustTunnel + H3 + REALITY завершён техническим стоп-фактором:
- current Xray REALITY surface работает на уровне TCP `net.Conn`, а не QUIC `PacketConn`;
- TrustTunnel outbound H3 path сейчас строит QUIC/TLS напрямую и не проходит через общий Xray `streamSettings.security` runtime;
- current runtime теперь явно режет `http3 + reality` на client и server сторонах вместо silent-misconfig.

Практический вывод:
- это не short-term parity task;
- future support возможен только после появления QUIC-capable REALITY transport/security layer в Xray core;
- до этого H2 + REALITY и H3 + TLS остаются раздельными validated paths.

### 2.4. Client-side parity после REALITY

Этот блок на текущем этапе закрыт для поддержанных H2/H3 + TLS и H2 + REALITY path:
- `post_quantum_group_enabled` wired в runtime через effective TLS/REALITY fingerprint и H3 TLS curve preferences;
- `has_ipv6` больше не ограничен literal-IPv6 gate: domain targets требуют outbound `targetStrategy useipv4/forceipv4`, а нарушение режется marker'ом `trusttunnel hasIpv6=false requires outbound targetStrategy useipv4/forceipv4 for domain targets`;
- `anti_dpi` больше не является no-op: на `HTTP/2 over TLS` и `HTTP/2 over REALITY` runtime делает split первой TCP-based записи ClientHello, а explicit `http3` по-прежнему режется как unsupported.

Практический вывод:
- client-side parity fields после REALITY больше не являются ближайшим открытым блоком;
- дальше нужен не ещё один parity-патч, а нормализация вокруг общей модели Xray.

## 3. Интеграция с общей моделью Xray

### 3.1. Нормализация вокруг `streamSettings`

Уже реализовано:
- per-request `streamSettings` override в общем outbound layer;
- config-build validator, который режет `http3 + reality`, `antiDpi=true` вне совместимого `HTTP/2 over TLS/REALITY` path и H2 `postQuantumGroupEnabled` без TLS/REALITY `streamSettings`;
- на non-HTTP3 path зафиксирована граница между compatibility fields и generic TLS surface: `streamSettings.tlsSettings` являются authoritative, а `hostname` / `skipVerification` только дополняют missing `serverName` / `allowInsecure`;
- validator дополнительно режет non-HTTP3 `hostname` mismatch с generic `tlsSettings.serverName`, `skipVerification=true` поверх explicit generic verify surface и `skipVerification=true` вместе с `certificatePem` / `certificatePemFile`;
- current runtime больше не строит второй TrustTunnel-local verify/router поверх generic `streamSettings.tlsSettings`.

Остаётся:
- держать эту границу синхронной с будущими upstream-изменениями generic `streamSettings` / TLS / REALITY surface;
- не расползаться новыми TrustTunnel-local policy checks там, где уже есть достаточный generic Xray surface;
- расширять validator только под новые действительно двусмысленные integration-комбинации, а не как отдельный параллельный policy-layer.

### 3.2. Общая TLS/REALITY surface Xray

Широкий integration-gap по этому блоку больше не открыт для поддержанных path:
- H2/TLS scenario-тестами подтверждены `serverName`, authority-verify через custom CA, `VerifyPeerCertByName`, `PinnedPeerCertSha256` и `Fingerprint`;
- H2 + REALITY уже подтверждён отдельным live production-path retest;
- `http3 + reality` зафиксирован как explicit unsupported combination, а не как “ещё не закрытая TLS/REALITY parity-задача”.

Остаётся:
- держать эту поверхность синхронной с upstream-изменениями generic TLS/REALITY layer Xray;
- не трактовать Windows-требование `disableSystemRoot=true` для custom-CA verify path как TrustTunnel-specific bug;
- расширять validator только там, где новая generic combination действительно должна fail-fast ещё на config-build этапе.

### 3.3. Остаточная inbound integration surface

Уже подтверждено:
- `sniffing + routeOnly` на TrustTunnel inbound;
- `rejectUnknownSni` на generic inbound TLS surface;
- TLS SNI `metadataOnly` не является отдельным TrustTunnel bug surface и следует общей семантике dispatcher metadata sniffers.

Остаётся:
- добирать dedicated coverage для `metadataOnly` или новых generic inbound transport settings только если они реально понадобятся как product path сверх уже подтверждённых сценариев.

### 3.4. Финальная матрица совместимости и validator hardening

Текущее состояние уже покрывает и валидирует комбинации:
- H2/H3;
- TLS/REALITY;
- TCP / `_udp2` / `_icmp` / `_check`;
- `clientRandom` / rules;
- common Xray outbound features `sendThrough`, `proxySettings`, `mux`, `targetStrategy`;
- common Xray inbound `sniffing + routeOnly`;
- dynamic user management через `HandlerService`;
- generic outbound/inbound TLS integration surface, включая `serverName`, custom-CA verify, `VerifyPeerCertByName`, `PinnedPeerCertSha256`, `Fingerprint` и inbound `rejectUnknownSni`;
- clean-head live traffic matrix lab → remote server → internet с separate functional и load verdict.

Остаётся:
- поддерживать matrix синхронной с общими integration-изменениями Xray;
- расширять validator только там, где комбинация действительно должна fail-fast на config-build этапе.
- после каждого merge/rebase на upstream main повторять non-TrustTunnel live regression audit минимум по `direct`, `tun`, `vless + tls`, `vless + reality`, `hysteria`; одноразовый throughput-noise не считать регрессией без повторяемого функционального расхождения.

### 3.5. Multi-endpoint outbound policy

Уже реализовано и подтверждено remote-live sequence:
- ordered outbound `servers[]` без схлопывания до одного endpoint;
- единый fallback до establish для stream / UDP / ICMP path;
- delayed racing между первыми двумя ready endpoint с `1s` задержкой старта secondary endpoint и немедленным стартом secondary при раннем fail primary;
- preference последнего успешно established endpoint;
- короткий cooldown после pre-establishment fail, чтобы следующий connect временно не бился в тот же проблемный endpoint первым;
- active probing cooling endpoint через реальный TrustTunnel `_check`, чтобы runtime мог вернуть восстановившийся endpoint в preferred-порядок раньше полного cooldown.
- runtime-expansion одного domain-valued `address` / `servers[].address` в несколько resolved IP на client init, чтобы тот же fallback/race/probe policy работал и для single logical server-entry.

Что уже подтверждено дополнительно:
- sequence `/opt/lab/xray-tt/logs/endpoint-policy-live-20260409-005720` на трёх remote endpoint показывает не только fallback `A -> B`, но и runtime-переупорядочивание `B -> C` при ещё не истекшем cooldown у `A`, а затем возврат `C -> A` после истечения cooldown.
- sequence `/opt/lab/xray-tt/logs/endpoint-race-live-20260409-044656` подтверждает hanging-primary delayed race для stream и UDP path: первый endpoint принимает TCP и зависает, клиент стартует второй endpoint ровно через `1s`, а end-to-end latency остаётся около `1.3s` для stream и `1.15s` для UDP вместо полного connect-timeout первичного endpoint.
- sequence `/opt/lab/xray-tt/logs/endpoint-active-probe-live-20260409-051636` подтверждает, что после fallback `A -> B` восстановившийся `A` возвращается в preferred-порядок не по голому истечению `5s`, а через background `_check` probe: client log фиксирует `trusttunnel active probe restored endpoint 1/2`, remote `a.log` фиксирует `trusttunnel H2 health-check accepted`, а следующий real-traffic CONNECT возвращается на `A` уже через `903ms`.
- sequence `/opt/lab/xray-tt/logs/endpoint-resolve-live-20260409-053846` подтверждает, что один domain-valued `address` на старте может превратиться в два runtime endpoint: client log пишет `trusttunnel server 1/2 failed...`, downstream probe даёт remote egress `37.252.0.130`, а remote `tcpdump` фиксирует трафик на `37.252.0.130:9443`.

Что остаётся дальше:
- решить, насколько глубоко форк должен повторять original client endpoint policy;
- ближайший следующий выбор архитектуры — нужен ли ещё один уровень endpoint-health / endpoint-selection модели поверх уже готовых fallback / delayed race / cooldown / active probe / resolved-address expansion, например более близкое к original relay/address-selection поведение;
- не смешивать этот блок с уже закрытыми H2/H3 transport gaps, `_icmp`, REALITY, validator или generic Xray integration.

### 3.6. Experimental multipath transport

Новая ветка `feat/trusttunnel-multipath` открыта под отдельный R&D-блок TrustTunnel Multipath Transport.

Ключевые правила для этого блока:
- не считать multipath “ещё одним endpoint-policy patch'ем”;
- не пытаться внедрить его сразу в H2/H3/UDP/REALITY;
- начать с `HTTP/2 over TLS` и explicit session/channel/frame layer;
- читать multipath TCP так, как он задан в исходной идее: несколько отдельных TCP-каналов на разные IP внутри одной логической сессии;
- обязательно подтверждать multi-IP data distribution remote-live прогонами, а не только unit/scenario checks.

Что уже сделано на текущем этапе:
- phase 1 больше не является только планом: `config.proto` / `config.pb.go`, JSON binding и validator уже содержат `multipath.*` surface и fail-fast guardrails;
- `proxy/trusttunnel/multipath_session.go` уже даёт не только `MultipathSession`, `MultipathChannel` и server-side registry skeleton, но и attach-secret, attach-deadline, replay-guard и channel-limit validation;
- `proxy/trusttunnel/multipath_control.go` и `proxy/trusttunnel/multipath_server.go` уже реализуют `_mptcp_open` / `_mptcp_attach`, attach-proof, primary session creation и server-side secondary-channel attach;
- phase 2 больше не считается только локально-зелёным control-path: bundle `/opt/lab/xray-tt/logs/multipath-phase2-live-20260410-194957` уже подтверждает Linux-to-Linux H2/TLS `_mptcp_open` на `192.168.1.50:9443` и `_mptcp_attach` на `192.168.1.51:9443` с `200/200` и server markers на второй VM `192.168.1.25`;
- client-side multipath payload path пока deliberately fail-fast режется marker'ом `trusttunnel multipath payload traffic is not implemented yet: control path exists but framed data path is still missing`, поэтому data-plane multipath path всё ещё не начат.

Что дальше:
- следующий кодовый шаг уже не `multipath.*` model и не control-path, а framed TCP payload layer, scheduler/reassembly и первый честный multi-channel client runtime;
- до этого не заявлять multipath как working runtime-path.

Полный поэтапный план, guardrails и точки интеграции зафиксированы в `docs/current/multipath-transport-plan.md`.

## 5. Порядок выполнения

1. для ветки `feat/trusttunnel-multipath` идти по `docs/current/multipath-transport-plan.md`: после уже закрытых phase 1 (`config/validator + session model skeleton`) и phase 2 (`_mptcp_open` / `_mptcp_attach` control path с Linux-to-Linux live validation) переходить к framed TCP data path → scheduler/recovery → remote-live multi-IP data validation
2. держать `streamSettings`-нормализацию синхронной с upstream generic TLS / REALITY / outbound plumbing
3. держать compatibility matrix и validator синхронными с новыми integration-комбинациями
4. добирать dedicated inbound / generic TLS coverage только при появлении новых product-level требований
