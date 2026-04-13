# TrustTunnel / Xray-Core — подтверждённые проверки и границы тестирования

Статус: current
Дата фиксации: 2026-04-13
Коммит состояния: `69ea1a44`
Область истины: подтверждённые тесты, preflight, критерии pass/fail, тестовые границы
Не использовать для: общей архитектуры и долгосрочного roadmap

## 0. Preflight перед любым interop-retest

Перед runtime-проверками должны быть зафиксированы:

- текущий commit и состояние рабочего дерева;
- успешная сборка тестируемого бинаря;
- путь к бинарю, который реально запускается в данном тесте;
- сертификат и trust chain, используемые именно в текущем запуске;
- конфиг Xray и конфиг official стороны, используемые в данном запуске;
- если участвует official client или official endpoint, нужно сохранить exact path их конфигов.

Минимальный набор команд фиксации:
- `git rev-parse HEAD`
- `git status --short`
- `go build -o /opt/lab/xray-tt/tmp/xray-tt-current ./main`
- фиксация exact launch command и binary path
- фиксация exact config file paths
- фиксация certificate/trust-chain inputs

Цель preflight:
- исключить повторение исторической ошибки с запуском старого бинаря после failed build;
- исключить подмену transport-результата сертификатным несоответствием;
- сделать retest воспроизводимым для людей и для Codex.

## 1. Общая тестовая рамка

Подтверждено на `4bfd8ac9`:
- `go test ./testing/scenarios -run "TestTrustTunnel(OutboundTLS|InboundRejectUnknownSNI)" -count=1 -timeout 30m -v`
- `go test ./infra/conf -run "TestTrustTunnel|TestConfigBuildRejectsTrustTunnel|TestConfigBuildAllowsTrustTunnelHTTP3PostQuantumWithoutOutboundSecurity" -count=1`
- `go test ./testing/scenarios -run "TestTrustTunnel(CommanderAddRemoveUser|OutboundProxySettings|OutboundMux|OutboundSendThroughOrigin|OutboundTargetStrategyUseIPv4|InboundSniffingRouteOnly)$" -count=1 -timeout 30m -v`
- `go test ./proxy/trusttunnel/... ./transport/internet/tcp ./app/proxyman/inbound ./app/proxyman/outbound -count=1`
- `go test ./proxy/trusttunnel/... ./transport/internet/tcp ./app/proxyman/inbound`
- `go test ./common/signal ./common/net ./common/mux ./common/singbridge ./transport/internet/tcp ./transport/internet/tls ./app/dispatcher ./app/proxyman/inbound ./app/proxyman/outbound ./transport/internet ./proxy/trusttunnel/...`
- `go test ./proxy/freedom ./proxy/http ./proxy/socks ./proxy/trojan ./proxy/vmess/... ./proxy/vless/... ./proxy/shadowsocks ./proxy/hysteria ./proxy/wireguard ./transport/internet/udp ./app/reverse`
- `$env:GOFLAGS='-buildvcs=false'; go test -run '^$' ./...`
- `go build -buildvcs=false -o ./tmp/xray-tt-current.exe ./main`
- `GOFLAGS=-buildvcs=false go test ./testing/scenarios -count=1 -timeout 90m -v` проходит локально;
- `GOFLAGS=-buildvcs=false go test ./testing/scenarios -count=1 -timeout 90m -v` проходит на Debian lab;
- sequential `GOFLAGS=-buildvcs=false go test -p 1 ./...` на Windows не показывает TrustTunnel-specific regress и останавливается только на `app/dns`, `app/router` и `infra/conf`.

Ограничение текущего full-tree verdict:
- `app/dns` останавливается на `TestQUICNameServer` с `quic://dns.adguard-dns.com got answer: google.com. -> [] ... <app/dns: record not found>`, то есть на внешнем QUIC DNS runtime, а не на TrustTunnel path;
- `app/router` (`TestGeoIPMatcher4CN`) и `infra/conf` (`TestToCidrList`) требуют `geoip.dat` в standard asset locations или `{project_root}/resources`;
- эти ограничения не выглядят следствием TrustTunnel / inbound-worker изменений текущей ветки.

### 1.1. TrustTunnel common-Xray integration scenarios

Подтверждено на `4bfd8ac9`:
- `TestTrustTunnelCommanderAddRemoveUser` доказывает, что `HandlerService` `AddUser` / `RemoveUser` и `GetInboundUsersCount` работают для TrustTunnel inbound, а traffic observable меняется вместе с составом пользователей;
- `TestTrustTunnelOutboundProxySettings` подтверждает совместимость TrustTunnel outbound с generic `proxySettings`;
- `TestTrustTunnelOutboundMux` подтверждает совместимость TrustTunnel outbound с generic `mux`;
- `TestTrustTunnelOutboundSendThroughOrigin` подтверждает `sendThrough=origin` по marker'у `use inbound local ip as sendthrough: 127.0.0.1`;
- `TestTrustTunnelOutboundTargetStrategyUseIPv4` подтверждает, что domain target с `hasIpv6=false` снова проходит через явный outbound `targetStrategy useipv4`;
- `TestTrustTunnelInboundSniffingRouteOnly` подтверждает `sniffing + routeOnly` через sniffed TLS SNI `sniffed.test`.
- `TestTrustTunnelOutboundTLSPinnedPeerCertSha256` и `TestTrustTunnelOutboundTLSPinnedPeerCertSha256WrongCert` подтверждают, что generic `PinnedPeerCertSha256` реально применяется на H2/TLS TrustTunnel path и даёт как positive, так и negative verdict;
- `TestTrustTunnelOutboundTLSServerNameAuthorityVerify` подтверждает generic `serverName` + authority-verify через custom CA; на Windows этот path воспроизводимо требует `DisableSystemRoot=true`, иначе generic TLS transport уходит в системный cert pool вместо custom-CA verify surface;
- `TestTrustTunnelOutboundTLSVerifyPeerCertByName` подтверждает generic `VerifyPeerCertByName` на том же H2/TLS path;
- `TestTrustTunnelOutboundTLSFingerprintPinnedPeerCert` подтверждает, что generic `Fingerprint` и `PinnedPeerCertSha256` совместимы между собой и не ломают TrustTunnel tunnel-path;
- `TestClientProcessAppliesTLSSkipVerificationCompatibilityOverride` подтверждает, что non-HTTP3 `skipVerification=true` теперь реально дополняет missing generic `allowInsecure=true` и `serverName`, а не остаётся мёртвым compatibility flag при наличии `streamSettings.tlsSettings`;
- `TestTrustTunnelStreamSettingsWithTLSCompatibilityFillsServerNameForExplicitVerifySurface` подтверждает, что `hostname` по non-HTTP3 path дополняет missing generic `serverName` даже при explicit generic verify surface, не переписывая сам verify surface;
- `TestConfigBuildRejectsTrustTunnelSkipVerificationConflictWithGenericTLSVerify`, `TestConfigBuildRejectsTrustTunnelSkipVerificationConflictWithCertificatePem` и `TestConfigBuildRejectsTrustTunnelTLSHostnameMismatchOnHTTP2EvenWhenSkipVerification` подтверждают новый fail-fast coverage validator для двусмысленных non-HTTP3 TLS combinations;
- `TestTrustTunnelInboundRejectUnknownSNI` подтверждает generic inbound TLS `RejectUnknownSni` на TrustTunnel inbound: корректный SNI проходит, а чужой SNI режется до прикладного traffic path.

Практическая граница:
- `metadataOnly` не образует отдельный positive TLS SNI routing-path для TrustTunnel: current `app/dispatcher` в режиме `metadataOnly=true` возвращает только metadata sniffers и не выполняет TLS content sniffing; отсутствие TLS-SNI override в этом режиме не считать отдельным TrustTunnel bug.

### 1.2. Multi-endpoint outbound fallback / preference / cooldown / delayed race / active probe

Подтверждено локально на 2026-04-09:
- `go test ./proxy/trusttunnel -run 'Test(ClientServerAttemptsPreferLastSuccessfulEndpoint|ClientServerAttemptsMoveCoolingDownEndpointToBack|ClientServerAttemptsCoolingDownPreferredEndpointTemporarilyUsesNextServer|ConnectUDPTunnelPrefersLastSuccessfulServer|ClientProcessFallsBackToNextConfiguredServer)$' -count=1`
- `go test ./proxy/trusttunnel -run 'TestClientConnectWithEndpointPolicy|TestClientServerAttempts|TestClientProcessFallsBackToNextConfiguredServer' -count=1 -v`
- `go test ./proxy/trusttunnel/... ./transport/internet/tcp ./app/proxyman/inbound ./app/proxyman/outbound -count=1`
- `$env:GOFLAGS='-buildvcs=false'; go test ./testing/scenarios -run 'TestTrustTunnel' -count=1 -timeout 90m -v`
- `go build -buildvcs=false -o ./tmp/xray-tt-current.exe ./main`

Подтверждено remote-live sequence на 2026-04-09:
- preflight code state: `71ff8d71`;
- lab repo: `/opt/lab/xray-tt/src/xray-core-trusttunnel`;
- lab binary: `/opt/lab/xray-tt/tmp/xray-tt-current-live`;
- remote binary: `/opt/trusttunnel-dev/tmp/xray-tt-current-endpoint-policy`;
- lab client config: `/opt/lab/xray-tt/configs/endpoint_policy_client_h2_tls.json`;
- remote endpoint configs:
  - `/opt/trusttunnel-dev/configs/endpoint_policy_h2_tls_a.json` (`:9443`);
  - `/opt/trusttunnel-dev/configs/endpoint_policy_h2_tls_b.json` (`:9444`);
  - `/opt/trusttunnel-dev/configs/endpoint_policy_h2_tls_c.json` (`:9445`);
- authoritative lab bundle: `/opt/lab/xray-tt/logs/endpoint-policy-live-20260409-005720`;
- authoritative remote bundle: `/opt/trusttunnel-dev/logs/endpoint-policy-live-20260409-005720`.

Что именно подтверждено:
- ordered `servers[]` реально используется runtime-слоем как список endpoint, а не схлопывается до одного адреса;
- `TestTrustTunnelOutboundFallsBackToNextConfiguredServerTLS` в `testing/scenarios` подтверждает фактический fallback на следующий endpoint в live local scenario;
- `TestClientServerAttemptsPreferLastSuccessfulEndpoint` подтверждает preference последнего успешно established endpoint на следующих соединениях;
- `TestClientServerAttemptsMoveCoolingDownEndpointToBack` и `TestClientServerAttemptsCoolingDownPreferredEndpointTemporarilyUsesNextServer` подтверждают короткий cooldown после pre-establishment fail и возврат endpoint в нормальный порядок после истечения cooldown;
- `TestConnectUDPTunnelPrefersLastSuccessfulServer` подтверждает, что runtime preference применяется не только к stream path, но и к UDP tunnel establish;
- `TestClientConnectWithEndpointPolicyUsesDelayedRaceWinner`, `TestClientConnectWithEndpointPolicyStartsSecondaryImmediatelyOnPrimaryFailure` и `TestClientConnectWithEndpointPolicyFallsBackAfterRacedPairFails` подтверждают delayed race между первыми двумя ready endpoint, немедленный старт secondary endpoint при раннем fail primary и корректный возврат к последовательному fallback после неуспеха raced-пары.
- `TestClientConnectWithEndpointPolicyRestoresCoolingEndpointViaActiveProbe` подтверждает, что cooling endpoint может быть восстановлен раньше полного cooldown через background probe и снова стать preferred.
- `TestTrustTunnelServersFromConfigExpandsResolvedDomainEndpoint`, `TestTrustTunnelServersFromConfigSkipsUnresolvedDomainWhenOthersExist` и `TestTrustTunnelServersFromConfigFailsWhenNoResolvedServersRemain` подтверждают, что один доменный server-entry на client init разворачивается в несколько runtime endpoint, а не остаётся одним opaque dial target.
- remote-live sequence на одном long-lived client-process подтверждает то же поведение на реальном traffic path lab -> remote -> internet:
  - `step1_only_a_success`: при живом только endpoint `A:9443` соединение проходит через `A`;
  - `step2_fallback_to_b`: при мёртвом `A:9443` и живых `B:9444`/`C:9445` client log пишет `trusttunnel server 1/3 failed; trying next endpoint`, а трафик уходит через `B`;
  - `step3_cooldown_skips_a_uses_c`: сразу после fail `A` остаётся в cooldown, при мёртвом preferred `B` и живых `A`/`C` client снова пишет `trusttunnel server 1/3 failed; trying next endpoint`, но successful CONNECT приходит уже на `C`, а не на `A`;
  - `step4_cooldown_expired_returns_to_a`: после ожидания больше `5s` cooldown истекает, при мёртвом preferred `C` и живых `A`/`B` successful CONNECT снова приходит на `A`, а не на `B`;
  - во всех четырёх шагах downstream probe через lab-side HTTP proxy даёт внешний IP `37.252.0.130`, то есть выбор endpoint подтверждён не synthetic dial-check, а реальным интернет-трафиком.

Подтверждено отдельным remote-live delayed-race sequence на 2026-04-09:
- preflight code state: `7376ab64`;
- lab repo: `/opt/lab/xray-tt/src/xray-core-trusttunnel`;
- lab binary: `/opt/lab/xray-tt/tmp/xray-tt-current-live`;
- remote binary: `/opt/trusttunnel-dev/tmp/xray-tt-current-endpoint-race`;
- lab client configs:
  - `/opt/lab/xray-tt/configs/endpoint_race_client_h2_tls.json`;
  - `/opt/lab/xray-tt/configs/endpoint_race_udp_client_h2_tls.json`;
- remote endpoint configs:
  - `/opt/trusttunnel-dev/configs/endpoint_race_h2_tls_a.json` (`:9443`);
  - `/opt/trusttunnel-dev/configs/endpoint_race_h2_tls_b.json` (`:9444`);
- authoritative lab bundle: `/opt/lab/xray-tt/logs/endpoint-race-live-20260409-044656`;
- authoritative remote bundle: `/opt/trusttunnel-dev/logs/endpoint-race-live-20260409-044656`.

Что именно подтверждено delayed-race sequence:
- `stream_hanging_primary_race_to_b`: primary endpoint `A:9443` не отвергает соединение сразу, а принимает TCP и зависает на handshake; client log пишет `trusttunnel delayed endpoint race started next endpoint after 1s`, второй endpoint `B:9444` принимает `trusttunnel H2 CONNECT accepted for tcp:api.ipify.org:443`, remote `a_hang.log` фиксирует `accepted`, downstream probe даёт `{"ip":"37.252.0.130"}`, а end-to-end latency остаётся `1.317677s`, то есть path завершается через delayed race, а не через полный connect-timeout primary endpoint;
- `stream_prefer_b_after_race`: после победы `B` следующий stream CONNECT на том же client-process сразу идёт в `B` без нового delayed-race marker'а, `A` остаётся без `trusttunnel H2 CONNECT accepted`, а latency опускается до `0.330642s`;
- `udp_hanging_primary_race_to_b`: тот же hanging-primary сценарий подтверждён на shared UDP helper path: client log пишет `trusttunnel delayed endpoint race started next UDP endpoint after 1s`, remote `b.log` фиксирует `trusttunnel H2 UDP mux accepted`, DNS probe возвращает `104.16.132.229` и `104.16.133.229`, а end-to-end latency остаётся `1.155s`;
- practically significant verdict: delayed race подтверждён не synthetic dial-check, а реальным stream internet traffic и реальным UDP DNS traffic между Linux lab и remote host.

Подтверждено отдельным remote-live active-probe sequence на 2026-04-09:
- preflight code state: `f89d65a4`;
- lab repo: `/opt/lab/xray-tt/src/xray-core-trusttunnel`;
- lab binary: `/opt/lab/xray-tt/tmp/xray-tt-current-live`;
- remote binary: `/opt/trusttunnel-dev/tmp/xray-tt-current-live`;
- lab client config: `/opt/lab/xray-tt/configs/endpoint_active_probe_client_h2_tls.json`;
- remote endpoint configs:
  - `/opt/trusttunnel-dev/configs/endpoint_policy_h2_tls_a.json` (`:9443`);
  - `/opt/trusttunnel-dev/configs/endpoint_policy_h2_tls_b.json` (`:9444`);
- authoritative lab bundle: `/opt/lab/xray-tt/logs/endpoint-active-probe-live-20260409-051636`;
- authoritative remote bundle: `/opt/trusttunnel-dev/logs/endpoint-active-probe-live-20260409-051636`.

Что именно подтверждено active-probe sequence:
- `step1_fallback_to_b`: при мёртвом endpoint `A:9443` и живом `B:9444` реальный downstream probe проходит через `B`, а client log содержит `trusttunnel server 1/2 failed before delayed race timeout; trying next endpoint immediately`;
- `active_probe_healthcheck`: после возврата `A` client не ждёт полного cooldown, а сам запускает `_check` probe в cooling endpoint; remote `a.log` фиксирует `trusttunnel H2 health-check accepted`, а client log фиксирует `trusttunnel active probe restored endpoint 1/2 in 59.008813ms`;
- `step2_return_to_a`: следующий real-traffic CONNECT до `tcp:api.ipify.org:443` уже идёт через `A`, а remote `a.log` фиксирует `trusttunnel H2 CONNECT accepted for tcp:api.ipify.org:443`;
- `step2_not_still_on_b`: remote `b.log` фиксирует только первый CONNECT и не получает новый successful CONNECT для второго шага;
- `returned_before_full_cooldown`: bundle `timing.env` показывает `STEP2_DELAY_MS=903`, то есть возврат на `A` произошёл меньше чем через секунду после step1 и существенно раньше полного `5s` cooldown.

Подтверждено отдельным remote-live resolved-address sequence на 2026-04-09:
- preflight code state: `507ff073`;
- lab repo: `/opt/lab/xray-tt/src/xray-core-trusttunnel`;
- lab binary: `/opt/lab/xray-tt/tmp/xray-tt-current-live`;
- remote binary: `/opt/trusttunnel-dev/tmp/xray-tt-current-live`;
- lab client config: `/opt/lab/xray-tt/configs/endpoint_resolve_client_h2_tls.json`;
- remote config: `/opt/trusttunnel-dev/configs/server_h2_tls_udp_remote.json`;
- authoritative lab bundle: `/opt/lab/xray-tt/logs/endpoint-resolve-live-20260409-053846`;
- authoritative remote bundle: `/opt/trusttunnel-dev/logs/endpoint-resolve-live-20260409-053846`.

Что именно подтверждено resolved-address sequence:
- single configured `settings.address = "ttmulti.lab"` не остаётся одним opaque dial target: lab `/etc/hosts` задаёт `ttmulti.lab -> 127.0.0.2, 37.252.0.130`, а client log фиксирует `trusttunnel server 1/2 failed before delayed race timeout; trying next endpoint immediately`, то есть один configured entry превратился в два runtime endpoint;
- первый resolved адрес `127.0.0.2:9443` действительно отбрасывается как failed endpoint, а downstream probe через SOCKS `127.0.0.1:18093` всё равно даёт `{"ip":"37.252.0.130"}`;
- remote bundle `tcpdump.txt` фиксирует трафик на `37.252.0.130:9443`, то есть fallback идёт именно на второй resolved remote IP, а не на synthetic local bypass.

### 1.3. Multipath phase 1-5: config / validator / control path / payload runtime / quorum hardening / recovery-rejoin

Подтверждено на 2026-04-13:
- multipath phase 1, phase 2, phase 3, phase 4 и phase 5 уже существуют не только в локальном worktree, но и в Linux live retest на второй VM `192.168.1.25`;
- validated scope уже включает config model, validator, session/control path, H2/TLS payload data-path, dynamic channel set, bounded reorder backpressure, strict channel-quorum semantics и recovery/rejoin после реального channel-loss;
- explicit outer-layer quorum-loss marker в negative live bundle и external multi-IP validation всё ещё остаются открытыми фазами.

Кодовые точки:
- `proxy/trusttunnel/config.proto`
- `proxy/trusttunnel/config.pb.go`
- `infra/conf/trusttunnel.go`
- `infra/conf/trusttunnel_lint.go`
- `proxy/trusttunnel/multipath_control.go`
- `proxy/trusttunnel/multipath_session.go`
- `proxy/trusttunnel/multipath_server.go`
- `proxy/trusttunnel/multipath_server_runtime.go`
- `proxy/trusttunnel/multipath_client.go`
- `proxy/trusttunnel/multipath_frame.go`
- `proxy/trusttunnel/server_test.go`
- `proxy/trusttunnel/server.go`
- `proxy/trusttunnel/client.go`
- `proxy/trusttunnel/stream_settings_compat.go`

Что именно подтверждено:
- protobuf/config model уже содержит `MultipathScheduler` и `MultipathConfig`, а outbound JSON binding принимает `multipath.*`;
- config-build validator уже fail-fast режет phase-1 invalid combinations:
  - не `transport=http2`;
  - не `streamSettings.security=tls`;
  - `udp=true`;
  - отсутствие multi-endpoint pool;
  - `multipath.minChannels < 2`;
  - `multipath.maxChannels < multipath.minChannels`;
- runtime layer уже содержит `MultipathSession`, `MultipathChannel`, server-side session registry, attach-secret, attach-deadline, replay-guard, channel-limit validation, ready/close lifecycle, reorder window, gap-timeout, per-channel accounting counters и explicit strict quorum-loss semantics;
- server-side H2 path уже реализует `_mptcp_open` / `_mptcp_attach`, attach-proof, primary session creation, secondary channel attach, payload dispatch после channel quorum и session teardown;
- client/runtime layer уже реализует payload data-plane: framed stream, round-robin write distribution, writer retry по surviving channels, reorder/reassembly на read-path и bounded backpressure вместо мгновенного `reorder window exceeded`;
- reassembler больше не роняет multipath stream по idle-timeout без реального reorder-gap: timeout теперь срабатывает только при pending gap;
- attach-deadline watcher больше не закрывает уже установленную multipath session после временной деградации quorum: после первого успешного quorum он ориентируется на `session.Ready()`, а не на текущий `Active()` state;
- peer channel-loss теперь может быть surfaced с удалённой стороны через control-frame `channel_closed`, после чего peer session деградирует этот channel в своём registry, а не продолжает считать его silently alive;
- server-side multipath session runtime больше не привязан к request-scoped context отдельного attach-канала: session-dispatch запускается на `context.WithoutCancel(ctx)` и закрывается только через session lifecycle, поэтому потеря attach channel больше не убивает всю session с `context canceled`;
- live preflight был таким:
  - local code state: `69ea1a44`;
  - local worktree: clean после code-commit;
  - local build path: `C:\Users\Vardo\GPTProject\xray-core-trusttunnel\tmp\xray-tt-multipath-linux-phase5`;
  - runtime host: вторая VM `192.168.1.25`, `root`, Debian 13;
  - runtime workspace: `/root/tt-multipath-phase3`;
  - runtime binary path: `/root/tt-multipath-phase3/xray-tt-multipath-linux-phase5`;
  - runtime config path: `/root/tt-multipath-phase3/server.json`, `/root/tt-multipath-phase3/client.json`;
  - cert/key path: `/root/tt-multipath-phase3/server.crt`, `/root/tt-multipath-phase3/server.key`;
  - authoritative positive bundle: `/root/tt-multipath-phase3/logs/multipath-phase3-live-20260413-092248`;
  - authoritative negative bundle: `/root/tt-multipath-phase3/logs/multipath-phase3-gap-20260413-092142`;
  - authoritative rejoin bundle: `/root/tt-multipath-phase3/logs/multipath-phase5-rejoin-20260413-194749`;
  - live topology: server слушает `:9443` на alias IP `192.168.1.50` и `192.168.1.51`, а client запускается внутри Linux netns `ttmpc` с address `10.200.0.2`;
- Linux positive live payload run дополнительно подтверждает:
  - `_mptcp_open` на `192.168.1.50:9443` возвращает `200` и server log фиксирует `trusttunnel H2 multipath open accepted for tcp:127.0.0.1:18080`;
  - `_mptcp_attach` на `192.168.1.51:9443` возвращает `200` и server log фиксирует `trusttunnel H2 multipath attach accepted for tcp:127.0.0.1:18080`;
  - `4 MiB` download через SOCKS → TrustTunnel multipath → local HTTP app даёт совпадающий SHA-256 `d3bc57b716f8caf3b4d1a113f58f4cca5d26dec9b151490aeb363e8aa2dd3c88`;
  - `4 MiB` upload даёт совпадающий SHA-256 `e150e00353f6c4cb2b887a603b815dd3f9d11477021d1ae93ee47f391a919267`;
  - `ss-9443.txt` внутри bundle фиксирует одновременные established TCP connections на `192.168.1.50:9443` и `192.168.1.51:9443` от `10.200.0.2` для download и upload session;
  - server после quorum реально делает downstream dispatch к `127.0.0.1:18080`, а не остаётся на control-path;
- Linux negative live reset-run дополнительно подтверждает:
  - harness на второй VM использует `nft reject with tcp reset`, потому что на этом Debian host отсутствует `iptables`;
  - `drop.log` фиксирует `drop-mode=nft`;
  - long-lived `64 MiB` download через SOCKS → TrustTunnel multipath → local HTTP app рвётся с `curl exitcode 18` и `end of response ... missing`;
  - `download.headers` успевает зафиксировать `HTTP/1.0 200 OK` и полный `Content-Length: 67108864`, то есть session стартует корректно, а ломается уже после начала payload transfer;
  - live bundle подтверждает реальный channel-loss path на одном alias IP, но explicit outer-layer marker `trusttunnel multipath channel quorum lost` в bundle logs пока ещё не surfaced;
- Linux live rejoin-run дополнительно подтверждает:
  - harness использует exact runtime binary `/root/tt-multipath-phase3/xray-tt-multipath-linux-phase5`, а не старый повреждённый `/root/tt-multipath-phase3/xray-tt`;
  - `curl.exitcode` равен `0`, `rejoin.waitcode` равен `0`;
  - `sha256sum download.bin` совпадает с ожидаемым `79cf58c41ad3d94d7b41c668dfb378899d2cc70b6a28736122c1331626476731`;
  - `ss-after-rejoin.txt` фиксирует повторное наличие двух `ESTAB` каналов на `192.168.1.50:9443` и `192.168.1.51:9443`;
  - server log фиксирует `trusttunnel multipath quorum degraded ... got=1 want=2`, затем `trusttunnel multipath quorum restored ... channels=2`, а rejoined attach проходит как `channel=3`;
  - client log фиксирует `trusttunnel multipath rejoined endpoint 192.168.1.51:9443 ... channel=3`;
  - прежний server-side failure marker `trusttunnel multipath server session dispatch ended ... context canceled` больше не воспроизводится;
- H1 и H3 pseudo-host path для multipath честно режутся как unsupported;
- current verdict уже не ограничен control-only phase 2 или initial payload-only phase 3: multi-IP traffic distribution, strict quorum semantics, reorder-window hardening и recovery/rejoin реально присутствуют в коде и подтверждены тестами;
- current verdict всё ещё deliberately не включает explicit outer-layer quorum-loss marker в negative live bundle и external multi-IP validation.

Подтверждённые команды:
- локально:
  - `go test ./proxy/trusttunnel -run 'TLSCompatibility|Multipath' -count=1`
  - `go test ./proxy/trusttunnel/... ./transport/internet/tcp ./app/proxyman/inbound -count=1`
  - `go test ./testing/scenarios -run 'TestTrustTunnel' -count=1 -timeout 90m -v`
  - `$env:GOFLAGS='-buildvcs=false'; go test -run '^$' ./...`
  - `go build -buildvcs=false -o ./tmp/xray-tt-current.exe ./main`
  - `$env:GOOS='linux'; $env:GOARCH='amd64'; go build -buildvcs=false -o ./tmp/xray-tt-multipath-linux-phase5 ./main`
- live:
  - `XRAY_BIN=/root/tt-multipath-phase3/xray-tt-multipath-linux-phase4 bash /root/tt-multipath-phase3/live.sh`
  - `XRAY_BIN=/root/tt-multipath-phase3/xray-tt-multipath-linux-phase4 bash /root/tt-multipath-phase3/gap.sh`
  - `XRAY_BIN=/root/tt-multipath-phase3/xray-tt-multipath-linux-phase5 bash /root/tt-multipath-phase3/multipath_phase5_rejoin_remote.sh`

Практический вывод:
- phase 1, phase 2, phase 3, phase 4 и phase 5 уже закрывают config/validator/session/control, payload/runtime verdict, quorum-hardening и recovery/rejoin для `HTTP/2 over TLS`;
- следующий шаг теперь действительно уже не `_mptcp_open` / `_mptcp_attach`, не первый framed payload path и не recovery/rejoin, а более явный outer-layer quorum-loss marker и более жёсткая external multi-IP validation.

### 1.4. Client-Side antiDPI runtime

Подтверждено dedicated live smoke на 2026-04-09:
- preflight code state: `7376ab64`;
- lab binary: `/opt/lab/xray-tt/tmp/xray-tt-current-live`;
- remote binary: `/opt/trusttunnel-dev/tmp/xray-tt-current-antidpi`;
- lab configs:
  - `/opt/lab/xray-tt/configs/our_client_to_remote_server_h2_tls_antidpi_true.json`;
  - `/opt/lab/xray-tt/configs/our_client_to_remote_server_h2_reality_antidpi_true.json`;
- remote configs:
  - `/opt/trusttunnel-dev/configs/server_h2_tls_udp_remote.json`;
  - `/opt/trusttunnel-dev/configs/server_h2_reality_remote.json`;
- authoritative lab bundle: `/opt/lab/xray-tt/logs/antidpi-live-20260409-045510`;
- authoritative remote bundle: `/opt/trusttunnel-dev/logs/antidpi-live-20260409-045510`.

Что именно подтверждено:
- H2/TLS anti-DPI path проходит через реальный traffic path lab -> remote -> internet: downstream probe через SOCKS `127.0.0.1:10844` даёт `{"ip":"37.252.0.130"}`, а remote log фиксирует `trusttunnel H2 CONNECT accepted for tcp:api.ipify.org:443`;
- H2/REALITY anti-DPI path проходит через тот же реальный traffic path: downstream probe через SOCKS `127.0.0.1:10833` даёт `{"ip":"37.252.0.130"}`, client log фиксирует `trusttunnel HTTP/2 path selected with REALITY and empty negotiated ALPN; using HTTP/2 preface path`, а remote log фиксирует `trusttunnel H2 CONNECT accepted for tcp:api.ipify.org:443`;
- practically significant verdict: `antiDpi=true` больше не считается explicit reject на поддержанных `HTTP/2 over TLS` и `HTTP/2 over REALITY` path; explicit `http3` остаётся отдельной unsupported combination.

## 2. Подтверждённые runtime-проверки

### 2.1. Official TrustTunnel client → our H3 server

Конфиги:
- `/opt/lab/xray-tt/configs/server_h3.json`
- `/opt/lab/xray-tt/configs/official_client_to_our_server_h3.toml`

Подтверждено:
- локальный SOCKS listener official client поднимается на `127.0.0.1:11080`;
- CONNECT до `https://example.com/` проходит;
- сервер логирует `trusttunnel H3 health-check accepted`;
- сервер логирует `trusttunnel H3 CONNECT accepted for tcp:example.com:443`;
- access path доходит до `[tt-in-h3 >> direct] email: u1`;
- сертификат проходит верификацию на стороне official client.

### 2.2. Our Xray client → official TrustTunnel endpoint по H3

Конфиги:
- `/opt/lab/xray-tt/configs/our_client_to_official_endpoint_h3.json`
- `/opt/lab/xray-tt/official-endpoint-lab/vpn.toml`
- `/opt/lab/xray-tt/official-endpoint-lab/hosts.toml`
- `/opt/lab/xray-tt/official-endpoint-lab/credentials.toml`

Подтверждено:
- локальный SOCKS listener поднимается на `127.0.0.1:10809`;
- CONNECT до `https://example.com/` проходит.

### 2.3. H3 UDP smoke-test и stats

Конфиги:
- `/opt/lab/xray-tt/configs/server_h3_udp_stats_iso.json`
- `/opt/lab/xray-tt/configs/our_client_udp_to_our_server_h3_stats_iso.json`

Подтверждено:
- DNS-запросы проходят через локальный UDP inbound клиента;
- сервер фиксирует `trusttunnel H3 UDP mux accepted`;
- API stats возвращает ненулевые значения для inbound и user traffic counters;
- `user>>>u1>>>online` должен трактоваться как `onlineMap`, а не как обычный counter.

### 2.4. H2 `_check` interop-retest

Preflight:
- commit: `9f18af9da4856bc15b5f9e63e604abf3e00158ee`;
- worktree: clean;
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- binary sha256: `b2f53503363027e600d6bb754509b051a0bd318e4f5863c79ed77c2c471980ac`;
- official client binary: `/opt/lab/xray-tt/bin/trusttunnel_client/trusttunnel_client`;
- success/auth-fail server config: `/opt/lab/xray-tt/configs/server_h2_official_cert.json`;
- rules server config: `/opt/lab/xray-tt/configs/server_h2_rules.json`;
- success client config: `/opt/lab/xray-tt/configs/official_client_to_our_server_h2_check_ok.toml`;
- auth-fail client config: `/opt/lab/xray-tt/configs/official_client_to_our_server_h2_check_authfail.toml`;
- rule-allow client config: `/opt/lab/xray-tt/configs/official_client_rules_allow.toml`;
- rule-deny client config: `/opt/lab/xray-tt/configs/official_client_rules_deny.toml`;
- server certificate fingerprint: `D8:2C:1F:B9:42:33:B4:1D:D2:C1:C9:2C:23:24:F9:A8:22:98:D3:2A:94:48:E0:CC:AE:A5:A8:99:E7:C2:D6:9F`;
- log bundle: `/opt/lab/xray-tt/logs/h2-check-retest-20260404-233636`.

Подтверждено:
- success-case логирует `trusttunnel H2 health-check accepted` и `trusttunnel H2 CONNECT accepted for tcp:example.com:443`;
- official client логирует `Certificate verified successfully`;
- auth-fail case возвращает `HTTP/2.0 407` на стороне official client;
- deny-case возвращает `HTTP/2.0 403` на стороне official client и логирует `matched rule[1] action=deny catch-all` на сервере;
- allow sanity-check логирует `matched rule[0] action=allow clientRandom=deadbeef`, `trusttunnel H2 health-check accepted` и `trusttunnel H2 CONNECT accepted for tcp:example.com:443`;
- сигнатуры `failed to open connection to tcp:_check:443` и `lookup _check: no such host` отсутствуют.

### 2.5. H2 rules retest

Конфиги:
- `/opt/lab/xray-tt/configs/server_h2_rules.json`
- `/opt/lab/xray-tt/configs/official_client_rules_allow.toml`
- `/opt/lab/xray-tt/configs/official_client_rules_deny.toml`

Подтверждено:
- allow-case пропускает трафик;
- deny-case возвращает `403` и блокирует трафик.

### 2.6. H3 rules retest

База retest:
- использован H3-вариант rules-конфигов, полученный из rules-сценария H2 заменой transport `http2 -> http3`;
- H2-конфиги для логики rules: `/opt/lab/xray-tt/configs/server_h2_rules.json`, `official_client_rules_allow.toml`, `official_client_rules_deny.toml`;
- H3-variant повторяет тот же rules-set, но работает через H3 transport path текущего состояния.

Подтверждено:
- allow-case логирует `matched rule[0] action=allow` и пропускает трафик;
- deny-case логирует deny-rule и блокирует и health-check, и CONNECT через `403`.

### 2.7. Retest исправления `H3_NO_ERROR`

Конфиги:
- `/opt/lab/xray-tt/configs/server_h3.json`
- `/opt/lab/xray-tt/configs/official_client_to_our_server_h3.toml`

Подтверждено:
- повторный H3 TCP тест проходит успешно;
- ложный хвост `... > H3_NO_ERROR` отсутствует.

### 2.8. Official client ↔ our server H2 `_icmp`

Preflight:
- commit: `5a21fd31dc19b3eee23b789f3a5b11338cddb117`;
- worktree: clean;
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- binary sha256: `d529ea54e25941c25121d216f84fd741c7a586e95d355ba9577359ba55404b2c`;
- official client binary: `/opt/lab/xray-tt/bin/trusttunnel_client/trusttunnel_client`;
- runtime server config: `/opt/lab/xray-tt/configs/server_h2_official_cert.json`;
- repo-local server config source: `testing/trusttunnel/server_h2_official_cert.json`;
- runtime client config: `/opt/lab/xray-tt/configs/official_client_to_our_server_h2_icmp_test.toml`;
- repo-local client config source: `testing/trusttunnel/official_client_to_our_server_h2_icmp.toml`;
- server certificate fingerprint: `F1:22:FD:22:AF:B0:C9:2B:03:05:A9:55:9B:F7:5E:8F:80:43:00:B9:7C:22:34:EA:6B:34:F9:24:7A:AD:64:9C`;
- log bundle: `/opt/lab/xray-tt/logs/icmp-h2-official-20260405-114407`.

Подтверждено:
- official client логирует `Certificate verified successfully`;
- сервер логирует `trusttunnel H2 health-check accepted` и `trusttunnel H2 ICMP mux accepted`;
- client log содержит `ICMP register_request` и `ICMP register_reply` с `type=0 code=0`;
- `ping 1.1.1.1` из namespace `tun` проходит с `3 packets transmitted, 3 received, 0% packet loss`;
- `server-errors.txt` пустой;
- сигнатура `fatal error: concurrent map writes` больше не воспроизводится на параллельных H2 stream `_check` + `_icmp`.

### 2.9. Official client ↔ our server H3 `_icmp`

Preflight:
- commit: `6c46922c7521ef4ae4ba672ee95d50f5fb0b1ae6`;
- worktree: clean;
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- binary sha256: `5fe6e0e7e28608b3187e1cd2ea9edce6603723eca5d92cc61d14ab198b5b65b0`;
- official client binary: `/opt/lab/xray-tt/bin/trusttunnel_client/trusttunnel_client`;
- runtime server config: `/opt/lab/xray-tt/configs/server_h3.json`;
- repo-local server config source: `testing/trusttunnel/server_h3.json`;
- runtime client config: `/opt/lab/xray-tt/configs/official_client_to_our_server_h3_icmp_test.toml`;
- repo-local client config source: `testing/trusttunnel/official_client_to_our_server_h3_icmp.toml`;
- server certificate fingerprint: `F1:22:FD:22:AF:B0:C9:2B:03:05:A9:55:9B:F7:5E:8F:80:43:00:B9:7C:22:34:EA:6B:34:F9:24:7A:AD:64:9C`;
- log bundle: `/opt/lab/xray-tt/logs/icmp-h3-official-20260405-120037`.

Подтверждено:
- official client логирует `Certificate verified successfully`;
- сервер логирует `trusttunnel H3 health-check accepted` и `trusttunnel H3 ICMP mux accepted`;
- client log содержит `ICMP register_request` и `ICMP register_reply` с `type=0 code=0`;
- `ping 1.1.1.1` из namespace `tun` проходит с `3 packets transmitted, 3 received, 0% packet loss`;
- `server-errors.txt` пустой;
- сигнатура `fatal error: concurrent map writes` не появляется и на H3 clean-HEAD retest.

## 3. Что считать pass/fail на текущем этапе

### 3.1. Pass

Признаки рабочего поведения:
- session устанавливается;
- H2 `_check` возвращает `200` / `407` / `403` согласно auth/rules сценарию;
- reserved pseudo-hosts `_check`, `_udp2` и `_icmp` не падают из H1/H2/H3 обратно в обычный dispatch path;
- H2/H3 `_icmp` при доступном raw ICMP открывает `200` mux stream и пишет reply-frames fixed-size codec;
- H2/H3 `_icmp` при недоступном raw socket отвечает `503`;
- outbound `clientRandom` на H2/H3 позволяет детерминированно проходить allow/deny по server-side rules;
- TCP CONNECT проходит и держит двусторонний обмен;
- UDP через `_udp2` проходит без развала session;
- H3 allow/deny определяется rule match, а не глобальным запретом;
- штатное завершение H3 stream не поднимается как прикладная ошибка;
- traffic counters инкрементируются;
- `user>>>...>>>online` анализируется отдельно как `onlineMap`.

### 3.2. Fail

Признаки регрессии:
- `failed to open connection to tcp:_check:443`;
- `lookup _check: no such host`;
- `failed to read trusttunnel request > H3_NO_ERROR (local)`;
- `fatal error: concurrent map writes`;
- `connect: connection refused` при ошибочном заходе TCP на QUIC listener;
- `peer certificate is missing` при неправильном порядке TLS verify в H3;
- `unknown transport protocol: trusttunnelh3`;
- любой глобальный отказ H3 path только из-за самого факта наличия rules при корректно извлечённом `client_random`.

## 4. Что уже не нужно повторно проверять как открытую проблему

На текущем состоянии не требуется повторная перепроверка как открытого дефекта:
- H2 `_check` как отдельного special path с `200` / `407` / `403`;
- official H2 `_icmp` interop как отдельного незакрытого server-side дефекта;
- official H3 `_icmp` interop как отдельного незакрытого server-side дефекта;
- полного UDP interop matrix как отдельного незакрытого compatibility gap;
- H2/TCP + REALITY и H2/UDP + REALITY как открытого production-gap, если live retest bundles от 2026-04-06 остаются воспроизводимыми;
- outbound `clientRandom` как отдельного чисто декларативного поля на H2/H3;
- transport-layer принадлежности рабочего H3 path;
- server-side H3 rules по `client_random`;
- auth и stats sanity-check как отдельного открытого compatibility gap, если `onlineMap` валидируется через non-loopback source IP;
- ложного `H3_NO_ERROR` в H3 TCP path.

Переоткрывать эти вопросы можно только при появлении более новых и воспроизводимых доказательств, чем фиксация `99e59352`.

## 5. Что остаётся предметом будущих проверок и что сохранено как воспроизводимый runbook

Открытые блоки для следующих циклов проверки:
- client-side parity fields после закрытия H2 REALITY production path;
- общая интеграция TrustTunnel с `streamSettings` и общими механизмами Xray.

Локально подтверждённые regression-тесты на 2026-04-05:
- `go test ./common/net` проходит, включая `Network_ICMP` string/destination coverage;
- `go test ./infra/conf -run 'TestNetwork(BuildSupportsICMP|ListBuildSupportsICMP)$'` проходит;
- `go test ./infra/conf -run '^TestTrustTunnelServerConfigBuildSupportsICMPSettings$'` проходит;
- `go test ./app/router -run '^$'` проходит как compile-only sanity-check для routing layer после добавления `Network_ICMP`;
- `TestClientProcessRejectsIncompleteICMPLink` подтверждает, что новый `_icmp` path не пытается работать с неполным `transport.Link`;
- `TestTrustTunnelICMPRequestFromBufferUsesFallbackDestination` подтверждает разбор raw echo-request с fallback destination;
- `TestTrustTunnelICMPRequestFromBufferRejectsNonEchoRequest` подтверждает, что client-side contract пока ограничен echo-request path;
- `TestRunTrustTunnelICMPTunnelEchoRoundTrip` подтверждает, что outbound `_icmp` path кодирует fixed-size request frame и локально восстанавливает raw echo-reply packet по сохранённому payload;
- `TestBuildTrustTunnelICMPSessionOptionsDefaults` и `TestBuildTrustTunnelICMPSessionOptionsUsesConfiguredValues` подтверждают binding `allowPrivateNetworkConnections`, `icmp.interfaceName`, `icmp.requestTimeoutSecs`, `icmp.recvMessageQueueCapacity`;
- `TestOpenICMPSessionUsesConfiguredOptions` подтверждает, что `Server.openICMPSession()` прокидывает эти значения в session factory;
- `TestRunTrustTunnelICMPTunnelTimeExceededRoundTrip` подтверждает representable client-side reconstruction для `time exceeded`;
- `TestTrustTunnelICMPReplyFromMessageMatchesDestinationUnreachable` подтверждает quoted echo-request matching для `destination unreachable`;
- `TestTrustTunnelICMPReplyQueueDropsOnOverflow` подтверждает bounded per-stream reply queue и drop-on-overflow semantics аналога official `recv_message_queue_capacity`;
- `TestTrustTunnelValidateICMPDestination` и `TestTrustTunnelICMPSessionRejectsPrivateDestinationWhenDisabled` подтверждают global-only policy по умолчанию и reject private destinations до raw-send path;
- `go test ./proxy/trusttunnel/... ./transport/internet/tcp ./app/proxyman/inbound` проходит;
- `GOFLAGS=-buildvcs=false go test -run '^$' ./...` проходит как compile-only sweep по дереву после добавления outbound `_icmp` path;
- `go build -buildvcs=false -o ./tmp/xray-tt-current.exe ./main` проходит;
- `TestAttachTrustTunnelClientRandomClonesSharedContent` защищает H2/H3 parallel streams от shared `session.Content.Attributes`;
- обычный H2 CONNECT auth-fail возвращает `407` и `Proxy-Authenticate`;
- H2 `_udp2` auth-fail возвращает `407` до UDP mux;
- H2 `_icmp` auth-fail возвращает `407`;
- H2 `_icmp` при недоступной ICMP session отвечает `503 Service Unavailable`;
- H2 `_icmp` при доступной fake-session возвращает `200` и reply-frame без dispatch;
- `settings.allowPrivateNetworkConnections = false` режет private/loopback/link-local destinations до raw ICMP path;
- H1 `_check` отвечает `200` без dispatch;
- H1 `_udp2` больше не уходит в обычный dispatch и отвечает явной HTTP-ошибкой;
- H1 `_icmp` больше не уходит в обычный dispatch и отвечает `501 Not Implemented`.

Расширенный regression sweep и bugfix на 2026-04-06 / `c6ff745b`:
- `go test ./common/signal ./common/net ./common/mux ./common/singbridge ./transport/internet/tcp ./transport/internet/tls ./app/dispatcher ./app/proxyman/inbound ./app/proxyman/outbound ./transport/internet ./proxy/trusttunnel/...` проходит;
- `go test ./proxy/freedom ./proxy/http ./proxy/socks ./proxy/trojan ./proxy/vmess/... ./proxy/vless/... ./proxy/shadowsocks ./proxy/hysteria ./proxy/wireguard ./transport/internet/udp ./app/reverse` проходит;
- `GOFLAGS=-buildvcs=false go test -run '^$' ./...` проходит как compile-only sweep по всему дереву;
- `go build -buildvcs=false -o ./tmp/xray-tt-current.exe ./main` проходит;
- branch-регрессия была найдена не в KCP, а в `TestDomainSniffing`: на bad HEAD отсутствовал marker `app/dispatcher: sniffed domain: www.github.com`, а downstream запрос уходил в `tcp:127.0.0.1:443` и падал `proxyconnect tcp: dial tcp 127.0.0.1:443: connect: connection refused`;
- root cause локализован в `app/proxyman/inbound/worker.go`: commit `bf23af9f` протащил `w.ctx` в generic `tcpWorker.Start()` listener path, хотя TrustTunnel требовался только явный hook `ListenerContext(context.Context) context.Context`;
- current fix `c6ff745b` возвращает generic TCP listener на `context.Background()`, но сохраняет explicit `ListenerContext(...)` hook для TrustTunnel-specific providers;
- после фикса проходят локально `TestDomainSniffing`, `TestProxyOverKCP`, `TestTLSOverKCP`, `TestVMessKCP` и `TestVMessKCPLarge`;
- полный `GOFLAGS=-buildvcs=false go test ./testing/scenarios -count=1 -timeout 90m -v` проходит и локально, и на Debian lab.

Linux package verification на Debian lab 2026-04-05 / `0fbc2ed5`:
- repo HEAD: `0fbc2ed5d5ad701c4cb554c184144f56e2f22859`;
- worktree: clean;
- `go test ./proxy/trusttunnel/... ./transport/internet/tcp ./app/proxyman/inbound` проходит;
- `go build -buildvcs=false -o /opt/lab/xray-tt/tmp/xray-tt-current ./main` проходит.

Linux root verification на Debian lab 2026-04-05 / `32b2eff2`:
- repo HEAD: `32b2eff2527e9da632c980823d8435166f38d75f`;
- worktree: clean;
- `go test ./proxy/trusttunnel -run TestTrustTunnelICMPSessionEchoV4Loopback -count=1` проходит;
- `go test ./proxy/trusttunnel/... ./transport/internet/tcp ./app/proxyman/inbound` проходит;
- `go build -buildvcs=false -o /opt/lab/xray-tt/tmp/xray-tt-current ./main` проходит.

Clean-HEAD runtime-retest outbound `clientRandom` на 2026-04-05 / `fc276340`:
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- binary sha256: `34f191ae00a47b192eba5cce3117991008f5101a75a44dcfa557c67b0a531ad4`;
- worktree: clean (`git-status.txt` size `0`);
- log bundle: `/opt/lab/xray-tt/logs/clientrandom-retest-clean-20260405-085845`;
- H2 allow-case: `matched rule[0] action=allow clientRandom=deadbeef` и `trusttunnel H2 CONNECT accepted for tcp:127.0.0.1:18080`;
- H2 deny-case: client log содержит `trusttunnel CONNECT failed with status 403: connection rejected by rule`;
- H3 allow-case: `matched rule[0] action=allow clientRandom=deadbeef` и `trusttunnel H3 CONNECT accepted for tcp:127.0.0.1:18080`;
- H3 deny-case: client log содержит `trusttunnel CONNECT failed with status 403: connection rejected by rule`.

Clean-HEAD official client ↔ our server H2 `_icmp` runtime-retest на 2026-04-05 / `5a21fd31`:
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- binary sha256: `d529ea54e25941c25121d216f84fd741c7a586e95d355ba9577359ba55404b2c`;
- worktree: clean (`git status --short` output empty);
- log bundle: `/opt/lab/xray-tt/logs/icmp-h2-official-20260405-114407`;
- runtime server config: `/opt/lab/xray-tt/configs/server_h2_official_cert.json`;
- runtime client config: `/opt/lab/xray-tt/configs/official_client_to_our_server_h2_icmp_test.toml`;
- repo-local client template: `testing/trusttunnel/official_client_to_our_server_h2_icmp.toml`;
- server log содержит `trusttunnel H2 health-check accepted` и `trusttunnel H2 ICMP mux accepted`;
- client log содержит `Certificate verified successfully`, `ICMP register_request` и `ICMP register_reply` с `type=0 code=0`;
- ping из namespace `tun`: `3 packets transmitted, 3 received, 0% packet loss`;
- `server-errors.txt` пустой, `fatal error: concurrent map writes` отсутствует.

Clean-HEAD official client ↔ our server H3 `_icmp` runtime-retest на 2026-04-05 / `6c46922c`:
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- binary sha256: `5fe6e0e7e28608b3187e1cd2ea9edce6603723eca5d92cc61d14ab198b5b65b0`;
- worktree: clean (`git status --short` output empty);
- log bundle: `/opt/lab/xray-tt/logs/icmp-h3-official-20260405-120037`;
- runtime server config: `/opt/lab/xray-tt/configs/server_h3.json`;
- runtime client config: `/opt/lab/xray-tt/configs/official_client_to_our_server_h3_icmp_test.toml`;
- repo-local client template: `testing/trusttunnel/official_client_to_our_server_h3_icmp.toml`;
- server log содержит `trusttunnel H3 health-check accepted` и `trusttunnel H3 ICMP mux accepted`;
- client log содержит `Certificate verified successfully`, `ICMP register_request` и `ICMP register_reply` с `type=0 code=0`;
- ping из namespace `tun`: `3 packets transmitted, 3 received, 0% packet loss`;
- `server-errors.txt` пустой, `fatal error: concurrent map writes` отсутствует.

### 2.10. Clean-HEAD our TUN client → our server H2/H3 `_icmp`

Подтверждено на 2026-04-05 / `96a9d053`:
- worktree: clean на lab (`git status --short` пустой);
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- H2 server config: `/opt/lab/xray-tt/configs/server_h2.json`;
- H2 client config: `/opt/lab/xray-tt/configs/our_client_tun_to_our_server_h2_icmp.json`;
- H2 log bundle: `/opt/lab/xray-tt/logs/h2-tun-netns-clean-20260405-165558`;
- H3 server config: `/opt/lab/xray-tt/configs/server_h3.json`;
- H3 client config: `/opt/lab/xray-tt/configs/our_client_tun_to_our_server_h3_icmp.json`;
- H3 log bundle: `/opt/lab/xray-tt/logs/h3-tun-netns-clean-20260405-165602`.

Подтверждённый Linux setup:
- Xray поднимает `xraytunh2` / `xraytunh3` в host namespace;
- interface переносится в отдельный namespace `tunxrayh2` / `tunxrayh3`;
- внутри namespace задаются `ip addr add 192.0.2.10/32 dev xraytunh*` и `ip route add 1.1.1.1/32 dev xraytunh*`;
- `ping -n -I 192.0.2.10 -c 1 -W 3 1.1.1.1` проходит как на H2, так и на H3.

Pass markers:
- H2 ping: `1 packets transmitted, 1 received, 0% packet loss`;
- H3 ping: `1 packets transmitted, 1 received, 0% packet loss`;
- server log содержит `trusttunnel H2 ICMP mux accepted` и `trusttunnel H3 ICMP mux accepted`;
- `tcpdump` внутри namespace фиксирует ровно один `ICMP echo request` и один `ICMP echo reply` в обоих run.

### 2.11. Host-namespace `/32` + route anti-pattern для TUN `_icmp`

Диагностический retest на 2026-04-05 / `96a9d053` показал, что host-namespace wiring вида `ip addr add 192.0.2.10/32 dev xraytunh2` + `ip route add 1.1.1.1/32 dev xraytunh2` воспроизводит ICMP request storm и не должен трактоваться как нормальный product-path.

Зафиксировано:
- log bundle: `/opt/lab/xray-tt/logs/h2-tun-manualroute-trace2-20260405-164238`;
- runtime state: dirty worktree только из-за trace-only instrumentation в `proxy/tun/icmp.go`, `proxy/tun/icmp_test.go`, `proxy/tun/stack_gvisor.go`, `proxy/tun/stack_gvisor_endpoint.go`;
- observed counters: `tun_read=9762`, `ingress=9760`, `egress=0`, `tt_requests=9760`, `mux=1`.

Вывод:
- проблема относится к unsafe host-namespace routing pattern, а не к отсутствию product-level `_icmp` source path в `proxy/tun`;
- current truth для Linux `_icmp` через `proxy/tun` должна опираться на clean-HEAD netns-based validation из раздела 2.10.

### 2.12. H2 `_icmp` private-network policy

Подтверждено на 2026-04-05 после code-state `0fbc2ed5`:
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- runtime deny server config: `/opt/lab/xray-tt/configs/server_h2_icmp_private_deny.json`;
- runtime allow server config: `/opt/lab/xray-tt/configs/server_h2_icmp_private_allow.json`;
- runtime client config: `/opt/lab/xray-tt/configs/our_client_tun_to_our_server_h2_icmp_private_test.json`;
- target private IP: `192.168.1.19`;
- log bundle: `/opt/lab/xray-tt/logs/h2-icmp-private-policy-20260405-175704`.

Pass markers:
- deny-case: `ping -n -I 192.0.2.10 -c 1 -W 3 192.168.1.19` даёт `1 packets transmitted, 0 received, 100% packet loss`;
- deny-case server log содержит `trusttunnel H2 ICMP mux accepted` и `private network connections are disabled`;
- allow-case: тот же ping даёт `1 packets transmitted, 1 received, 0% packet loss`;
- allow-case server log содержит `trusttunnel H2 ICMP mux accepted`.

### 2.13. H2 `_icmp` invalid `interfaceName`

Подтверждено на 2026-04-05 после code-state `0fbc2ed5`:
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- runtime server config: `/opt/lab/xray-tt/configs/server_h2_icmp_bad_ifname.json`;
- runtime client config: `/opt/lab/xray-tt/configs/our_client_tun_to_our_server_h2_icmp_ifname_test.json`;
- target IP: `1.1.1.1`;
- log bundle: `/opt/lab/xray-tt/logs/h2-icmp-interface-name-20260405-180010`.

Pass markers:
- `ping -n -I 192.0.2.10 -c 1 -W 3 1.1.1.1` даёт `1 packets transmitted, 0 received, 100% packet loss`;
- server log содержит `trusttunnel H2 ICMP unavailable > route ip+net: no such network interface`.

### 2.14. H2 `_icmp` dedicated `requestTimeoutSecs` runtime

Подтверждено на 2026-04-05 после code-state `aa9444f3`:
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- runtime server config: `/opt/lab/xray-tt/configs/server_h2_icmp_timeout_1s.json`;
- runtime client config: `/opt/lab/xray-tt/configs/our_client_tun_to_our_server_h2_icmp_timeout_test.json`;
- egress blackhole для raw ICMP создавался через `tc qdisc add dev eth0 clsact` и `tc filter add dev eth0 egress protocol ip prio 1 flower ip_proto icmp dst_ip 1.1.1.1 action drop`;
- log bundle: `/opt/lab/xray-tt/logs/h2-icmp-timeout-1s-tc-20260405-183916`.

Pass markers:
- server log содержит `trusttunnel icmp raw send v4 dst=1.1.1.1` и примерно через одну секунду `trusttunnel icmp request timed out dst=1.1.1.1`;
- ping log даёт `1 packets transmitted, 0 received, 100% packet loss`;
- runtime подтверждает, что `settings.icmp.requestTimeoutSecs = 1` доходит именно до server-side timeout path, а не маскируется send failure.

### 2.15. H2 `_icmp` `time exceeded` runtime

Подтверждено на 2026-04-05 после code-state `aa9444f3`:
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- runtime server config: `/opt/lab/xray-tt/configs/server_h2.json`;
- runtime client config: `/opt/lab/xray-tt/configs/our_client_tun_to_our_server_h2_icmp.json`;
- raw source check выполнялся через `ip netns exec tunxrayh2 ping -n -e 0 -I 192.0.2.10 -c 1 -W 5 -t 1 1.1.1.1`;
- log bundle: `/opt/lab/xray-tt/logs/h2-icmp-timeexceeded-rawping-20260405-185429`.

Pass markers:
- `tcpdump` на `xraytunh2` фиксирует request с `ttl 1`;
- reply на той же трассе является `ICMP time exceeded in-transit`;
- server log содержит `trusttunnel icmp raw reply src=192.168.1.1 id=0 seq=1 type=11 code=0` и `trusttunnel H2 icmp reply ... type=11 code=0`;
- representable runtime parity для `time exceeded` подтверждена end-to-end.

### 2.16. Direct H2 `_icmp` `ipv6Available` probe

Подтверждено на 2026-04-05 после code-state `aa9444f3`:
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- runtime server config false-case: `/opt/lab/xray-tt/configs/server_h2_icmp_ipv6_probe_false.json`;
- runtime server config true-case: `/opt/lab/xray-tt/configs/server_h2_icmp_ipv6_probe_true.json`;
- direct probe выполнялся lab-local helper scripts `/root/icmp_h2_probe.go` и `/root/lab_icmp_ipv6_probe.sh`;
- log bundle: `/opt/lab/xray-tt/logs/h2-icmp-ipv6-available-probe-20260405-190025`.

Pass markers:
- false-case server log содержит `failed to handle trusttunnel icmp request > IPv6 ICMP is unavailable`, probe завершается `read_err=EOF`;
- true-case server log содержит `trusttunnel icmp raw send v6 dst=2001:4860:4860::8888` и `trusttunnel H2 icmp reply ... type=129 code=0`;
- probe получает `reply source=2001:4860:4860::8888 type=129 code=0 seq=1`;
- `ipv6Available` подтверждён как observable server-side `_icmp` runtime setting.

### 2.17. Clean-HEAD полный UDP interop matrix

Подтверждено на 2026-04-05 / `6fcb3a28`:
- worktree: clean на lab (`git status --short` пустой);
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- binary sha256: `5b8ea165ba62eaecdb992ae10803fb1d3b1e11fd1615fd5bf42fcee439f46673`;
- official client binary: `/opt/lab/xray-tt/bin/trusttunnel_client/trusttunnel_client`;
- official endpoint config: `/opt/lab/xray-tt/official-endpoint-lab/vpn.toml`;
- H2 official-client server config: `/opt/lab/xray-tt/configs/server_h2_udp_official_cert.json`;
- H2 reopen server config: `/opt/lab/xray-tt/configs/server_h2_udp_official_cert_timeout_1.json`;
- H3 official-client server config: `/opt/lab/xray-tt/configs/server_h3_udp.json`;
- H3 reopen server config: `/opt/lab/xray-tt/configs/server_h3_udp_timeout_1.json`;
- official client configs: `/opt/lab/xray-tt/configs/official_client_to_our_server_h2_udp.toml`, `/opt/lab/xray-tt/configs/official_client_to_our_server_h3_udp.toml`;
- our client configs: `/opt/lab/xray-tt/configs/our_client_udp_to_official_endpoint_h2.json`, `/opt/lab/xray-tt/configs/our_client_udp_to_official_endpoint_h3.json`, `/opt/lab/xray-tt/configs/our_client_udp_to_official_endpoint_h2_ipv6.json`, `/opt/lab/xray-tt/configs/our_client_udp_to_official_endpoint_h3_ipv6.json`;
- repo-local config sources: `testing/trusttunnel/server_h2_udp_official_cert.json`, `testing/trusttunnel/server_h3_udp.json`, `testing/trusttunnel/official_client_to_our_server_h2_udp.toml`, `testing/trusttunnel/official_client_to_our_server_h3_udp.toml`, `testing/trusttunnel/our_client_udp_to_official_endpoint_h2.json`, `testing/trusttunnel/our_client_udp_to_official_endpoint_h3.json`;
- log bundle: `/opt/lab/xray-tt/logs/udp-matrix-20260405-222820`.

Pass markers:
- official client → our server H2: `dig-v4-cf.txt`, `dig-v4-google.txt` и `dig-v6-cf.txt` дают `answers=2`, server log содержит `trusttunnel H2 UDP mux accepted`;
- official client → our server H3: те же probes проходят на H3, server log содержит `trusttunnel H3 UDP mux accepted`;
- H2 reopen-case на timeout-1 config проходит: `dig-reopen-v4.txt` даёт `answers=2`;
- H3 reopen-case на timeout-1 config проходит: `dig-reopen-v4.txt` даёт `answers=2`;
- our client → official endpoint H2 IPv4/IPv6 проходит: локальные probes на `127.0.0.1:5304` и `127.0.0.1:5306` дают `answers=2`, а client log больше не содержит `trusttunnel CONNECT failed with status 502`;
- our client → official endpoint H3 IPv4/IPv6 проходит: локальные probes на `127.0.0.1:5305` и `127.0.0.1:5307` дают `answers=2`;
- previous H2 outbound interop breakage закрыта practically significant fix: UDP CONNECT authority выровнен с official protocol на `_udp2`, при этом server-side backward-compat на `_udp2:0` сохранён.

### 2.18. Observable timeout surface подтверждён downstream-observable retest

Подтверждено на 2026-04-06 / `57d8d5e1`:
- worktree: clean;
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- binary sha256: `465ab69d760ce440e81431b9dfbb246bdba929e92a359befc59dbc86b59c7662`;
- base config dir: `/opt/lab/xray-tt/configs/timeout-retest-20260405-210405`;
- client config: `/opt/lab/xray-tt/src/xray-core-trusttunnel/testing/trusttunnel/our_client_to_our_server.json`;
- udp client config: `/opt/lab/xray-tt/src/xray-core-trusttunnel/testing/trusttunnel/our_client_udp_to_our_server_h2.json`;
- server cert fingerprint: `F1:22:FD:22:AF:B0:C9:2B:03:05:A9:55:9B:F7:5E:8F:80:43:00:B9:7C:22:34:EA:6B:34:F9:24:7A:AD:64:9C`;
- log bundles: `/opt/lab/xray-tt/logs/timeout-observability-20260406-010625`, `/opt/lab/xray-tt/logs/timeout-listener-tls-20260406-010206`, `/opt/lab/xray-tt/logs/h2-client-listener-raw-20260406-010548`, плюс сохранённый UDP reopen bundle `/opt/lab/xray-tt/logs/timeout-retest-20260405-210405`.

Подтверждено:
- `udp_connections_timeout_secs` сохраняет downstream-observable reopen marker: `h2_udp_timeout_dig1.txt` и `h2_udp_timeout_dig2.txt` оба успешны, а `h2_udp_timeout_reopen_count.txt` содержит `2`;
- `tls_handshake_timeout_secs = 3` downstream-observable на probe `h2-tls-handshake-probe.txt`: `first_read_bytes=0`, `closed_after=3.00`; server log показывает, что silent peer больше не зависает в pre-handshake `client_random` extraction path;
- `client_listener_timeout_secs = 3` подтверждён общим probe `h2-client-listener-probe.txt`: `alpn=h2`, `initial_bytes=45`, `closed_after=4.00`; raw H2 trace `probe.txt` из bundle `/opt/lab/xray-tt/logs/h2-client-listener-raw-20260406-010548` дополнительно показывает GOAWAY frame `0000080700000000000000000000000000` через `tail_after=3.00`, а финальный transport-close наступает примерно через секунду;
- `connection_establishment_timeout_secs = 4` downstream-observable на probe `h2-connect-establish-probe.txt`: `elapsed_ms=4064`, `returncode=52`, `Empty reply from server`; server log фиксирует `trusttunnel H2 CONNECT accepted` и последующий fail примерно через четыре секунды;
- `tcp_connections_timeout_secs = 3` downstream-observable на probe `h2-tcp-idle-probe.txt`: `elapsed_ms=3026`, `returncode=52`, `Empty reply from server`; server log фиксирует `trusttunnel H2 CONNECT accepted for tcp:127.0.0.1:18080` в `01:06:41.504810` и close в `01:06:44.507383`.

Вывод:
- timeout block вне `_icmp` на текущем состоянии закрыт;
- downstream-observable markers теперь есть для всех пяти timeout fields;
- practically significant bug заключался в том, что pre-handshake ClientHello extraction раньше обходил `tls_handshake_timeout_secs`; он закрыт transport-fix на `57d8d5e1`.

### 2.19. Clean-HEAD auth и stats sanity-check

Подтверждено на 2026-04-05 / `6fcb3a28`:
- worktree: clean на lab (`git status --short` пустой);
- binary: `/opt/lab/xray-tt/tmp/xray-tt-current`;
- binary sha256: `d1683fab2c607826a7410cd9b59402f6d08c22344a0394e073e7b093c65489ee`;
- official client binary: `/opt/lab/xray-tt/bin/trusttunnel_client/trusttunnel_client`;
- H2 auth server config: `/opt/lab/xray-tt/configs/server_h2_official_cert.json`;
- H2 auth-fail client config: `/opt/lab/xray-tt/configs/official_client_to_our_server_h2_check_authfail.toml`;
- H2 auth-success client config: `/opt/lab/xray-tt/configs/official_client_to_our_server_h2_check_ok.toml`;
- H2 stats server config: `/opt/lab/xray-tt/configs/server_h2_tcp_stats.json`;
- H2 stats client config: `/opt/lab/xray-tt/src/xray-core-trusttunnel/testing/trusttunnel/our_client_to_our_server.json`;
- H3 UDP stats server config: `/opt/lab/xray-tt/configs/server_h3_udp_stats_iso.json`;
- H3 UDP stats client config: runtime-generated `/opt/lab/xray-tt/logs/auth-stats-sanity-20260405-231514/our_client_udp_to_our_server_h3_stats_iso_lan.json` на базе `/opt/lab/xray-tt/configs/our_client_udp_to_our_server_h3_stats_iso.json`;
- API ports: H2 stats `127.0.0.1:10085`, H3 UDP stats `127.0.0.1:10096`;
- log bundle: `/opt/lab/xray-tt/logs/auth-stats-sanity-20260405-231514`.

Pass markers:
- H2 auth-fail path на official client остаётся observable как `407`, при этом snapshot `h2-auth-server-after-authfail.log` не содержит `trusttunnel H2 health-check accepted` и не воспроизводит legacy `_check` сигнатуры;
- без перезапуска H2 server subsequent official-client session с корректным auth проходит: `h2-auth-server.log` содержит `trusttunnel H2 health-check accepted` и `trusttunnel H2 CONNECT accepted for tcp:example.com:443`, а `h2-auth-success-client.log` содержит `Certificate verified successfully`;
- H2 TCP stats sanity-check против локального HTTP target `127.0.0.1:18080` даёт ненулевые `inbound>>>...`, `outbound>>>...` и `user>>>u1>>>traffic>>>*` counters через API `127.0.0.1:10085`;
- H3 UDP stats sanity-check через non-loopback server address `192.168.1.19` даёт ненулевые `user>>>u1>>>traffic>>>*` counters, `api statsonline --email u1` возвращает `value = 1`, `api statsonlineiplist --email u1` возвращает IP `192.168.1.19`, а `api statsgetallonlineusers` возвращает `user>>>u1>>>online`;
- `user>>>...>>>online` подтверждён как отдельный `onlineMap`, а не как counter: для него нужно использовать `statsonline` / `statsonlineiplist` / `statsgetallonlineusers`, а не `statsquery`.

Практически значимое ограничение:
- `app/stats/online_map.go` намеренно игнорирует `127.0.0.1` и `[::1]`, поэтому localhost-only lab configs пригодны для traffic counters, но не для подтверждения ненулевого `onlineMap`; для online-state нужен non-loopback source IP.

Отдельное внешнее ограничение локального test-run:
- полный `go test ./infra/conf ./app/router` по-прежнему цепляется за отсутствие `geoip.dat`; это исторический fixture-gap текущего окружения, а не регрессия `Network_ICMP`.

### 2.20. Live-traffic H2/TCP + REALITY против remote server

Preflight:
- origin repo HEAD: `c6ff745b579eb70e05c32375d5d10574b95f82cb`;
- lab repo HEAD: `c6ff745b579eb70e05c32375d5d10574b95f82cb`, worktree clean;
- remote repo HEAD: `55e89c26aedddc2bb0679648057427ea8ce90786`; current smoke не опирается на этот worktree для build, потому что remote host остаётся без Go;
- lab binary: `/opt/lab/xray-tt/tmp/xray-tt-regress-linux`;
- remote runtime binary: `/opt/trusttunnel-dev/tmp/xray-tt-regress-linux`;
- lab/remote binary sha256: `b68a868c9b3b9f2fcbc4aa1d8a3680999461fed72a554f82c485d132d3a4040c`;
- lab client config: `/opt/lab/xray-tt/configs/our_client_to_remote_server_h2_reality.json`;
- remote server config: `/opt/trusttunnel-dev/configs/server_h2_reality_remote.json`;
- REALITY trust inputs: `serverName = www.google.com`, `publicKey = E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM`, `shortId = 0123456789abcdef`, `fingerprint = chrome`;
- lab bundle: `/opt/lab/xray-tt/logs/workerfix-h2-reality-lab-20260406-153646`;
- remote bundle: `/opt/trusttunnel-dev/logs/workerfix-h2-reality-remote-20260406-153646`.

Подтверждено:
- lab client log содержит `trusttunnel transport=http2 requested with REALITY and empty negotiated ALPN; using HTTP/2 preface path`;
- remote server log содержит `trusttunnel H2 CONNECT accepted for tcp:www.cloudflare.com:443` и `trusttunnel H2 CONNECT accepted for tcp:api.ipify.org:443`;
- downstream probe через SOCKS даёт `ip=37.252.0.130`, `http=http/2` и `{"ip":"37.252.0.130"}`.

Практическая граница:
- runtime server config остаётся lab-only artifact, потому что содержит REALITY `privateKey` и не должен попадать в tracked tree.

### 2.21. Live-traffic H2/UDP + REALITY против remote server

Preflight:
- origin repo HEAD: `c6ff745b579eb70e05c32375d5d10574b95f82cb`;
- lab repo HEAD: `c6ff745b579eb70e05c32375d5d10574b95f82cb`, worktree clean;
- remote repo HEAD: `55e89c26aedddc2bb0679648057427ea8ce90786`; current smoke не использует remote worktree как build source;
- lab binary: `/opt/lab/xray-tt/tmp/xray-tt-regress-linux`;
- remote runtime binary: `/opt/trusttunnel-dev/tmp/xray-tt-regress-linux`;
- lab/remote binary sha256: `b68a868c9b3b9f2fcbc4aa1d8a3680999461fed72a554f82c485d132d3a4040c`;
- lab client config: `/opt/lab/xray-tt/configs/our_client_udp_to_remote_server_h2_reality.json`;
- remote server config: `/opt/trusttunnel-dev/configs/server_h2_udp_reality_remote.json`;
- REALITY trust inputs: `serverName = www.google.com`, `publicKey = E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM`, `shortId = 0123456789abcdef`, `fingerprint = chrome`;
- lab bundle: `/opt/lab/xray-tt/logs/workerfix-h2-reality-udp-lab-20260406-153758`;
- remote bundle: `/opt/trusttunnel-dev/logs/workerfix-h2-reality-udp-remote-20260406-153758`.

Подтверждено:
- remote server log содержит `trusttunnel H2 UDP mux accepted`, `dispatch request to: udp:1.1.1.1:53`, `proxy/freedom: connection opened to udp:1.1.1.1:53`;
- downstream DNS probe для `cloudflare.com` возвращает `104.16.132.229` и `104.16.133.229`.

Практическая граница:
- runtime UDP server config тоже остаётся lab-only artifact, потому что содержит REALITY `privateKey`.

### 2.22. Controlled load-test и CPU verdict для H2/REALITY

Preflight:
- origin repo HEAD: `ae621d2444af095ae15a566c1bff5714f1c728b6`;
- lab repo HEAD: `ae621d2444af095ae15a566c1bff5714f1c728b6`, worktree clean;
- remote repo HEAD: `55e89c26aedddc2bb0679648057427ea8ce90786`, top commit message `trusttunnel: prefer h2 path for reality without alpn`, worktree clean;
- lab binary: `/opt/lab/xray-tt/tmp/xray-tt-reality-linux`;
- remote binary: `/opt/trusttunnel-dev/tmp/xray-tt-reality-linux`;
- lab client config: `/opt/lab/xray-tt/configs/our_client_to_remote_server_h2_reality_iperf_tcp.json`;
- remote TrustTunnel server config: `/opt/trusttunnel-dev/configs/server_h2_reality_remote.json`;
- controlled target: remote `iperf3 -s -B 127.0.0.1 -p 5201 --one-off`;
- lab bundle: `/opt/lab/xray-tt/logs/load-h2-reality-20260406-111027`;
- remote bundle: `/opt/trusttunnel-dev/logs/load-h2-reality-20260406-111027`.

Подтверждено:
- upload baseline `iperf3 -c 127.0.0.1 -p 15201 -t 20 -P 4 -J`: `sum_sent.bits_per_second = 177931398.09`, `sum_received.bits_per_second = 166071992.75`, retransmits `47`, lab CPU avg/max `65.57 / 94.0`, remote CPU avg/max `46.91 / 73.0`;
- reverse baseline `iperf3 -c 127.0.0.1 -p 15201 -t 20 -P 4 -R -J`: `sum_sent.bits_per_second = 100365886.11`, `sum_received.bits_per_second = 87760712.30`, retransmits `94`, lab CPU avg/max `47.05 / 69.0`, remote CPU avg/max `14.62 / 21.0`;
- upload stress `iperf3 -c 127.0.0.1 -p 15201 -t 20 -P 8 -J`: `sum_sent.bits_per_second = 265157427.70`, `sum_received.bits_per_second = 238399901.19`, retransmits `375`, lab CPU avg/max `92.86 / 117.0`, remote CPU avg/max `69.73 / 87.0`;
- reverse stress `iperf3 -c 127.0.0.1 -p 15201 -t 20 -P 8 -R -J`: `sum_sent.bits_per_second = 177187608.90`, `sum_received.bits_per_second = 148312584.30`, retransmits `145`, lab CPU avg/max `89.95 / 119.8`, remote CPU avg/max `23.4 / 39.0`.

Практический вывод:
- H2/REALITY path переносит большой TCP traffic без функционального срыва;
- lab-side Xray client является более горячей стороной, чем remote server;
- process CPU выше `100%` в этих измерениях означает использование более чем одного ядра.

### 2.23. H3 + REALITY explicit unsupported verdict

Preflight:
- origin repo HEAD: `55c97b163ff80f9d265bf453291c734c65476412`, worktree clean;
- lab repo HEAD: `55c97b163ff80f9d265bf453291c734c65476412`, worktree clean;
- lab binary: `/opt/lab/xray-tt/tmp/xray-tt-current-h3r`;
- lab package check: `go test ./proxy/trusttunnel/... ./transport/internet/tcp ./app/proxyman/outbound -count=1`;
- generated lab-only server configs: `/opt/lab/xray-tt/configs/server_h3_reality_unsupported.json`, `/opt/lab/xray-tt/configs/server_h2h3_reality_unsupported.json`;
- generated lab-only client config: `/opt/lab/xray-tt/configs/our_client_to_remote_server_h3_reality_unsupported.json`;
- server reject bundle: `/opt/lab/xray-tt/logs/h3-reality-server-reject-20260406-161144`;
- client reject bundle: `/opt/lab/xray-tt/logs/h3-reality-client-reject-20260406-161144`.

Подтверждено:
- package check на lab проходит: `proxy/trusttunnel`, `transport/internet/tcp`, `app/proxyman/outbound`;
- pure server config с `transports = ["http3"]` и `security = "reality"` завершается `exit=255` и логирует `transport/internet/tcp: trusttunnel http3 with REALITY is unsupported: current Xray REALITY transport is TCP-only`;
- mixed server config с `transports = ["http2","http3"]` и `security = "reality"` тоже завершается `exit=255` с тем же marker'ом, то есть current runtime не оставляет частично рабочий H2 path при явном H3+REALITY request;
- client config с `settings.transport = "http3"` и `streamSettings.security = "reality"` даёт failed downstream SOCKS probe (`curl exit=35`) и client log `proxy/trusttunnel: trusttunnel http3 with REALITY is unsupported: current Xray REALITY transport is TCP-only`.

Технический вывод:
- это больше не “непроверенный H3 REALITY path”, а explicit unsupported combination;
- future support потребует нового QUIC-capable REALITY transport/security layer в Xray core, а не локального TrustTunnel patch.

### 2.24. Client-Side `hasIpv6` / `antiDpi` / `postQuantumGroupEnabled` runtime gates

Preflight:
- origin repo HEAD: `effe19274b23e10c46a98833c9880fec23c8dca8`, tracked worktree clean;
- lab repo HEAD: `effe19274b23e10c46a98833c9880fec23c8dca8`, tracked worktree clean;
- local compile-only sweep: `GOFLAGS=-buildvcs=false go test -run '^$' ./...`;
- lab binary: `/opt/lab/xray-tt/tmp/xray-tt-client-parity-linux`;
- remote runtime binary: `/opt/trusttunnel-dev/tmp/xray-tt-regress-linux`;
- lab runtime configs: `/opt/lab/xray-tt/configs/our_client_to_remote_server_h2_reality_baseline.json`, `/opt/lab/xray-tt/configs/our_client_to_remote_server_h2_reality_hasipv6_false.json`, `/opt/lab/xray-tt/configs/our_client_to_remote_server_h2_reality_antidpi_true.json`;
- lab bundle: `/opt/lab/xray-tt/logs/client-parity-20260406-171758`;
- remote server bundle: `/opt/trusttunnel-dev/logs/client-parity-remote-20260406-141747`.

Подтверждено:
- baseline config на `127.0.0.1:10831` проходит explicit IPv4 literal probe `https://1.1.1.1/cdn-cgi/trace` с `curl exit=0`; downstream trace содержит `ip=37.252.0.130`, `http=http/2`, `kex=X25519MLKEM768`, а client log сохраняет REALITY marker `trusttunnel transport=http2 requested with REALITY and empty negotiated ALPN; using HTTP/2 preface path`;
- remote server log bundle фиксирует для baseline `trusttunnel H2 CONNECT accepted for tcp:1.1.1.1:443` и `proxy/freedom: connection opened to tcp:1.1.1.1:443`;
- config с `hasIpv6=false` на `127.0.0.1:10832` сохраняет working path для explicit IPv4 literal target: `curl exit=0`, trace снова содержит `ip=37.252.0.130`, `http=http/2`, `kex=X25519MLKEM768`, а remote server log повторно фиксирует `trusttunnel H2 CONNECT accepted for tcp:1.1.1.1:443`;
- тот же config с `hasIpv6=false` режет explicit IPv6 literal target `https://[2606:4700:4700::1111]/cdn-cgi/trace` с `curl exit=35` и client log marker'ом `trusttunnel IPv6 target is disabled by hasIpv6=false`;
- historical first parity retest на `effe1927` ещё фиксировал explicit reject `antiDpi=true` для REALITY-path; этот verdict больше не считать актуальным после code-state `7376ab64` и dedicated live bundle `/opt/lab/xray-tt/logs/antidpi-live-20260409-045510`.

Технический вывод:
- `hasIpv6` больше не является чисто декларативным полем: current runtime реально режет явные IPv6 literal targets, не ломает explicit IPv4 literal path и на clean-HEAD matrix дополнительно режет domain targets без `targetStrategy useipv4/forceipv4`;
- `antiDpi` больше не остаётся silent no-op: historical explicit reject закрыт, а current runtime после `7376ab64` реально работает на `HTTP/2 over TLS` и `HTTP/2 over REALITY`; explicit `http3` остаётся unsupported combination.
- `postQuantumGroupEnabled` является реальной guarded runtime-функцией на поддержанных H2/TLS, H2/REALITY и H3/TLS path.

### 2.25. Clean-HEAD full live functional/load matrix

Preflight:
- origin repo HEAD: `4bfd8ac941c9fe8ac7664bc24a3612678e416d2a`, tracked worktree clean; локально оставались только untracked `.gocache/`, `.gopath/`, `tmp/`;
- lab binary: `/opt/lab/xray-tt/tmp/xray-tt-current-live`;
- remote binary: `/opt/trusttunnel-dev/tmp/xray-tt-current-live`;
- binary sha256: `82b623b5bf0f76e0dbc0f31dc90c4dfe233f1ea3b191e3e3a27349bf309d5cf2`;
- remote server profiles: `/opt/trusttunnel-dev/configs/server_h2_tls_udp_remote.json`, `/opt/trusttunnel-dev/configs/server_h2_udp_reality_remote.json`, `/opt/trusttunnel-dev/configs/server_h3_tls_udp_remote.json`;
- lab client configs root: `/opt/lab/xray-tt/configs-live/`;
- functional bundle root: lab `/opt/lab/xray-tt/logs/full-live-20260407-153034`, remote `/opt/trusttunnel-dev/logs/full-live-20260407-153034`;
- authoritative load bundle root: lab `/opt/lab/xray-tt/logs/full-live-20260407-140912`, remote `/opt/trusttunnel-dev/logs/full-live-20260407-140912`.
- representative current-head H2/TLS load smoke for touched non-HTTP3 TLS path: lab `/opt/lab/xray-tt/logs/full-live-20260407-153909-h2_tls_auto_load_tcp`, remote `/opt/trusttunnel-dev/logs/full-live-20260407-153909-h2_tls_auto_load_tcp`;
- remote runtime verification использовала прямой binary sync по SHA через `pscp` в `/opt/trusttunnel-dev/tmp/xray-tt-current-live`; dirty remote git tree сознательно не использовалось как источник истины для этого rerun.

Functional verdict:
- harness проходит `15/15` cases без fail-fast и без незапланированных negative-results;
- H2 TLS TCP cases `h2_tls_auto`, `h2_tls_pq_on`, `h2_tls_pq_off` используют lab configs `/opt/lab/xray-tt/configs-live/h2_tls_*_socks.json`, server profile `/opt/trusttunnel-dev/configs/server_h2_tls_udp_remote.json`, client marker `transport/internet/tcp: dialing TCP to tcp:37.252.0.130:9443`, server marker `trusttunnel H2 CONNECT accepted`;
- H2 REALITY TCP cases `h2_reality_auto`, `h2_reality_pq_on`, `h2_reality_pq_off` используют lab configs `/opt/lab/xray-tt/configs-live/h2_reality_*_socks.json`, server profile `/opt/trusttunnel-dev/configs/server_h2_udp_reality_remote.json`, client marker `trusttunnel transport=http2 requested with REALITY and empty negotiated ALPN; using HTTP/2 preface path`, server marker `trusttunnel H2 CONNECT accepted`;
- H3 TLS TCP cases `h3_tls_auto`, `h3_tls_pq_on`, `h3_tls_pq_off` используют lab configs `/opt/lab/xray-tt/configs-live/h3_tls_*_socks.json`, server profile `/opt/trusttunnel-dev/configs/server_h3_tls_udp_remote.json`, client marker `accepted tcp:www.cloudflare.com:443`, server marker `trusttunnel H3 CONNECT accepted`;
- H2 TLS / H2 REALITY / H3 TLS UDP DNS cases используют lab configs `/opt/lab/xray-tt/configs-live/h2_tls_udp_dns.json`, `/opt/lab/xray-tt/configs-live/h2_reality_udp_dns.json`, `/opt/lab/xray-tt/configs-live/h3_tls_udp_dns.json`, client marker `accepted udp:1.1.1.1:53`, server markers `trusttunnel H2 UDP mux accepted` или `trusttunnel H3 UDP mux accepted`;
- negative-case `h2_reality_hasipv6_domain_fail` через `/opt/lab/xray-tt/configs-live/h2_reality_hasipv6_domain_fail.json` ожидаемо возвращает marker `trusttunnel hasIpv6=false requires outbound targetStrategy useipv4/forceipv4 for domain targets`;
- allow-case `h2_reality_hasipv6_forceipv4` через `/opt/lab/xray-tt/configs-live/h2_reality_hasipv6_forceipv4.json` снова проходит working H2/REALITY path с client marker `resolved to:` и server marker `trusttunnel H2 CONNECT accepted`;
- negative-case `h3_reality_unsupported` через `/opt/lab/xray-tt/configs-live/h3_reality_unsupported_socks.json` ожидаемо возвращает marker `trusttunnel http3 with REALITY is unsupported: current Xray REALITY transport is TCP-only`;
- downstream functional probes в success-cases дают live internet path: TCP trace содержит `ip=37.252.0.130`, `http=http/2` или рабочий H3 trace-path, а DNS cases возвращают живой answer для `1.1.1.1:53`.

Load verdict:
- authoritative full-matrix harness проходит `12/12` load cases без fail-fast на clean rerun `full-live-20260407-140912`;
- `h2_tls_auto_load_tcp`: `252.39 Mbit/s`, lab CPU avg/max `33.19 / 55`, remote CPU avg/max `54.05 / 101`;
- `h2_tls_pq_on_load_tcp`: `336.39 Mbit/s`, lab CPU avg/max `39.82 / 81`, remote CPU avg/max `60.18 / 106`;
- `h2_tls_pq_off_load_tcp`: `326.22 Mbit/s`, lab CPU avg/max `40.10 / 89`, remote CPU avg/max `61.05 / 109`;
- `h2_reality_auto_load_tcp`: `264.72 Mbit/s`, lab CPU avg/max `30.43 / 68`, remote CPU avg/max `50.05 / 99`;
- `h2_reality_pq_on_load_tcp`: `310.13 Mbit/s`, lab CPU avg/max `35.47 / 85`, remote CPU avg/max `56.71 / 108`;
- `h2_reality_pq_off_load_tcp`: `373.45 Mbit/s`, lab CPU avg/max `45.62 / 99`, remote CPU avg/max `64.38 / 112`;
- `h3_tls_auto_load_tcp`: `191.44 Mbit/s`, lab CPU avg/max `77.33 / 162`, remote CPU avg/max `68.50 / 116`;
- `h3_tls_pq_on_load_tcp`: `176.42 Mbit/s`, lab CPU avg/max `78.85 / 155`, remote CPU avg/max `64.90 / 110`;
- `h3_tls_pq_off_load_tcp`: `219.23 Mbit/s`, lab CPU avg/max `91.15 / 161`, remote CPU avg/max `72.75 / 113`;
- `h2_tls_udp_load_udp`: `105.82 Mbit/s`, lab CPU avg/max `96.21 / 173`, remote CPU avg/max `45.15 / 99`;
- `h2_reality_udp_load_udp`: `108.50 Mbit/s`, lab CPU avg/max `98.12 / 190`, remote CPU avg/max `43.19 / 107`;
- `h3_tls_udp_load_udp`: `85.85 Mbit/s`, lab CPU avg/max `107.27 / 199`, remote CPU avg/max `45.00 / 104`.
- representative current-head smoke для непосредственно затронутого non-HTTP3 TLS path `h2_tls_auto_load_tcp` проходит отдельно через bundle `full-live-20260407-153909-h2_tls_auto_load_tcp` с `61.97 Mbit/s`, lab CPU avg/max `9.14 / 21`, remote CPU avg/max `23.23 / 47`; этот smoke подтверждает отсутствие functional/runtime regressions на `4bfd8ac9`, но не заменяет authoritative 12-case load rerun `140912`.

Технический вывод:
- intermediate full-load attempt under `full-live-20260407-134320` зафиксировал lab-local harness read race на `remote pidstat` для `h2_reality_pq_on_load_tcp`; это не был TrustTunnel runtime-fail, и авторитетным load verdict считать clean rerun `140912` после фикса ожидания/чтения `pidstat`;
- current-head rerun `153034` подтверждает, что patch `4bfd8ac9` не ломает live functional matrix, а direct SHA-synced binary на remote host даёт тот же validated traffic path без зависимости от состояния удалённого git tree;
- fastest TCP case текущего clean-HEAD matrix-run — `h2_reality_pq_off_load_tcp`;
- H3 TLS path функционально рабочий и load-stable, но client-side CPU заметно выше H2;
- UDP load figures относятся к flood-style `_udp2` stress-path и не должны трактоваться как функциональный DNS/interoperability fail.

Для воспроизводимости outbound `clientRandom` retest зафиксированы:
- server H2 rules: `testing/trusttunnel/server_h2_rules.json`;
- server H3 rules: `testing/trusttunnel/server_h3_rules.json`;
- client H2 allow: `testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json`;
- client H2 deny: `testing/trusttunnel/our_client_to_our_server_h2_clientrandom_deny.json`;
- client H3 allow: `testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json`;
- client H3 deny: `testing/trusttunnel/our_client_to_our_server_h3_clientrandom_deny.json`.

Для воспроизводимости подтверждённого H2 `_check` retest зафиксированы:
- server success/auth-fail: `testing/trusttunnel/server_h2_official_cert.json`, который в lab копируется в `/opt/lab/xray-tt/configs/server_h2_official_cert.json`
- server rule-gated allow/deny: `testing/trusttunnel/server_h2_rules.json`
- official client success: `testing/trusttunnel/official_client_to_our_server_h2_check_ok.toml`
- official client auth-fail: `testing/trusttunnel/official_client_to_our_server_h2_check_authfail.toml`
- official client rule-allow: `testing/trusttunnel/official_client_rules_allow.toml`
- official client rule-deny: `testing/trusttunnel/official_client_rules_deny.toml`

Для воспроизводимости подтверждённого H2 `_icmp` retest зафиксированы:
- server: `testing/trusttunnel/server_h2_official_cert.json`, который в lab копируется в `/opt/lab/xray-tt/configs/server_h2_official_cert.json`
- official client template: `testing/trusttunnel/official_client_to_our_server_h2_icmp.toml`, который в clean-head retest использовался как runtime-copy `/opt/lab/xray-tt/configs/official_client_to_our_server_h2_icmp_test.toml`

Для воспроизводимости подтверждённого H3 `_icmp` retest зафиксированы:
- server: `testing/trusttunnel/server_h3.json`, который в lab копируется в `/opt/lab/xray-tt/configs/server_h3.json`
- official client template: `testing/trusttunnel/official_client_to_our_server_h3_icmp.toml`, который в clean-head retest использовался как runtime-copy `/opt/lab/xray-tt/configs/official_client_to_our_server_h3_icmp_test.toml`

### 5.1. Debian lab runbook для H2 `_check`

Предпосылки:
- рабочее дерево находится в `/opt/lab/xray-tt/src/xray-core-trusttunnel`;
- тестируемый Xray binary собирается в `/opt/lab/xray-tt/tmp/xray-tt-current`;
- official CLI client доступен как `/opt/lab/xray-tt/bin/trusttunnel_client/trusttunnel_client`;
- runtime-конфиги кладутся в `/opt/lab/xray-tt/configs`;
- логи пишутся в `/opt/lab/xray-tt/logs`.

Подготовка и preflight:

```bash
export LAB_ROOT=/opt/lab/xray-tt
export XRAY_REPO=$LAB_ROOT/src/xray-core-trusttunnel
export XRAY_BIN=$LAB_ROOT/tmp/xray-tt-current
export OFFICIAL_CLIENT_BIN=$LAB_ROOT/bin/trusttunnel_client/trusttunnel_client
export CONFIG_DIR=$LAB_ROOT/configs
export LOG_DIR=$LAB_ROOT/logs

cd "$XRAY_REPO"

git rev-parse HEAD
git status --short
go build -o "$XRAY_BIN" ./main

install -m 0644 testing/trusttunnel/server_h2_rules.json \
  "$CONFIG_DIR/server_h2_rules.json"
install -m 0644 testing/trusttunnel/server_h2_official_cert.json \
  "$CONFIG_DIR/server_h2_official_cert.json"
install -m 0644 testing/trusttunnel/official_client_to_our_server_h2_check_ok.toml \
  "$CONFIG_DIR/official_client_to_our_server_h2_check_ok.toml"
install -m 0644 testing/trusttunnel/official_client_to_our_server_h2_check_authfail.toml \
  "$CONFIG_DIR/official_client_to_our_server_h2_check_authfail.toml"
install -m 0644 testing/trusttunnel/official_client_rules_allow.toml \
  "$CONFIG_DIR/official_client_rules_allow.toml"
install -m 0644 testing/trusttunnel/official_client_rules_deny.toml \
  "$CONFIG_DIR/official_client_rules_deny.toml"

sha256sum "$XRAY_BIN"
ls -l \
  "$CONFIG_DIR/server_h2_official_cert.json" \
  "$CONFIG_DIR/server_h2_rules.json" \
  "$CONFIG_DIR/official_client_to_our_server_h2_check_ok.toml" \
  "$CONFIG_DIR/official_client_to_our_server_h2_check_authfail.toml" \
  "$CONFIG_DIR/official_client_rules_allow.toml" \
  "$CONFIG_DIR/official_client_rules_deny.toml"
```

#### 5.1.1. Success case: `_check` -> `200`

```bash
export SERVER_LOG=$LOG_DIR/h2-check-server-ok.log
export CLIENT_LOG=$LOG_DIR/h2-check-client-ok.log

pkill -f "$XRAY_BIN" || true
pkill -f "$OFFICIAL_CLIENT_BIN" || true

: >"$SERVER_LOG"
: >"$CLIENT_LOG"

"$XRAY_BIN" run -c "$CONFIG_DIR/server_h2_official_cert.json" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 2

"$OFFICIAL_CLIENT_BIN" -c "$CONFIG_DIR/official_client_to_our_server_h2_check_ok.toml" >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
sleep 5

ss -ltnp | grep -E '(:9443|:11081)\b'
curl --socks5-hostname 127.0.0.1:11081 https://example.com/ -I --max-time 15

grep -n 'trusttunnel H2 health-check accepted' "$SERVER_LOG"
grep -n 'trusttunnel H2 CONNECT accepted for tcp:example.com:443' "$SERVER_LOG"
if grep -nE 'failed to open connection to tcp:_check:443|lookup _check: no such host' "$SERVER_LOG"; then
  false
fi

kill "$CLIENT_PID" "$SERVER_PID"
wait "$CLIENT_PID" "$SERVER_PID" 2>/dev/null || true
```

Ожидание:
- SOCKS listener official client поднимается на `127.0.0.1:11081`;
- `_check` отвечает `200`, что проявляется логом `trusttunnel H2 health-check accepted`;
- последующий CONNECT до `https://example.com/` проходит;
- старые `_check`-сигнатуры отсутствуют.

#### 5.1.2. Auth-fail case: `_check` -> `407`

```bash
export SERVER_LOG=$LOG_DIR/h2-check-server-authfail.log
export CLIENT_LOG=$LOG_DIR/h2-check-client-authfail.log

pkill -f "$XRAY_BIN" || true
pkill -f "$OFFICIAL_CLIENT_BIN" || true

: >"$SERVER_LOG"
: >"$CLIENT_LOG"

"$XRAY_BIN" run -c "$CONFIG_DIR/server_h2_official_cert.json" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 2

"$OFFICIAL_CLIENT_BIN" -c "$CONFIG_DIR/official_client_to_our_server_h2_check_authfail.toml" >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
sleep 5

ss -ltnp | grep -E '(:9443|:11082)\b'
curl --socks5-hostname 127.0.0.1:11082 https://example.com/ -I --max-time 15 && false

grep -nEi '407|authentication failed|proxy authentication' "$CLIENT_LOG"
if grep -n 'trusttunnel H2 health-check accepted' "$SERVER_LOG"; then
  false
fi
if grep -nE 'failed to open connection to tcp:_check:443|lookup _check: no such host' "$SERVER_LOG"; then
  false
fi

kill "$CLIENT_PID" "$SERVER_PID"
wait "$CLIENT_PID" "$SERVER_PID" 2>/dev/null || true
```

Ожидание:
- `authFailureStatusCode=407` остаётся observable на стороне official client;
- success-log для H2 health-check не появляется;
- старые `_check`-сигнатуры отсутствуют.

#### 5.1.3. Rule-deny case: `_check` -> `403`

```bash
export SERVER_LOG=$LOG_DIR/h2-check-server-deny.log
export CLIENT_LOG=$LOG_DIR/h2-check-client-deny.log

pkill -f "$XRAY_BIN" || true
pkill -f "$OFFICIAL_CLIENT_BIN" || true

: >"$SERVER_LOG"
: >"$CLIENT_LOG"

"$XRAY_BIN" run -c "$CONFIG_DIR/server_h2_rules.json" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 2

"$OFFICIAL_CLIENT_BIN" -c "$CONFIG_DIR/official_client_rules_deny.toml" >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
sleep 5

ss -ltnp | grep -E '(:9443|:11080)\b'
curl --socks5-hostname 127.0.0.1:11080 https://example.com/ -I --max-time 15 && false

grep -n 'matched rule' "$SERVER_LOG"
grep -n '403' "$CLIENT_LOG"
if grep -n 'trusttunnel H2 CONNECT accepted for tcp:example.com:443' "$SERVER_LOG"; then
  false
fi
if grep -nE 'failed to open connection to tcp:_check:443|lookup _check: no such host' "$SERVER_LOG"; then
  false
fi

kill "$CLIENT_PID" "$SERVER_PID"
wait "$CLIENT_PID" "$SERVER_PID" 2>/dev/null || true
```

Ожидание:
- deny-rule блокирует и health-check, и CONNECT через `403`;
- path остаётся в rules/health-check ветке и не падает обратно в обычный dispatch `_check`.

#### 5.1.4. Rule-allow sanity-check

```bash
export SERVER_LOG=$LOG_DIR/h2-check-server-allow.log
export CLIENT_LOG=$LOG_DIR/h2-check-client-allow.log

pkill -f "$XRAY_BIN" || true
pkill -f "$OFFICIAL_CLIENT_BIN" || true

: >"$SERVER_LOG"
: >"$CLIENT_LOG"

"$XRAY_BIN" run -c "$CONFIG_DIR/server_h2_rules.json" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 2

"$OFFICIAL_CLIENT_BIN" -c "$CONFIG_DIR/official_client_rules_allow.toml" >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
sleep 5

curl --socks5-hostname 127.0.0.1:11080 https://example.com/ -I --max-time 15
grep -n 'matched rule\[0\] action=allow' "$SERVER_LOG"
grep -n 'trusttunnel H2 health-check accepted' "$SERVER_LOG"

kill "$CLIENT_PID" "$SERVER_PID"
wait "$CLIENT_PID" "$SERVER_PID" 2>/dev/null || true
```

Ожидание:
- allow-rule пропускает и health-check, и CONNECT;
- success path логируется без возврата к историческим `_check`-ошибкам.

### 5.2. Debian lab runbook для H2 `_icmp`

Предпосылки:
- рабочее дерево находится в `/opt/lab/xray-tt/src/xray-core-trusttunnel`;
- тестируемый Xray binary собирается в `/opt/lab/xray-tt/tmp/xray-tt-current`;
- official CLI client доступен как `/opt/lab/xray-tt/bin/trusttunnel_client/trusttunnel_client`;
- runtime-конфиги кладутся в `/opt/lab/xray-tt/configs`;
- raw ICMP запускается под `root`, а official client поднимает `ip netns exec tun`.

Подготовка и preflight:

```bash
export LAB_ROOT=/opt/lab/xray-tt
export XRAY_REPO=$LAB_ROOT/src/xray-core-trusttunnel
export XRAY_BIN=$LAB_ROOT/tmp/xray-tt-current
export OFFICIAL_CLIENT_BIN=$LAB_ROOT/bin/trusttunnel_client/trusttunnel_client
export CONFIG_DIR=$LAB_ROOT/configs
export LOG_DIR=$LAB_ROOT/logs

cd "$XRAY_REPO"

git rev-parse HEAD
git status --short
go build -buildvcs=false -o "$XRAY_BIN" ./main

install -m 0644 testing/trusttunnel/server_h2_official_cert.json \
  "$CONFIG_DIR/server_h2_official_cert.json"
install -m 0644 testing/trusttunnel/official_client_to_our_server_h2_icmp.toml \
  "$CONFIG_DIR/official_client_to_our_server_h2_icmp_test.toml"

sha256sum "$XRAY_BIN"
ls -l \
  "$CONFIG_DIR/server_h2_official_cert.json" \
  "$CONFIG_DIR/official_client_to_our_server_h2_icmp_test.toml"
```

Success case:

```bash
export SERVER_LOG=$LOG_DIR/h2-icmp-server.log
export CLIENT_LOG=$LOG_DIR/h2-icmp-client.log
export PING_LOG=$LOG_DIR/h2-icmp-ping.log

pkill -f "$XRAY_BIN" || true
pkill -f "$OFFICIAL_CLIENT_BIN" || true

: >"$SERVER_LOG"
: >"$CLIENT_LOG"
: >"$PING_LOG"

"$XRAY_BIN" run -c "$CONFIG_DIR/server_h2_official_cert.json" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 2

"$OFFICIAL_CLIENT_BIN" -c "$CONFIG_DIR/official_client_to_our_server_h2_icmp_test.toml" >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
sleep 3

ip netns exec tun ip a show tun0
ip netns exec tun ping -n -c 3 -W 3 1.1.1.1 | tee "$PING_LOG"

grep -n 'Certificate verified successfully' "$CLIENT_LOG"
grep -n 'ICMP register_request' "$CLIENT_LOG"
grep -n 'ICMP register_reply' "$CLIENT_LOG"
grep -n 'trusttunnel H2 health-check accepted' "$SERVER_LOG"
grep -n 'trusttunnel H2 ICMP mux accepted' "$SERVER_LOG"
if grep -n 'fatal error: concurrent map writes' "$SERVER_LOG"; then
  false
fi

kill "$CLIENT_PID" "$SERVER_PID"
wait "$CLIENT_PID" "$SERVER_PID" 2>/dev/null || true
```

Ожидание:
- official client проходит certificate verification;
- H2 `_check` и `_icmp` не разваливаются на параллельных stream;
- server log содержит `trusttunnel H2 health-check accepted` и `trusttunnel H2 ICMP mux accepted`;
- client log содержит `ICMP register_request` и `ICMP register_reply`;
- `ping` из namespace `tun` проходит с ненулевым RTT и без packet loss.

### 5.3. Debian lab runbook для H3 `_icmp`

Предпосылки:
- рабочее дерево находится в `/opt/lab/xray-tt/src/xray-core-trusttunnel`;
- тестируемый Xray binary собирается в `/opt/lab/xray-tt/tmp/xray-tt-current`;
- official CLI client доступен как `/opt/lab/xray-tt/bin/trusttunnel_client/trusttunnel_client`;
- runtime-конфиги кладутся в `/opt/lab/xray-tt/configs`;
- raw ICMP запускается под `root`, а official client поднимает `ip netns exec tun`.

Подготовка и preflight:

```bash
export LAB_ROOT=/opt/lab/xray-tt
export XRAY_REPO=$LAB_ROOT/src/xray-core-trusttunnel
export XRAY_BIN=$LAB_ROOT/tmp/xray-tt-current
export OFFICIAL_CLIENT_BIN=$LAB_ROOT/bin/trusttunnel_client/trusttunnel_client
export CONFIG_DIR=$LAB_ROOT/configs
export LOG_DIR=$LAB_ROOT/logs

cd "$XRAY_REPO"

git rev-parse HEAD
git status --short
go build -buildvcs=false -o "$XRAY_BIN" ./main

install -m 0644 testing/trusttunnel/server_h3.json \
  "$CONFIG_DIR/server_h3.json"
install -m 0644 testing/trusttunnel/official_client_to_our_server_h3_icmp.toml \
  "$CONFIG_DIR/official_client_to_our_server_h3_icmp_test.toml"

sha256sum "$XRAY_BIN"
ls -l \
  "$CONFIG_DIR/server_h3.json" \
  "$CONFIG_DIR/official_client_to_our_server_h3_icmp_test.toml"
```

Success case:

```bash
export SERVER_LOG=$LOG_DIR/h3-icmp-server.log
export CLIENT_LOG=$LOG_DIR/h3-icmp-client.log
export PING_LOG=$LOG_DIR/h3-icmp-ping.log

pkill -f "$XRAY_BIN" || true
pkill -f "$OFFICIAL_CLIENT_BIN" || true

: >"$SERVER_LOG"
: >"$CLIENT_LOG"
: >"$PING_LOG"

"$XRAY_BIN" run -c "$CONFIG_DIR/server_h3.json" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 2

"$OFFICIAL_CLIENT_BIN" -c "$CONFIG_DIR/official_client_to_our_server_h3_icmp_test.toml" >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
sleep 3

ip netns exec tun ip a show tun0
ip netns exec tun ping -n -c 3 -W 3 1.1.1.1 | tee "$PING_LOG"

grep -n 'Certificate verified successfully' "$CLIENT_LOG"
grep -n 'ICMP register_request' "$CLIENT_LOG"
grep -n 'ICMP register_reply' "$CLIENT_LOG"
grep -n 'trusttunnel H3 health-check accepted' "$SERVER_LOG"
grep -n 'trusttunnel H3 ICMP mux accepted' "$SERVER_LOG"
if grep -n 'fatal error: concurrent map writes' "$SERVER_LOG"; then
  false
fi

kill "$CLIENT_PID" "$SERVER_PID"
wait "$CLIENT_PID" "$SERVER_PID" 2>/dev/null || true
```

Ожидание:
- official client проходит certificate verification;
- H3 `_check` и `_icmp` не разваливаются на параллельных stream;
- server log содержит `trusttunnel H3 health-check accepted` и `trusttunnel H3 ICMP mux accepted`;
- client log содержит `ICMP register_request` и `ICMP register_reply`;
- `ping` из namespace `tun` проходит с ненулевым RTT и без packet loss.

### 5.4. Upstream main sync и non-TrustTunnel live regression audit

Preflight:
- текущая ветка догнана merge commit `e83795ab`, который подтягивает `upstream/main` до `e5a9fb75` (`QUIC sniffer: Fix potential panic on malformed QUIC packets (#5866)`);
- upstream compare-worktree для A/B расположен в `C:\Users\Vardo\GPTProject\xray-core-upstream-main-compare`, HEAD `e5a9fb75`;
- lab binaries: `/opt/lab/xray-compare/bin/xray-fork`, `/opt/lab/xray-compare/bin/xray-upstream`;
- remote binaries: `/opt/xray-compare/bin/xray-fork`, `/opt/xray-compare/bin/xray-upstream`;
- lab configs: `/opt/lab/xray-compare/configs/lab_direct_socks.json`, `/opt/lab/xray-compare/configs/lab_tun_direct.json`, `/opt/lab/xray-compare/configs/lab_vless_tls_socks.json`, `/opt/lab/xray-compare/configs/lab_vless_reality_socks.json`, `/opt/lab/xray-compare/configs/lab_hysteria2_socks.json`;
- remote configs: `/opt/xray-compare/configs/remote_vless_tls_server.json`, `/opt/xray-compare/configs/remote_vless_reality_server.json`, `/opt/xray-compare/configs/remote_hysteria2_server.json`;
- remote payloads: `/opt/xray-compare/http/test32.bin`, `/opt/xray-compare/http/test128.bin`;
- authoritative live result root: `/opt/lab/xray-compare/results/non-tt-live-20260407-210442`.

Post-merge code checks:
- `go test ./app/observatory ./app/proxyman/inbound ./app/proxyman/outbound ./common/protocol/quic ./proxy/hysteria ./proxy/tun ./proxy/wireguard ./transport/internet/... ./proxy/trusttunnel/... -count=1`;
- `go test ./testing/scenarios -count=1 -timeout 90m -v`;
- `GOFLAGS=-buildvcs=false go test -run '^$' ./...`;
- `go build -buildvcs=false -o ./tmp/xray-tt-current.exe ./main`.

Authoritative live verdict:
- `10/10` real-traffic cases прошли на lab → remote → internet;
- все path дали одинаковую функциональную семантику между fork и upstream: `ipify` совпадает попарно, `test32.bin` всегда даёт SHA-256 `e448489238b0c182ce38452f1a073d2f7676e5868f25e3124ac3fd58e536ab73`;
- direct/TUN path выходят в интернет с lab egress `109.252.70.98`, а server-mediated path (`vless + tls`, `vless + reality`, `hysteria`) выходят через remote egress `37.252.0.130`;
- подтверждённого поведенческого расхождения fork vs upstream вне TrustTunnel в этих live-сценариях нет.

Сводная таблица live A/B matrix:

| Case | Path | Exit IP | Throughput | Lab CPU avg/max | Remote CPU avg/max | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `direct_fork` | SOCKS -> freedom -> remote HTTP | `109.252.70.98` | `~42.66 Mbit/s` | `6.83 / 9` | `NA / NA` | PASS |
| `direct_upstream` | SOCKS -> freedom -> remote HTTP | `109.252.70.98` | `~34.43 Mbit/s` | `7.49 / 14` | `NA / NA` | PASS |
| `vless_tls_fork` | SOCKS -> VLESS/TLS -> remote HTTP | `37.252.0.130` | `~30.48 Mbit/s` | `6.50 / 9` | `1.08 / 3` | PASS |
| `vless_tls_upstream` | SOCKS -> VLESS/TLS -> remote HTTP | `37.252.0.130` | `~45.08 Mbit/s` | `8.83 / 14` | `1.92 / 3` | PASS |
| `vless_reality_fork` | SOCKS -> VLESS/REALITY -> remote HTTP | `37.252.0.130` | `~32.26 Mbit/s` | `6.42 / 9` | `0.92 / 4` | PASS |
| `vless_reality_upstream` | SOCKS -> VLESS/REALITY -> remote HTTP | `37.252.0.130` | `~41.99 Mbit/s` | `6.83 / 11` | `1.08 / 4` | PASS |
| `hysteria_fork` | SOCKS -> Hysteria2 -> remote HTTP | `37.252.0.130` | `~520.72 Mbit/s` | `17.92 / 103` | `15.75 / 94` | PASS |
| `hysteria_upstream` | SOCKS -> Hysteria2 -> remote HTTP | `37.252.0.130` | `~523.60 Mbit/s` | `17.17 / 107` | `16.08 / 96` | PASS |
| `tun_direct_fork` | Linux TUN namespace -> freedom -> remote HTTP | `109.252.70.98` | `~46.92 Mbit/s` | `23.92 / 41` | `NA / NA` | PASS |
| `tun_direct_upstream` | Linux TUN namespace -> freedom -> remote HTTP | `109.252.70.98` | `~45.84 Mbit/s` | `22.00 / 33` | `NA / NA` | PASS |

Практический вывод:
- функционально fork и upstream ведут себя одинаково на проверенных non-TrustTunnel path;
- one-shot throughput шумит сильнее, чем функциональные различия, поэтому speed delta между отдельными прогонами не трактуется как регрессия без повторяемого расхождения по поведению или стабильного benchmark-gap;
- initial false-fail в этом блоке были orchestration-only: Windows parallel `go test` давал ложный `finalmask/sudoku` UDP bind fail, desktop -> remote SSH path пришлось заменить на lab jump, а первая Hysteria-матрица падала на harness wait/cleanup ошибках, не на runtime divergence Xray.
