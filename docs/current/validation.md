# TrustTunnel / Xray-Core — подтверждённые проверки и границы тестирования

Статус: current
Дата фиксации: 2026-04-05
Коммит состояния: `81dfc323`
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

Подтверждено:
- `go test ./proxy/trusttunnel/... ./transport/internet/tcp ./app/proxyman/inbound`
- `go build -o /opt/lab/xray-tt/tmp/xray-tt-current ./main`

Ограничение:
- полный `go test ./...` исторически не считался обязательным зелёным критерием вне зоны доработки;
- известные внешние ограничения включали `geoip.dat` и `transport/internet/tls/TestECHDial`.

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
- outbound `clientRandom` как отдельного чисто декларативного поля на H2/H3;
- transport-layer принадлежности рабочего H3 path;
- server-side H3 rules по `client_random`;
- ложного `H3_NO_ERROR` в H3 TCP path.

Переоткрывать эти вопросы можно только при появлении более новых и воспроизводимых доказательств, чем фиксация `99e59352`.

## 5. Что остаётся предметом будущих проверок и что сохранено как воспроизводимый runbook

Открытые блоки для следующих циклов проверки:
- explicit config surface для ICMP timeout/interface/private-network semantics;
- error-type parity для `_icmp` сверх подтверждённого echo-request/echo-reply path;
- полный UDP interop matrix;
- observable server behavior для `ipv6_available`, private-network и timeout settings;
- REALITY на H2 и исследовательский трек H3 + REALITY.

Локально подтверждённые regression-тесты на 2026-04-05:
- `go test ./common/net` проходит, включая `Network_ICMP` string/destination coverage;
- `go test ./infra/conf -run 'TestNetwork(BuildSupportsICMP|ListBuildSupportsICMP)$'` проходит;
- `go test ./app/router -run '^$'` проходит как compile-only sanity-check для routing layer после добавления `Network_ICMP`;
- `TestClientProcessRejectsIncompleteICMPLink` подтверждает, что новый `_icmp` path не пытается работать с неполным `transport.Link`;
- `TestTrustTunnelICMPRequestFromBufferUsesFallbackDestination` подтверждает разбор raw echo-request с fallback destination;
- `TestTrustTunnelICMPRequestFromBufferRejectsNonEchoRequest` подтверждает, что client-side contract пока ограничен echo-request path;
- `TestRunTrustTunnelICMPTunnelEchoRoundTrip` подтверждает, что outbound `_icmp` path кодирует fixed-size request frame и локально восстанавливает raw echo-reply packet по сохранённому payload;
- `go test ./proxy/trusttunnel/... ./transport/internet/tcp ./app/proxyman/inbound` проходит;
- `GOFLAGS=-buildvcs=false go test -run '^$' ./...` проходит как compile-only sweep по дереву после добавления outbound `_icmp` path;
- `TestAttachTrustTunnelClientRandomClonesSharedContent` защищает H2/H3 parallel streams от shared `session.Content.Attributes`;
- обычный H2 CONNECT auth-fail возвращает `407` и `Proxy-Authenticate`;
- H2 `_udp2` auth-fail возвращает `407` до UDP mux;
- H2 `_icmp` auth-fail возвращает `407`;
- H2 `_icmp` при недоступной ICMP session отвечает `503 Service Unavailable`;
- H2 `_icmp` при доступной fake-session возвращает `200` и reply-frame без dispatch;
- H1 `_check` отвечает `200` без dispatch;
- H1 `_udp2` больше не уходит в обычный dispatch и отвечает явной HTTP-ошибкой;
- H1 `_icmp` больше не уходит в обычный dispatch и отвечает `501 Not Implemented`.

Linux package verification на Debian lab 2026-04-05 / `81dfc323`:
- repo HEAD: `81dfc3238ebe1ff342dc2330d5b276a501e740ef`;
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

Отдельное внешнее ограничение локального test-run:
- полный `go test ./infra/conf ./app/router` по-прежнему цепляется за отсутствие `geoip.dat`; это исторический fixture-gap текущего окружения, а не регрессия `Network_ICMP`.

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
