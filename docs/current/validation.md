# TrustTunnel / Xray-Core — подтверждённые проверки и границы тестирования

Статус: current
Дата фиксации: 2026-04-02
Коммит состояния: `99e59352`
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

### 2.4. H2 rules retest

Конфиги:
- `/opt/lab/xray-tt/configs/server_h2_rules.json`
- `/opt/lab/xray-tt/configs/official_client_rules_allow.toml`
- `/opt/lab/xray-tt/configs/official_client_rules_deny.toml`

Подтверждено:
- allow-case пропускает трафик;
- deny-case возвращает `403` и блокирует трафик.

### 2.5. H3 rules retest

База retest:
- использован H3-вариант rules-конфигов, полученный из rules-сценария H2 заменой transport `http2 -> http3`;
- H2-конфиги для логики rules: `/opt/lab/xray-tt/configs/server_h2_rules.json`, `official_client_rules_allow.toml`, `official_client_rules_deny.toml`;
- H3-variant повторяет тот же rules-set, но работает через H3 transport path текущего состояния.

Подтверждено:
- allow-case логирует `matched rule[0] action=allow` и пропускает трафик;
- deny-case логирует deny-rule и блокирует и health-check, и CONNECT через `403`.

### 2.6. Retest исправления `H3_NO_ERROR`

Конфиги:
- `/opt/lab/xray-tt/configs/server_h3.json`
- `/opt/lab/xray-tt/configs/official_client_to_our_server_h3.toml`

Подтверждено:
- повторный H3 TCP тест проходит успешно;
- ложный хвост `... > H3_NO_ERROR` отсутствует.

## 3. Что считать pass/fail на текущем этапе

### 3.1. Pass

Признаки рабочего поведения:
- session устанавливается;
- TCP CONNECT проходит и держит двусторонний обмен;
- UDP через `_udp2` проходит без развала session;
- H3 allow/deny определяется rule match, а не глобальным запретом;
- штатное завершение H3 stream не поднимается как прикладная ошибка;
- traffic counters инкрементируются;
- `user>>>...>>>online` анализируется отдельно как `onlineMap`.

### 3.2. Fail

Признаки регрессии:
- `failed to read trusttunnel request > H3_NO_ERROR (local)`;
- `connect: connection refused` при ошибочном заходе TCP на QUIC listener;
- `peer certificate is missing` при неправильном порядке TLS verify в H3;
- `unknown transport protocol: trusttunnelh3`;
- любой глобальный отказ H3 path только из-за самого факта наличия rules при корректно извлечённом `client_random`.

## 4. Что уже не нужно повторно проверять как открытую проблему

На текущем состоянии не требуется повторная перепроверка как открытого дефекта:
- transport-layer принадлежности рабочего H3 path;
- server-side H3 rules по `client_random`;
- ложного `H3_NO_ERROR` в H3 TCP path.

Переоткрывать эти вопросы можно только при появлении более новых и воспроизводимых доказательств, чем фиксация `99e59352`.

## 5. Что остаётся предметом будущих проверок

Открытые блоки для следующих циклов проверки:
- H2 `_check` как отдельный special path;
- `_icmp`;
- outbound `clientRandom`;
- полный UDP interop matrix;
- observable server behavior для `ipv6_available`, private-network и timeout settings;
- REALITY на H2 и исследовательский трек H3 + REALITY.
