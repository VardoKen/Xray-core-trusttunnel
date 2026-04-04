# TrustTunnel / Xray-Core — история разработки

Статус: history
Дата фиксации слоя: 2026-04-04
Область истины: хронология этапов, тупиковые ветки, ошибки разработки, исторические диагностические сигнатуры
Не использовать для: описания текущего состояния проекта вместо `docs/current/*`

## 1. Назначение

Документ сохраняет:
- эволюцию интеграции TrustTunnel;
- последовательность этапов;
- ошибки и нарушения порядка разработки;
- старые ограничения, уже не относящиеся к текущей эксплуатации;
- важные interop-детали и диагностические сигнатуры.

Примечание по дате слоя:
- большая часть исходных исторических текстов датирована 2026-04-01;
- этот consolidated history-слой обновлён до 2026-04-04 и включает этап `99e59352`, зафиксированный по состоянию 2026-04-02.

## 2. База проекта и этапы

Исходная ветка:
- `feat/trusttunnel-v1`

Ключевые этапы:
- `82e8ad7a` — bootstrap protocol registration and stub startup
- `7d35fa78` — account model and inbound user store
- `1425361b` — basic auth CONNECT tunnel for tcp e2e
- `11471270` — http2 connect path for tcp
- `120bd49d` — h2 tls verification path for tcp
- `368704b5` — finish h2 rules and client_random enforcement
- `5ea5329d` — add http3 client and inbound mvp
- `858b4c69` — add udp mux over h2
- `73ea42f5` — add trusttunnel h3 udp configs
- `803e9864` — fix runtime user keying and tcp user stats path
- `88de13f8` — fix trusttunnel h3 inbound traffic stats
- `d9470252` — merge `upstream/main`
- `83dd4692` — harden h3 inbound behavior
- `bf85dfc5` — move h3 inbound into tcp transport
- `d91156d0` — extract h3 client_random from quic initial
- `99e59352` — remove legacy h3 handler, enable h3 client_random rules and suppress H3_NO_ERROR

## 3. Этапы по смыслу

### 3.1. Этап 01–05: закрытие H2

К точке `368704b5` были закрыты:
- protocol registration;
- protobuf schema;
- JSON binding;
- MemoryAccount и UserStore;
- inbound/outbound HTTP/1.1 CONNECT;
- inbound/outbound HTTP/2 CONNECT;
- ручная TLS verification;
- H2 interop с official client;
- H2 rules и `client_random`.

### 3.2. Этап H3 MVP

К точке `5ea5329d` были подтверждены:
- outbound H3 CONNECT;
- inbound H3 CONNECT;
- Xray client → official endpoint по H3;
- official client → наш Xray server по H3 на тогдашнем MVP path.

### 3.3. Этап UDP и stats

К точкам `858b4c69`, `803e9864`, `88de13f8` были закрыты:
- H2 UDP mux;
- H3 UDP mux;
- runtime user keying при пустом `email`;
- TCP user stats path;
- H3 inbound counters.

### 3.4. Этап post-merge H3 cleanup

После merge upstream/main:
- H3 path перестал опираться на отдельный trusttunnel-specific worker;
- H3 listener был перенесён в `transport/internet/tcp`;
- server-side H3 `client_random` стал извлекаться из QUIC Initial без отдельного форка `quic-go`.

### 3.5. Этап фиксации `99e59352`

На этом состоянии были закрыты:
- legacy H3-path первой попытки реализации;
- искусственная блокировка H3 rules;
- ложный `H3_NO_ERROR` в журналировании H3 TCP path.

## 4. Критически важный исторический interop по сертификатам

### 4.1. Initial self-signed сертификат был недостаточен

Official client не принимал ранний лабораторный self-signed сертификат в требуемой форме.

### 4.2. Рабочий interop был получен после перехода на certificate chain формата official endpoint

Критичны были:
- SAN;
- имя `vpn.lab.local`;
- формат сертификата;
- поведение trust chain на стороне official client.

Практический маркер успеха:
- лог `Certificate verified successfully`.

## 5. Историческая деталь по H2 `_check`

На историческом H2 этапе official client регулярно открывал `tcp:_check:443`, а сервер логировал:
- `failed to open connection to tcp:_check:443`
- `lookup _check: no such host`

Это не блокировало пользовательский трафик, но показывало, что H2 `_check` тогда ещё не имел отдельной обработки.

## 6. Подтверждённые ошибки и нарушения по ходу разработки

- H3 был начат до полного закрытия обязательных H2 interop-проверок.
- Была начата тупиковая отдельная ветка `trusttunnelh3`.
- Была ошибка попытки идти TCP к UDP/QUIC listener.
- Был неверный порядок TLS verify в H3.
- Была пропущена регистрация transport protocol на тупиковой H3-ветке.
- После failed build запускался старый бинарь.
- В одном пакете тип `readerOnly` был объявлен дважды.
- Диагностика периодами становилась избыточной и шумной.
- Попытка переносить stats wrapping в UDP transport привела к import cycle.

## 7. Исторические диагностические сигнатуры

- `failed to read trusttunnel request > H3_NO_ERROR (local)`
- `failed to open connection to tcp:_check:443`
- `lookup _check: no such host`
- `connect: connection refused`
- `peer certificate is missing`
- `unknown transport protocol: trusttunnelh3`

## 8. Историческая карта лаборатории

Каталоги:
- `/opt/lab/xray-tt/src/xray-core-trusttunnel`
- `/opt/lab/xray-tt/src/xray-core-upstream`
- `/opt/lab/xray-tt/src/trusttunnel-ref`
- `/opt/lab/xray-tt/src/trusttunnel-client-ref`
- `/opt/lab/xray-tt/bin`
- `/opt/lab/xray-tt/configs`
- `/opt/lab/xray-tt/certs`
- `/opt/lab/xray-tt/logs`
- `/opt/lab/xray-tt/tmp`
- `/opt/lab/xray-tt/pcap`

Версии:
- Debian 13 (trixie), amd64
- Xray-core `v26.2.6` как ранняя базовая версия
- TrustTunnel endpoint `v1.0.17`
- TrustTunnel client `v1.0.23`
- Go `1.26.1`
- protoc `3.21.12`
- protoc-gen-go `v1.36.11`

## 9. Историческая граница тестов

Исторически важно сохранять факт:
- целевые trusttunnel-пакеты и runtime-сценарии проверялись и фиксировались;
- полный `go test ./...` не всегда был зелёным вне зоны доработки;
- это не считалось автоматическим блокером этапа.

## 10. Правило использования исторического слоя

Этот документ отвечает на вопрос: «как проект пришёл в текущее состояние».

Если он противоречит `docs/current/*`, это означает только то, что он описывает более ранний этап, а не что current-слой ошибочен.
