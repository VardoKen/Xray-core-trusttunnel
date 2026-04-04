# TrustTunnel / Xray-Core — текущее состояние проекта

Статус: current
Дата фиксации: 2026-04-02
Коммит состояния: `99e59352`
Ветка: `feat/trusttunnel-v1-sync-upstream-2026-03-30`
Область истины: фактическое состояние проекта после сессии, закрывшей H3 rules, ложный `H3_NO_ERROR` и legacy H3-path
Не использовать для: исторической хронологии, описания старых тупиковых веток и промежуточных решений

## 1. Краткий факт состояния

TrustTunnel в текущем дереве подтверждённо находится в рабочем состоянии по следующим направлениям:
- H2 TCP;
- H3 TCP;
- H2 UDP mux;
- H3 UDP mux;
- H2 rules по `client_random`;
- H3 rules по `client_random`;
- server-side traffic stats;
- базовая межоперабельность в направлениях official client → our server и our client → official endpoint.

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

## 3. Что считается текущей истиной

Текущую истину по проекту определяют:
- этот документ;
- `docs/current/architecture.md`;
- `docs/current/operations.md`;
- `docs/current/validation.md`;
- `docs/current/roadmap.md`.

Исторические и миграционные документы могут объяснять, почему раньше было иначе, но не могут переопределять этот current-слой.

## 4. Что остаётся открытым после этой фиксации

Открытыми задачами текущего этапа считаются не H3-баги, а следующие блоки:
- H2 `_check` как отдельный special path;
- выравнивание auth semantics на всех pseudo-host path;
- outbound `clientRandom` как реальная runtime-функция;
- `_icmp` client/server path;
- привязка `ipv6_available`, private-network policy и timeout settings к реальному runtime;
- полный UDP interop matrix;
- REALITY;
- нормализация TrustTunnel вокруг `streamSettings` и общей модели Xray.

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
