# AGENTS.md

Область действия: корень репозитория. Этот файл применяется ко всему репозиторию, если более глубокий `AGENTS.md` не переопределяет инструкции.

## 0. Bootstrap после клонирования

Если репозиторий был клонирован без текущей документации, а затем `docs/*` и `AGENTS.md` были добавлены вручную из dev-стенда до первого запуска Codex, считать обязательным bootstrap-шагом отдельный локальный commit, который фиксирует документационный baseline.

Правила для такого случая:

- сначала скопировать в репозиторий актуальные `docs/*` и этот `AGENTS.md`;
- затем сделать отдельный commit только под фиксацию текущего документированного состояния;
- после этого запускать Codex уже поверх этого commit;
- этот commit трактовать как intentional documentation baseline, а не как подозрительное незадокументированное изменение кода;
- не тратить время на расследование происхождения такого commit, если его message явно описывает bootstrap / docs baseline / codex bootstrap.

Рекомендуемая идея commit message:

- `docs: bootstrap codex baseline from dev stand state`

## 1. Что читать первым

Если задача затрагивает код TrustTunnel, конфиги, тесты или документацию, читать в таком порядке:

1. `docs/README.md`
2. `docs/current/current-state.md`
3. релевантные документы из current-слоя:
   - `docs/current/architecture.md`
   - `docs/current/operations.md`
   - `docs/current/validation.md`
   - `docs/current/roadmap.md`
4. `docs/history/development-history.md` — только для исторического контекста
5. `docs/migration/source-reconciliation.md` — только для контекста сверки источников

Если задача относится к текущему поведению проекта, не начинать со старых `docs/test-matrix/*`, старого `docs/trusttunnel-v1.md` или импортированных исторических заметок.

## 2. Правила слоя истины

- `docs/current/*` — единственный слой текущей истины.
- `docs/history/*`, `docs/migration/*` и `docs/archive/*` не являются текущей истиной.
- Не переносить утверждения из history, migration, archive или старых заметок обратно в `docs/current/*`, если нет более новых подтверждений кодом, тестами или runtime-проверкой.
- Для H3-части TrustTunnel не переоткрывать закрытую H3-тройку без более новых доказательств, чем состояние от 2026-04-02 / коммит `99e59352`:
  - активный runtime path H3
  - серверные H3 rules
  - ложный `H3_NO_ERROR`

## 3. Карта репозитория

- `proxy/trusttunnel/*` — основная протокольная логика TrustTunnel
- `transport/internet/tcp/*` — QUIC/H3 transport, обёртка H3 request, извлечение `client_random`
- `infra/conf/trusttunnel.go` — JSON/protobuf binding конфига
- `app/proxyman/inbound/*` — worker-layer plumbing для stats
- `testing/trusttunnel/*` — примеры конфигов и локальные тестовые артефакты
- `docs/current/*` — каноническая документация по текущему состоянию проекта

## 4. Правила работы

- Предпочитать узкие и локальные правки. Не переписывать большие области без необходимости.
- Если меняется поведение, сначала обновить `docs/current/current-state.md`, затем конкретные документы current-слоя, которых касается изменение.
- Держать H3-описание синхронизированным с transport-layer runtime path, а не с удалённым legacy-кодом.
- Не заявлять parity по полю или функции, пока runtime-поведение не подтверждено.
- Считать поля compatibility surface декларативными, пока нет доказательства кодом и тестами, что они реально активны.
- Не оставлять противоречащие друг другу утверждения в разных файлах `docs/current/*`.

## 5. Проверки по типу изменений

### 5.1. Только документация

Запустить:
- `find docs -maxdepth 3 -type f | sort`
- `test -f docs/current/current-state.md`
- `test -f AGENTS.md`

Для `docs/current/*` старые H3-формулировки не должны протекать обратно. Эта команда должна возвращать пустой результат:
- `rg -n "не поддерживает client_random rules|not support client_random rules|final H3 interop is unconfirmed|legacy H3-path is active" docs/current`

Если правится roadmap или validation, сохранять:
- точные имена полей
- точные пути к конфигам, если они известны
- preflight-ожидания для interop-тестов

### 5.2. Изменения в коде TrustTunnel

Запустить:
- `go test ./proxy/trusttunnel/... ./transport/internet/tcp ./app/proxyman/inbound`
- `go build -o /tmp/xray-tt-current ./main`

Если runtime-поведение изменилось:
- обновить `docs/current/validation.md` с конфигами, pass/fail-маркерами и оставшимися открытыми вопросами
- обновить `docs/current/operations.md`, если изменилось пользовательское поведение или рекомендации по конфигу
- обновить `docs/current/architecture.md`, если изменился runtime path или набор активных полей
- обновить `docs/current/roadmap.md` и `docs/current/current-state.md`, если проблема закрыта или переоткрыта

### 5.3. Interop-retest

Перед тем как заявлять успех, зафиксировать:
- текущий commit и состояние worktree
- успешную сборку и точный путь к бинарю, который реально запускался
- точные пути серверного и клиентского конфигов
- сертификат и trust chain, использованные в тесте
- использовались ли official client или official endpoint

## 6. Guardrails для TrustTunnel

- Трактовать `user>>>...>>>online` как `onlineMap`, а не как обычный counter.
- Не считать domain UDP targets реализованными без проверки кода и тестов.
- Не представлять outbound `clientRandom`, `HasIpv6` или `AntiDpi` как активные runtime-функции без подтверждения.
- Для H2 interop с official client детали сертификата и trust chain критичны. Не сводить это к общей фразе вида «TLS работает».

## 7. Правила качества ответа

- Предпочитать точные file paths, config paths и log signatures вместо расплывчатых пересказов.
- Если изменение неполное или подтверждено только частично, говорить об этом прямо.
- Держать инструкции уровня репозитория короткими. Если какому-то поддереву позже понадобятся более узкие правила, добавлять более глубокий `AGENTS.md`, а не раздувать корневой файл.
