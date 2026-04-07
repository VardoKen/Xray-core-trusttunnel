# Документация Форка TrustTunnel

English version: [README.md](README.md)

В этом каталоге лежит поддерживаемый комплект документации для форка Xray-core с TrustTunnel.

## С Чего Начать

Публичная документация форка:

- обзор форка: [../README.ru.md](../README.ru.md)
- руководство по конфигам: [configuration.ru.md](configuration.ru.md)
- English configuration guide: [configuration.md](configuration.md)

Канонический current-слой:

- состояние: [current/current-state.md](current/current-state.md)
- архитектура: [current/architecture.md](current/architecture.md)
- эксплуатация: [current/operations.md](current/operations.md)
- проверки: [current/validation.md](current/validation.md)
- roadmap: [current/roadmap.md](current/roadmap.md)

## Слои Документации

- `docs/current/*`
  - Единственный слой текущей истины.
  - Используется для фактического поведения, поддержанных path, подтверждённых конфигов и открытых задач.
- `docs/history/*`
  - Исторические заметки по разработке.
  - Нужны только для понимания того, как проект пришёл к текущему состоянию.
- `docs/migration/*`
  - Документы по сверке и переносу старых источников.
- `docs/archive/*`
  - Хранимые, но не текущие материалы.

## Порядок Чтения

Для любой задачи по TrustTunnel, конфигам, тестам или runtime:

1. [current/current-state.md](current/current-state.md)
2. один или несколько профильных current-документов:
   - [current/architecture.md](current/architecture.md)
   - [current/operations.md](current/operations.md)
   - [current/validation.md](current/validation.md)
   - [current/roadmap.md](current/roadmap.md)
3. исторические документы только если current-слоя недостаточно

## Практическое Правило

Нельзя поднимать тезисы из `history`, `migration`, `archive` или старых заметок обратно в `docs/current/*`, если они не подтверждены более новым кодом, тестами или runtime-фактами.
