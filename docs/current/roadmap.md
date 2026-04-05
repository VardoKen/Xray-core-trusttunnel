# TrustTunnel / Xray-Core — roadmap

Статус: current
Дата фиксации: 2026-04-06
База roadmap: состояние проекта после закрытия `_icmp` protocol/runtime gap, H2/H3 official `_icmp` interop, product-level Linux TUN path, auth semantics на pseudo-host path, outbound clientRandom, полного UDP interop matrix, auth/stats sanity-check и observable timeout surface
Область истины: только открытые задачи после закрытия H3 rules, ложного `H3_NO_ERROR`, legacy H3-path, H2 `_check`, auth semantics на pseudo-host path, outbound clientRandom, `_icmp` protocol/runtime surface, полного UDP interop matrix, auth/stats sanity-check и observable timeout surface
Не использовать для: фиксации уже закрытых багов и исторической хронологии

## 1. Принцип чтения roadmap

Этот документ не повторяет уже закрытые H3-дефекты, не переоткрывает закрытый H2 `_check` и не возвращает auth/stats sanity-check или observable timeout surface в список открытых проблем без новых доказательств.

Текущее направление разработки:
1. реализовать и проверить REALITY;
2. довести TrustTunnel до корректной интеграции с общими механизмами Xray-Core.

Переоткрывать закрытую H3-тройку можно только при появлении более новых доказательств, чем фиксация `99e59352`.

## 2. REALITY после базовой совместимости

### 2.1. Архитектурная точка внедрения

REALITY должен внедряться через общий Xray `streamSettings.security`, а не через trusttunnel-specific `settings`.

### 2.2. Production-путь

Приоритетный production path:
- TrustTunnel + H2/TCP + REALITY;
- затем TrustTunnel + H2/UDP + REALITY.

### 2.3. Исследовательский путь

Отдельный R&D:
- TrustTunnel + H3 + REALITY.

Условия трека:
- не считать его обычным включением флага;
- не ломать уже рабочий H3/TLS path;
- завершать либо working prototype, либо технически доказанным стоп-фактором.

### 2.4. Client-side parity после REALITY

После production-ready REALITY остаются поля:
- `post_quantum_group_enabled`;
- `anti_dpi`;
- `has_ipv6`.

## 3. Интеграция с общей моделью Xray

### 3.1. Нормализация вокруг `streamSettings`

Нужно:
- определить границу между compatibility fields и реальным transport/security layer;
- ввести validator unsupported combinations;
- не строить второй runtime-router поверх `streamSettings`.

### 3.2. Общая TLS/REALITY surface Xray

Нужно проверить и доработать:
- `serverName`;
- verify options;
- pinning;
- fingerprint/uTLS surface там, где она должна применяться;
- корректное сосуществование `tls` и `reality`.

### 3.3. Common outbound features

Нужно проверить совместимость TrustTunnel outbound с:
- `sendThrough`;
- `proxySettings`;
- `mux`;
- `targetStrategy`.

### 3.4. Common inbound features

Нужно проверить совместимость TrustTunnel inbound с:
- `sniffing`;
- route-only behavior;
- metadataOnly scenarios;
- общими inbound transport settings.

### 3.5. `_icmp` в модели Xray

После реализации `_icmp` нужно определить его место в:
- routing;
- policy;
- stats;
- API semantics.

### 3.6. Dynamic user management

Нужно добавить AddUser/RemoveUser через `HandlerService` для TrustTunnel inbound.

### 3.7. Финальная матрица совместимости

Нужно зафиксировать и валидировать комбинации:
- H2/H3;
- TLS/REALITY;
- TCP / `_udp2` / `_icmp` / `_check`;
- `clientRandom` / rules;
- common Xray inbound/outbound features.

## 5. Порядок выполнения

1. TrustTunnel + H2/TCP + REALITY
2. TrustTunnel + H2/UDP + REALITY
3. R&D по TrustTunnel + H3 + REALITY
4. client-side parity fields после REALITY
5. нормализация вокруг `streamSettings`
6. full TLS/REALITY surface
7. common outbound features
8. common inbound features
9. `_icmp` в routing/policy/stats модели Xray
10. dynamic user management
11. финальная матрица совместимости и validator
