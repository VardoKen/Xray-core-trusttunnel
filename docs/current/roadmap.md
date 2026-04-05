# TrustTunnel / Xray-Core — roadmap

Статус: current
Дата фиксации: 2026-04-05
База roadmap: состояние проекта после clean-HEAD H2 official `_icmp` interop, server-side `_icmp` mux, закрытия auth semantics на pseudo-host path и outbound clientRandom
Область истины: только открытые задачи после закрытия H3 rules, ложного `H3_NO_ERROR`, legacy H3-path, H2 `_check`, auth semantics на pseudo-host path, outbound clientRandom и server-side `_icmp` mux
Не использовать для: фиксации уже закрытых багов и исторической хронологии

## 1. Принцип чтения roadmap

Этот документ не повторяет уже закрытые H3-дефекты и не переоткрывает закрытый H2 `_check`.

Текущее направление разработки:
1. закрыть оставшиеся обязательные протокольные пробелы TrustTunnel;
2. реализовать и проверить REALITY;
3. довести TrustTunnel до корректной интеграции с общими механизмами Xray-Core.

Переоткрывать закрытую H3-тройку можно только при появлении более новых доказательств, чем фиксация `99e59352`.

## 2. Открытые задачи уровня обязательной совместимости

### 2.1. `_icmp`

Server-side H2/H3 `_icmp` mux по official wire-format уже реализован на `32b2eff2`, включая raw ICMP echo-reply path и `503` при недоступном raw socket. Clean-HEAD official client ↔ our server H2/H3 interop подтверждён на `5a21fd31` и `6c46922c`.

Открытым остаётся:
- Xray-side/client-side модель `_icmp`, потому что в текущем core нет отдельного `Network_ICMP`;
- explicit config surface для ICMP timeout/interface/private-network semantics;
- error-type parity сверх подтверждённого echo-reply path.

### 2.2. Observable server behavior

Нужно привязать к runtime следующие поля и эффекты:
- `ipv6_available`;
- `allow_private_network_connections`;
- `tls_handshake_timeout_secs`;
- `client_listener_timeout_secs`;
- `connection_establishment_timeout_secs`;
- `tcp_connections_timeout_secs`;
- `udp_connections_timeout_secs`;
- `auth_failure_status_code`.

### 2.3. Полный UDP interop matrix

Нужно закрыть:
- official client → our server по H2/UDP и H3/UDP;
- our client → official endpoint по H2/UDP и H3/UDP;
- IPv4 и IPv6 target;
- несколько flows в одной session;
- idle timeout и reopen;
- корректное поле `App Name`.

### 2.4. Auth и stats sanity-check

После закрытия interop-пробелов нужно перепроверить:
- `407` → новая сессия;
- inbound/outbound/user traffic counters;
- `onlineMap` отдельно от counters.

## 3. REALITY после базовой совместимости

### 3.1. Архитектурная точка внедрения

REALITY должен внедряться через общий Xray `streamSettings.security`, а не через trusttunnel-specific `settings`.

### 3.2. Production-путь

Приоритетный production path:
- TrustTunnel + H2/TCP + REALITY;
- затем TrustTunnel + H2/UDP + REALITY.

### 3.3. Исследовательский путь

Отдельный R&D:
- TrustTunnel + H3 + REALITY.

Условия трека:
- не считать его обычным включением флага;
- не ломать уже рабочий H3/TLS path;
- завершать либо working prototype, либо технически доказанным стоп-фактором.

### 3.4. Client-side parity после REALITY

После production-ready REALITY остаются поля:
- `post_quantum_group_enabled`;
- `anti_dpi`;
- `has_ipv6`.

## 4. Интеграция с общей моделью Xray

### 4.1. Нормализация вокруг `streamSettings`

Нужно:
- определить границу между compatibility fields и реальным transport/security layer;
- ввести validator unsupported combinations;
- не строить второй runtime-router поверх `streamSettings`.

### 4.2. Общая TLS/REALITY surface Xray

Нужно проверить и доработать:
- `serverName`;
- verify options;
- pinning;
- fingerprint/uTLS surface там, где она должна применяться;
- корректное сосуществование `tls` и `reality`.

### 4.3. Common outbound features

Нужно проверить совместимость TrustTunnel outbound с:
- `sendThrough`;
- `proxySettings`;
- `mux`;
- `targetStrategy`.

### 4.4. Common inbound features

Нужно проверить совместимость TrustTunnel inbound с:
- `sniffing`;
- route-only behavior;
- metadataOnly scenarios;
- общими inbound transport settings.

### 4.5. `_icmp` в модели Xray

После реализации `_icmp` нужно определить его место в:
- routing;
- policy;
- stats;
- API semantics.

### 4.6. Dynamic user management

Нужно добавить AddUser/RemoveUser через `HandlerService` для TrustTunnel inbound.

### 4.7. Финальная матрица совместимости

Нужно зафиксировать и валидировать комбинации:
- H2/H3;
- TLS/REALITY;
- TCP / `_udp2` / `_icmp` / `_check`;
- `clientRandom` / rules;
- common Xray inbound/outbound features.

## 5. Порядок выполнения

1. `_icmp` interop и Xray-side model
2. observable server behavior
3. полный UDP interop matrix
4. auth/stats sanity-check
5. TrustTunnel + H2/TCP + REALITY
6. TrustTunnel + H2/UDP + REALITY
7. R&D по TrustTunnel + H3 + REALITY
8. client-side parity fields после REALITY
9. нормализация вокруг `streamSettings`
10. full TLS/REALITY surface
11. common outbound features
12. common inbound features
13. `_icmp` в routing/policy/stats модели Xray
14. dynamic user management
15. финальная матрица совместимости и validator
