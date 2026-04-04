# TrustTunnel / Xray-Core — roadmap

Статус: current
Дата фиксации: 2026-04-04
База roadmap: состояние проекта после коммита `99e59352`
Область истины: только открытые задачи после закрытия H3 rules, ложного `H3_NO_ERROR` и legacy H3-path
Не использовать для: фиксации уже закрытых багов и исторической хронологии

## 1. Принцип чтения roadmap

Этот документ не повторяет уже закрытые H3-дефекты.

Текущее направление разработки:
1. закрыть оставшиеся обязательные протокольные пробелы TrustTunnel;
2. реализовать и проверить REALITY;
3. довести TrustTunnel до корректной интеграции с общими механизмами Xray-Core.

Переоткрывать закрытую H3-тройку можно только при появлении более новых доказательств, чем фиксация `99e59352`.

## 2. Открытые задачи уровня обязательной совместимости

### 2.1. H2 `_check`

Нужно:
- довести до end-to-end closure отдельную обработку `_check` на H2;
- зафиксировать retest, что `_check` больше не уходит в обычный dispatch path;
- подтвердить корректные `200` и `407` в рамках `authFailureStatusCode`.

### 2.2. Единые auth semantics на pseudo-host path

Нужно выровнять поведение для:
- обычного TCP CONNECT;
- `_check`;
- `_udp2`;
- `_icmp`.

### 2.3. Outbound `clientRandom`

Нужно сделать `clientRandom` на стороне Xray-client реальной runtime-функцией для H2 и H3.

### 2.4. `_icmp`

Нужно реализовать полноценный client/server path `_icmp` по спецификации, без обходной логики через TCP/UDP.

### 2.5. Observable server behavior

Нужно привязать к runtime следующие поля и эффекты:
- `ipv6_available`;
- `allow_private_network_connections`;
- `tls_handshake_timeout_secs`;
- `client_listener_timeout_secs`;
- `connection_establishment_timeout_secs`;
- `tcp_connections_timeout_secs`;
- `udp_connections_timeout_secs`;
- `auth_failure_status_code`.

### 2.6. Полный UDP interop matrix

Нужно закрыть:
- official client → our server по H2/UDP и H3/UDP;
- our client → official endpoint по H2/UDP и H3/UDP;
- IPv4 и IPv6 target;
- несколько flows в одной session;
- idle timeout и reopen;
- корректное поле `App Name`.

### 2.7. Auth и stats sanity-check

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

1. H2 `_check`
2. auth semantics на всех pseudo-host path
3. outbound `clientRandom`
4. `_icmp`
5. observable server behavior
6. полный UDP interop matrix
7. auth/stats sanity-check
8. TrustTunnel + H2/TCP + REALITY
9. TrustTunnel + H2/UDP + REALITY
10. R&D по TrustTunnel + H3 + REALITY
11. client-side parity fields после REALITY
12. нормализация вокруг `streamSettings`
13. full TLS/REALITY surface
14. common outbound features
15. common inbound features
16. `_icmp` в routing/policy/stats модели Xray
17. dynamic user management
18. финальная матрица совместимости и validator
