# TrustTunnel / Xray-Core — roadmap

Статус: current
Дата фиксации: 2026-04-07
База roadmap: состояние проекта после закрытия `_icmp` protocol/runtime gap, H2/H3 official `_icmp` interop, product-level Linux TUN path, auth semantics на pseudo-host path, outbound clientRandom, полного UDP interop matrix, auth/stats sanity-check, observable timeout surface, client-side `postQuantumGroupEnabled`, `hasIpv6` domain-target guard, explicit `antiDpi` reject, H3 raw-stream tunnel fix и clean-head live traffic matrix
Область истины: только открытые задачи после закрытия H3 rules, ложного `H3_NO_ERROR`, legacy H3-path, H2 `_check`, auth semantics на pseudo-host path, outbound clientRandom, `_icmp` protocol/runtime surface, полного UDP interop matrix, auth/stats sanity-check, observable timeout surface и immediate client-side parity gaps после REALITY
Не использовать для: фиксации уже закрытых багов и исторической хронологии

## 1. Принцип чтения roadmap

Этот документ не повторяет уже закрытые H3-дефекты, не переоткрывает закрытый H2 `_check` и не возвращает auth/stats sanity-check или observable timeout surface в список открытых проблем без новых доказательств.

Текущее направление разработки:
1. не переоткрывать уже закрытый H2 production path по REALITY без новых доказательств;
2. довести TrustTunnel до корректной интеграции с общими механизмами Xray-Core;
3. не переоткрывать H3 + REALITY как “просто ещё один parity-gap”: current R&D уже упёрся в stop-factor текущего Xray transport layer.

Переоткрывать закрытую H3-тройку можно только при появлении более новых доказательств, чем фиксация `99e59352`.

## 2. REALITY после базовой совместимости

### 2.1. Архитектурная точка внедрения

REALITY должен внедряться через общий Xray `streamSettings.security`, а не через trusttunnel-specific `settings`.

### 2.2. Закрытый production-path

Закрыто real-traffic retest на 2026-04-06 / `ae621d24`, затем повторно подтверждено current-head smoke на 2026-04-06 / `c6ff745b`:
- TrustTunnel + H2/TCP + REALITY;
- TrustTunnel + H2/UDP + REALITY.

Практически значимый итог:
- REALITY на H2 больше не является открытым production-gap;
- текущий runtime идёт через общий Xray `streamSettings.security = "reality"`, а не через trusttunnel-specific поле;
- отдельным post-fix verdict зафиксировано, что H2 path не должен падать в HTTP/1.1 fallback только из-за пустого negotiated ALPN у REALITY-wrapper.

### 2.3. H3 + REALITY stop-factor

R&D по TrustTunnel + H3 + REALITY завершён техническим стоп-фактором:
- current Xray REALITY surface работает на уровне TCP `net.Conn`, а не QUIC `PacketConn`;
- TrustTunnel outbound H3 path сейчас строит QUIC/TLS напрямую и не проходит через общий Xray `streamSettings.security` runtime;
- current runtime теперь явно режет `http3 + reality` на client и server сторонах вместо silent-misconfig.

Практический вывод:
- это не short-term parity task;
- future support возможен только после появления QUIC-capable REALITY transport/security layer в Xray core;
- до этого H2 + REALITY и H3 + TLS остаются раздельными validated paths.

### 2.4. Client-side parity после REALITY

Этот блок на текущем этапе закрыт для поддержанных H2/H3 + TLS и H2 + REALITY path:
- `post_quantum_group_enabled` wired в runtime через effective TLS/REALITY fingerprint и H3 TLS curve preferences;
- `has_ipv6` больше не ограничен literal-IPv6 gate: domain targets требуют outbound `targetStrategy useipv4/forceipv4`, а нарушение режется marker'ом `trusttunnel hasIpv6=false requires outbound targetStrategy useipv4/forceipv4 for domain targets`;
- `anti_dpi` перестал быть silent no-op и имеет explicit unsupported verdict, который уже покрывается live negative-case.

Практический вывод:
- client-side parity fields после REALITY больше не являются ближайшим открытым блоком;
- дальше нужен не ещё один parity-патч, а нормализация вокруг общей модели Xray.

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

1. нормализация вокруг `streamSettings`
2. full TLS/REALITY surface
3. common outbound features
4. common inbound features
5. `_icmp` в routing/policy/stats модели Xray
6. dynamic user management
7. финальная матрица совместимости и validator
