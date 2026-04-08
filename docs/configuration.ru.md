# Руководство по конфигам TrustTunnel

English version: [configuration.md](configuration.md)

Этот документ объясняет, как писать публичные и deployment-neutral конфиги TrustTunnel для этого форка Xray-core.

## 1. Базовая модель

TrustTunnel доступен и как:

- inbound-протокол: `protocol: "trusttunnel"`
- outbound-протокол: `protocol: "trusttunnel"`

Подтверждённые transport/security-комбинации:

- HTTP/2 over TLS
- HTTP/2 over REALITY
- HTTP/3 over TLS

Подтверждённые режимы выбора transport:

- `transport: "http2"`
- `transport: "http3"`
- `transport: "auto"`

Подтверждённое поведение выбора server endpoint:

- упорядоченные списки `servers[]` с последовательным fallback по endpoint
- legacy-форма `address` + `port` для single-endpoint конфига

Подтверждённые payload-path:

- TCP CONNECT
- UDP-мультиплексирование через `_udp2`
- ICMP-мультиплексирование через `_icmp`
- путь health-check через `_check`

Подтверждённые серверные policy-механизмы:

- лимиты входящих соединений по клиентам с отдельными счётчиками для H1/H2 и H3
- явный HTTP `429 Too Many Requests` при превышении лимита

Для `HTTP/2 over REALITY` нужно использовать `streamSettings.security = "reality"`. Этот path не использует обычную certificate-chain model доверия так же, как `HTTP/2 over TLS` или `HTTP/3 over TLS`.

## 2. Минимальные и рекомендуемые примеры

В этом руководстве используются два типа примеров:

- минимальные примеры показывают кратчайшую валидную форму конфига
- рекомендуемые примеры показывают более правильный вариант по умолчанию для реальных deployment-сценариев

На практике лучше начинать с рекомендуемого примера, если тебе специально не нужен максимально короткий конфиг.

## 3. Поддержанные transport/security-комбинации

| Комбинация | Статус | Примечание |
| --- | --- | --- |
| HTTP/2 over TLS | Поддержано | Основной certificate-based H2 path; поддерживает опциональный `antiDpi=true` |
| HTTP/2 over REALITY | Поддержано | Использует `streamSettings.security = "reality"`; поддерживает опциональный `antiDpi=true` |
| HTTP/3 over TLS | Поддержано | H3 path поверх QUIC |
| HTTP/3 over REALITY | Не поддержано | Текущий REALITY runtime построен вокруг TCP stream layer |

Поведение выбора transport:

- `transport: "http2"` жёстко выбирает HTTP/2 path.
- `transport: "http3"` предпочитает HTTP/3 и переходит на HTTP/2 при transport-level ошибках поднятия H3 tunnel.
- `transport: "auto"` предпочитает HTTP/3, если конфиг совместим с QUIC path, переходит на HTTP/2 при transport-level ошибках H3 и сразу идёт в HTTP/2, когда конфиг требует TCP-based path.

Дополнительные ограничения:

- `antiDpi=true` поддерживается на `HTTP/2 over TLS` и `HTTP/2 over REALITY`. При `transport: "auto"` оно сразу переводит клиент в HTTP/2 path.
- UDP domain targets не описываются как поддержанный product path. Для UDP нужно использовать IP-назначения.
- При `hasIpv6=false` для domain targets нужен `targetStrategy: "useipv4"` или `"forceipv4"`.

## 4. Быстрый старт для outbound

### 4.1. Минимальный HTTP/2 over TLS outbound

```json
{
  "protocol": "trusttunnel",
  "settings": {
    "address": "server.example.com",
    "port": 9443,
    "username": "u1",
    "password": "p1",
    "hostname": "vpn.example.com",
    "transport": "http2",
    "udp": false
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "vpn.example.com",
      "alpn": ["h2"]
    }
  }
}
```

Рекомендуемое дополнение:

```json
"clientRandom": "deadbeef"
```

Опциональное anti-DPI дополнение только для `HTTP/2 over TLS`:

```json
"antiDpi": true
```

Правила:

- требует `streamSettings.security = "tls"`
- также работает с `streamSettings.security = "reality"` на `HTTP/2`
- отклоняется для `HTTP/3`
- текущий runtime реализует это как split первой TCP-based записи ClientHello

Tracked examples:

- минимальный: [../testing/trusttunnel/client_h2.json](../testing/trusttunnel/client_h2.json)
- рекомендуемый: [../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json)
- anti-DPI: [../testing/trusttunnel/client_h2_antidpi.json](../testing/trusttunnel/client_h2_antidpi.json)

### 4.2. Минимальный HTTP/2 over REALITY outbound

```json
{
  "protocol": "trusttunnel",
  "settings": {
    "address": "server.example.com",
    "port": 9443,
    "username": "u1",
    "password": "p1",
    "hostname": "www.example.com",
    "transport": "http2",
    "hasIpv6": true,
    "udp": false
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "fingerprint": "chrome",
      "serverName": "www.example.com",
      "publicKey": "REPLACE_ME",
      "shortId": "0123456789abcdef",
      "spiderX": "/"
    }
  }
}
```

Рекомендуемое дополнение:

```json
"clientRandom": "deadbeef"
```

Опциональное anti-DPI дополнение:

```json
"antiDpi": true
```

Правила:

- `streamSettings.security` должен быть `"reality"`
- `realitySettings.serverName` должен совпадать с `settings.hostname`
- `publicKey`, `shortId` и `fingerprint` должны соответствовать серверу
- текущая поддержка REALITY подтверждена только для HTTP/2

Tracked example:

- рекомендуемый: [../testing/trusttunnel/our_client_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_to_remote_server_h2_reality.json)

### 4.3. Минимальный HTTP/3 over TLS outbound

```json
{
  "protocol": "trusttunnel",
  "settings": {
    "address": "server.example.com",
    "port": 9443,
    "username": "u1",
    "password": "p1",
    "hostname": "vpn.example.com",
    "transport": "http3",
    "udp": false
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "vpn.example.com",
      "alpn": ["h3"]
    }
  }
}
```

Рекомендуемое дополнение:

```json
"clientRandom": "deadbeef"
```

Правила:

- использовать `transport: "http3"`
- использовать TLS, а не REALITY
- generic `tlsSettings` остаются authoritative для verify surface и host identity
- ALPN должен быть `h3`

Tracked example:

- рекомендуемый: [../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json)

### 4.4. Автоматический выбор transport

Используй:

```json
"transport": "auto"
```

Поведение:

- клиент сначала пробует HTTP/3, если конфиг совместим с QUIC path
- если HTTP/3 CONNECT ломается на transport stage, тот же tunnel перезапускается через HTTP/2
- если включен `antiDpi=true`, клиент пропускает HTTP/3 и сразу идёт в HTTP/2 path
- если конфиг использует REALITY, клиент пропускает HTTP/3 и сразу идёт в HTTP/2 path

Этот режим подтверждён для:

- TCP over TLS
- TCP over REALITY
- UDP mux over TLS

### 4.5. Несколько outbound server endpoint

Используй `servers`, когда нужен не один, а несколько TrustTunnel endpoint:

```json
"servers": [
  { "address": "tt-a.example.com", "port": 9443 },
  { "address": "tt-b.example.com", "port": 9443 }
]
```

Правила:

- клиент пробует endpoint в том порядке, в котором они перечислены
- если endpoint ломается до установления tunnel, клиент переходит к следующему endpoint
- если tunnel уже установлен, runtime-ошибка на нём не вызывает скрытого переключения на другой endpoint
- `servers` нельзя смешивать с shorthand-полями `address` и `port` в одном outbound-конфиге
- shorthand `address` + `port` остаётся валидным и трактуется как single-endpoint конфиг

Рекомендуемое применение:

- `address` + `port` для самого короткого single-endpoint конфига
- `servers[]` для явного failover между несколькими TrustTunnel-серверами

Tracked example:

- [../testing/trusttunnel/client_h2_servers_fallback.json](../testing/trusttunnel/client_h2_servers_fallback.json)

### 4.6. UDP outbound

Нужно задать:

```json
"udp": true
```

Подтверждённый scope:

- HTTP/2 UDP mux
- HTTP/3 UDP mux
- HTTP/2 UDP mux over REALITY

Для UDP нужно использовать IP-назначения.

Tracked examples:

- [../testing/trusttunnel/our_client_udp_to_our_server_h2.json](../testing/trusttunnel/our_client_udp_to_our_server_h2.json)
- [../testing/trusttunnel/our_client_udp_to_our_server_h3.json](../testing/trusttunnel/our_client_udp_to_our_server_h3.json)
- [../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json)

## 5. `clientRandom` и `client_random rules`

### 5.1. Что такое `clientRandom`

`clientRandom` — это outbound-поле, которое формирует TLS ClientHello random так, чтобы сервер мог сопоставить соединение с TrustTunnel `client_random` rules.

Практическое правило:

- в минимальных примерах его можно опустить
- в рекомендуемых примерах его лучше задавать явно
- если нет причины его не задавать, лучше задать его явно
- особенно это важно, когда несколько клиентов сидят за одним публичным IP или NAT

### 5.2. Что такое `client_random rules`

`client_random` rules — это inbound-правила доступа внутри `settings.rules[]`.

Каждое правило может матчить:

- `cidr`
- `clientRandom`
- оба поля сразу
- ни одно из них, и тогда это catch-all rule

Также каждое правило содержит:

- `allow: true`
- или `allow: false`

### 5.3. Порядок применения правил

Семантика правил точная:

- правила проверяются сверху вниз
- срабатывает первое совпавшее правило
- если не совпало ни одно правило, запрос разрешается по умолчанию
- если клиент не отправил пригодный `clientRandom`, правило с полем `clientRandom` не совпадёт

Именно поэтому на вопрос «будет ли клиент без `clientRandom` отклонён» нет одного ответа без условия:

- если сервер не опирается на совпадение по `client_random`, соединение может быть принято
- если сервер разрешает только определённые `client_random` и затем завершает список catch-all deny-правилом, клиент без подходящего `clientRandom` будет отклонён

### 5.4. Как писать `client_random` rules

`clientRandom` внутри правила допускает:

- hex-prefix, например `deadbeef`
- или prefix с mask, например `d0adbeef/f0ffffff`

Пример:

```json
"rules": [
  { "clientRandom": "deadbeef", "allow": true },
  { "allow": false }
]
```

Что это означает:

- клиент, у которого effective ClientHello random начинается с `deadbeef`, будет разрешён
- клиент без явного `clientRandom`, или с другим значением, не совпадёт с первым правилом
- второе правило является catch-all deny-правилом, поэтому такой клиент будет отклонён

Если тебе нужно allow-by-default поведение, не добавляй финальное catch-all deny-правило.

Tracked rule example:

- [../testing/trusttunnel/server_h2_rules.json](../testing/trusttunnel/server_h2_rules.json)

## 6. Справочник outbound-полей

| Поле | Тип | Обязательно | Назначение | Примечание |
| --- | --- | --- | --- | --- |
| `address` | string | Да, если не задан `servers` | Адрес TrustTunnel-сервера | IP или домен; shorthand для single-endpoint конфига |
| `port` | integer | Да, если не задан `servers` | Порт TrustTunnel-сервера | В примерах обычно `9443` |
| `servers` | array | Да, если не заданы `address` и `port` | Упорядоченный список TrustTunnel endpoint | Последовательный fallback в указанном порядке; не смешивать с `address` и `port` |
| `username` | string | Да | Имя пользователя для TrustTunnel auth | Должно совпадать с сервером |
| `password` | string | Да | Пароль для TrustTunnel auth | Должен совпадать с сервером |
| `hostname` | string | Да | Логическое имя хоста TrustTunnel | Для REALITY должно совпадать с `realitySettings.serverName` |
| `transport` | string | Да | Выбор транспорта | `http2`, `http3` или `auto` |
| `udp` | boolean | Нет | Включает UDP mux path | Использовать IP-назначения |
| `skipVerification` | boolean | Нет | Разрешает insecure certificate verification behavior | Не смешивать двусмысленно с generic verify settings |
| `certificatePem` | string | Нет | Inline trusted PEM certificate | Только для TLS-path |
| `certificatePemFile` | string | Нет | Путь к trusted PEM certificate file | Только для TLS-path |
| `clientRandom` | string | Нет, но крайне рекомендуется | Формирует ClientHello random для `client_random` rules | Лучше задавать явно, если нет причины этого не делать |
| `hasIpv6` | boolean | Нет | Управляет разрешением IPv6-целей | `false` режет literal IPv6 и требует IPv4-only target strategy для domain targets |
| `postQuantumGroupEnabled` | boolean | Нет | Включает post-quantum group profile там, где он поддержан | Runtime-active для H2 TLS, H2 REALITY и H3 TLS |
| `antiDpi` | boolean | Нет | Включает anti-DPI поведение через split ClientHello | Поддержано на `HTTP/2 over TLS` и `HTTP/2 over REALITY`; `auto` переводит трафик сразу в HTTP/2; явный `http3` отклоняется |

## 7. Быстрый старт для inbound

### 7.1. Минимальный HTTP/2 over TLS inbound

```json
{
  "protocol": "trusttunnel",
  "listen": "0.0.0.0",
  "port": 9443,
  "settings": {
    "users": [
      { "email": "u1@example.com", "username": "u1", "password": "p1" }
    ],
    "hosts": [
      {
        "hostname": "vpn.example.com",
        "certificateFile": "/path/to/server.crt",
        "keyFile": "/path/to/server.key"
      }
    ],
    "transports": ["http2"],
    "rules": [],
    "authFailureStatusCode": 407,
    "udp": false
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "alpn": ["h2"],
      "certificates": [
        {
          "certificateFile": "/path/to/server.crt",
          "keyFile": "/path/to/server.key"
        }
      ]
    }
  }
}
```

Tracked example:

- [../testing/trusttunnel/server_h2.json](../testing/trusttunnel/server_h2.json)

### 7.2. Минимальный HTTP/2 over REALITY inbound

```json
{
  "protocol": "trusttunnel",
  "listen": "0.0.0.0",
  "port": 9443,
  "settings": {
    "users": [
      { "email": "u1@example.com", "username": "u1", "password": "p1" }
    ],
    "transports": ["http2"],
    "rules": [],
    "authFailureStatusCode": 407,
    "udp": false
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "dest": "www.example.com:443",
      "serverNames": ["www.example.com"],
      "privateKey": "REPLACE_ME",
      "shortIds": ["0123456789abcdef"]
    }
  }
}
```

Tracked example:

- [../testing/trusttunnel/server_h2_reality_remote.json](../testing/trusttunnel/server_h2_reality_remote.json)

### 7.3. Минимальный HTTP/3 over TLS inbound

Используется тот же протокол, но с:

- `settings.transports: ["http3"]`
- inbound TLS ALPN `["h3"]`

Tracked example:

- [../testing/trusttunnel/server_h3.json](../testing/trusttunnel/server_h3.json)

### 7.4. Рекомендуемая политика лимитов входящих соединений

Пример добавлений внутрь `settings`:

```json
{
  "users": [
    { "email": "u1@example.com", "username": "u1", "password": "p1", "maxHttp2Conns": 1, "maxHttp3Conns": 2 },
    { "email": "u2@example.com", "username": "u2", "password": "p2" }
  ],
  "defaultMaxHttp2ConnsPerClient": 2,
  "defaultMaxHttp3ConnsPerClient": 4
}
```

Правила:

- `users[].maxHttp2Conns` и `users[].maxHttp3Conns` переопределяют значения по умолчанию, если они не равны `0`.
- `0` означает отсутствие персонального override. Если и персональное значение, и default равны `0`, то соответствующий счётчик не ограничен.
- HTTP/1 и HTTP/2 используют общий счётчик лимитов.
- HTTP/3 использует отдельный счётчик.
- `_check` не расходует слот.
- обычный CONNECT, `_udp2` и `_icmp` расходуют слот.
- при превышении лимита сервер явно отвечает HTTP `429 Too Many Requests`.

Tracked example:

- [../testing/trusttunnel/server_h2_limits.json](../testing/trusttunnel/server_h2_limits.json)

## 8. Справочник inbound-полей

| Поле | Тип | Обязательно | Назначение | Примечание |
| --- | --- | --- | --- | --- |
| `users` | array | Да | Пользователи TrustTunnel, которых принимает сервер | У каждого должны быть `username` и `password`; `email` полезен для identity и stats |
| `users[].maxHttp2Conns` | integer | Нет | Персональное переопределение лимита для общего счётчика HTTP/1 и HTTP/2 | `0` означает использовать `defaultMaxHttp2ConnsPerClient`; если и там `0`, счётчик не ограничен |
| `users[].maxHttp3Conns` | integer | Нет | Персональное переопределение лимита для счётчика HTTP/3 | `0` означает использовать `defaultMaxHttp3ConnsPerClient`; если и там `0`, счётчик не ограничен |
| `hosts` | array | Нет | Compatibility host/certificate mapping | Не надо трактовать как generic host-routing system |
| `transports` | array | Нет | Список разрешённых transport | Не надо трактовать как generic transport-routing system |
| `rules` | array | Нет | Правила доступа, которые применяются до dispatch | См. раздел 5 |
| `authFailureStatusCode` | integer | Нет | HTTP status для auth-failure | Типичное значение `407` |
| `defaultMaxHttp2ConnsPerClient` | integer | Нет | Лимит по умолчанию для общего счётчика HTTP/1 и HTTP/2 | `0` означает отсутствие лимита, если нет персонального override |
| `defaultMaxHttp3ConnsPerClient` | integer | Нет | Лимит по умолчанию для счётчика HTTP/3 | `0` означает отсутствие лимита, если нет персонального override |
| `udp` | boolean | Нет | Включает поддержку UDP mux | Нужен для `_udp2` |
| `allowPrivateNetworkConnections` | boolean | Нет | Разрешает private-network ICMP-targets | Относится к `_icmp` |
| `icmp.interfaceName` | string | Нет | Имя исходящего интерфейса для ICMP | Только для `_icmp` |
| `icmp.requestTimeoutSecs` | integer | Нет | Таймаут одного ICMP-запроса в секундах | Только для `_icmp` |
| `icmp.recvMessageQueueCapacity` | integer | Нет | Ёмкость очереди reply-сообщений ICMP runtime | Только для `_icmp` |
| `tlsHandshakeTimeoutSecs` | integer | Нет | Таймаут TLS-handshake в секундах | Контроль inbound timeout |
| `clientListenerTimeoutSecs` | integer | Нет | Таймаут стадии client listener | Контроль inbound timeout |
| `connectionEstablishmentTimeoutSecs` | integer | Нет | Таймаут установления upstream-соединения | Контроль inbound timeout |
| `tcpConnectionsTimeoutSecs` | integer | Нет | Таймаут неактивности TCP-соединения в секундах | Контроль inbound timeout |
| `udpConnectionsTimeoutSecs` | integer | Нет | Таймаут UDP-сессии в секундах | Контроль inbound timeout |
| `ipv6Available` | boolean | Нет | Управляет доступностью IPv6 для `_icmp` runtime | Только для `_icmp` |

Семантика лимитера:

- H1 и H2 используют общий счётчик, потому что проходят через один TCP-side path допуска tunnel-соединений.
- H3 использует отдельный счётчик.
- `_check` не подпадает под connection limits.
- `_udp2` и `_icmp` учитываются в том же счётчике, что и обычный CONNECT на соответствующем transport.
- При превышении лимита сервер отклоняет запрос с HTTP `429 Too Many Requests`.

## 9. Граница между `settings` и `streamSettings`

Generic Xray `streamSettings` authoritative для transport security TrustTunnel. H3 использует отдельный QUIC CONNECT path, но verify surface и host identity всё равно берутся из effective generic `streamSettings`.

Это означает:

- `settings.hostname` может заполнить отсутствующий `tlsSettings.serverName`
- `settings.skipVerification=true` может заполнить отсутствующий `tlsSettings.allowInsecure=true`
- `settings.skipVerification` не должен переопределять явно заданные generic verify settings
- `certificatePem` и `certificatePemFile` нельзя двусмысленно смешивать с явно заданными generic verify settings

Validator режет эти комбинации ещё до runtime:

- `http3 + reality`
- `antiDpi=true` вне `HTTP/2 over TLS` или `HTTP/2 over REALITY`
- H2 `postQuantumGroupEnabled=true` без TLS или REALITY `streamSettings`
- конфликт `hostname` с generic `tlsSettings.serverName`
- `skipVerification=true` вместе с явно заданными generic verify settings
- `skipVerification=true` вместе с `certificatePem` или `certificatePemFile`
- `certificatePem` или `certificatePemFile` вместе с явно заданными generic verify settings

## 10. Сочетание TrustTunnel с общими возможностями Xray

Уже подтверждено:

- `proxySettings`
- `mux`
- `sendThrough = "origin"`
- outbound `targetStrategy = "useipv4"` и `"forceipv4"`
- inbound `sniffing + routeOnly`
- inbound generic TLS `rejectUnknownSni`
- динамическое управление inbound-пользователями через `HandlerService`
- generic TLS-опции на HTTP/2 и HTTP/3 TLS path:
  - `serverName`
  - custom-CA verify
  - `VerifyPeerCertByName`
  - `PinnedPeerCertSha256`
- generic TLS `Fingerprint` на HTTP/2 TLS path

Примечание для Windows:

- если на Windows используется custom-CA verify через generic TLS settings, ставь `disableSystemRoot = true`, чтобы проверка действительно шла по intended custom-CA path

## 11. Неподдержанные или guarded-комбинации

- `HTTP/3 over REALITY` не поддерживается, потому что текущий REALITY runtime построен вокруг TCP stream layer.
- `antiDpi=true` ограничен только `HTTP/2 over TLS` и `HTTP/2 over REALITY`, потому что текущая реализация умеет делать split только первой TCP-based записи ClientHello. `transport: "auto"` обрабатывает это через прямой выбор HTTP/2.
- UDP domain targets не являются документированным product path.
- `settings.hosts[]` не является самостоятельным generic host-routing layer.
- `settings.transports[]` не является самостоятельным generic transport-routing layer.

## 12. Tracked examples

Полезные стартовые шаблоны:

- [../testing/trusttunnel/client_h2.json](../testing/trusttunnel/client_h2.json)
- [../testing/trusttunnel/server_h2.json](../testing/trusttunnel/server_h2.json)
- [../testing/trusttunnel/server_h2_limits.json](../testing/trusttunnel/server_h2_limits.json)
- [../testing/trusttunnel/server_h2_reality_remote.json](../testing/trusttunnel/server_h2_reality_remote.json)
- [../testing/trusttunnel/server_h3.json](../testing/trusttunnel/server_h3.json)
- [../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json)
- [../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json)
- [../testing/trusttunnel/our_client_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_to_remote_server_h2_reality.json)
- [../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json)
- [../testing/trusttunnel/server_h2_rules.json](../testing/trusttunnel/server_h2_rules.json)

Во всех placeholder-примерах нужно заменить адреса, сертификаты, учётные данные, public keys, private keys и short IDs на свои значения.
