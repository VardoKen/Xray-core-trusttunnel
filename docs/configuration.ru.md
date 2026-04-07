# Руководство По Конфигам TrustTunnel

English version: [configuration.md](configuration.md)

Этот документ объясняет, как писать конфиги для форка Xray-core с TrustTunnel. Это публичное и deployment-neutral руководство, сфокусированное на поддержанных паттернах конфигурации.

## 1. Базовая Модель

TrustTunnel доступен как:

- inbound-протокол: `protocol: "trusttunnel"`
- outbound-протокол: `protocol: "trusttunnel"`

Текущая подтверждённая transport-поверхность:

- HTTP/2 over TLS
- HTTP/2 over REALITY
- HTTP/3 over TLS

Текущая подтверждённая payload-поверхность:

- TCP CONNECT
- UDP mux через `_udp2`
- ICMP mux через `_icmp`
- health-check path через `_check`

## 2. Матрица Транспортов

Поддержано:

- `transport: "http2"` с `streamSettings.security: "tls"`
- `transport: "http2"` с `streamSettings.security: "reality"`
- `transport: "http3"` с `streamSettings.security: "tls"`

Явно не поддержано:

- `transport: "http3"` с `streamSettings.security: "reality"`
- `antiDpi: true`

Защитные ограничения:

- UDP domain targets не считаются подтверждённым product path. Использовать IP-адреса.
- `hasIpv6: false` требует `targetStrategy: "useipv4"` или `"forceipv4"` для domain targets.
- inbound `hosts[]` и `transports[]` не являются сами по себе универсальным host-routing layer.

## 3. Outbound Конфиг

### 3.1. Минимальная Форма

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

### 3.2. Поля Outbound, Которые Реально Участвуют В Runtime

Практически обязательны:

- `address`
- `port`
- `username`
- `password`
- `hostname`
- `transport`

Поддержанные runtime-поля:

- `udp`
- `skipVerification`
- `certificatePem`
- `certificatePemFile`
- `clientRandom`
- `hasIpv6`
- `postQuantumGroupEnabled`

Явно unsupported поле:

- `antiDpi`

### 3.3. Граница Между `settings` И `streamSettings`

Для non-HTTP3 path authoritative являются generic Xray `streamSettings.tlsSettings`. Это означает:

- `settings.hostname` может только заполнить отсутствующий `tlsSettings.serverName`
- `settings.skipVerification=true` может только заполнить отсутствующий `tlsSettings.allowInsecure=true`
- `settings.skipVerification` не должен переопределять explicit generic verify settings
- `settings.certificatePem` и `settings.certificatePemFile` нельзя комбинировать с explicit generic verify surface двусмысленно

Validator режет эти комбинации ещё до runtime:

- H2 `postQuantumGroupEnabled=true` без TLS или REALITY `streamSettings`
- `http3 + reality`
- `antiDpi=true`
- конфликт `hostname` с generic `tlsSettings.serverName`
- `skipVerification=true` вместе с explicit generic verify surface
- `skipVerification=true` вместе с `certificatePem` или `certificatePemFile`
- `certificatePem` или `certificatePemFile` вместе с explicit generic verify surface

### 3.4. Минимальный HTTP/2 + TLS Outbound

```json
{
  "protocol": "trusttunnel",
  "settings": {
    "address": "127.0.0.1",
    "port": 9443,
    "username": "u1",
    "password": "p1",
    "hostname": "vpn.example.com",
    "transport": "http2",
    "skipVerification": false,
    "certificatePemFile": "/path/to/server.crt",
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

Tracked example:

- [../testing/trusttunnel/client_h2.json](../testing/trusttunnel/client_h2.json)

### 3.5. Минимальный HTTP/2 + REALITY Outbound

```json
{
  "protocol": "trusttunnel",
  "settings": {
    "address": "server.example.com",
    "port": 9443,
    "username": "u1",
    "password": "p1",
    "hostname": "www.google.com",
    "transport": "http2",
    "hasIpv6": true,
    "skipVerification": false,
    "udp": false
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "fingerprint": "chrome",
      "serverName": "www.google.com",
      "publicKey": "REPLACE_ME",
      "shortId": "0123456789abcdef",
      "spiderX": "/"
    }
  }
}
```

Правила:

- `streamSettings.security` должен быть `"reality"`
- `realitySettings.serverName` должен совпадать с `settings.hostname`
- `publicKey`, `shortId` и `fingerprint` должны соответствовать серверу
- текущая поддержка REALITY подтверждена только для HTTP/2

Tracked example:

- [../testing/trusttunnel/our_client_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_to_remote_server_h2_reality.json)

### 3.6. Минимальный HTTP/3 + TLS Outbound

```json
{
  "protocol": "trusttunnel",
  "settings": {
    "address": "127.0.0.1",
    "port": 9443,
    "username": "u1",
    "password": "p1",
    "hostname": "vpn.example.com",
    "transport": "http3",
    "skipVerification": true,
    "udp": false
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "vpn.example.com",
      "allowInsecure": true,
      "alpn": ["h3"]
    }
  }
}
```

Правила:

- использовать `transport: "http3"`
- использовать TLS, а не REALITY
- ALPN должен быть `h3`

Tracked example:

- [../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json)

### 3.7. UDP Outbound

Нужно задать:

- `settings.udp: true`

Подтверждённый scope:

- HTTP/2 UDP mux
- HTTP/3 UDP mux
- HTTP/2 UDP mux поверх REALITY

Важное правило:

- подтверждены только UDP назначения в виде IP literal, не домены

Tracked examples:

- [../testing/trusttunnel/our_client_udp_to_our_server_h2.json](../testing/trusttunnel/our_client_udp_to_our_server_h2.json)
- [../testing/trusttunnel/our_client_udp_to_our_server_h3.json](../testing/trusttunnel/our_client_udp_to_our_server_h3.json)
- [../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json)

### 3.8. `clientRandom`

`clientRandom` является реальной runtime-функцией для HTTP/2 и HTTP/3.

Использовать, когда:

- сервер применяет TrustTunnel rules по `client_random`

Результат:

- исходящий TLS ClientHello random формируется так, чтобы соответствовать configured TrustTunnel rule spec

Tracked examples:

- [../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json)
- [../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json)

### 3.9. `hasIpv6`, `postQuantumGroupEnabled`, `antiDpi`

`hasIpv6`:

- при `true` оставляет обычное IPv6-поведение
- при `false` режет literal IPv6 targets
- также режет domain targets, если outbound `targetStrategy` не равен `useipv4` или `forceipv4`

`postQuantumGroupEnabled`:

- это реальный runtime-toggle
- для H2 TLS и H2 REALITY меняет effective TLS/REALITY fingerprint profile
- для H3 TLS меняет curve preferences

`antiDpi`:

- как runtime-функция не реализован
- явно отклоняется

## 4. Inbound Конфиг

### 4.1. Минимальный HTTP/2 + TLS Inbound

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

### 4.2. Минимальный HTTP/3 + TLS Inbound

Используется тот же протокол, но с:

- `settings.transports: ["http3"]`
- inbound TLS ALPN `["h3"]`

Tracked example:

- [../testing/trusttunnel/server_h3.json](../testing/trusttunnel/server_h3.json)

### 4.3. Inbound Поля, Которые Реально Участвуют В Runtime

Подтверждённые runtime-поля:

- `users`
- `rules`
- `authFailureStatusCode`
- `udp`
- `allowPrivateNetworkConnections` для `_icmp`
- `icmp.interfaceName`
- `icmp.requestTimeoutSecs`
- `icmp.recvMessageQueueCapacity`
- `tlsHandshakeTimeoutSecs`
- `clientListenerTimeoutSecs`
- `connectionEstablishmentTimeoutSecs`
- `tcpConnectionsTimeoutSecs`
- `udpConnectionsTimeoutSecs`
- `ipv6Available` для `_icmp`

Поля, которые нельзя переобещать:

- `hosts`
- `transports`

Они входят в compatibility surface и config model, но не являются самостоятельной общей routing-системой.

## 5. Сочетание TrustTunnel С Общими Возможностями Xray

Уже подтверждено:

- `proxySettings`
- `mux`
- `sendThrough = "origin"`
- outbound `targetStrategy = "useipv4"` и `"forceipv4"`
- inbound `sniffing + routeOnly`
- generic inbound TLS `rejectUnknownSni`
- динамическое управление пользователями inbound через `HandlerService`
- generic TLS-опции на non-HTTP3 path:
  - `serverName`
  - custom-CA verify
  - `VerifyPeerCertByName`
  - `PinnedPeerCertSha256`
  - `Fingerprint`

Примечание для Windows:

- если используешь authority verify через custom CA в generic TLS settings, нужно ставить `disableSystemRoot = true`, чтобы проверка действительно шла по intended custom-CA path

## 6. Как Это Работает

Высокоуровневая runtime-модель:

- outbound открывает TrustTunnel CONNECT поверх HTTP/2 или HTTP/3
- TCP использует обычный dispatcher link Xray
- UDP использует `_udp2` mux внутри той же TrustTunnel session
- ICMP использует `_icmp` mux с fixed-size request/reply frame
- `_check` является reserved health-check path
- stats, routing, policy и generic transport-возможности Xray остаются интегрированы через общие слои Xray

## 7. Неподдержанные Или Guarded Комбинации

Нельзя считать рабочими product path:

- `http3 + reality`
- `antiDpi=true`
- UDP domain targets
- generic server host/cert selection только через `settings.hosts[]`
- generic server transport routing только через `settings.transports[]`
- deployment-specific ключи или secrets в tracked files репозитория

## 8. Tracked Examples

Полезные стартовые шаблоны:

- [../testing/trusttunnel/client_h2.json](../testing/trusttunnel/client_h2.json)
- [../testing/trusttunnel/server_h2.json](../testing/trusttunnel/server_h2.json)
- [../testing/trusttunnel/server_h3.json](../testing/trusttunnel/server_h3.json)
- [../testing/trusttunnel/our_client_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_to_remote_server_h2_reality.json)
- [../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json)
- [../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json)
- [../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json)

Для реальных deployment нужно заменить все placeholder hostnames, сертификаты, учётные данные и ключи на свои.
