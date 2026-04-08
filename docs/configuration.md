# TrustTunnel Configuration Guide

Russian version: [configuration.ru.md](configuration.ru.md)

This guide explains how to write public, deployment-neutral TrustTunnel configs for this fork of Xray-core.

## 1. Quick model

TrustTunnel is available as both:

- an inbound protocol: `protocol: "trusttunnel"`
- an outbound protocol: `protocol: "trusttunnel"`

Validated transport and security combinations:

- HTTP/2 over TLS
- HTTP/2 over REALITY
- HTTP/3 over TLS

Validated transport selection modes:

- `transport: "http2"`
- `transport: "http3"`
- `transport: "auto"`

Validated payload paths:

- TCP CONNECT
- UDP multiplexing via `_udp2`
- ICMP multiplexing via `_icmp`
- health-check path via `_check`

For `HTTP/2 over REALITY`, use `streamSettings.security = "reality"`. This path does not use the regular certificate-chain trust model in the same way as `HTTP/2 over TLS` or `HTTP/3 over TLS`.

## 2. Minimal vs recommended examples

This guide uses two kinds of examples:

- minimal examples show the shortest valid config shape
- recommended examples show the better default for real deployments

In practice, start from a recommended example unless you explicitly need the smallest possible config.

## 3. Supported transport and security combinations

| Combination | Status | Notes |
| --- | --- | --- |
| HTTP/2 over TLS | Supported | Main certificate-based H2 path; supports optional `antiDpi=true` |
| HTTP/2 over REALITY | Supported | Uses `streamSettings.security = "reality"`; supports optional `antiDpi=true` |
| HTTP/3 over TLS | Supported | H3 path over QUIC |
| HTTP/3 over REALITY | Unsupported | Current REALITY runtime is TCP-stream based |

Transport selection behavior:

- `transport: "http2"` forces the HTTP/2 path.
- `transport: "http3"` prefers HTTP/3 and falls back to HTTP/2 on transport-level H3 connect failures.
- `transport: "auto"` prefers HTTP/3 when compatible, falls back to HTTP/2 on transport-level H3 connect failures, and bypasses HTTP/3 entirely when the config requires the TCP-based HTTP/2 path.

Additional limits:

- `antiDpi=true` is supported on `HTTP/2 over TLS` and `HTTP/2 over REALITY`. With `transport: "auto"`, it bypasses HTTP/3 and goes directly to HTTP/2.
- UDP domain targets are not documented as a supported product path. Use IP targets for UDP.
- With `hasIpv6=false`, domain targets require `targetStrategy: "useipv4"` or `"forceipv4"`.

## 4. Outbound quick start

### 4.1. Minimal HTTP/2 over TLS outbound

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

Recommended addition:

```json
"clientRandom": "deadbeef"
```

Optional anti-DPI addition for `HTTP/2 over TLS` only:

```json
"antiDpi": true
```

Rules:

- it requires `streamSettings.security = "tls"`
- it also works with `streamSettings.security = "reality"` on `HTTP/2`
- it is rejected for `HTTP/3`
- the current runtime implements it by splitting the first TCP-based ClientHello write

Tracked examples:

- minimal: [../testing/trusttunnel/client_h2.json](../testing/trusttunnel/client_h2.json)
- recommended: [../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json)
- anti-DPI: [../testing/trusttunnel/client_h2_antidpi.json](../testing/trusttunnel/client_h2_antidpi.json)

### 4.2. Minimal HTTP/2 over REALITY outbound

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

Recommended addition:

```json
"clientRandom": "deadbeef"
```

Optional anti-DPI addition:

```json
"antiDpi": true
```

Rules:

- `streamSettings.security` must be `"reality"`.
- `realitySettings.serverName` must match `settings.hostname`.
- `publicKey`, `shortId`, and `fingerprint` must match the server.
- REALITY support is currently validated for HTTP/2 only.

Tracked example:

- recommended: [../testing/trusttunnel/our_client_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_to_remote_server_h2_reality.json)

### 4.3. Minimal HTTP/3 over TLS outbound

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

Recommended addition:

```json
"clientRandom": "deadbeef"
```

Rules:

- use `transport: "http3"`
- use TLS, not REALITY
- generic `tlsSettings` remain authoritative for verification and host identity
- ALPN must be `h3`

Tracked example:

- recommended: [../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json)

### 4.4. Automatic transport selection

Use:

```json
"transport": "auto"
```

Behavior:

- the client tries HTTP/3 first when the config is compatible with the QUIC path
- if the HTTP/3 CONNECT attempt fails at the transport stage, the client retries the same tunnel over HTTP/2
- if the config enables `antiDpi=true`, the client skips HTTP/3 and goes directly to the HTTP/2 path
- if the config uses REALITY, the client skips HTTP/3 and goes directly to the HTTP/2 path

This mode is validated for:

- TCP over TLS
- TCP over REALITY
- UDP mux over TLS

### 4.5. UDP outbound

Set:

```json
"udp": true
```

Validated scope:

- HTTP/2 UDP mux
- HTTP/3 UDP mux
- HTTP/2 UDP mux over REALITY

Use IP destinations for UDP.

Tracked examples:

- [../testing/trusttunnel/our_client_udp_to_our_server_h2.json](../testing/trusttunnel/our_client_udp_to_our_server_h2.json)
- [../testing/trusttunnel/our_client_udp_to_our_server_h3.json](../testing/trusttunnel/our_client_udp_to_our_server_h3.json)
- [../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json)

## 5. `clientRandom` and `client_random` rules

### 5.1. What `clientRandom` is

`clientRandom` is an outbound setting that shapes the TLS ClientHello random so that the server can match the connection against TrustTunnel `client_random` rules.

Practical guidance:

- minimal examples may omit it
- recommended examples should set it explicitly
- if you do not have a reason to omit it, set it explicitly
- it is especially important when multiple clients share the same public IP or NAT

### 5.2. What `client_random` rules are

`client_random` rules are inbound access rules under `settings.rules[]`.

Each rule can match:

- `cidr`
- `clientRandom`
- both together
- neither, which makes the rule a catch-all rule

Each rule also carries:

- `allow: true`
- or `allow: false`

### 5.3. Rule evaluation order

Rule evaluation is exact:

- rules are checked from top to bottom
- the first matching rule wins
- if no rule matches, the request is allowed by default
- if the client did not send a usable `clientRandom`, any rule that contains `clientRandom` does not match

This is why there is no single unconditional answer to “will a client without `clientRandom` be rejected?”:

- if the server does not rely on a matching `client_random` rule, the connection can still be accepted
- if the server allows only specific `client_random` values and then ends the list with a catch-all deny rule, a client without a matching `clientRandom` will be denied

### 5.4. How to write `client_random` rules

`clientRandom` in a rule accepts:

- a hex prefix, for example `deadbeef`
- or a prefix with a mask, for example `d0adbeef/f0ffffff`

Example:

```json
"rules": [
  { "clientRandom": "deadbeef", "allow": true },
  { "allow": false }
]
```

Meaning:

- a client whose effective ClientHello random starts with `deadbeef` is allowed
- a client with no explicit `clientRandom`, or with a different value, does not match the first rule
- the second rule is a catch-all deny rule, so that client is denied

If you want allow-by-default behavior, do not add the final catch-all deny rule.

Tracked rule example:

- [../testing/trusttunnel/server_h2_rules.json](../testing/trusttunnel/server_h2_rules.json)

## 6. Outbound field reference

| Field | Type | Required | Meaning | Notes |
| --- | --- | --- | --- | --- |
| `address` | string | Yes | TrustTunnel server address | IP or domain |
| `port` | integer | Yes | TrustTunnel server port | Usually `9443` in examples |
| `username` | string | Yes | Username for TrustTunnel auth | Must match server user |
| `password` | string | Yes | Password for TrustTunnel auth | Must match server user |
| `hostname` | string | Yes | Logical TrustTunnel host name | For REALITY, match `realitySettings.serverName` |
| `transport` | string | Yes | Transport selection | `http2`, `http3`, or `auto` |
| `udp` | boolean | No | Enables UDP mux path | Use IP targets |
| `skipVerification` | boolean | No | Allows insecure certificate verification behavior | Do not combine ambiguously with generic verify settings |
| `certificatePem` | string | No | Inline trusted PEM certificate | TLS path only |
| `certificatePemFile` | string | No | Path to trusted PEM certificate file | TLS path only |
| `clientRandom` | string | No, but strongly recommended | Shapes ClientHello random for `client_random` rules | Set it explicitly unless you have a reason not to |
| `hasIpv6` | boolean | No | Controls IPv6 target allowance | `false` blocks literal IPv6 and requires IPv4-only target strategy for domain targets |
| `postQuantumGroupEnabled` | boolean | No | Enables the post-quantum group profile where supported | Runtime-active for H2 TLS, H2 REALITY, and H3 TLS |
| `antiDpi` | boolean | No | Enables split-ClientHello anti-DPI behavior | Supported on `HTTP/2 over TLS` and `HTTP/2 over REALITY`; `auto` bypasses HTTP/3 and selects HTTP/2; explicit `http3` is rejected |

## 7. Inbound quick start

### 7.1. Minimal HTTP/2 over TLS inbound

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

### 7.2. Minimal HTTP/2 over REALITY inbound

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

### 7.3. Minimal HTTP/3 over TLS inbound

Use the same protocol with:

- `settings.transports: ["http3"]`
- inbound TLS ALPN `["h3"]`

Tracked example:

- [../testing/trusttunnel/server_h3.json](../testing/trusttunnel/server_h3.json)

## 8. Inbound field reference

| Field | Type | Required | Meaning | Notes |
| --- | --- | --- | --- | --- |
| `users` | array | Yes | TrustTunnel users accepted by the server | Each user needs `username` and `password`; `email` is useful for identity and stats |
| `hosts` | array | No | Compatibility host/certificate mapping | Do not treat it as a generic host-routing system |
| `transports` | array | No | Allowed transport list | Do not treat it as a generic transport-routing system |
| `rules` | array | No | Access rules evaluated before dispatch | See Section 5 |
| `authFailureStatusCode` | integer | No | HTTP status used for auth failure | `407` is the common value |
| `udp` | boolean | No | Enables UDP mux support | Required for `_udp2` |
| `allowPrivateNetworkConnections` | boolean | No | Allows private-network ICMP targets | Applies to `_icmp` |
| `icmp.interfaceName` | string | No | Outgoing interface name for ICMP | `_icmp` only |
| `icmp.requestTimeoutSecs` | integer | No | Per-request ICMP timeout in seconds | `_icmp` only |
| `icmp.recvMessageQueueCapacity` | integer | No | Reply queue capacity for ICMP runtime | `_icmp` only |
| `tlsHandshakeTimeoutSecs` | integer | No | TLS handshake timeout in seconds | Inbound timeout control |
| `clientListenerTimeoutSecs` | integer | No | Timeout for client listener stage | Inbound timeout control |
| `connectionEstablishmentTimeoutSecs` | integer | No | Timeout for establishing upstream connection | Inbound timeout control |
| `tcpConnectionsTimeoutSecs` | integer | No | TCP connection idle timeout in seconds | Inbound timeout control |
| `udpConnectionsTimeoutSecs` | integer | No | UDP session timeout in seconds | Inbound timeout control |
| `ipv6Available` | boolean | No | Controls IPv6 availability for `_icmp` runtime | `_icmp` only |

## 9. Boundary between `settings` and `streamSettings`

Generic Xray `streamSettings` are authoritative for TrustTunnel transport security. H3 uses a dedicated QUIC CONNECT path, but it still consumes the effective generic TLS verification and host-identity surface from `streamSettings`.

That means:

- `settings.hostname` may fill a missing `tlsSettings.serverName`
- `settings.skipVerification=true` may fill a missing `tlsSettings.allowInsecure=true`
- `settings.skipVerification` must not override explicit generic verify settings
- `certificatePem` and `certificatePemFile` must not be mixed ambiguously with explicit generic verify settings

The validator rejects these combinations before runtime:

- `http3 + reality`
- `antiDpi=true` outside `HTTP/2 over TLS` or `HTTP/2 over REALITY`
- H2 `postQuantumGroupEnabled=true` without TLS or REALITY `streamSettings`
- `hostname` conflicting with generic `tlsSettings.serverName`
- `skipVerification=true` combined with explicit generic verify settings
- `skipVerification=true` combined with `certificatePem` or `certificatePemFile`
- `certificatePem` or `certificatePemFile` combined with explicit generic verify settings

## 10. Combining TrustTunnel with generic Xray features

Already validated:

- `proxySettings`
- `mux`
- `sendThrough = "origin"`
- outbound `targetStrategy = "useipv4"` and `"forceipv4"`
- inbound `sniffing + routeOnly`
- inbound generic TLS `rejectUnknownSni`
- dynamic inbound user management via `HandlerService`
- generic TLS options on HTTP/2 and HTTP/3 TLS paths:
  - `serverName`
  - custom-CA verify
  - `VerifyPeerCertByName`
  - `PinnedPeerCertSha256`
- generic TLS `Fingerprint` on HTTP/2 TLS paths

Windows note:

- if you use custom-CA verification through generic TLS settings on Windows, set `disableSystemRoot = true` so verification stays on the intended custom-CA path

## 11. Unsupported or guarded combinations

- `HTTP/3 over REALITY` is unsupported because the current REALITY runtime is TCP-stream based.
- `antiDpi=true` is guarded to `HTTP/2 over TLS` and `HTTP/2 over REALITY` only, because the current implementation only splits the first TCP-based ClientHello write. `transport: "auto"` handles this by selecting HTTP/2 directly.
- UDP domain targets are not a documented product path.
- `settings.hosts[]` is not a standalone generic host-routing layer.
- `settings.transports[]` is not a standalone generic transport-routing layer.

## 12. Tracked examples

Useful starting points:

- [../testing/trusttunnel/client_h2.json](../testing/trusttunnel/client_h2.json)
- [../testing/trusttunnel/server_h2.json](../testing/trusttunnel/server_h2.json)
- [../testing/trusttunnel/server_h2_reality_remote.json](../testing/trusttunnel/server_h2_reality_remote.json)
- [../testing/trusttunnel/server_h3.json](../testing/trusttunnel/server_h3.json)
- [../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json)
- [../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json)
- [../testing/trusttunnel/our_client_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_to_remote_server_h2_reality.json)
- [../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json)
- [../testing/trusttunnel/server_h2_rules.json](../testing/trusttunnel/server_h2_rules.json)

Replace all placeholder addresses, certificates, credentials, public keys, private keys, and short IDs with your own deployment values.
