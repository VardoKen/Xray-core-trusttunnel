# TrustTunnel Configuration Guide

Russian version: [configuration.ru.md](configuration.ru.md)

This document explains how to write configs for the TrustTunnel fork of Xray-core. It is a practical guide, not the authoritative behavior spec. When this file and `docs/current/*` differ, `docs/current/*` wins.

Primary references:

- Current state: [current/current-state.md](current/current-state.md)
- Operations: [current/operations.md](current/operations.md)
- Architecture: [current/architecture.md](current/architecture.md)
- Validation: [current/validation.md](current/validation.md)

## 1. Mental Model

TrustTunnel is available as both:

- an inbound protocol: `protocol: "trusttunnel"`
- an outbound protocol: `protocol: "trusttunnel"`

The current validated transport surface is:

- HTTP/2 over TLS
- HTTP/2 over REALITY
- HTTP/3 over TLS

The current validated payload surface is:

- TCP CONNECT
- UDP mux via `_udp2`
- ICMP mux via `_icmp`
- health-check path via `_check`

## 2. Transport Matrix

Supported:

- `transport: "http2"` with `streamSettings.security: "tls"`
- `transport: "http2"` with `streamSettings.security: "reality"`
- `transport: "http3"` with `streamSettings.security: "tls"`

Explicitly unsupported:

- `transport: "http3"` with `streamSettings.security: "reality"`
- `antiDpi: true`

Guarded limitations:

- UDP domain targets are not a validated product path. Use IP targets.
- `hasIpv6: false` requires `targetStrategy: "useipv4"` or `"forceipv4"` for domain targets.
- Inbound `hosts[]` and `transports[]` are not a generic host-routing layer by themselves.

## 3. Outbound Config

### 3.1. Minimum Shape

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

### 3.2. Outbound Fields That Matter In Runtime

Required in practice:

- `address`
- `port`
- `username`
- `password`
- `hostname`
- `transport`

Supported runtime fields:

- `udp`
- `skipVerification`
- `certificatePem`
- `certificatePemFile`
- `clientRandom`
- `hasIpv6`
- `postQuantumGroupEnabled`

Explicit unsupported field:

- `antiDpi`

### 3.3. Boundary Between `settings` And `streamSettings`

For non-HTTP3 paths, generic Xray `streamSettings.tlsSettings` are authoritative. That means:

- `settings.hostname` may fill a missing `tlsSettings.serverName`
- `settings.skipVerification=true` may fill a missing `tlsSettings.allowInsecure=true`
- `settings.skipVerification` must not override explicit generic verify settings
- `settings.certificatePem` and `settings.certificatePemFile` must not be combined with explicit generic verify surface in ambiguous ways

The validator rejects these combinations before runtime:

- H2 `postQuantumGroupEnabled=true` without TLS or REALITY `streamSettings`
- `http3 + reality`
- `antiDpi=true`
- `hostname` conflicting with generic `tlsSettings.serverName`
- `skipVerification=true` combined with explicit generic verify surface
- `skipVerification=true` combined with `certificatePem` or `certificatePemFile`
- `certificatePem` or `certificatePemFile` combined with explicit generic verify surface

### 3.4. Minimal HTTP/2 + TLS Outbound

```json
{
  "protocol": "trusttunnel",
  "settings": {
    "address": "127.0.0.1",
    "port": 9443,
    "username": "u1",
    "password": "p1",
    "hostname": "vpn.lab.local",
    "transport": "http2",
    "skipVerification": false,
    "certificatePemFile": "/path/to/server.crt",
    "udp": false
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "vpn.lab.local",
      "alpn": ["h2"]
    }
  }
}
```

Tracked example:

- [../testing/trusttunnel/client_h2.json](../testing/trusttunnel/client_h2.json)

### 3.5. Minimal HTTP/2 + REALITY Outbound

```json
{
  "protocol": "trusttunnel",
  "settings": {
    "address": "37.252.0.130",
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

Rules:

- `streamSettings.security` must be `"reality"`
- `realitySettings.serverName` must match `settings.hostname`
- `publicKey`, `shortId`, and `fingerprint` must match the server
- current REALITY support is validated for HTTP/2 only

Tracked example:

- [../testing/trusttunnel/our_client_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_to_remote_server_h2_reality.json)

### 3.6. Minimal HTTP/3 + TLS Outbound

```json
{
  "protocol": "trusttunnel",
  "settings": {
    "address": "127.0.0.1",
    "port": 9443,
    "username": "u1",
    "password": "p1",
    "hostname": "vpn.lab.local",
    "transport": "http3",
    "skipVerification": true,
    "udp": false
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "vpn.lab.local",
      "allowInsecure": true,
      "alpn": ["h3"]
    }
  }
}
```

Rules:

- use `transport: "http3"`
- use TLS, not REALITY
- ALPN must be `h3`

Tracked example:

- [../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json)

### 3.7. UDP Outbound

Set:

- `settings.udp: true`

Validated scope:

- HTTP/2 UDP mux
- HTTP/3 UDP mux
- HTTP/2 UDP mux over REALITY

Important rule:

- validated UDP destinations are IP literals, not domains

Tracked examples:

- [../testing/trusttunnel/our_client_udp_to_our_server_h2.json](../testing/trusttunnel/our_client_udp_to_our_server_h2.json)
- [../testing/trusttunnel/our_client_udp_to_our_server_h3.json](../testing/trusttunnel/our_client_udp_to_our_server_h3.json)
- [../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json)

### 3.8. `clientRandom`

`clientRandom` is a real runtime feature for HTTP/2 and HTTP/3.

Use it when:

- the server enforces TrustTunnel rules by `client_random`

Result:

- outgoing TLS ClientHello random is shaped to match the configured TrustTunnel rule spec

Tracked examples:

- [../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json)
- [../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json)

### 3.9. `hasIpv6`, `postQuantumGroupEnabled`, `antiDpi`

`hasIpv6`:

- allows normal IPv6 behavior when `true`
- blocks literal IPv6 targets when `false`
- also blocks domain targets unless the outbound target strategy is `useipv4` or `forceipv4`

`postQuantumGroupEnabled`:

- real runtime toggle
- for H2 TLS and H2 REALITY it changes the effective TLS/REALITY fingerprint profile
- for H3 TLS it changes curve preferences

`antiDpi`:

- not implemented as a runtime feature
- rejected explicitly

## 4. Inbound Config

### 4.1. Minimum HTTP/2 + TLS Inbound

```json
{
  "protocol": "trusttunnel",
  "listen": "0.0.0.0",
  "port": 9443,
  "settings": {
    "users": [
      { "email": "u1@lab", "username": "u1", "password": "p1" }
    ],
    "hosts": [
      {
        "hostname": "vpn.lab.local",
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

### 4.2. Minimum HTTP/3 + TLS Inbound

Use the same protocol with:

- `settings.transports: ["http3"]`
- inbound TLS ALPN `["h3"]`

Tracked example:

- [../testing/trusttunnel/server_h3.json](../testing/trusttunnel/server_h3.json)

### 4.3. Inbound Fields That Matter In Runtime

Validated runtime fields:

- `users`
- `rules`
- `authFailureStatusCode`
- `udp`
- `allowPrivateNetworkConnections` for `_icmp`
- `icmp.interfaceName`
- `icmp.requestTimeoutSecs`
- `icmp.recvMessageQueueCapacity`
- `tlsHandshakeTimeoutSecs`
- `clientListenerTimeoutSecs`
- `connectionEstablishmentTimeoutSecs`
- `tcpConnectionsTimeoutSecs`
- `udpConnectionsTimeoutSecs`
- `ipv6Available` for `_icmp`

Fields that should not be oversold:

- `hosts`
- `transports`

They are part of the compatibility surface and configuration model, but they are not a standalone generic routing system.

## 5. Combining TrustTunnel With Generic Xray Features

Already validated:

- `proxySettings`
- `mux`
- `sendThrough = "origin"`
- outbound `targetStrategy = "useipv4"` and `"forceipv4"`
- inbound `sniffing + routeOnly`
- inbound generic TLS `rejectUnknownSni`
- dynamic inbound user management via `HandlerService`
- generic TLS options on non-HTTP3 paths:
  - `serverName`
  - custom-CA verify
  - `VerifyPeerCertByName`
  - `PinnedPeerCertSha256`
  - `Fingerprint`

Windows note:

- if you rely on custom-CA authority verification through generic TLS settings on Windows, use `disableSystemRoot = true` to keep verification on the intended custom-CA path

## 6. How It Works

High-level runtime model:

- outbound opens TrustTunnel CONNECT over HTTP/2 or HTTP/3
- TCP uses the normal Xray dispatcher link
- UDP uses `_udp2` mux over the same TrustTunnel session
- ICMP uses `_icmp` mux with fixed-size request and reply frames
- `_check` is a reserved health-check path
- stats, routing, policy, and generic Xray transport features remain integrated through common Xray layers

## 7. Unsupported Or Guarded Combinations

Do not rely on these as working product paths:

- `http3 + reality`
- `antiDpi=true`
- UDP domain targets
- generic server host/cert selection only through `settings.hosts[]`
- generic server transport routing only through `settings.transports[]`
- lab-only keys or secrets committed into tracked files

## 8. Tracked Examples

Useful starting points:

- [../testing/trusttunnel/client_h2.json](../testing/trusttunnel/client_h2.json)
- [../testing/trusttunnel/server_h2.json](../testing/trusttunnel/server_h2.json)
- [../testing/trusttunnel/server_h3.json](../testing/trusttunnel/server_h3.json)
- [../testing/trusttunnel/our_client_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_to_remote_server_h2_reality.json)
- [../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json](../testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json)
- [../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json)
- [../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json](../testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json)

For exact runtime verdicts, certificates, and pass/fail markers, always check [current/validation.md](current/validation.md).
