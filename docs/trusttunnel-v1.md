# TrustTunnel v1 MVP

## Цель этапа
Добиться, чтобы xray-core:
- принимал `protocol: "trusttunnel"` в inbound;
- принимал `protocol: "trusttunnel"` в outbound;
- успешно парсил JSON settings;
- успешно создавал protobuf config;
- успешно регистрировал inbound/outbound handler;
- стартовал с stub-конфигом без unknown protocol и без ошибок парсинга.

## Что входит в текущий checkpoint
- inbound protocol: trusttunnel
- outbound protocol: trusttunnel
- auth: username/password
- transport enums: http2, http3
- hosts
- rules
- client_random
- tls hostname / certificate fields
- udp flag
- registration через common.RegisterConfig
- JSON -> protobuf builder в infra/conf

## Что НЕ реализуется на этом шаге
- реальный HTTP/2 transport
- реальный HTTP/3 transport
- реальный TCP forwarding
- реальный UDP forwarding
- UserManager логика
- stats
- interop

## Критерий успеха
Бинарь xray-tt стартует с `server_stub.json`:
- без `unknown config id: trusttunnel`
- без `unknown protocol: trusttunnel`
- без ошибки Build() для trusttunnel settings
