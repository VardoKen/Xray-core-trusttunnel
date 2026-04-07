# Xray-core TrustTunnel Fork

Russian version: [README.ru.md](README.ru.md)

This repository is a downstream fork of [XTLS/Xray-core](https://github.com/XTLS/Xray-core) that carries a production-focused TrustTunnel implementation and the related integration work inside Xray-core.

It exists for one reason: keep TrustTunnel as a maintained, testable Xray runtime instead of a loose prototype. The fork includes protocol support, config binding, validator guards, live-traffic regression checks, and current documentation for the exact behavior that is already confirmed.

## What This Fork Adds

- TrustTunnel inbound and outbound support in Xray-core.
- Validated HTTP/2 and HTTP/3 TCP paths.
- Validated HTTP/2 and HTTP/3 UDP mux paths.
- Validated HTTP/2 + REALITY path for TCP and UDP.
- TrustTunnel `_check`, `_udp2`, and `_icmp` protocol handling.
- TrustTunnel-specific config validation and compatibility guards.
- Runtime support for `clientRandom`, `postQuantumGroupEnabled`, and `hasIpv6` guards.
- Ongoing upstream sync with targeted regression audits outside TrustTunnel.

## Current Validated Scope

Authoritative current state lives in [docs/current/current-state.md](docs/current/current-state.md). At the moment this fork has confirmed:

- H2 TCP
- H3 TCP
- H2 UDP mux
- H3 UDP mux
- H2 TCP + REALITY
- H2 UDP + REALITY
- official interop for `_check`, `_udp2`, `_icmp`
- outbound `clientRandom` runtime path
- Linux TUN-backed `_icmp` product path
- common Xray integration with `proxySettings`, `mux`, `sendThrough=origin`, `targetStrategy useipv4/forceipv4`, `sniffing + routeOnly`, and inbound `rejectUnknownSni`

## Important Limits

This fork is not a blanket statement that every historical or official TrustTunnel field is active in runtime.

Current hard limits are:

- `http3 + reality` is explicitly unsupported and rejected.
- `antiDpi=true` is explicitly unsupported and rejected.
- UDP domain targets are not a validated product path.
- `hosts[]` and `transports[]` on inbound are not a generic virtual-host/router layer by themselves.
- Lab-only secrets and deployment keys must stay outside tracked repository files.

## Documentation

Start here:

- Documentation index: [docs/README.md](docs/README.md)
- Configuration guide: [docs/configuration.md](docs/configuration.md)
- Russian configuration guide: [docs/configuration.ru.md](docs/configuration.ru.md)

Current source of truth:

- State: [docs/current/current-state.md](docs/current/current-state.md)
- Architecture: [docs/current/architecture.md](docs/current/architecture.md)
- Operations: [docs/current/operations.md](docs/current/operations.md)
- Validation: [docs/current/validation.md](docs/current/validation.md)
- Roadmap: [docs/current/roadmap.md](docs/current/roadmap.md)

Historical layers:

- Docs index explains the difference between `current`, `history`, `migration`, and `archive`.

## Config Examples

Tracked examples live under [testing/trusttunnel](testing/trusttunnel):

- [testing/trusttunnel/client_h2.json](testing/trusttunnel/client_h2.json)
- [testing/trusttunnel/server_h2.json](testing/trusttunnel/server_h2.json)
- [testing/trusttunnel/server_h3.json](testing/trusttunnel/server_h3.json)
- [testing/trusttunnel/our_client_to_remote_server_h2_reality.json](testing/trusttunnel/our_client_to_remote_server_h2_reality.json)
- [testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json](testing/trusttunnel/our_client_udp_to_remote_server_h2_reality.json)
- [testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json](testing/trusttunnel/our_client_to_our_server_h2_clientrandom_allow.json)
- [testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json](testing/trusttunnel/our_client_to_our_server_h3_clientrandom_allow.json)

Treat them as tracked templates, not as deployment secrets.

## Build

Windows PowerShell:

```powershell
$env:CGO_ENABLED = 0
go build -buildvcs=false -o .\tmp\xray-tt-current.exe .\main
```

Linux:

```bash
CGO_ENABLED=0 go build -buildvcs=false -o ./tmp/xray-tt-current ./main
```

## Upstream Tracking

This fork follows upstream Xray-core, but it is not presented as an upstream-ready patch stack. The working policy is:

1. keep the fork synced with upstream `main`
2. rerun regression checks after each upstream merge/rebase
3. treat `docs/current/*` as the only current source of truth for this fork
4. split out upstreamable work later, only after the fork behavior stays stable

## License

This repository remains under the same project license as Xray-core: [Mozilla Public License Version 2.0](LICENSE).
