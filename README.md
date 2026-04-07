# Xray-core TrustTunnel Fork

Russian version: [README.ru.md](README.ru.md)

This repository is a downstream fork of [XTLS/Xray-core](https://github.com/XTLS/Xray-core) with TrustTunnel support integrated into Xray-core.

The fork exists to provide a maintained Xray runtime for TrustTunnel scenarios instead of keeping TrustTunnel support as an external prototype or a private patch set.

## What This Fork Contains

- TrustTunnel inbound and outbound protocol support
- HTTP/2 and HTTP/3 TCP paths
- HTTP/2 and HTTP/3 UDP mux paths
- HTTP/2 + REALITY support
- TrustTunnel `_check`, `_udp2`, and `_icmp`
- config validation for unsupported TrustTunnel combinations

## Current Feature Scope

Publicly documented and intended features in this fork:

- TrustTunnel over HTTP/2 + TLS
- TrustTunnel over HTTP/2 + REALITY
- TrustTunnel over HTTP/3 + TLS
- TrustTunnel TCP, UDP mux, and ICMP support
- compatibility with common Xray routing and transport configuration

## Known Limits

- `http3 + reality` is unsupported
- `antiDpi=true` is unsupported
- UDP domain targets are not documented as a supported product path

## Documentation

- Documentation index: [docs/README.md](docs/README.md)
- Configuration guide: [docs/configuration.md](docs/configuration.md)
- Russian configuration guide: [docs/configuration.ru.md](docs/configuration.ru.md)

## Example Templates

Sanitized example templates are provided under [testing/trusttunnel](testing/trusttunnel).

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

## License

This repository remains under the same license as Xray-core: [Mozilla Public License Version 2.0](LICENSE).
