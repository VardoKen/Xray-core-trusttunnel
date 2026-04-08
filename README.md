# Xray-core TrustTunnel Fork

Russian version: [README.ru.md](README.ru.md)

This repository is a downstream fork of [XTLS/Xray-core](https://github.com/XTLS/Xray-core) with TrustTunnel integrated directly into Xray-core.

The goal of the fork is straightforward: keep TrustTunnel usable as a maintained Xray runtime instead of leaving it as a private patch set or a standalone prototype.

## Supported configurations

- HTTP/2 over TLS
- HTTP/2 over REALITY
- HTTP/3 over TLS
- `transport: "auto"` with HTTP/3-first selection and HTTP/2 fallback
- Ordered outbound `servers[]` lists with sequential fallback and last-successful endpoint preference
- Per-client inbound connection limits with separate H1/H2 and H3 counters
- TCP tunneling
- UDP multiplexing via `_udp2`
- ICMP tunneling via `_icmp`
- Health-check path via `_check`

## `clientRandom`

`clientRandom` is not required to make every TrustTunnel connection work, but it is the recommended default for real deployments.

If the server uses `client_random` rules and finishes the rule list with a fallback deny rule, a client without a matching `clientRandom` will be denied. If the server does not require a matching `client_random` rule, the tunnel can still work without an explicit `clientRandom`.

The configuration guide includes:

- minimal examples, which show the shortest valid config shape
- recommended examples, which show the safer default for real deployments
- a precise explanation of `client_random` rules and how to write them
- inbound limit-policy examples for per-client H1/H2 and H3 connection limits

## Unsupported combinations

- `HTTP/3 over REALITY` is unsupported because the current REALITY runtime in Xray is built around the TCP stream layer, while TrustTunnel H3 uses QUIC.
- `antiDpi=true` is supported on `HTTP/2 over TLS` and `HTTP/2 over REALITY`. With `transport: "auto"`, it bypasses HTTP/3 and goes directly to the HTTP/2 path. It remains unsupported for explicit `HTTP/3` because the current implementation only splits the first TCP-based ClientHello write.
- UDP domain targets are not documented as a supported product path. The validated UDP path uses IP targets.

## Documentation

- Documentation index: [docs/README.md](docs/README.md)
- Configuration guide: [docs/configuration.md](docs/configuration.md)
- Russian configuration guide: [docs/configuration.ru.md](docs/configuration.ru.md)

## Example templates

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
