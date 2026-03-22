Test ID: CP4
Date: 2026-03-22
Scope: HTTP/2 + TLS verification path via socks inbound -> trusttunnel outbound -> trusttunnel inbound -> freedom
Runtime server config: /opt/lab/xray-tt/configs/server_h2.json
Runtime client config: /opt/lab/xray-tt/configs/client_h2.json
Runtime cert: /opt/lab/xray-tt/certs/server.crt
Repo server config copy: testing/trusttunnel/server_h2.json
Repo client config copy: testing/trusttunnel/client_h2.json
Repo cert copy: testing/trusttunnel/server_h2_san.crt
Result: PASS
Observed:
- trusttunnel outbound completed TLS handshake to vpn.lab.local
- trusttunnel outbound verified peer certificate using hostname + certificatePemFile
- trusttunnel inbound accepted HTTP/2 CONNECT
- freedom opened outbound TCP connection to example.com:443
- end-to-end request to https://example.com/ succeeded
Notes:
- test certificate must contain SAN DNS:vpn.lab.local
- streamSettings.tlsSettings.serverName must currently match settings.hostname
- HTTP/1.1 fallback still exists in code
- HTTP/3 is not implemented
- rules, client_random, UDP are not implemented
