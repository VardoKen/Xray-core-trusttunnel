Test ID: CP3
Date: 2026-03-22
Scope: HTTP/2 transport path via socks inbound -> trusttunnel outbound -> trusttunnel inbound -> freedom
Runtime server config: /opt/lab/xray-tt/configs/server_h2.json
Runtime client config: /opt/lab/xray-tt/configs/client_h2.json
Repo server config copy: testing/trusttunnel/server_h2.json
Repo client config copy: testing/trusttunnel/client_h2.json
Result: PASS
Observed:
- trusttunnel inbound accepted HTTP/2 CONNECT
- trusttunnel inbound dispatched tcp:example.com:443 via freedom
- freedom opened outbound TCP connection to example.com:443
- trusttunnel outbound connected to trusttunnel inbound over TLS+ALPN h2 path
Notes:
- HTTP/1.1 fallback still exists in code
- HTTP/3 is not implemented
- client_random, rules, UDP are not implemented
- certificate pinning runtime semantics are not implemented
