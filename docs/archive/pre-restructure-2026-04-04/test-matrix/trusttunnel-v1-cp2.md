Test ID: CP2
Date: 2026-03-22
Scope: End-to-end TCP via socks inbound -> trusttunnel outbound -> trusttunnel inbound -> freedom
Runtime server config: /opt/lab/xray-tt/configs/server_stub.json
Runtime client config: /opt/lab/xray-tt/configs/client_stub.json
Repo server config copy: testing/trusttunnel/server_stub.json
Repo client config copy: testing/trusttunnel/client_stub.json
Command: curl -vk --socks5-hostname 127.0.0.1:10808 https://example.com/ --max-time 15
Result: PASS
Observed:
- outbound trusttunnel generated CONNECT request
- inbound trusttunnel accepted Basic auth
- inbound trusttunnel dispatched CONNECT target via freedom
- HTTPS to example.com completed successfully
Limitations:
- current implementation uses HTTP/1.1 CONNECT over raw TCP
- HTTP/2 is not implemented
- HTTP/3 is not implemented
- TLS-specific trusttunnel semantics are not implemented
- rules, client_random, UDP are not implemented
