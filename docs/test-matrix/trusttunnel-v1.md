Test ID: CP1
Commit: UNCOMMITTED
Date: 2026-03-22
Server config: /opt/lab/xray-tt/configs/server_stub.json
Client config: none
Command: timeout 5 /opt/lab/xray-tt/bin/xray-tt run -c /opt/lab/xray-tt/configs/server_stub.json
Result: PASS
Logs:
- stdout/stderr console output
Pcap:
- none
Notes:
- xray started successfully
- no unknown protocol trusttunnel
- no settings parse error
- TCP listener opened on 0.0.0.0:8443
- timeout exit 124 was expected from wrapper
