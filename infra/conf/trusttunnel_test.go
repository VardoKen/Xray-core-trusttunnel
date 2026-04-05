package conf

import (
	"testing"

	"github.com/xtls/xray-core/proxy/trusttunnel"
)

func TestTrustTunnelServerConfigBuildSupportsICMPSettings(t *testing.T) {
	config, err := (&TrustTunnelServerConfig{
		Users: []*TrustTunnelUserConfig{
			{
				Username: "u1",
				Password: "p1",
			},
		},
		AllowPrivateNetworkConnections:     true,
		IPv6Available:                      true,
		AuthFailureStatusCode:              407,
		TLSHandshakeTimeoutSecs:            10,
		ClientListenerTimeoutSecs:          600,
		ConnectionEstablishmentTimeoutSecs: 30,
		TCPConnectionsTimeoutSecs:          604800,
		UDPConnectionsTimeoutSecs:          300,
		ICMP: &TrustTunnelICMPConfig{
			InterfaceName:            "eth0",
			RequestTimeoutSecs:       9,
			RecvMessageQueueCapacity: 17,
		},
	}).Build()
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	built := config.(*trusttunnel.ServerConfig)
	if !built.GetAllowPrivateNetworkConnections() {
		t.Fatal("allowPrivateNetworkConnections = false, want true")
	}
	if !built.GetIpv6Available() {
		t.Fatal("ipv6Available = false, want true")
	}
	if built.GetIcmpInterfaceName() != "eth0" {
		t.Fatalf("icmpInterfaceName = %q, want %q", built.GetIcmpInterfaceName(), "eth0")
	}
	if built.GetIcmpRequestTimeoutSecs() != 9 {
		t.Fatalf("icmpRequestTimeoutSecs = %d, want 9", built.GetIcmpRequestTimeoutSecs())
	}
	if built.GetIcmpRecvMessageQueueCapacity() != 17 {
		t.Fatalf("icmpRecvMessageQueueCapacity = %d, want 17", built.GetIcmpRecvMessageQueueCapacity())
	}
	if built.GetTlsHandshakeTimeoutSecs() != 10 {
		t.Fatalf("tlsHandshakeTimeoutSecs = %d, want 10", built.GetTlsHandshakeTimeoutSecs())
	}
	if built.GetClientListenerTimeoutSecs() != 600 {
		t.Fatalf("clientListenerTimeoutSecs = %d, want 600", built.GetClientListenerTimeoutSecs())
	}
	if built.GetConnectionEstablishmentTimeoutSecs() != 30 {
		t.Fatalf("connectionEstablishmentTimeoutSecs = %d, want 30", built.GetConnectionEstablishmentTimeoutSecs())
	}
	if built.GetTcpConnectionsTimeoutSecs() != 604800 {
		t.Fatalf("tcpConnectionsTimeoutSecs = %d, want 604800", built.GetTcpConnectionsTimeoutSecs())
	}
	if built.GetUdpConnectionsTimeoutSecs() != 300 {
		t.Fatalf("udpConnectionsTimeoutSecs = %d, want 300", built.GetUdpConnectionsTimeoutSecs())
	}
}
