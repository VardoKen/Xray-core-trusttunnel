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
		AllowPrivateNetworkConnections: true,
		IPv6Available:                  true,
		AuthFailureStatusCode:          407,
		ICMP: &TrustTunnelICMPConfig{
			InterfaceName:      "eth0",
			RequestTimeoutSecs: 9,
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
}
