package conf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/net"
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

func TestTrustTunnelClientConfigBuildSupportsPostQuantumGroupEnabled(t *testing.T) {
	trueValue := true
	falseValue := false

	tests := []struct {
		name string
		flag *bool
		want trusttunnel.PostQuantumGroupSetting
	}{
		{
			name: "auto when omitted",
			flag: nil,
			want: trusttunnel.PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_AUTO,
		},
		{
			name: "enabled when true",
			flag: &trueValue,
			want: trusttunnel.PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_ENABLED,
		},
		{
			name: "disabled when false",
			flag: &falseValue,
			want: trusttunnel.PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_DISABLED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config, err := (&TrustTunnelClientConfig{
				Address:          &Address{Address: net.ParseAddress("127.0.0.1")},
				Port:             9443,
				Username:         "u1",
				Password:         "p1",
				Hostname:         "www.google.com",
				Transport:        "http2",
				PostQuantumGroup: tc.flag,
			}).Build()
			if err != nil {
				t.Fatalf("Build() failed: %v", err)
			}

			built := config.(*trusttunnel.ClientConfig)
			if built.GetPostQuantumGroupEnabled() != tc.want {
				t.Fatalf("postQuantumGroupEnabled = %v, want %v", built.GetPostQuantumGroupEnabled(), tc.want)
			}
		})
	}
}

func TestConfigBuildRejectsTrustTunnelHTTP3RealityOutbound(t *testing.T) {
	raw := json.RawMessage(`{
		"address": "127.0.0.1",
		"port": 9443,
		"username": "u1",
		"password": "p1",
		"hostname": "localhost",
		"transport": "http3"
	}`)

	_, err := (&Config{
		OutboundConfigs: []OutboundDetourConfig{
			{
				Protocol:      "trusttunnel",
				Settings:      &raw,
				StreamSetting: &StreamConfig{Security: "reality"},
			},
		},
	}).Build()
	if err == nil || !strings.Contains(err.Error(), "http3 with REALITY is unsupported") {
		t.Fatalf("Build() error = %v, want http3 reality unsupported", err)
	}
}

func TestConfigBuildRejectsTrustTunnelHTTP3RealityInbound(t *testing.T) {
	raw := json.RawMessage(`{
		"users": [{"username": "u1", "password": "p1"}],
		"transports": ["http3"]
	}`)

	_, err := (&Config{
		InboundConfigs: []InboundDetourConfig{
			{
				Protocol:      "trusttunnel",
				PortList:      &PortList{Range: []PortRange{{From: 9443, To: 9443}}},
				ListenOn:      &Address{Address: net.ParseAddress("127.0.0.1")},
				Settings:      &raw,
				StreamSetting: &StreamConfig{Security: "reality"},
			},
		},
	}).Build()
	if err == nil || !strings.Contains(err.Error(), "http3 with REALITY is unsupported") {
		t.Fatalf("Build() error = %v, want http3 reality unsupported", err)
	}
}

func TestConfigBuildRejectsTrustTunnelAntiDpi(t *testing.T) {
	raw := json.RawMessage(`{
		"address": "127.0.0.1",
		"port": 9443,
		"username": "u1",
		"password": "p1",
		"hostname": "localhost",
		"transport": "http2",
		"antiDpi": true
	}`)

	_, err := (&Config{
		OutboundConfigs: []OutboundDetourConfig{
			{
				Protocol: "trusttunnel",
				Settings: &raw,
			},
		},
	}).Build()
	if err == nil || !strings.Contains(err.Error(), "antiDpi is unsupported") {
		t.Fatalf("Build() error = %v, want antiDpi unsupported", err)
	}
}

func TestConfigBuildRejectsTrustTunnelPostQuantumWithoutSecurityOnHTTP2(t *testing.T) {
	raw := json.RawMessage(`{
		"address": "127.0.0.1",
		"port": 9443,
		"username": "u1",
		"password": "p1",
		"hostname": "localhost",
		"transport": "http2",
		"postQuantumGroupEnabled": true
	}`)

	_, err := (&Config{
		OutboundConfigs: []OutboundDetourConfig{
			{
				Protocol: "trusttunnel",
				Settings: &raw,
			},
		},
	}).Build()
	if err == nil || !strings.Contains(err.Error(), "postQuantumGroupEnabled is unsupported") {
		t.Fatalf("Build() error = %v, want postQuantum unsupported", err)
	}
}

func TestConfigBuildAllowsTrustTunnelHTTP3PostQuantumWithoutOutboundSecurity(t *testing.T) {
	raw := json.RawMessage(`{
		"address": "127.0.0.1",
		"port": 9443,
		"username": "u1",
		"password": "p1",
		"hostname": "localhost",
		"transport": "http3",
		"postQuantumGroupEnabled": true
	}`)

	_, err := (&Config{
		OutboundConfigs: []OutboundDetourConfig{
			{
				Protocol: "trusttunnel",
				Settings: &raw,
			},
		},
	}).Build()
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}
}
