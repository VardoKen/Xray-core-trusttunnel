package trusttunnel

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestBuildTrustTunnelICMPSessionOptionsDefaults(t *testing.T) {
	options := buildTrustTunnelICMPSessionOptions(&ServerConfig{})

	if options.ipv6Available {
		t.Fatal("ipv6Available = true, want false")
	}
	if options.interfaceName != "" {
		t.Fatalf("interfaceName = %q, want empty", options.interfaceName)
	}
	if options.allowPrivateNetworkConnections {
		t.Fatal("allowPrivateNetworkConnections = true, want false")
	}
	if options.requestTimeout != trustTunnelICMPRequestTimeout {
		t.Fatalf("requestTimeout = %v, want %v", options.requestTimeout, trustTunnelICMPRequestTimeout)
	}
}

func TestBuildTrustTunnelICMPSessionOptionsUsesConfiguredValues(t *testing.T) {
	options := buildTrustTunnelICMPSessionOptions(&ServerConfig{
		Ipv6Available:                  true,
		IcmpInterfaceName:              "eth-test0",
		IcmpRequestTimeoutSecs:         9,
		AllowPrivateNetworkConnections: true,
	})

	if !options.ipv6Available {
		t.Fatal("ipv6Available = false, want true")
	}
	if options.interfaceName != "eth-test0" {
		t.Fatalf("interfaceName = %q, want %q", options.interfaceName, "eth-test0")
	}
	if !options.allowPrivateNetworkConnections {
		t.Fatal("allowPrivateNetworkConnections = false, want true")
	}
	if options.requestTimeout != 9*time.Second {
		t.Fatalf("requestTimeout = %v, want %v", options.requestTimeout, 9*time.Second)
	}
}

func TestOpenICMPSessionUsesConfiguredOptions(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		Ipv6Available:                  true,
		IcmpInterfaceName:              "eth-test1",
		IcmpRequestTimeoutSecs:         11,
		AllowPrivateNetworkConnections: true,
	})

	var got trustTunnelICMPSessionOptions
	server.newICMPSession = func(options trustTunnelICMPSessionOptions) (trustTunnelICMPHandler, error) {
		got = options
		return &fakeTrustTunnelICMPSession{}, nil
	}

	session, err := server.openICMPSession()
	if err != nil {
		t.Fatalf("openICMPSession() failed: %v", err)
	}
	defer session.Close()

	if !got.ipv6Available {
		t.Fatal("ipv6Available = false, want true")
	}
	if got.interfaceName != "eth-test1" {
		t.Fatalf("interfaceName = %q, want %q", got.interfaceName, "eth-test1")
	}
	if !got.allowPrivateNetworkConnections {
		t.Fatal("allowPrivateNetworkConnections = false, want true")
	}
	if got.requestTimeout != 11*time.Second {
		t.Fatalf("requestTimeout = %v, want %v", got.requestTimeout, 11*time.Second)
	}
}

func TestTrustTunnelValidateICMPDestination(t *testing.T) {
	tests := []struct {
		name         string
		ip           net.IP
		allowPrivate bool
		wantErr      bool
	}{
		{name: "global-v4", ip: net.ParseIP("1.1.1.1"), wantErr: false},
		{name: "global-v6", ip: net.ParseIP("2606:4700:4700::1111"), wantErr: false},
		{name: "private-v4", ip: net.ParseIP("10.0.0.1"), wantErr: true},
		{name: "loopback-v4", ip: net.ParseIP("127.0.0.1"), wantErr: true},
		{name: "private-v6", ip: net.ParseIP("fd00::1"), wantErr: true},
		{name: "loopback-v6", ip: net.ParseIP("::1"), wantErr: true},
		{name: "mapped-private", ip: net.ParseIP("::ffff:10.0.0.1"), wantErr: true},
		{name: "allow-private", ip: net.ParseIP("10.0.0.1"), allowPrivate: true, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := trustTunnelValidateICMPDestination(tt.ip, tt.allowPrivate)
			if tt.wantErr && err == nil {
				t.Fatal("trustTunnelValidateICMPDestination() = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("trustTunnelValidateICMPDestination() failed: %v", err)
			}
		})
	}
}

func TestTrustTunnelICMPSessionRejectsPrivateDestinationWhenDisabled(t *testing.T) {
	session := &trustTunnelICMPSession{
		timeout:                        trustTunnelICMPRequestTimeout,
		allowPrivateNetworkConnections: false,
	}

	_, ok, err := session.HandleRequest(context.Background(), trustTunnelICMPRequestPacket{
		ID:          1,
		Destination: net.ParseIP("10.0.0.1"),
		Sequence:    1,
		TTL:         64,
		DataSize:    8,
	})
	if err == nil {
		t.Fatal("HandleRequest() = nil, want error")
	}
	if ok {
		t.Fatal("HandleRequest() ok = true, want false")
	}
}
