package trusttunnel

import (
	"testing"
	"time"
)

func TestServerConfigTimeoutDefaults(t *testing.T) {
	cfg := &ServerConfig{}

	if got := cfg.tlsHandshakeTimeout(); got != defaultTrustTunnelTLSHandshakeTimeout {
		t.Fatalf("tlsHandshakeTimeout() = %v, want %v", got, defaultTrustTunnelTLSHandshakeTimeout)
	}
	if got := cfg.clientListenerTimeout(); got != defaultTrustTunnelClientListenerTimeout {
		t.Fatalf("clientListenerTimeout() = %v, want %v", got, defaultTrustTunnelClientListenerTimeout)
	}
	if got := cfg.connectionEstablishmentTimeout(); got != defaultTrustTunnelConnectionEstablishmentTime {
		t.Fatalf("connectionEstablishmentTimeout() = %v, want %v", got, defaultTrustTunnelConnectionEstablishmentTime)
	}
	if got := cfg.tcpConnectionsTimeout(); got != defaultTrustTunnelTCPConnectionsTimeout {
		t.Fatalf("tcpConnectionsTimeout() = %v, want %v", got, defaultTrustTunnelTCPConnectionsTimeout)
	}
	if got := cfg.udpConnectionsTimeout(); got != defaultTrustTunnelUDPConnectionsTimeout {
		t.Fatalf("udpConnectionsTimeout() = %v, want %v", got, defaultTrustTunnelUDPConnectionsTimeout)
	}
}

func TestServerConfigTimeoutOverrides(t *testing.T) {
	cfg := &ServerConfig{
		TlsHandshakeTimeoutSecs:            9,
		ClientListenerTimeoutSecs:          120,
		ConnectionEstablishmentTimeoutSecs: 31,
		TcpConnectionsTimeoutSecs:          77,
		UdpConnectionsTimeoutSecs:          33,
	}

	if got := cfg.tlsHandshakeTimeout(); got != 9*time.Second {
		t.Fatalf("tlsHandshakeTimeout() = %v, want 9s", got)
	}
	if got := cfg.clientListenerTimeout(); got != 120*time.Second {
		t.Fatalf("clientListenerTimeout() = %v, want 120s", got)
	}
	if got := cfg.connectionEstablishmentTimeout(); got != 31*time.Second {
		t.Fatalf("connectionEstablishmentTimeout() = %v, want 31s", got)
	}
	if got := cfg.tcpConnectionsTimeout(); got != 77*time.Second {
		t.Fatalf("tcpConnectionsTimeout() = %v, want 77s", got)
	}
	if got := cfg.udpConnectionsTimeout(); got != 33*time.Second {
		t.Fatalf("udpConnectionsTimeout() = %v, want 33s", got)
	}
}
