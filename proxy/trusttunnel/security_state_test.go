package trusttunnel

import (
	"context"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/stat"
)

type fakeTrustTunnelConnectionState struct {
	NegotiatedProtocol string
	PeerCertificates   []*x509.Certificate
}

type fakeTrustTunnelStateConn struct {
	state          fakeTrustTunnelConnectionState
	handshakeErr   error
	handshakeCalls int
}

func (c *fakeTrustTunnelStateConn) Read([]byte) (int, error)         { return 0, nil }
func (c *fakeTrustTunnelStateConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *fakeTrustTunnelStateConn) Close() error                     { return nil }
func (c *fakeTrustTunnelStateConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *fakeTrustTunnelStateConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *fakeTrustTunnelStateConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeTrustTunnelStateConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeTrustTunnelStateConn) SetWriteDeadline(time.Time) error { return nil }

func (c *fakeTrustTunnelStateConn) HandshakeContext(context.Context) error {
	c.handshakeCalls++
	return c.handshakeErr
}

func (c *fakeTrustTunnelStateConn) ConnectionState() fakeTrustTunnelConnectionState {
	return c.state
}

func TestTrustTunnelNegotiatedProtocolReadsReflectedConnectionState(t *testing.T) {
	conn := &stat.CounterConnection{
		Connection: &fakeTrustTunnelStateConn{
			state: fakeTrustTunnelConnectionState{
				NegotiatedProtocol: "h2",
			},
		},
	}

	if got := trustTunnelNegotiatedProtocol(conn); got != "h2" {
		t.Fatalf("trustTunnelNegotiatedProtocol() = %q, want %q", got, "h2")
	}
}

func TestTrustTunnelClientSecurityStateUsesReflectedConnectionState(t *testing.T) {
	peerCerts := []*x509.Certificate{{}}
	rawConn := &fakeTrustTunnelStateConn{
		state: fakeTrustTunnelConnectionState{
			NegotiatedProtocol: "h2",
			PeerCertificates:   peerCerts,
		},
	}
	conn := &stat.CounterConnection{Connection: rawConn}

	state, err := trustTunnelClientSecurityState(context.Background(), conn)
	if err != nil {
		t.Fatalf("trustTunnelClientSecurityState() error = %v", err)
	}
	if state.NegotiatedProtocol != "h2" {
		t.Fatalf("NegotiatedProtocol = %q, want %q", state.NegotiatedProtocol, "h2")
	}
	if len(state.PeerCertificates) != 1 || state.PeerCertificates[0] != peerCerts[0] {
		t.Fatalf("PeerCertificates = %#v, want %#v", state.PeerCertificates, peerCerts)
	}
	if rawConn.handshakeCalls != 1 {
		t.Fatalf("HandshakeContext calls = %d, want 1", rawConn.handshakeCalls)
	}
}

func TestTrustTunnelClientSecurityStateReportsHandshakeFailure(t *testing.T) {
	conn := &stat.CounterConnection{
		Connection: &fakeTrustTunnelStateConn{
			handshakeErr: context.DeadlineExceeded,
		},
	}

	_, err := trustTunnelClientSecurityState(context.Background(), conn)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed security handshake") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTrustTunnelShouldUseHTTP2(t *testing.T) {
	tests := []struct {
		name  string
		state trustTunnelSecurityState
		want  bool
	}{
		{
			name: "explicit h2",
			state: trustTunnelSecurityState{
				NegotiatedProtocol: "h2",
			},
			want: true,
		},
		{
			name: "reality without alpn",
			state: trustTunnelSecurityState{
				UsesReality: true,
			},
			want: true,
		},
		{
			name: "reality with explicit http11",
			state: trustTunnelSecurityState{
				UsesReality:        true,
				NegotiatedProtocol: "http/1.1",
			},
			want: false,
		},
		{
			name:  "plain empty alpn",
			state: trustTunnelSecurityState{},
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := trustTunnelShouldUseHTTP2(tc.state); got != tc.want {
				t.Fatalf("trustTunnelShouldUseHTTP2() = %v, want %v", got, tc.want)
			}
		})
	}
}
