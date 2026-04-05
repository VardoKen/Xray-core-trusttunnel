package tcp

import (
	"context"
	"io"
	"net"
	gonet "net"
	"testing"
	"time"
)

type fakeTrustTunnelHandshakeConn struct {
	setDeadlines []time.Time
	handshakes   int
	timeoutSeen  time.Duration
}

func (*fakeTrustTunnelHandshakeConn) Read([]byte) (int, error)  { return 0, io.EOF }
func (*fakeTrustTunnelHandshakeConn) Write([]byte) (int, error) { return 0, nil }
func (*fakeTrustTunnelHandshakeConn) Close() error              { return nil }
func (*fakeTrustTunnelHandshakeConn) LocalAddr() gonet.Addr     { return &gonet.TCPAddr{} }
func (*fakeTrustTunnelHandshakeConn) RemoteAddr() gonet.Addr    { return &gonet.TCPAddr{} }

func (c *fakeTrustTunnelHandshakeConn) SetDeadline(t time.Time) error {
	c.setDeadlines = append(c.setDeadlines, t)
	return nil
}

func (c *fakeTrustTunnelHandshakeConn) SetReadDeadline(t time.Time) error {
	return c.SetDeadline(t)
}

func (c *fakeTrustTunnelHandshakeConn) SetWriteDeadline(t time.Time) error {
	return c.SetDeadline(t)
}

func (c *fakeTrustTunnelHandshakeConn) HandshakeContext(ctx context.Context) error {
	c.handshakes++
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.DeadlineExceeded
	}
	c.timeoutSeen = time.Until(deadline)
	return nil
}

func (*fakeTrustTunnelHandshakeConn) VerifyHostname(string) error { return nil }

func (c *fakeTrustTunnelHandshakeConn) HandshakeContextServerName(ctx context.Context) string {
	_ = c.HandshakeContext(ctx)
	return ""
}

func (*fakeTrustTunnelHandshakeConn) NegotiatedProtocol() string { return "" }

func TestTrustTunnelServerHandshakeSetsAndClearsDeadline(t *testing.T) {
	conn := &fakeTrustTunnelHandshakeConn{}

	if err := trustTunnelServerHandshake(conn, 3*time.Second); err != nil {
		t.Fatalf("trustTunnelServerHandshake() error = %v", err)
	}
	if conn.handshakes != 1 {
		t.Fatalf("handshake count = %d, want 1", conn.handshakes)
	}
	if len(conn.setDeadlines) != 2 {
		t.Fatalf("SetDeadline count = %d, want 2", len(conn.setDeadlines))
	}
	if conn.setDeadlines[0].IsZero() {
		t.Fatal("expected non-zero handshake deadline")
	}
	if !conn.setDeadlines[1].IsZero() {
		t.Fatal("expected deadline clear after handshake")
	}
	if conn.timeoutSeen < 2*time.Second || conn.timeoutSeen > 4*time.Second {
		t.Fatalf("handshake context timeout = %v, want around 3s", conn.timeoutSeen)
	}
}

func TestWrapTrustTunnelClientRandomConnWithTimeoutSilentPeer(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		_ = wrapTrustTunnelClientRandomConnWithTimeout(serverConn, 100*time.Millisecond)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wrapTrustTunnelClientRandomConnWithTimeout() did not return")
	}

	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("wrapTrustTunnelClientRandomConnWithTimeout() took too long: %v", elapsed)
	}
}
