package tls

import (
	"io"
	stdnet "net"
	"testing"
	"time"
)

type fakeAntiDPIConn struct {
	writes     [][]byte
	writeTimes []time.Time
}

func (c *fakeAntiDPIConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *fakeAntiDPIConn) Write(p []byte) (int, error) {
	clone := make([]byte, len(p))
	copy(clone, p)
	c.writes = append(c.writes, clone)
	c.writeTimes = append(c.writeTimes, time.Now())
	return len(p), nil
}

func (*fakeAntiDPIConn) Close() error                     { return nil }
func (*fakeAntiDPIConn) LocalAddr() stdnet.Addr           { return nil }
func (*fakeAntiDPIConn) RemoteAddr() stdnet.Addr          { return nil }
func (*fakeAntiDPIConn) SetDeadline(time.Time) error      { return nil }
func (*fakeAntiDPIConn) SetReadDeadline(time.Time) error  { return nil }
func (*fakeAntiDPIConn) SetWriteDeadline(time.Time) error { return nil }
func (*fakeAntiDPIConn) SetNoDelay(bool) error            { return nil }

func TestWrapConnWithAntiDPISplitsFirstTLSClientHelloWrite(t *testing.T) {
	base := &fakeAntiDPIConn{}
	conn := WrapConnWithAntiDPI(base)

	payload := []byte{0x16, 0x03, 0x03, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0c, 0x03, 0x03}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(payload))
	}

	if len(base.writes) != 2 {
		t.Fatalf("write count = %d, want 2", len(base.writes))
	}
	if got := base.writes[0]; len(got) != 1 || got[0] != payload[0] {
		t.Fatalf("first write = %v, want [%d]", got, payload[0])
	}
	if got := base.writes[1]; string(got) != string(payload[1:]) {
		t.Fatalf("second write = %v, want %v", got, payload[1:])
	}
	if delta := base.writeTimes[1].Sub(base.writeTimes[0]); delta < 20*time.Millisecond {
		t.Fatalf("write delay = %v, want at least 20ms", delta)
	}
}

func TestWrapConnWithAntiDPIDoesNotSplitNonTLSWrite(t *testing.T) {
	base := &fakeAntiDPIConn{}
	conn := WrapConnWithAntiDPI(base)

	payload := []byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(payload))
	}

	if len(base.writes) != 1 {
		t.Fatalf("write count = %d, want 1", len(base.writes))
	}
	if got := base.writes[0]; string(got) != string(payload) {
		t.Fatalf("write payload = %q, want %q", string(got), string(payload))
	}
}

func TestWrapConnWithAntiDPISplitsOnlyOnce(t *testing.T) {
	base := &fakeAntiDPIConn{}
	conn := WrapConnWithAntiDPI(base)

	payload := []byte{0x16, 0x03, 0x03, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0c, 0x03, 0x03}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}

	if len(base.writes) != 3 {
		t.Fatalf("write count = %d, want 3", len(base.writes))
	}
	if got := base.writes[2]; string(got) != string(payload) {
		t.Fatalf("third write = %v, want unsplit %v", got, payload)
	}
}
