package trusttunnel

import (
	"context"
	"os"
	"runtime"
	"testing"
)

func TestTrustTunnelICMPSessionEchoV4Loopback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux raw ICMP required")
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges required for raw ICMP")
	}

	session, err := newTrustTunnelICMPSession(false)
	if err != nil {
		t.Fatalf("failed to create ICMP session: %v", err)
	}
	defer session.Close()

	reply, ok, err := session.HandleRequest(context.Background(), trustTunnelICMPRequestPacket{
		ID:          0x2345,
		Destination: []byte{127, 0, 0, 1},
		Sequence:    11,
		TTL:         64,
		DataSize:    32,
	})
	if err != nil {
		t.Fatalf("unexpected request error: %v", err)
	}
	if !ok {
		t.Fatal("expected ICMP reply, got timeout")
	}
	if got := reply.Source.String(); got != "127.0.0.1" {
		t.Fatalf("unexpected reply source: got %q", got)
	}
	if reply.Sequence != 11 {
		t.Fatalf("unexpected reply sequence: got %d, want 11", reply.Sequence)
	}
}
