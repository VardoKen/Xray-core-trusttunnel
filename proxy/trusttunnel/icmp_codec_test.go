package trusttunnel

import (
	"net"
	"testing"
)

func TestTrustTunnelICMPRequestDecoderHandlesFragments(t *testing.T) {
	wire, err := encodeTrustTunnelICMPRequest(trustTunnelICMPRequestPacket{
		ID:          0x1234,
		Destination: net.IPv4(1, 2, 3, 4),
		Sequence:    9,
		TTL:         32,
		DataSize:    56,
	})
	if err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}

	var decoder trustTunnelICMPRequestDecoder
	packets, err := decoder.Feed(wire[:7])
	if err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if len(packets) != 0 {
		t.Fatalf("unexpected packet count after partial feed: got %d, want 0", len(packets))
	}

	packets, err = decoder.Feed(wire[7:])
	if err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("unexpected packet count: got %d, want 1", len(packets))
	}
	if got := packets[0].Destination.String(); got != "1.2.3.4" {
		t.Fatalf("unexpected destination: got %q", got)
	}
	if packets[0].ID != 0x1234 || packets[0].Sequence != 9 || packets[0].TTL != 32 || packets[0].DataSize != 56 {
		t.Fatalf("unexpected packet: %+v", packets[0])
	}
}

func TestEncodeTrustTunnelICMPReply(t *testing.T) {
	wire, err := encodeTrustTunnelICMPReply(trustTunnelICMPReplyPacket{
		ID:       0x0102,
		Source:   net.IPv4(5, 6, 7, 8),
		Type:     3,
		Code:     1,
		Sequence: 0x0304,
	})
	if err != nil {
		t.Fatalf("failed to encode reply: %v", err)
	}
	if len(wire) != trustTunnelICMPResponseSize {
		t.Fatalf("unexpected reply size: got %d, want %d", len(wire), trustTunnelICMPResponseSize)
	}
	if wire[18] != 3 || wire[19] != 1 {
		t.Fatalf("unexpected type/code bytes: %v", wire[18:20])
	}
}
