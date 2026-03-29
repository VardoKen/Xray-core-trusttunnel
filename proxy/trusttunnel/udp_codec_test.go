package trusttunnel

import (
	"bytes"
	stdnet "net"
	"testing"
)

func TestTrustTunnelUDPRequestCodecRoundTripIPv4(t *testing.T) {
	src := &stdnet.UDPAddr{IP: stdnet.IPv4(10, 0, 0, 2), Port: 53000}
	dst := &stdnet.UDPAddr{IP: stdnet.IPv4(1, 1, 1, 1), Port: 53}

	wire, err := encodeTrustTunnelUDPRequest(trustTunnelUDPRequestPacket{
		Source:      src,
		Destination: dst,
		AppName:     "dns",
		Payload:     []byte{0xde, 0xad, 0xbe, 0xef},
	})
	if err != nil {
		t.Fatal(err)
	}

	var dec trustTunnelUDPRequestDecoder
	packets, err := dec.Feed(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}

	got := packets[0]
	if !got.Source.IP.Equal(src.IP) {
		t.Fatalf("unexpected source ip: %v", got.Source.IP)
	}
	if got.Source.Port != src.Port {
		t.Fatalf("unexpected source port: %d", got.Source.Port)
	}
	if !got.Destination.IP.Equal(dst.IP) {
		t.Fatalf("unexpected destination ip: %v", got.Destination.IP)
	}
	if got.Destination.Port != dst.Port {
		t.Fatalf("unexpected destination port: %d", got.Destination.Port)
	}
	if got.AppName != "dns" {
		t.Fatalf("unexpected app name: %q", got.AppName)
	}
	if !bytes.Equal(got.Payload, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("unexpected payload: %x", got.Payload)
	}
}

func TestTrustTunnelUDPRequestDecoderSplitFeed(t *testing.T) {
	src := &stdnet.UDPAddr{IP: stdnet.ParseIP("2001:db8::10"), Port: 40000}
	dst := &stdnet.UDPAddr{IP: stdnet.ParseIP("2001:4860:4860::8888"), Port: 53}

	wire, err := encodeTrustTunnelUDPRequest(trustTunnelUDPRequestPacket{
		Source:      src,
		Destination: dst,
		AppName:     "dns6",
		Payload:     []byte("hello"),
	})
	if err != nil {
		t.Fatal(err)
	}

	var dec trustTunnelUDPRequestDecoder

	part1, err := dec.Feed(wire[:7])
	if err != nil {
		t.Fatal(err)
	}
	if len(part1) != 0 {
		t.Fatalf("expected 0 packets on partial feed, got %d", len(part1))
	}

	part2, err := dec.Feed(wire[7:])
	if err != nil {
		t.Fatal(err)
	}
	if len(part2) != 1 {
		t.Fatalf("expected 1 packet after full feed, got %d", len(part2))
	}

	got := part2[0]
	if !got.Source.IP.Equal(src.IP) {
		t.Fatalf("unexpected source ip: %v", got.Source.IP)
	}
	if got.Source.Port != src.Port {
		t.Fatalf("unexpected source port: %d", got.Source.Port)
	}
	if !got.Destination.IP.Equal(dst.IP) {
		t.Fatalf("unexpected destination ip: %v", got.Destination.IP)
	}
	if got.Destination.Port != dst.Port {
		t.Fatalf("unexpected destination port: %d", got.Destination.Port)
	}
	if got.AppName != "dns6" {
		t.Fatalf("unexpected app name: %q", got.AppName)
	}
	if !bytes.Equal(got.Payload, []byte("hello")) {
		t.Fatalf("unexpected payload: %q", got.Payload)
	}
}

func TestTrustTunnelUDPResponseCodecRoundTrip(t *testing.T) {
	src := &stdnet.UDPAddr{IP: stdnet.IPv4(8, 8, 8, 8), Port: 53}
	dst := &stdnet.UDPAddr{IP: stdnet.IPv4(10, 0, 0, 2), Port: 53000}

	wire, err := encodeTrustTunnelUDPResponse(trustTunnelUDPResponsePacket{
		Source:      src,
		Destination: dst,
		Payload:     []byte{1, 2, 3, 4, 5},
	})
	if err != nil {
		t.Fatal(err)
	}

	var dec trustTunnelUDPResponseDecoder
	packets, err := dec.Feed(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}

	got := packets[0]
	if !got.Source.IP.Equal(src.IP) {
		t.Fatalf("unexpected source ip: %v", got.Source.IP)
	}
	if got.Source.Port != src.Port {
		t.Fatalf("unexpected source port: %d", got.Source.Port)
	}
	if !got.Destination.IP.Equal(dst.IP) {
		t.Fatalf("unexpected destination ip: %v", got.Destination.IP)
	}
	if got.Destination.Port != dst.Port {
		t.Fatalf("unexpected destination port: %d", got.Destination.Port)
	}
	if !bytes.Equal(got.Payload, []byte{1, 2, 3, 4, 5}) {
		t.Fatalf("unexpected payload: %x", got.Payload)
	}
}
