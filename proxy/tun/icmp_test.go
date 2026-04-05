package tun

import (
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestICMPConnectionHandlerCreatesPerDestinationFlow(t *testing.T) {
	created := make(chan createdFlow, 4)
	handler := newICMPConnectionHandler(func(conn xnet.Conn, dst xnet.Destination) {
		created <- createdFlow{conn: conn.(*icmpConn), dst: dst}
	}, func([]byte, xnet.Destination, xnet.Destination) error {
		return nil
	})

	src := xnet.ICMPDestination(xnet.ParseAddress("192.0.2.10"))
	dst1 := xnet.ICMPDestination(xnet.ParseAddress("1.1.1.1"))
	dst2 := xnet.ICMPDestination(xnet.ParseAddress("8.8.8.8"))

	echoReq := mustMarshalICMPMessage(t, &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0x1001,
			Seq:  1,
			Data: []byte("ping"),
		},
	})

	if !handler.HandlePacket(src, dst1, echoReq) {
		t.Fatal("HandlePacket() = false, want true for echo request")
	}
	first := mustReceiveCreatedFlow(t, created)
	if first.dst != dst1 {
		t.Fatalf("first flow dst = %v, want %v", first.dst, dst1)
	}

	if !handler.HandlePacket(src, dst1, echoReq) {
		t.Fatal("HandlePacket() = false on existing flow, want true")
	}
	assertNoCreatedFlow(t, created)

	if !handler.HandlePacket(src, dst2, echoReq) {
		t.Fatal("HandlePacket() = false, want true for second destination")
	}
	second := mustReceiveCreatedFlow(t, created)
	if second.dst != dst2 {
		t.Fatalf("second flow dst = %v, want %v", second.dst, dst2)
	}

	echoReply := mustMarshalICMPMessage(t, &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0x1001,
			Seq:  1,
			Data: []byte("pong"),
		},
	})
	if handler.HandlePacket(src, dst1, echoReply) {
		t.Fatal("HandlePacket() = true, want false for non-request packet")
	}
	assertNoCreatedFlow(t, created)

	if got := len(handler.icmpConns); got != 2 {
		t.Fatalf("len(icmpConns) = %d, want 2", got)
	}

	_ = first.conn.Close()
	_ = second.conn.Close()
	if got := len(handler.icmpConns); got != 0 {
		t.Fatalf("len(icmpConns) after Close() = %d, want 0", got)
	}
}

func TestICMPConnWriteMultiBufferHonorsSourceOverride(t *testing.T) {
	type writeCall struct {
		payload []byte
		src     xnet.Destination
		dst     xnet.Destination
	}

	var (
		mu    sync.Mutex
		calls []writeCall
	)

	handler := newICMPConnectionHandler(func(xnet.Conn, xnet.Destination) {}, func(data []byte, src xnet.Destination, dst xnet.Destination) error {
		mu.Lock()
		calls = append(calls, writeCall{
			payload: append([]byte(nil), data...),
			src:     src,
			dst:     dst,
		})
		mu.Unlock()
		return nil
	})

	src := xnet.ICMPDestination(xnet.ParseAddress("192.0.2.10"))
	dst := xnet.ICMPDestination(xnet.ParseAddress("1.1.1.1"))
	conn := &icmpConn{
		handler: handler,
		key:     icmpFlowKey{src: src, dst: dst},
		egress:  make(chan []byte, 1),
		src:     src,
		dst:     dst,
	}

	reply := buf.FromBytes([]byte{1, 2, 3, 4})
	override := xnet.ICMPDestination(xnet.ParseAddress("9.9.9.9"))
	reply.UDP = &override
	mb := buf.MultiBuffer{reply}
	defer buf.ReleaseMulti(mb)

	if err := conn.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("WriteMultiBuffer() failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(calls) != 1 {
		t.Fatalf("len(calls) = %d, want 1", len(calls))
	}
	if got := calls[0].src.String(); got != override.String() {
		t.Fatalf("write src = %q, want %q", got, override.String())
	}
	if got := calls[0].dst.String(); got != src.String() {
		t.Fatalf("write dst = %q, want %q", got, src.String())
	}
	if got := string(calls[0].payload); got != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("write payload = %v, want %v", calls[0].payload, []byte{1, 2, 3, 4})
	}
}

func TestBuildRawICMPNetworkPacket(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		payload := mustMarshalICMPMessage(t, &icmp.Message{
			Type: ipv4.ICMPTypeEchoReply,
			Code: 0,
			Body: &icmp.Echo{
				ID:   0x1234,
				Seq:  7,
				Data: []byte("pong4"),
			},
		})

		src := xnet.ICMPDestination(xnet.ParseAddress("1.1.1.1"))
		dst := xnet.ICMPDestination(xnet.ParseAddress("192.0.2.10"))
		wire, proto, err := buildRawICMPNetworkPacket(payload, src, dst)
		if err != nil {
			t.Fatalf("buildRawICMPNetworkPacket() failed: %v", err)
		}
		if proto != header.IPv4ProtocolNumber {
			t.Fatalf("proto = %v, want %v", proto, header.IPv4ProtocolNumber)
		}

		ipHdr := header.IPv4(wire[:header.IPv4MinimumSize])
		srcAddr := ipHdr.SourceAddress()
		if got := srcAddr.AsSlice(); string(got) != string(src.Address.IP()) {
			t.Fatalf("source = %v, want %v", got, src.Address.IP())
		}
		dstAddr := ipHdr.DestinationAddress()
		if got := dstAddr.AsSlice(); string(got) != string(dst.Address.IP()) {
			t.Fatalf("destination = %v, want %v", got, dst.Address.IP())
		}
		msg, err := icmp.ParseMessage(1, wire[header.IPv4MinimumSize:])
		if err != nil {
			t.Fatalf("ParseMessage() failed: %v", err)
		}
		if got := msg.Type.(ipv4.ICMPType); got != ipv4.ICMPTypeEchoReply {
			t.Fatalf("type = %v, want %v", got, ipv4.ICMPTypeEchoReply)
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		payload := mustMarshalICMPMessage(t, &icmp.Message{
			Type: ipv6.ICMPTypeEchoReply,
			Code: 0,
			Body: &icmp.Echo{
				ID:   0x4321,
				Seq:  9,
				Data: []byte("pong6"),
			},
		})

		src := xnet.ICMPDestination(xnet.ParseAddress("2001:4860:4860::8888"))
		dst := xnet.ICMPDestination(xnet.ParseAddress("2001:db8::10"))
		wire, proto, err := buildRawICMPNetworkPacket(payload, src, dst)
		if err != nil {
			t.Fatalf("buildRawICMPNetworkPacket() failed: %v", err)
		}
		if proto != header.IPv6ProtocolNumber {
			t.Fatalf("proto = %v, want %v", proto, header.IPv6ProtocolNumber)
		}

		ipHdr := header.IPv6(wire[:header.IPv6MinimumSize])
		srcAddr := ipHdr.SourceAddress()
		if got := srcAddr.AsSlice(); string(got) != string(src.Address.IP()) {
			t.Fatalf("source = %v, want %v", got, src.Address.IP())
		}
		dstAddr := ipHdr.DestinationAddress()
		if got := dstAddr.AsSlice(); string(got) != string(dst.Address.IP()) {
			t.Fatalf("destination = %v, want %v", got, dst.Address.IP())
		}
		msg, err := icmp.ParseMessage(58, wire[header.IPv6MinimumSize:])
		if err != nil {
			t.Fatalf("ParseMessage() failed: %v", err)
		}
		if got := msg.Type.(ipv6.ICMPType); got != ipv6.ICMPTypeEchoReply {
			t.Fatalf("type = %v, want %v", got, ipv6.ICMPTypeEchoReply)
		}
	})
}

func TestExtractRawICMPPacket(t *testing.T) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.ICMPv4MinimumSize,
		Payload:            buffer.MakeWithData([]byte("tail")),
	})
	defer pkt.DecRef()

	hdr := pkt.TransportHeader().Push(header.ICMPv4MinimumSize)
	copy(hdr, []byte{8, 0, 0x12, 0x34, 0xab, 0xcd, 0x00, 0x01})

	got := extractRawICMPPacket(pkt)
	want := []byte{8, 0, 0x12, 0x34, 0xab, 0xcd, 0x00, 0x01, 't', 'a', 'i', 'l'}
	if string(got) != string(want) {
		t.Fatalf("extractRawICMPPacket() = %v, want %v", got, want)
	}
}

func mustReceiveCreatedFlow(t *testing.T, ch <-chan createdFlow) createdFlow {
	t.Helper()

	select {
	case flow := <-ch:
		return flow
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for flow creation")
		return createdFlow{}
	}
}

func assertNoCreatedFlow(t *testing.T, ch <-chan createdFlow) {
	t.Helper()

	select {
	case flow := <-ch:
		t.Fatalf("unexpected flow creation for %v", flow.dst)
	case <-time.After(50 * time.Millisecond):
	}
}

type createdFlow struct {
	conn *icmpConn
	dst  xnet.Destination
}

func mustMarshalICMPMessage(t *testing.T, msg *icmp.Message) []byte {
	t.Helper()

	wire, err := msg.Marshal(nil)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}
	return wire
}
