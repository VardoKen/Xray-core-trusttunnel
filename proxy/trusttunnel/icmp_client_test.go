package trusttunnel

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type testMultiBufferReader struct {
	mbs []buf.MultiBuffer
}

func (r *testMultiBufferReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(r.mbs) == 0 {
		return nil, io.EOF
	}
	mb := r.mbs[0]
	r.mbs = r.mbs[1:]
	return mb, nil
}

type testMultiBufferWriter struct {
	mbs []buf.MultiBuffer
}

func (w *testMultiBufferWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.mbs = append(w.mbs, cloneMultiBuffer(mb))
	buf.ReleaseMulti(mb)
	return nil
}

type scriptedICMPTunnelConn struct {
	ready      chan struct{}
	readyOnce  sync.Once
	mu         sync.Mutex
	written    []byte
	reply      []byte
	replyErr   error
	replyBuilt bool
	buildReply func([]byte) ([]byte, error)
}

func newScriptedICMPTunnelConn(buildReply func([]byte) ([]byte, error)) *scriptedICMPTunnelConn {
	return &scriptedICMPTunnelConn{
		ready:      make(chan struct{}),
		buildReply: buildReply,
	}
}

func (c *scriptedICMPTunnelConn) Read(p []byte) (int, error) {
	<-c.ready

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.replyErr != nil {
		err := c.replyErr
		c.replyErr = nil
		return 0, err
	}
	if len(c.reply) == 0 {
		return 0, io.EOF
	}

	n := copy(p, c.reply)
	c.reply = c.reply[n:]
	if len(c.reply) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func (c *scriptedICMPTunnelConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.written = append(c.written, p...)
	if !c.replyBuilt {
		c.replyBuilt = true
		if c.buildReply != nil {
			c.reply, c.replyErr = c.buildReply(append([]byte(nil), c.written...))
		}
		c.readyOnce.Do(func() {
			close(c.ready)
		})
	}
	return len(p), nil
}

func (c *scriptedICMPTunnelConn) Close() error {
	c.readyOnce.Do(func() {
		close(c.ready)
	})
	return nil
}

func TestTrustTunnelICMPRequestFromBufferUsesFallbackDestination(t *testing.T) {
	reqWire := mustMarshalICMPMessage(t, &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0x1234,
			Seq:  0x0021,
			Data: []byte("hello"),
		},
	})

	b := buf.New()
	if _, err := b.Write(reqWire); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	defer b.Release()

	dest := xnet.ICMPDestination(xnet.ParseAddress("1.1.1.1"))
	pkt, payload, key, err := trustTunnelICMPRequestFromBuffer(b, dest, 0)
	if err != nil {
		t.Fatalf("trustTunnelICMPRequestFromBuffer() failed: %v", err)
	}

	if got := pkt.Destination.String(); got != "1.1.1.1" {
		t.Fatalf("Destination = %q, want %q", got, "1.1.1.1")
	}
	if pkt.ID != 0x1234 || pkt.Sequence != 0x0021 {
		t.Fatalf("request = %+v, want id=0x1234 seq=0x0021", pkt)
	}
	if pkt.TTL != trustTunnelICMPDefaultTTL {
		t.Fatalf("TTL = %d, want %d", pkt.TTL, trustTunnelICMPDefaultTTL)
	}
	if pkt.DataSize != uint16(len("hello")) {
		t.Fatalf("DataSize = %d, want %d", pkt.DataSize, len("hello"))
	}
	if string(payload) != "hello" {
		t.Fatalf("payload = %q, want %q", string(payload), "hello")
	}
	if key.peer != "1.1.1.1" || key.v6 || key.id != 0x1234 || key.seq != 0x0021 {
		t.Fatalf("key = %+v, want peer=1.1.1.1 v6=false id=0x1234 seq=0x0021", key)
	}
}

func TestTrustTunnelICMPRequestFromBufferUsesTTLMetadata(t *testing.T) {
	reqWire := mustMarshalICMPMessage(t, &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0x3456,
			Seq:  0x0002,
			Data: []byte("ttl"),
		},
	})

	b := buf.New()
	if _, err := b.Write(reqWire); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	defer b.Release()

	dest := xnet.ICMPDestination(xnet.ParseAddress("1.1.1.1"))
	dest.Port = 9
	b.UDP = &dest

	pkt, _, _, err := trustTunnelICMPRequestFromBuffer(b, xnet.ICMPDestination(xnet.ParseAddress("9.9.9.9")), trustTunnelICMPTTLFromBuffer(b, trustTunnelICMPDefaultTTL))
	if err != nil {
		t.Fatalf("trustTunnelICMPRequestFromBuffer() failed: %v", err)
	}
	if pkt.TTL != 9 {
		t.Fatalf("TTL = %d, want 9", pkt.TTL)
	}
}

func TestTrustTunnelICMPRequestFromBufferRejectsNonEchoRequest(t *testing.T) {
	replyWire := mustMarshalICMPMessage(t, &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0x1234,
			Seq:  1,
			Data: []byte("bad"),
		},
	})

	b := buf.New()
	if _, err := b.Write(replyWire); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	defer b.Release()

	dest := xnet.ICMPDestination(xnet.ParseAddress("1.1.1.1"))
	if _, _, _, err := trustTunnelICMPRequestFromBuffer(b, dest, trustTunnelICMPDefaultTTL); err == nil {
		t.Fatal("expected non-echo request error, got nil")
	}
}

func TestRunTrustTunnelICMPTunnelEchoRoundTrip(t *testing.T) {
	requestData := []byte("payload-123")
	requestWire := mustMarshalICMPMessage(t, &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0x1234,
			Seq:  7,
			Data: requestData,
		},
	})

	b := buf.New()
	if _, err := b.Write(requestWire); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	dest := xnet.ICMPDestination(xnet.ParseAddress("1.1.1.1"))
	b.UDP = &dest

	link := &transport.Link{
		Reader: &testMultiBufferReader{mbs: []buf.MultiBuffer{{b}}},
		Writer: &testMultiBufferWriter{},
	}

	tunnelConn := newScriptedICMPTunnelConn(func(written []byte) ([]byte, error) {
		var decoder trustTunnelICMPRequestDecoder
		packets, err := decoder.Feed(written)
		if err != nil {
			t.Fatalf("decoder.Feed() failed: %v", err)
		}
		if len(packets) != 1 {
			t.Fatalf("decoder.Feed() produced %d packets, want 1", len(packets))
		}

		pkt := packets[0]
		if pkt.ID != 0x1234 || pkt.Sequence != 7 {
			t.Fatalf("request packet = %+v, want id=0x1234 seq=7", pkt)
		}
		if got := pkt.Destination.String(); got != "1.1.1.1" {
			t.Fatalf("Destination = %q, want %q", got, "1.1.1.1")
		}
		if pkt.TTL != trustTunnelICMPDefaultTTL {
			t.Fatalf("TTL = %d, want %d", pkt.TTL, trustTunnelICMPDefaultTTL)
		}
		if pkt.DataSize != uint16(len(requestData)) {
			t.Fatalf("DataSize = %d, want %d", pkt.DataSize, len(requestData))
		}

		return encodeTrustTunnelICMPReply(trustTunnelICMPReplyPacket{
			ID:       pkt.ID,
			Source:   pkt.Destination,
			Type:     uint8(ipv4.ICMPTypeEchoReply),
			Code:     0,
			Sequence: pkt.Sequence,
		})
	})

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: xnet.ICMPDestination(xnet.ParseAddress("192.0.2.10")),
	})
	if err := runTrustTunnelICMPTunnel(ctx, link, tunnelConn, xnet.ICMPDestination(xnet.ParseAddress("9.9.9.9"))); err != nil {
		t.Fatalf("runTrustTunnelICMPTunnel() failed: %v", err)
	}

	writer := link.Writer.(*testMultiBufferWriter)
	if len(writer.mbs) != 1 {
		t.Fatalf("writer got %d MultiBuffers, want 1", len(writer.mbs))
	}
	if len(writer.mbs[0]) != 1 {
		t.Fatalf("writer got %d buffers, want 1", len(writer.mbs[0]))
	}

	replyBuf := writer.mbs[0][0]
	defer buf.ReleaseMulti(writer.mbs[0])

	if replyBuf.UDP == nil {
		t.Fatal("replyBuf.UDP is nil")
	}
	if replyBuf.UDP.Network != xnet.Network_ICMP || replyBuf.UDP.Address.String() != "1.1.1.1" {
		t.Fatalf("replyBuf.UDP = %+v, want icmp:1.1.1.1", replyBuf.UDP)
	}

	msg, err := icmp.ParseMessage(1, replyBuf.Bytes())
	if err != nil {
		t.Fatalf("ParseMessage() failed: %v", err)
	}
	if got := msg.Type.(ipv4.ICMPType); got != ipv4.ICMPTypeEchoReply {
		t.Fatalf("Type = %v, want %v", got, ipv4.ICMPTypeEchoReply)
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("Body type = %T, want *icmp.Echo", msg.Body)
	}
	if echo.ID != 0x1234 || echo.Seq != 7 {
		t.Fatalf("echo = %+v, want id=0x1234 seq=7", echo)
	}
	if string(echo.Data) != string(requestData) {
		t.Fatalf("echo.Data = %q, want %q", string(echo.Data), string(requestData))
	}
}

func TestRunTrustTunnelICMPTunnelDestinationUnreachableRoundTrip(t *testing.T) {
	requestData := []byte("payload-err")
	requestWire := mustMarshalICMPMessage(t, &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0x1234,
			Seq:  9,
			Data: requestData,
		},
	})

	b := buf.New()
	if _, err := b.Write(requestWire); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	dest := xnet.ICMPDestination(xnet.ParseAddress("1.1.1.1"))
	b.UDP = &dest

	link := &transport.Link{
		Reader: &testMultiBufferReader{mbs: []buf.MultiBuffer{{b}}},
		Writer: &testMultiBufferWriter{},
	}

	tunnelConn := newScriptedICMPTunnelConn(func(written []byte) ([]byte, error) {
		var decoder trustTunnelICMPRequestDecoder
		packets, err := decoder.Feed(written)
		if err != nil {
			t.Fatalf("decoder.Feed() failed: %v", err)
		}
		pkt := packets[0]
		return encodeTrustTunnelICMPReply(trustTunnelICMPReplyPacket{
			ID:       pkt.ID,
			Source:   net.ParseIP("203.0.113.1"),
			Type:     uint8(ipv4.ICMPTypeDestinationUnreachable),
			Code:     1,
			Sequence: pkt.Sequence,
		})
	})

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: xnet.ICMPDestination(xnet.ParseAddress("192.0.2.10")),
	})
	if err := runTrustTunnelICMPTunnel(ctx, link, tunnelConn, xnet.ICMPDestination(xnet.ParseAddress("9.9.9.9"))); err != nil {
		t.Fatalf("runTrustTunnelICMPTunnel() failed: %v", err)
	}

	writer := link.Writer.(*testMultiBufferWriter)
	if len(writer.mbs) != 1 || len(writer.mbs[0]) != 1 {
		t.Fatalf("writer output = %d/%d, want 1/1", len(writer.mbs), len(writer.mbs[0]))
	}

	replyBuf := writer.mbs[0][0]
	defer buf.ReleaseMulti(writer.mbs[0])

	if replyBuf.UDP == nil {
		t.Fatal("replyBuf.UDP is nil")
	}
	if got := replyBuf.UDP.Address.String(); got != "203.0.113.1" {
		t.Fatalf("replyBuf.UDP.Address = %q, want %q", got, "203.0.113.1")
	}

	msg, err := icmp.ParseMessage(1, replyBuf.Bytes())
	if err != nil {
		t.Fatalf("ParseMessage() failed: %v", err)
	}
	if got := msg.Type.(ipv4.ICMPType); got != ipv4.ICMPTypeDestinationUnreachable {
		t.Fatalf("Type = %v, want %v", got, ipv4.ICMPTypeDestinationUnreachable)
	}
	body, ok := msg.Body.(*icmp.DstUnreach)
	if !ok {
		t.Fatalf("Body type = %T, want *icmp.DstUnreach", msg.Body)
	}
	if len(body.Data) < 28 {
		t.Fatalf("len(body.Data) = %d, want >= 28", len(body.Data))
	}
	if got := net.IP(body.Data[12:16]).String(); got != "192.0.2.10" {
		t.Fatalf("quoted src = %q, want %q", got, "192.0.2.10")
	}
	if got := net.IP(body.Data[16:20]).String(); got != "1.1.1.1" {
		t.Fatalf("quoted dst = %q, want %q", got, "1.1.1.1")
	}
	quoted, err := icmp.ParseMessage(1, body.Data[20:])
	if err != nil {
		t.Fatalf("ParseMessage(quoted) failed: %v", err)
	}
	echo, ok := quoted.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("quoted body type = %T, want *icmp.Echo", quoted.Body)
	}
	if echo.ID != 0x1234 || echo.Seq != 9 {
		t.Fatalf("quoted echo = %+v, want id=0x1234 seq=9", echo)
	}
	if string(echo.Data) != string(requestData) {
		t.Fatalf("quoted echo data = %q, want %q", string(echo.Data), string(requestData))
	}
}

func TestRunTrustTunnelICMPTunnelTimeExceededRoundTrip(t *testing.T) {
	requestWire := mustMarshalICMPMessage(t, &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0x2345,
			Seq:  4,
			Data: []byte("ttl"),
		},
	})

	b := buf.New()
	if _, err := b.Write(requestWire); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	dest := xnet.ICMPDestination(xnet.ParseAddress("1.1.1.1"))
	b.UDP = &dest

	link := &transport.Link{
		Reader: &testMultiBufferReader{mbs: []buf.MultiBuffer{{b}}},
		Writer: &testMultiBufferWriter{},
	}

	tunnelConn := newScriptedICMPTunnelConn(func(written []byte) ([]byte, error) {
		var decoder trustTunnelICMPRequestDecoder
		packets, err := decoder.Feed(written)
		if err != nil {
			t.Fatalf("decoder.Feed() failed: %v", err)
		}
		pkt := packets[0]
		return encodeTrustTunnelICMPReply(trustTunnelICMPReplyPacket{
			ID:       pkt.ID,
			Source:   net.ParseIP("203.0.113.254"),
			Type:     uint8(ipv4.ICMPTypeTimeExceeded),
			Code:     0,
			Sequence: pkt.Sequence,
		})
	})

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: xnet.ICMPDestination(xnet.ParseAddress("192.0.2.10")),
	})
	if err := runTrustTunnelICMPTunnel(ctx, link, tunnelConn, xnet.ICMPDestination(xnet.ParseAddress("9.9.9.9"))); err != nil {
		t.Fatalf("runTrustTunnelICMPTunnel() failed: %v", err)
	}

	writer := link.Writer.(*testMultiBufferWriter)
	replyBuf := writer.mbs[0][0]
	defer buf.ReleaseMulti(writer.mbs[0])

	msg, err := icmp.ParseMessage(1, replyBuf.Bytes())
	if err != nil {
		t.Fatalf("ParseMessage() failed: %v", err)
	}
	if got := msg.Type.(ipv4.ICMPType); got != ipv4.ICMPTypeTimeExceeded {
		t.Fatalf("Type = %v, want %v", got, ipv4.ICMPTypeTimeExceeded)
	}
	if _, ok := msg.Body.(*icmp.TimeExceeded); !ok {
		t.Fatalf("Body type = %T, want *icmp.TimeExceeded", msg.Body)
	}
}

func cloneMultiBuffer(mb buf.MultiBuffer) buf.MultiBuffer {
	cloned := make(buf.MultiBuffer, 0, len(mb))
	for _, bb := range mb {
		nb := buf.New()
		if _, err := nb.Write(bb.Bytes()); err != nil {
			panic(err)
		}
		if bb.UDP != nil {
			dest := *bb.UDP
			nb.UDP = &dest
		}
		cloned = append(cloned, nb)
	}
	return cloned
}

func mustMarshalICMPMessage(t *testing.T, msg *icmp.Message) []byte {
	t.Helper()

	wire, err := msg.Marshal(nil)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}
	return wire
}
