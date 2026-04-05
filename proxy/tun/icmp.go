package tun

import (
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type outboundPacketInjector interface {
	InjectOutbound(dest tcpip.Address, packet *buffer.View) tcpip.Error
}

type icmpFlowKey struct {
	src net.Destination
	dst net.Destination
}

type icmpPacket struct {
	wire []byte
	ttl  uint8
}

type icmpConnectionHandler struct {
	sync.Mutex

	icmpConns map[icmpFlowKey]*icmpConn

	handleConnection func(conn net.Conn, dest net.Destination)
	writePacket      func(data []byte, src net.Destination, dst net.Destination) error
}

func newICMPConnectionHandler(handleConnection func(conn net.Conn, dest net.Destination), writePacket func(data []byte, src net.Destination, dst net.Destination) error) *icmpConnectionHandler {
	return &icmpConnectionHandler{
		icmpConns:        make(map[icmpFlowKey]*icmpConn),
		handleConnection: handleConnection,
		writePacket:      writePacket,
	}
}

func (h *icmpConnectionHandler) HandlePacket(src net.Destination, dst net.Destination, wire []byte, ttl uint8) bool {
	if !isSupportedICMPEchoRequest(dst, wire) {
		return false
	}

	key := icmpFlowKey{src: src, dst: dst}
	packet := icmpPacket{
		wire: append([]byte(nil), wire...),
		ttl:  ttl,
	}

	h.Lock()
	conn, found := h.icmpConns[key]
	if !found {
		conn = &icmpConn{
			handler: h,
			key:     key,
			egress:  make(chan icmpPacket, 16),
			src:     src,
			dst:     dst,
		}
		h.icmpConns[key] = conn
		go h.handleConnection(conn, dst)
	}
	select {
	case conn.egress <- packet:
	default:
	}
	h.Unlock()

	return true
}

func (h *icmpConnectionHandler) connectionFinished(key icmpFlowKey) {
	h.Lock()
	conn, found := h.icmpConns[key]
	if found {
		delete(h.icmpConns, key)
		close(conn.egress)
	}
	h.Unlock()
}

type icmpConn struct {
	handler *icmpConnectionHandler
	key     icmpFlowKey

	egress chan icmpPacket
	src    net.Destination
	dst    net.Destination
}

func (c *icmpConn) readPacket() (icmpPacket, bool) {
	packet, ok := <-c.egress
	return packet, ok
}

func (c *icmpConn) Read(p []byte) (int, error) {
	packet, ok := c.readPacket()
	if !ok {
		return 0, io.EOF
	}

	n := copy(p, packet.wire)
	return n, nil
}

func (c *icmpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	packet, ok := c.readPacket()
	if !ok {
		return nil, io.EOF
	}

	b := buf.FromBytes(packet.wire)
	metadata := c.dst
	if packet.ttl != 0 {
		metadata.Port = net.Port(packet.ttl)
	}
	b.UDP = &metadata
	return buf.MultiBuffer{b}, nil
}

func (c *icmpConn) Write(p []byte) (int, error) {
	if err := c.handler.writePacket(p, c.dst, c.src); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *icmpConn) Close() error {
	c.handler.connectionFinished(c.key)
	return nil
}

func (c *icmpConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: c.dst.Address.IP()}
}

func (c *icmpConn) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: c.src.Address.IP()}
}

func (c *icmpConn) SetDeadline(time.Time) error {
	return nil
}

func (c *icmpConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *icmpConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *icmpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	var wrote bool
	for _, b := range mb {
		dst := c.dst
		if b.UDP != nil {
			dst = *b.UDP
		}

		if !dst.IsValid() || dst.Address == nil || dst.Address.IP() == nil {
			return errors.New("icmp reply destination is invalid")
		}
		if dst.Address.Family() != c.dst.Address.Family() {
			return errors.New("icmp reply destination family does not match flow")
		}

		if err := c.handler.writePacket(b.Bytes(), dst, c.src); err != nil {
			return err
		}
		wrote = true
	}

	if !wrote && !mb.IsEmpty() {
		return errors.New("icmp reply was not written")
	}
	return nil
}

func isSupportedICMPEchoRequest(dst net.Destination, wire []byte) bool {
	if !dst.IsValid() || dst.Address == nil || dst.Address.IP() == nil {
		return false
	}

	proto := 1
	v6 := dst.Address.Family().IsIPv6()
	if v6 {
		proto = 58
	}

	msg, err := icmp.ParseMessage(proto, wire)
	if err != nil {
		return false
	}

	if v6 {
		typed, ok := msg.Type.(ipv6.ICMPType)
		return ok && typed == ipv6.ICMPTypeEchoRequest && msg.Code == 0
	}

	typed, ok := msg.Type.(ipv4.ICMPType)
	return ok && typed == ipv4.ICMPTypeEcho && msg.Code == 0
}

func extractRawICMPPacket(pkt *stack.PacketBuffer) []byte {
	headerBytes := pkt.TransportHeader().Slice()
	dataBytes := pkt.Data().AsRange().ToSlice()
	if len(headerBytes) == 0 && len(dataBytes) == 0 {
		return nil
	}

	wire := make([]byte, 0, len(headerBytes)+len(dataBytes))
	wire = append(wire, headerBytes...)
	wire = append(wire, dataBytes...)
	return wire
}

func extractICMPTTL(pkt *stack.PacketBuffer) uint8 {
	networkHeader := pkt.NetworkHeader().Slice()
	if len(networkHeader) == 0 {
		return 0
	}

	switch networkHeader[0] >> 4 {
	case 4:
		if len(networkHeader) >= header.IPv4MinimumSize {
			return networkHeader[8]
		}
	case 6:
		if len(networkHeader) >= header.IPv6MinimumSize {
			return networkHeader[7]
		}
	}

	return 0
}

func buildRawICMPNetworkPacket(payload []byte, src net.Destination, dst net.Destination) ([]byte, tcpip.NetworkProtocolNumber, error) {
	if src.Address == nil || dst.Address == nil {
		return nil, 0, errors.New("icmp packet addresses are missing")
	}

	srcIP := src.Address.IP()
	dstIP := dst.Address.IP()
	if srcIP == nil || dstIP == nil {
		return nil, 0, errors.New("icmp packet addresses must be IPs")
	}
	if src.Address.Family() != dst.Address.Family() {
		return nil, 0, errors.New("icmp packet address families do not match")
	}

	if dst.Address.Family().IsIPv4() {
		wire := make([]byte, header.IPv4MinimumSize+len(payload))
		copy(wire[header.IPv4MinimumSize:], payload)

		ipHdr := header.IPv4(wire[:header.IPv4MinimumSize])
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(wire)),
			TTL:         64,
			Protocol:    uint8(header.ICMPv4ProtocolNumber),
			SrcAddr:     tcpip.AddrFromSlice(srcIP),
			DstAddr:     tcpip.AddrFromSlice(dstIP),
		})
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

		return wire, header.IPv4ProtocolNumber, nil
	}

	wire := make([]byte, header.IPv6MinimumSize+len(payload))
	copy(wire[header.IPv6MinimumSize:], payload)

	ipHdr := header.IPv6(wire[:header.IPv6MinimumSize])
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(payload)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFromSlice(srcIP),
		DstAddr:           tcpip.AddrFromSlice(dstIP),
	})

	return wire, header.IPv6ProtocolNumber, nil
}

func (t *stackGVisor) writeRawICMPPacket(payload []byte, src net.Destination, dst net.Destination) error {
	wire, ipProto, err := buildRawICMPNetworkPacket(payload, src, dst)
	if err != nil {
		return err
	}

	if injector, ok := t.endpoint.(outboundPacketInjector); ok {
		view := buffer.NewViewWithData(wire)
		defer view.Release()

		if err := injector.InjectOutbound(tcpip.AddrFromSlice(dst.Address.IP()), view); err != nil {
			return errors.New("failed to inject raw icmp packet to link endpoint", err)
		}
		errors.LogDebug(t.ctx, "proxy/tun: injected icmp reply src=", src, " dst=", dst, " bytes=", len(wire))
		return nil
	}

	if err := t.stack.WriteRawPacket(defaultNIC, ipProto, buffer.MakeWithData(wire)); err != nil {
		return errors.New("failed to write raw icmp packet back to stack", err)
	}
	errors.LogDebug(t.ctx, "proxy/tun: injected icmp reply src=", src, " dst=", dst, " bytes=", len(wire))

	return nil
}
