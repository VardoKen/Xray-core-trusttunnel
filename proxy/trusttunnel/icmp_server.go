package trusttunnel

import (
	"context"
	"crypto/rand"
	"io"
	stdnet "net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const trustTunnelICMPRequestTimeout = 3 * time.Second

type trustTunnelICMPSessionOptions struct {
	ipv6Available                  bool
	interfaceName                  string
	requestTimeout                 time.Duration
	allowPrivateNetworkConnections bool
}

type trustTunnelICMPHandler interface {
	HandleRequest(context.Context, trustTunnelICMPRequestPacket) (trustTunnelICMPReplyPacket, bool, error)
	Close() error
}

type trustTunnelICMPWaitKey struct {
	peer string
	v6   bool
	id   uint16
	seq  uint16
}

type trustTunnelICMPSession struct {
	timeout                        time.Duration
	interfaceIndex                 int
	allowPrivateNetworkConnections bool
	v4                             *icmp.PacketConn
	v4pc                           *ipv4.PacketConn
	v6                             *icmp.PacketConn
	v6pc                           *ipv6.PacketConn

	waiters map[trustTunnelICMPWaitKey]chan trustTunnelICMPReplyPacket
	mu      sync.Mutex

	closeOnce sync.Once
}

func buildTrustTunnelICMPSessionOptions(config *ServerConfig) trustTunnelICMPSessionOptions {
	options := trustTunnelICMPSessionOptions{
		ipv6Available:                  config.GetIpv6Available(),
		interfaceName:                  config.GetIcmpInterfaceName(),
		allowPrivateNetworkConnections: config.GetAllowPrivateNetworkConnections(),
		requestTimeout:                 trustTunnelICMPRequestTimeout,
	}
	if secs := config.GetIcmpRequestTimeoutSecs(); secs > 0 {
		options.requestTimeout = time.Duration(secs) * time.Second
	}
	return options
}

func newTrustTunnelICMPSession(options trustTunnelICMPSessionOptions) (trustTunnelICMPHandler, error) {
	v4, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	session := &trustTunnelICMPSession{
		timeout:                        options.requestTimeout,
		allowPrivateNetworkConnections: options.allowPrivateNetworkConnections,
		v4:                             v4,
		v4pc:                           v4.IPv4PacketConn(),
		waiters:                        make(map[trustTunnelICMPWaitKey]chan trustTunnelICMPReplyPacket),
	}

	if session.timeout <= 0 {
		session.timeout = trustTunnelICMPRequestTimeout
	}

	if options.interfaceName != "" {
		iface, err := stdnet.InterfaceByName(options.interfaceName)
		if err != nil {
			_ = v4.Close()
			return nil, err
		}
		session.interfaceIndex = iface.Index
	}

	if options.ipv6Available {
		if v6, err := icmp.ListenPacket("ip6:ipv6-icmp", "::"); err == nil {
			session.v6 = v6
			session.v6pc = v6.IPv6PacketConn()
			go session.readLoopV6()
		}
	}

	go session.readLoopV4()
	return session, nil
}

func (s *Server) openICMPSession() (trustTunnelICMPHandler, error) {
	options := buildTrustTunnelICMPSessionOptions(s.config)
	if s.newICMPSession != nil {
		return s.newICMPSession(options)
	}
	return newTrustTunnelICMPSession(options)
}

func (s *Server) serveICMPMuxRequest(proto string, ctx context.Context, w http.ResponseWriter, req *http.Request) {
	session, err := s.openICMPSession()
	if err != nil {
		writeH2Response(w, http.StatusServiceUnavailable, "icmp is unavailable\n", nil)
		errors.LogWarningInner(ctx, err, "trusttunnel "+proto+" ICMP unavailable")
		return
	}
	defer session.Close()

	errors.LogInfo(ctx, "trusttunnel ", proto, " ICMP mux accepted")
	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}

	var flusher http.Flusher
	if f, ok := w.(http.Flusher); ok {
		flusher = f
	}
	writer := &flushWriter{w: w, f: flusher}

	var decoder trustTunnelICMPRequestDecoder
	var writeMu sync.Mutex
	var workers sync.WaitGroup
	tmp := make([]byte, 64*1024)

	for {
		n, readErr := req.Body.Read(tmp)
		if n > 0 {
			packets, decodeErr := decoder.Feed(tmp[:n])
			if decodeErr != nil {
				errors.LogWarningInner(ctx, decodeErr, "failed to decode trusttunnel icmp request")
				break
			}

			for _, pkt := range packets {
				pkt := pkt
				workers.Add(1)
				go func() {
					defer workers.Done()

					errors.LogDebug(ctx, "trusttunnel ", proto, " icmp request id=", pkt.ID, " dst=", pkt.Destination.String(), " seq=", pkt.Sequence, " size=", pkt.DataSize)

					reply, ok, handleErr := session.HandleRequest(ctx, pkt)
					if handleErr != nil {
						errors.LogWarningInner(ctx, handleErr, "failed to handle trusttunnel icmp request")
						return
					}
					if !ok {
						return
					}

					wire, err := encodeTrustTunnelICMPReply(reply)
					if err != nil {
						errors.LogWarningInner(ctx, err, "failed to encode trusttunnel icmp reply")
						return
					}

					errors.LogDebug(ctx, "trusttunnel ", proto, " icmp reply id=", reply.ID, " src=", reply.Source.String(), " type=", reply.Type, " code=", reply.Code, " seq=", reply.Sequence)

					writeMu.Lock()
					_, err = writer.Write(wire)
					writeMu.Unlock()
					if err != nil {
						errors.LogWarningInner(ctx, err, "failed to write trusttunnel icmp reply")
					}
				}()
			}
		}

		if readErr != nil {
			if readErr != io.EOF {
				errors.LogWarningInner(ctx, readErr, "trusttunnel icmp mux read error")
			}
			break
		}
	}

	workers.Wait()
}

func (s *trustTunnelICMPSession) HandleRequest(ctx context.Context, pkt trustTunnelICMPRequestPacket) (trustTunnelICMPReplyPacket, bool, error) {
	var zero trustTunnelICMPReplyPacket

	dst := trustTunnelCloneIP(pkt.Destination)
	if dst == nil {
		return zero, false, stdnet.InvalidAddrError("invalid ICMP destination")
	}
	if err := trustTunnelValidateICMPDestination(dst, s.allowPrivateNetworkConnections); err != nil {
		return zero, false, err
	}

	data := make([]byte, int(pkt.DataSize))
	if _, err := rand.Read(data); err != nil {
		return zero, false, err
	}

	ttl := pkt.TTL
	if ttl == 0 {
		ttl = 64
	}

	key := trustTunnelICMPWaitKey{
		peer: dst.String(),
		v6:   dst.To4() == nil,
		id:   pkt.ID,
		seq:  pkt.Sequence,
	}
	ch := make(chan trustTunnelICMPReplyPacket, 1)
	s.registerWaiter(key, ch)
	defer s.unregisterWaiter(key, ch)

	if dst.To4() != nil {
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   int(pkt.ID),
				Seq:  int(pkt.Sequence),
				Data: data,
			},
		}
		wire, err := msg.Marshal(nil)
		if err != nil {
			return zero, false, err
		}
		control := &ipv4.ControlMessage{TTL: int(ttl)}
		if s.interfaceIndex != 0 {
			control.IfIndex = s.interfaceIndex
		}
		if _, err := s.v4pc.WriteTo(wire, control, &stdnet.IPAddr{IP: dst}); err != nil {
			return zero, false, err
		}
		errors.LogDebug(ctx, "trusttunnel icmp raw send v4 dst=", dst.String(), " id=", pkt.ID, " seq=", pkt.Sequence)
	} else {
		if s.v6pc == nil {
			return zero, false, stdnet.InvalidAddrError("IPv6 ICMP is unavailable")
		}
		msg := icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest,
			Code: 0,
			Body: &icmp.Echo{
				ID:   int(pkt.ID),
				Seq:  int(pkt.Sequence),
				Data: data,
			},
		}
		wire, err := msg.Marshal(nil)
		if err != nil {
			return zero, false, err
		}
		control := &ipv6.ControlMessage{HopLimit: int(ttl)}
		if s.interfaceIndex != 0 {
			control.IfIndex = s.interfaceIndex
		}
		if _, err := s.v6pc.WriteTo(wire, control, &stdnet.IPAddr{IP: dst}); err != nil {
			return zero, false, err
		}
		errors.LogDebug(ctx, "trusttunnel icmp raw send v6 dst=", dst.String(), " id=", pkt.ID, " seq=", pkt.Sequence)
	}

	timer := time.NewTimer(s.timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return zero, false, ctx.Err()
	case <-timer.C:
		errors.LogDebug(ctx, "trusttunnel icmp request timed out dst=", dst.String(), " id=", pkt.ID, " seq=", pkt.Sequence)
		return zero, false, nil
	case reply := <-ch:
		return reply, true, nil
	}
}

func (s *trustTunnelICMPSession) Close() error {
	s.closeOnce.Do(func() {
		if s.v4 != nil {
			_ = s.v4.Close()
		}
		if s.v6 != nil {
			_ = s.v6.Close()
		}
	})
	return nil
}

func (s *trustTunnelICMPSession) registerWaiter(key trustTunnelICMPWaitKey, ch chan trustTunnelICMPReplyPacket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.waiters[key] = ch
}

func (s *trustTunnelICMPSession) unregisterWaiter(key trustTunnelICMPWaitKey, ch chan trustTunnelICMPReplyPacket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.waiters[key]; ok && current == ch {
		delete(s.waiters, key)
	}
}

func (s *trustTunnelICMPSession) deliverReply(key trustTunnelICMPWaitKey, reply trustTunnelICMPReplyPacket) {
	s.mu.Lock()
	ch, ok := s.waiters[key]
	s.mu.Unlock()
	if !ok {
		return
	}

	select {
	case ch <- reply:
	default:
	}
}

func (s *trustTunnelICMPSession) readLoopV4() {
	s.readLoop(s.v4, 1, false)
}

func (s *trustTunnelICMPSession) readLoopV6() {
	s.readLoop(s.v6, 58, true)
}

func (s *trustTunnelICMPSession) readLoop(conn *icmp.PacketConn, proto int, v6 bool) {
	if conn == nil {
		return
	}

	buf := make([]byte, 64*1024)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}

		msg, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		reply, key, ok := trustTunnelICMPReplyFromMessage(msg, peer, v6)
		if !ok {
			continue
		}
		errors.LogDebug(context.Background(), "trusttunnel icmp raw reply src=", reply.Source.String(), " id=", reply.ID, " seq=", reply.Sequence, " type=", reply.Type, " code=", reply.Code)
		s.deliverReply(key, reply)
	}
}

func trustTunnelCloneIP(ip stdnet.IP) stdnet.IP {
	if ip == nil {
		return nil
	}
	out := make(stdnet.IP, len(ip))
	copy(out, ip)
	return out
}

func trustTunnelICMPTypeValue(typ icmp.Type, v6 bool) uint8 {
	if v6 {
		if typed, ok := typ.(ipv6.ICMPType); ok {
			return uint8(typed)
		}
		return 0
	}
	if typed, ok := typ.(ipv4.ICMPType); ok {
		return uint8(typed)
	}
	return 0
}

func trustTunnelICMPIsReplyType(typ icmp.Type, v6 bool) bool {
	if v6 {
		typed, ok := typ.(ipv6.ICMPType)
		if !ok {
			return false
		}
		switch typed {
		case ipv6.ICMPTypeEchoReply, ipv6.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeTimeExceeded, ipv6.ICMPTypePacketTooBig, ipv6.ICMPTypeParameterProblem:
			return true
		default:
			return false
		}
	}
	typed, ok := typ.(ipv4.ICMPType)
	if !ok {
		return false
	}
	switch typed {
	case ipv4.ICMPTypeEchoReply, ipv4.ICMPTypeDestinationUnreachable, ipv4.ICMPTypeTimeExceeded, ipv4.ICMPTypeParameterProblem:
		return true
	default:
		return false
	}
}

func trustTunnelICMPReplyFromMessage(msg *icmp.Message, peer stdnet.Addr, v6 bool) (trustTunnelICMPReplyPacket, trustTunnelICMPWaitKey, bool) {
	var zeroReply trustTunnelICMPReplyPacket
	var zeroKey trustTunnelICMPWaitKey

	if !trustTunnelICMPIsReplyType(msg.Type, v6) {
		return zeroReply, zeroKey, false
	}

	ipAddr, ok := peer.(*stdnet.IPAddr)
	if !ok {
		return zeroReply, zeroKey, false
	}

	reply := trustTunnelICMPReplyPacket{
		Source: trustTunnelCloneIP(ipAddr.IP),
		Type:   trustTunnelICMPTypeValue(msg.Type, v6),
		Code:   uint8(msg.Code),
	}

	if echo, ok := msg.Body.(*icmp.Echo); ok {
		reply.ID = uint16(echo.ID)
		reply.Sequence = uint16(echo.Seq)
		return reply, trustTunnelICMPWaitKey{
			peer: reply.Source.String(),
			v6:   v6,
			id:   reply.ID,
			seq:  reply.Sequence,
		}, true
	}

	matchPeer, id, seq, ok := trustTunnelICMPRespondedEchoRequest(msg.Body, v6)
	if !ok {
		return zeroReply, zeroKey, false
	}
	reply.ID = id
	reply.Sequence = seq
	return reply, trustTunnelICMPWaitKey{
		peer: matchPeer,
		v6:   v6,
		id:   id,
		seq:  seq,
	}, true
}

func trustTunnelICMPRespondedEchoRequest(body icmp.MessageBody, v6 bool) (string, uint16, uint16, bool) {
	switch typed := body.(type) {
	case *icmp.DstUnreach:
		return trustTunnelQuotedICMPEchoRequest(typed.Data, v6)
	case *icmp.TimeExceeded:
		return trustTunnelQuotedICMPEchoRequest(typed.Data, v6)
	case *icmp.PacketTooBig:
		return trustTunnelQuotedICMPEchoRequest(typed.Data, v6)
	case *icmp.ParamProb:
		return trustTunnelQuotedICMPEchoRequest(typed.Data, v6)
	default:
		return "", 0, 0, false
	}
}

func trustTunnelQuotedICMPEchoRequest(data []byte, v6 bool) (string, uint16, uint16, bool) {
	if v6 {
		if len(data) < 40+8 {
			return "", 0, 0, false
		}
		dst := trustTunnelCloneIP(stdnet.IP(data[24:40]))
		msg, err := icmp.ParseMessage(58, data[40:])
		if err != nil {
			return "", 0, 0, false
		}
		echo, err := trustTunnelParseICMPEchoRequest(msg, true)
		if err != nil {
			return "", 0, 0, false
		}
		return dst.String(), uint16(echo.ID), uint16(echo.Seq), true
	}

	if len(data) < 20+8 {
		return "", 0, 0, false
	}
	headerLen := int(data[0]&0x0f) * 4
	if headerLen < 20 || len(data) < headerLen+8 {
		return "", 0, 0, false
	}
	dst := trustTunnelCloneIP(stdnet.IP(data[16:20]))
	msg, err := icmp.ParseMessage(1, data[headerLen:])
	if err != nil {
		return "", 0, 0, false
	}
	echo, err := trustTunnelParseICMPEchoRequest(msg, false)
	if err != nil {
		return "", 0, 0, false
	}
	return dst.String(), uint16(echo.ID), uint16(echo.Seq), true
}

func trustTunnelValidateICMPDestination(ip stdnet.IP, allowPrivateNetworkConnections bool) error {
	if trustTunnelCloneIP(ip) == nil {
		return stdnet.InvalidAddrError("invalid ICMP destination")
	}
	if allowPrivateNetworkConnections {
		return nil
	}
	if !trustTunnelIsGlobalIP(ip) {
		return stdnet.InvalidAddrError("private network connections are disabled")
	}
	return nil
}

func trustTunnelIsGlobalIP(ip stdnet.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsPrivate() {
		return false
	}
	return addr.IsGlobalUnicast()
}
