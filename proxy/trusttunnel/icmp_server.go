package trusttunnel

import (
	"context"
	"crypto/rand"
	"io"
	stdnet "net"
	"net/http"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const trustTunnelICMPRequestTimeout = 3 * time.Second

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
	timeout time.Duration
	v4      *icmp.PacketConn
	v4pc    *ipv4.PacketConn
	v6      *icmp.PacketConn
	v6pc    *ipv6.PacketConn

	waiters map[trustTunnelICMPWaitKey]chan trustTunnelICMPReplyPacket
	mu      sync.Mutex

	closeOnce sync.Once
}

func newTrustTunnelICMPSession(ipv6Available bool) (trustTunnelICMPHandler, error) {
	v4, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	session := &trustTunnelICMPSession{
		timeout: trustTunnelICMPRequestTimeout,
		v4:      v4,
		v4pc:    v4.IPv4PacketConn(),
		waiters: make(map[trustTunnelICMPWaitKey]chan trustTunnelICMPReplyPacket),
	}

	if ipv6Available {
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
	if s.newICMPSession != nil {
		return s.newICMPSession(s.config.GetIpv6Available())
	}
	return newTrustTunnelICMPSession(s.config.GetIpv6Available())
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
		if _, err := s.v4pc.WriteTo(wire, &ipv4.ControlMessage{TTL: int(ttl)}, &stdnet.IPAddr{IP: dst}); err != nil {
			return zero, false, err
		}
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
		if _, err := s.v6pc.WriteTo(wire, &ipv6.ControlMessage{HopLimit: int(ttl)}, &stdnet.IPAddr{IP: dst}); err != nil {
			return zero, false, err
		}
	}

	timer := time.NewTimer(s.timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return zero, false, ctx.Err()
	case <-timer.C:
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
		if !trustTunnelICMPIsReplyType(msg.Type, v6) {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		ipAddr, ok := peer.(*stdnet.IPAddr)
		if !ok {
			continue
		}

		reply := trustTunnelICMPReplyPacket{
			ID:       uint16(echo.ID),
			Source:   trustTunnelCloneIP(ipAddr.IP),
			Type:     trustTunnelICMPTypeValue(msg.Type, v6),
			Code:     uint8(msg.Code),
			Sequence: uint16(echo.Seq),
		}

		key := trustTunnelICMPWaitKey{
			peer: reply.Source.String(),
			v6:   v6,
			id:   reply.ID,
			seq:  reply.Sequence,
		}
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
		return ok && typed == ipv6.ICMPTypeEchoReply
	}
	typed, ok := typ.(ipv4.ICMPType)
	return ok && typed == ipv4.ICMPTypeEchoReply
}
