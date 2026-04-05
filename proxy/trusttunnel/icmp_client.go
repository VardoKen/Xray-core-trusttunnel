package trusttunnel

import (
	"context"
	"crypto/x509"
	"io"
	stdnet "net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtlstls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	trustTunnelICMPPseudoHost = "_icmp:0"
	trustTunnelICMPDefaultTTL = 64
)

type trustTunnelICMPEchoStore struct {
	mu     sync.Mutex
	exact  map[trustTunnelICMPWaitKey]trustTunnelICMPStoredRequest
	simple map[trustTunnelICMPSimpleKey][]trustTunnelICMPWaitKey
}

type trustTunnelICMPSimpleKey struct {
	v6  bool
	id  uint16
	seq uint16
}

type trustTunnelICMPStoredRequest struct {
	payload       []byte
	requestWire   []byte
	sourceIP      stdnet.IP
	destinationIP stdnet.IP
	ttl           uint8
}

func newTrustTunnelICMPEchoStore() *trustTunnelICMPEchoStore {
	return &trustTunnelICMPEchoStore{
		exact:  make(map[trustTunnelICMPWaitKey]trustTunnelICMPStoredRequest),
		simple: make(map[trustTunnelICMPSimpleKey][]trustTunnelICMPWaitKey),
	}
}

func (s *trustTunnelICMPEchoStore) Store(key trustTunnelICMPWaitKey, request trustTunnelICMPStoredRequest) {
	s.mu.Lock()
	s.exact[key] = request
	simpleKey := trustTunnelICMPSimpleKey{
		v6:  key.v6,
		id:  key.id,
		seq: key.seq,
	}
	s.simple[simpleKey] = append(s.simple[simpleKey], key)
	s.mu.Unlock()
}

func (s *trustTunnelICMPEchoStore) Take(pkt trustTunnelICMPReplyPacket) (trustTunnelICMPStoredRequest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var zero trustTunnelICMPStoredRequest

	v6 := pkt.Source.To4() == nil
	exactKey := trustTunnelICMPWaitKey{
		peer: pkt.Source.String(),
		v6:   v6,
		id:   pkt.ID,
		seq:  pkt.Sequence,
	}
	if request, ok := s.exact[exactKey]; ok {
		s.removeLocked(exactKey)
		return request, true, nil
	}

	simpleKey := trustTunnelICMPSimpleKey{
		v6:  v6,
		id:  pkt.ID,
		seq: pkt.Sequence,
	}
	keys := s.simple[simpleKey]
	if len(keys) == 0 {
		return zero, false, nil
	}
	if len(keys) > 1 {
		return zero, false, errors.New("multiple outstanding trusttunnel icmp requests match reply id=", pkt.ID, " seq=", pkt.Sequence)
	}

	request, ok := s.exact[keys[0]]
	if !ok {
		return zero, false, nil
	}
	s.removeLocked(keys[0])
	return request, true, nil
}

func (s *trustTunnelICMPEchoStore) removeLocked(key trustTunnelICMPWaitKey) {
	delete(s.exact, key)

	simpleKey := trustTunnelICMPSimpleKey{
		v6:  key.v6,
		id:  key.id,
		seq: key.seq,
	}
	keys := s.simple[simpleKey]
	for i, current := range keys {
		if current == key {
			keys = append(keys[:i], keys[i+1:]...)
			break
		}
	}
	if len(keys) == 0 {
		delete(s.simple, simpleKey)
		return
	}
	s.simple[simpleKey] = keys
}

func (c *Client) processICMP(ctx context.Context, link *transport.Link, dialer internet.Dialer, account *MemoryAccount, fallbackDest xnet.Destination) error {
	if link == nil || link.Reader == nil || link.Writer == nil {
		return errors.New("trusttunnel icmp link is incomplete")
	}

	tunnelConn, err := c.connectICMPTunnel(ctx, dialer, account)
	if err != nil {
		return err
	}
	defer tunnelConn.Close()

	if err := runTrustTunnelICMPTunnel(ctx, link, tunnelConn, fallbackDest); err != nil {
		return errors.New("trusttunnel icmp connection ends").Base(err).AtInfo()
	}

	return nil
}

func runTrustTunnelICMPTunnel(ctx context.Context, link *transport.Link, tunnelConn io.ReadWriteCloser, fallbackDest xnet.Destination) error {
	store := newTrustTunnelICMPEchoStore()
	sourceIP := trustTunnelICMPLocalSourceFromContext(ctx)

	requestDone := func() error {
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}

			for _, b := range mb {
				req, payload, key, reqErr := trustTunnelICMPRequestFromBuffer(b, fallbackDest, trustTunnelICMPDefaultTTL)
				if reqErr != nil {
					buf.ReleaseMulti(mb)
					return reqErr
				}

				store.Store(key, trustTunnelICMPStoredRequest{
					payload:       payload,
					requestWire:   append([]byte(nil), b.Bytes()...),
					sourceIP:      trustTunnelCloneIP(sourceIP),
					destinationIP: trustTunnelCloneIP(req.Destination),
					ttl:           req.TTL,
				})

				wire, encErr := encodeTrustTunnelICMPRequest(req)
				if encErr != nil {
					buf.ReleaseMulti(mb)
					return encErr
				}
				errors.LogDebug(ctx, "trusttunnel icmp request id=", req.ID, " dst=", req.Destination.String(), " seq=", req.Sequence, " size=", req.DataSize)
				if _, writeErr := tunnelConn.Write(wire); writeErr != nil {
					buf.ReleaseMulti(mb)
					return writeErr
				}
			}

			buf.ReleaseMulti(mb)
		}
	}

	responseDone := func() error {
		var decoder trustTunnelICMPReplyDecoder
		tmp := make([]byte, 64*1024)

		for {
			n, err := tunnelConn.Read(tmp)
			if n > 0 {
				packets, derr := decoder.Feed(tmp[:n])
				if derr != nil {
					return derr
				}

				for _, pkt := range packets {
					errors.LogDebug(ctx, "trusttunnel icmp reply id=", pkt.ID, " src=", pkt.Source.String(), " type=", pkt.Type, " code=", pkt.Code, " seq=", pkt.Sequence)
					mb, convErr := trustTunnelICMPReplyToMultiBuffer(pkt, store)
					if convErr != nil {
						return convErr
					}
					if writeErr := link.Writer.WriteMultiBuffer(mb); writeErr != nil {
						buf.ReleaseMulti(mb)
						return writeErr
					}
				}
			}

			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
		}
	}

	requestDonePost := task.OnSuccess(requestDone, task.Close(tunnelConn))
	return task.Run(ctx, requestDonePost, responseDone)
}

func trustTunnelICMPRequestFromBuffer(b *buf.Buffer, fallbackDest xnet.Destination, ttl uint8) (trustTunnelICMPRequestPacket, []byte, trustTunnelICMPWaitKey, error) {
	var zeroPkt trustTunnelICMPRequestPacket
	var zeroKey trustTunnelICMPWaitKey

	dest, err := trustTunnelICMPTargetFromBuffer(b, fallbackDest)
	if err != nil {
		return zeroPkt, nil, zeroKey, err
	}

	dstIP := dest.Address.IP()
	if dstIP == nil {
		return zeroPkt, nil, zeroKey, errors.New("trusttunnel icmp destination must be an IP address")
	}

	proto := 1
	v6 := dstIP.To4() == nil
	if v6 {
		proto = 58
	}

	msg, err := icmp.ParseMessage(proto, b.Bytes())
	if err != nil {
		return zeroPkt, nil, zeroKey, err
	}

	echo, err := trustTunnelParseICMPEchoRequest(msg, v6)
	if err != nil {
		return zeroPkt, nil, zeroKey, err
	}
	if len(echo.Data) > 0xFFFF {
		return zeroPkt, nil, zeroKey, errors.New("trusttunnel icmp payload is too large: ", len(echo.Data))
	}

	key := trustTunnelICMPWaitKey{
		peer: dstIP.String(),
		v6:   v6,
		id:   uint16(echo.ID),
		seq:  uint16(echo.Seq),
	}

	if ttl == 0 {
		ttl = trustTunnelICMPDefaultTTL
	}

	return trustTunnelICMPRequestPacket{
		ID:          uint16(echo.ID),
		Destination: trustTunnelCloneIP(dstIP),
		Sequence:    uint16(echo.Seq),
		TTL:         ttl,
		DataSize:    uint16(len(echo.Data)),
	}, append([]byte(nil), echo.Data...), key, nil
}

func trustTunnelICMPTargetFromBuffer(b *buf.Buffer, fallbackDest xnet.Destination) (xnet.Destination, error) {
	dest := fallbackDest
	if b.UDP != nil {
		dest = *b.UDP
	}
	if !dest.IsValid() {
		return xnet.Destination{}, errors.New("trusttunnel icmp destination is invalid")
	}
	if dest.Address.IP() == nil {
		return xnet.Destination{}, errors.New("trusttunnel icmp destination must be an IP address")
	}
	if dest.Network == xnet.Network_Unknown {
		dest.Network = xnet.Network_ICMP
	}
	return dest, nil
}

func trustTunnelParseICMPEchoRequest(msg *icmp.Message, v6 bool) (*icmp.Echo, error) {
	if v6 {
		typed, ok := msg.Type.(ipv6.ICMPType)
		if !ok || typed != ipv6.ICMPTypeEchoRequest || msg.Code != 0 {
			return nil, errors.New("trusttunnel icmp client contract currently supports only IPv6 echo request packets")
		}
	} else {
		typed, ok := msg.Type.(ipv4.ICMPType)
		if !ok || typed != ipv4.ICMPTypeEcho || msg.Code != 0 {
			return nil, errors.New("trusttunnel icmp client contract currently supports only IPv4 echo request packets")
		}
	}

	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return nil, errors.New("trusttunnel icmp request body is not echo")
	}
	return echo, nil
}

func trustTunnelICMPReplyToMultiBuffer(pkt trustTunnelICMPReplyPacket, store *trustTunnelICMPEchoStore) (buf.MultiBuffer, error) {
	if pkt.Source == nil {
		return nil, errors.New("trusttunnel icmp reply source is nil")
	}

	request, ok, err := store.Take(pkt)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("missing payload for trusttunnel icmp echo reply")
	}

	v6 := pkt.Source.To4() == nil
	msg, err := trustTunnelBuildICMPReplyMessage(pkt, request, v6)
	if err != nil {
		return nil, err
	}

	proto := 1
	if v6 {
		proto = 58
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return nil, err
	}
	if _, err := icmp.ParseMessage(proto, wire); err != nil {
		return nil, err
	}

	b := buf.New()
	if _, err := b.Write(wire); err != nil {
		b.Release()
		return nil, err
	}
	source := xnet.ICMPDestination(xnet.IPAddress(pkt.Source))
	b.UDP = &source
	return buf.MultiBuffer{b}, nil
}

func trustTunnelBuildICMPReplyMessage(pkt trustTunnelICMPReplyPacket, request trustTunnelICMPStoredRequest, v6 bool) (*icmp.Message, error) {
	if v6 {
		switch ipv6.ICMPType(pkt.Type) {
		case ipv6.ICMPTypeEchoReply:
			return &icmp.Message{
				Type: ipv6.ICMPTypeEchoReply,
				Code: int(pkt.Code),
				Body: &icmp.Echo{
					ID:   int(pkt.ID),
					Seq:  int(pkt.Sequence),
					Data: append([]byte(nil), request.payload...),
				},
			}, nil
		case ipv6.ICMPTypeDestinationUnreachable:
			quoted, err := trustTunnelBuildICMPQuotedPacket(request, true)
			if err != nil {
				return nil, err
			}
			return &icmp.Message{
				Type: ipv6.ICMPTypeDestinationUnreachable,
				Code: int(pkt.Code),
				Body: &icmp.DstUnreach{Data: quoted},
			}, nil
		case ipv6.ICMPTypeTimeExceeded:
			quoted, err := trustTunnelBuildICMPQuotedPacket(request, true)
			if err != nil {
				return nil, err
			}
			return &icmp.Message{
				Type: ipv6.ICMPTypeTimeExceeded,
				Code: int(pkt.Code),
				Body: &icmp.TimeExceeded{Data: quoted},
			}, nil
		default:
			return nil, errors.New("trusttunnel icmp client contract does not represent IPv6 ICMP type ", pkt.Type, " with current reply frame")
		}
	}

	switch ipv4.ICMPType(pkt.Type) {
	case ipv4.ICMPTypeEchoReply:
		return &icmp.Message{
			Type: ipv4.ICMPTypeEchoReply,
			Code: int(pkt.Code),
			Body: &icmp.Echo{
				ID:   int(pkt.ID),
				Seq:  int(pkt.Sequence),
				Data: append([]byte(nil), request.payload...),
			},
		}, nil
	case ipv4.ICMPTypeDestinationUnreachable:
		quoted, err := trustTunnelBuildICMPQuotedPacket(request, false)
		if err != nil {
			return nil, err
		}
		return &icmp.Message{
			Type: ipv4.ICMPTypeDestinationUnreachable,
			Code: int(pkt.Code),
			Body: &icmp.DstUnreach{Data: quoted},
		}, nil
	case ipv4.ICMPTypeTimeExceeded:
		quoted, err := trustTunnelBuildICMPQuotedPacket(request, false)
		if err != nil {
			return nil, err
		}
		return &icmp.Message{
			Type: ipv4.ICMPTypeTimeExceeded,
			Code: int(pkt.Code),
			Body: &icmp.TimeExceeded{Data: quoted},
		}, nil
	default:
		return nil, errors.New("trusttunnel icmp client contract does not represent IPv4 ICMP type ", pkt.Type, " with current reply frame")
	}
}

func trustTunnelICMPLocalSourceFromContext(ctx context.Context) stdnet.IP {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return nil
	}
	return trustTunnelCloneIP(inbound.Source.Address.IP())
}

func trustTunnelBuildICMPQuotedPacket(request trustTunnelICMPStoredRequest, v6 bool) ([]byte, error) {
	if request.sourceIP == nil || request.destinationIP == nil {
		return nil, errors.New("trusttunnel icmp quoted packet requires source and destination IPs")
	}
	if len(request.requestWire) == 0 {
		return nil, errors.New("trusttunnel icmp quoted packet requires original request bytes")
	}
	ttl := request.ttl
	if ttl == 0 {
		ttl = trustTunnelICMPDefaultTTL
	}

	if v6 {
		wire := make([]byte, 40+len(request.requestWire))
		wire[0] = 0x60
		wire[6] = 58
		wire[7] = ttl
		payloadLen := len(request.requestWire)
		wire[4] = byte(payloadLen >> 8)
		wire[5] = byte(payloadLen)
		copy(wire[8:24], request.sourceIP.To16())
		copy(wire[24:40], request.destinationIP.To16())
		copy(wire[40:], request.requestWire)
		return wire, nil
	}

	src := request.sourceIP.To4()
	dst := request.destinationIP.To4()
	if src == nil || dst == nil {
		return nil, errors.New("trusttunnel icmp quoted IPv4 packet requires IPv4 addresses")
	}
	wire := make([]byte, 20+len(request.requestWire))
	wire[0] = 0x45
	wire[8] = ttl
	wire[9] = 1
	totalLen := len(wire)
	wire[2] = byte(totalLen >> 8)
	wire[3] = byte(totalLen)
	copy(wire[12:16], src)
	copy(wire[16:20], dst)
	checksum := trustTunnelIPv4HeaderChecksum(wire[:20])
	wire[10] = byte(checksum >> 8)
	wire[11] = byte(checksum)
	copy(wire[20:], request.requestWire)
	return wire, nil
}

func trustTunnelIPv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (c *Client) connectICMPTunnel(ctx context.Context, dialer internet.Dialer, account *MemoryAccount) (io.ReadWriteCloser, error) {
	if c.config.GetTransport() == TransportProtocol_HTTP3 {
		serverAddr := c.server.Destination.NetAddr()
		if serverAddr == "" {
			return nil, errors.New("invalid trusttunnel server address")
		}

		tunnelConn, err := connectHTTP3(ctx, serverAddr, trustTunnelICMPPseudoHost, account, c.config)
		if err != nil {
			return nil, errors.New("failed to establish trusttunnel HTTP/3 ICMP CONNECT").Base(err).AtWarning()
		}
		return tunnelConn, nil
	}

	ctx = xtlstls.ContextWithClientHelloRandomSpec(ctx, c.config.GetClientRandom())

	rawConn, err := dialer.Dial(ctx, c.server.Destination)
	if err != nil {
		return nil, errors.New("failed to dial trusttunnel server").Base(err).AtWarning()
	}
	conn := rawConn.(stat.Connection)

	req, err := buildConnectRequest(trustTunnelICMPPseudoHost, account)
	if err != nil {
		_ = conn.Close()
		return nil, errors.New("failed to create ICMP CONNECT request").Base(err)
	}

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		_ = conn.Close()
		return nil, errors.New("failed to set deadline").Base(err).AtWarning()
	}

	nextProto := ""
	var peerCerts []*x509.Certificate

	iConn := stat.TryUnwrapStatsConn(conn)
	if tlsConn, ok := iConn.(*xtlstls.Conn); ok {
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, errors.New("failed TLS handshake").Base(err).AtWarning()
		}
		state := tlsConn.ConnectionState()
		nextProto = state.NegotiatedProtocol
		peerCerts = state.PeerCertificates
	} else if tlsConn, ok := iConn.(*xtlstls.UConn); ok {
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, errors.New("failed uTLS handshake").Base(err).AtWarning()
		}
		state := tlsConn.ConnectionState()
		nextProto = state.NegotiatedProtocol
		peerCerts = state.PeerCertificates
	}

	if err := verifyTrustTunnelTLS(peerCerts, c.config); err != nil {
		_ = conn.Close()
		return nil, errors.New("trusttunnel TLS verification failed").Base(err).AtWarning()
	}

	if nextProto != "h2" {
		_ = conn.Close()
		return nil, errors.New("trusttunnel icmp over http2 requires negotiated ALPN h2, got ", nextProto)
	}

	tunnelConn, err := connectHTTP2(conn, req)
	if err != nil {
		_ = conn.Close()
		return nil, errors.New("failed to establish trusttunnel ICMP CONNECT").Base(err).AtWarning()
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = tunnelConn.Close()
		return nil, errors.New("failed to clear deadline").Base(err).AtWarning()
	}

	return tunnelConn, nil
}
