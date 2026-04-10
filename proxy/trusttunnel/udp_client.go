package trusttunnel

import (
	"context"
	"io"
	stdnet "net"
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
)

const (
	trustTunnelUDPPseudoHost       = "_udp2"
	trustTunnelLegacyUDPPseudoHost = "_udp2:0"
)

func (c *Client) processUDP(ctx context.Context, link *transport.Link, dialer internet.Dialer, fallbackDest xnet.Destination) error {
	if !c.config.GetEnableUdp() {
		return errors.New("trusttunnel udp is disabled in client config")
	}

	tunnelConn, err := c.connectUDPTunnel(ctx, dialer)
	if err != nil {
		return err
	}
	defer tunnelConn.Close()

	sourceAddr := trustTunnelUDPSourceFromContext(ctx)

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
				dest := fallbackDest
				if b.UDP != nil {
					dest = *b.UDP
				}

				destAddr, err := trustTunnelDestinationToUDPAddr(dest)
				if err != nil {
					b.Release()
					buf.ReleaseMulti(mb)
					return err
				}

				wire, err := encodeTrustTunnelUDPRequest(trustTunnelUDPRequestPacket{
					Source:      sourceAddr,
					Destination: destAddr,
					AppName:     "xray-core",
					Payload:     append([]byte(nil), b.Bytes()...),
				})
				b.Release()
				if err != nil {
					buf.ReleaseMulti(mb)
					return err
				}

				if _, err := tunnelConn.Write(wire); err != nil {
					buf.ReleaseMulti(mb)
					return err
				}
			}

			buf.ReleaseMulti(mb)
		}
	}

	responseDone := func() error {
		var decoder trustTunnelUDPResponseDecoder
		tmp := make([]byte, 64*1024)

		for {
			n, err := tunnelConn.Read(tmp)
			if n > 0 {
				packets, derr := decoder.Feed(tmp[:n])
				if derr != nil {
					return derr
				}

				for _, pkt := range packets {
					mb, err := trustTunnelUDPResponseToMultiBuffer(pkt)
					if err != nil {
						return err
					}
					if err := link.Writer.WriteMultiBuffer(mb); err != nil {
						buf.ReleaseMulti(mb)
						return err
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
	if err := task.Run(ctx, requestDonePost, responseDone); err != nil {
		return errors.New("trusttunnel udp connection ends").Base(err).AtInfo()
	}

	return nil
}

func (c *Client) connectUDPTunnel(ctx context.Context, dialer internet.Dialer) (io.ReadWriteCloser, error) {
	ctx = xtlstls.ContextWithClientHelloRandomSpec(ctx, c.config.GetClientRandom())
	ctx, tlsHandledByStreamSettings, err := trustTunnelContextWithTransportSecurityOverrides(ctx, dialer, c.config)
	if err != nil {
		return nil, err
	}

	attemptHTTP3, skipHTTP3Reason, err := trustTunnelHTTP3AttemptPolicy(c.config, dialer)
	if err != nil {
		return nil, err
	}
	if !attemptHTTP3 && c.config.GetTransport() == TransportProtocol_AUTO && skipHTTP3Reason != "" {
		errors.LogInfo(ctx, "trusttunnel transport=auto bypasses HTTP/3 UDP path: ", skipHTTP3Reason)
	}

	attempts := c.serverAttempts()
	if len(attempts) == 0 {
		return nil, errors.New("no target trusttunnel server found")
	}

	return c.connectWithEndpointPolicy(ctx, attempts, "UDP endpoint", func(runCtx context.Context, attempt trustTunnelServerAttempt) (io.ReadWriteCloser, error) {
		server := attempt.server
		account, err := trustTunnelAccountFromServer(server)
		if err != nil {
			return nil, err
		}

		if attemptHTTP3 {
			serverAddr := server.Destination.NetAddr()
			if serverAddr == "" {
				return nil, errors.New("invalid trusttunnel server address")
			}

			http3Ctx, cancelHTTP3 := trustTunnelContextWithHTTP3FallbackTimeout(runCtx, c.config)
			tunnelConn, err := trustTunnelConnectHTTP3Func(http3Ctx, serverAddr, trustTunnelUDPPseudoHost, account, c.config)
			cancelHTTP3()
			if err != nil {
				if !trustTunnelTransportAllowsHTTP2Fallback(c.config) || !trustTunnelHTTP3FallbackEligible(err) {
					return nil, errors.New("failed to establish trusttunnel HTTP/3 UDP CONNECT").Base(err).AtWarning()
				}
				errors.LogWarning(runCtx, "trusttunnel HTTP/3 UDP CONNECT failed; falling back to HTTP/2 path: ", err)
			} else {
				return tunnelConn, nil
			}
		}

		rawConn, err := dialer.Dial(runCtx, server.Destination)
		if err != nil {
			return nil, errors.New("failed to dial trusttunnel server").Base(err).AtWarning()
		}
		conn := rawConn.(stat.Connection)

		req, err := buildConnectRequest(trustTunnelUDPPseudoHost, account)
		if err != nil {
			_ = conn.Close()
			return nil, errors.New("failed to create UDP CONNECT request").Base(err)
		}

		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			_ = conn.Close()
			return nil, errors.New("failed to set deadline").Base(err).AtWarning()
		}

		securityState, err := trustTunnelClientSecurityState(runCtx, conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}

		if !securityState.UsesReality && !tlsHandledByStreamSettings {
			if err := verifyTrustTunnelTLS(securityState.PeerCertificates, c.config); err != nil {
				_ = conn.Close()
				return nil, errors.New("trusttunnel TLS verification failed").Base(err).AtWarning()
			}
		}

		if !trustTunnelShouldUseHTTP2(securityState) {
			_ = conn.Close()
			return nil, errors.New("trusttunnel udp over http2 requires negotiated ALPN h2, got ", securityState.NegotiatedProtocol)
		}

		tunnelConn, err := connectHTTP2(conn, req)
		if err != nil {
			_ = conn.Close()
			return nil, errors.New("failed to establish trusttunnel UDP CONNECT").Base(err).AtWarning()
		}

		if err := conn.SetDeadline(time.Time{}); err != nil {
			_ = tunnelConn.Close()
			return nil, errors.New("failed to clear deadline").Base(err).AtWarning()
		}

		return tunnelConn, nil
	}, func(runCtx context.Context, attempt trustTunnelServerAttempt) error {
		server := attempt.server
		account, err := trustTunnelAccountFromServer(server)
		if err != nil {
			return err
		}
		return c.probeStreamEndpointHealth(runCtx, dialer, server, account, tlsHandledByStreamSettings)
	})
}

func trustTunnelUDPSourceFromContext(ctx context.Context) *stdnet.UDPAddr {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || !inbound.Source.IsValid() {
		return &stdnet.UDPAddr{
			IP:   stdnet.IPv4zero,
			Port: 0,
		}
	}

	ip := inbound.Source.Address.IP()
	if ip == nil {
		ip = stdnet.IPv4zero
	}

	return &stdnet.UDPAddr{
		IP:   ip,
		Port: int(inbound.Source.Port),
	}
}

func trustTunnelDestinationToUDPAddr(dest xnet.Destination) (*stdnet.UDPAddr, error) {
	if !dest.IsValid() {
		return nil, errors.New("trusttunnel udp destination is invalid")
	}

	ip := dest.Address.IP()
	if ip == nil {
		return nil, errors.New("trusttunnel udp destination must be an IP address")
	}

	return &stdnet.UDPAddr{
		IP:   ip,
		Port: int(dest.Port),
	}, nil
}

func trustTunnelUDPResponseToMultiBuffer(pkt trustTunnelUDPResponsePacket) (buf.MultiBuffer, error) {
	if pkt.Source == nil {
		return nil, errors.New("trusttunnel udp response source is nil")
	}

	source := xnet.DestinationFromAddr(pkt.Source)

	b := buf.New()
	if _, err := b.Write(pkt.Payload); err != nil {
		b.Release()
		return nil, err
	}
	b.UDP = &source

	return buf.MultiBuffer{b}, nil
}
