package tcp

import (
	"context"
	gotls "crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type Listener struct {
	listener      net.Listener
	packetConn    net.PacketConn
	h3listener    *quic.EarlyListener
	h3server      *http3.Server
	tlsConfig     *gotls.Config
	realityConfig *goreality.Config
	authConfig    internet.ConnectionAuthenticator
	config        *Config
	addConn       internet.ConnHandler
	address       net.Address
	port          net.Port
}

func isH3TLSConfig(cfg *gotls.Config) bool {
	return cfg != nil && len(cfg.NextProtos) == 1 && cfg.NextProtos[0] == "h3"
}

func ListenTCP(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	l := &Listener{
		addConn: handler,
		address: address,
		port:    port,
	}

	tcpSettings := streamSettings.ProtocolSettings.(*Config)
	l.config = tcpSettings
	if l.config != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
		streamSettings.SocketSettings.AcceptProxyProtocol = l.config.AcceptProxyProtocol || streamSettings.SocketSettings.AcceptProxyProtocol
	}

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		l.tlsConfig = config.GetTLSConfig()
	}
	if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		l.realityConfig = config.GetREALITYConfig()
		go goreality.DetectPostHandshakeRecordsLens(l.realityConfig)
	}

	if tcpSettings.HeaderSettings != nil {
		headerConfig, err := tcpSettings.HeaderSettings.GetInstance()
		if err != nil {
			return nil, errors.New("invalid header settings").Base(err).AtError()
		}
		auth, err := internet.CreateConnectionAuthenticator(headerConfig)
		if err != nil {
			return nil, errors.New("invalid header settings.").Base(err).AtError()
		}
		l.authConfig = auth
	}

	if port != net.Port(0) && isH3TLSConfig(l.tlsConfig) {
		packetConn, err := internet.ListenSystemPacket(ctx, &net.UDPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen UDP on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening H3/QUIC on ", address, ":", port)

		h3listener, err := quic.ListenEarly(packetConn, l.tlsConfig, &quic.Config{})
		if err != nil {
			_ = packetConn.Close()
			return nil, errors.New("failed to listen QUIC on ", address, ":", port).Base(err)
		}

		l.packetConn = packetConn
		l.h3listener = h3listener

		localAddr := packetConn.LocalAddr()
		l.h3server = &http3.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				remoteAddr, err := net.ResolveUDPAddr("udp", req.RemoteAddr)
				if err != nil {
					remoteAddr = &net.UDPAddr{
						IP:   []byte{0, 0, 0, 0},
						Port: 0,
					}
				}

				l.addConn(stat.Connection(newHTTP3RequestConn(req, w, remoteAddr, localAddr)))
			}),
		}

		go l.keepAcceptingH3()
		return l, nil
	}

	var listener net.Listener
	var err error

	if port == net.Port(0) {
		if !address.Family().IsDomain() {
			return nil, errors.New("invalid unix listen: ", address).AtError()
		}
		listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen Unix Domain Socket on ", address).Base(err)
		}
		errors.LogInfo(ctx, "listening Unix Domain Socket on ", address)
	} else {
		listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen TCP on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening TCP on ", address, ":", port)
	}

	if streamSettings.TcpmaskManager != nil {
		listener, _ = streamSettings.TcpmaskManager.WrapListener(listener)
	}

	if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol {
		errors.LogWarning(ctx, "accepting PROXY protocol")
	}

	l.listener = listener

	go l.keepAccepting()
	return l, nil
}

func (v *Listener) keepAccepting() {
	for {
		conn, err := v.listener.Accept()
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "closed") {
				break
			}
			errors.LogWarningInner(context.Background(), err, "failed to accepted raw connections")
			if strings.Contains(errStr, "too many") {
				time.Sleep(time.Millisecond * 500)
			}
			continue
		}

		go func() {
			if v.tlsConfig != nil {
				conn = wrapTrustTunnelClientRandomConn(conn)
				conn = tls.Server(conn, v.tlsConfig)
			} else if v.realityConfig != nil {
				if conn, err = reality.Server(conn, v.realityConfig); err != nil {
					errors.LogInfo(context.Background(), err.Error())
					return
				}
			}
			if v.authConfig != nil {
				conn = v.authConfig.Server(conn)
			}
			v.addConn(stat.Connection(conn))
		}()
	}
}

func (v *Listener) keepAcceptingH3() {
	for {
		conn, err := v.h3listener.Accept(context.Background())
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "closed") {
				break
			}
			errors.LogWarningInner(context.Background(), err, "failed to accept h3 connections")
			if strings.Contains(errStr, "too many") {
				time.Sleep(time.Millisecond * 500)
			}
			continue
		}

		go func() {
			if err := v.h3server.ServeQUICConn(conn); err != nil {
				errors.LogDebugInner(context.Background(), err, "h3 connection ended")
			}
			_ = conn.CloseWithError(0, "")
		}()
	}
}

func (v *Listener) Addr() net.Addr {
	if v.listener != nil {
		return v.listener.Addr()
	}
	if v.packetConn != nil {
		return v.packetConn.LocalAddr()
	}
	return nil
}

func (v *Listener) Close() error {
	var ret error

	if v.h3server != nil {
		if err := v.h3server.Close(); ret == nil {
			ret = err
		}
	}
	if v.h3listener != nil {
		if err := v.h3listener.Close(); ret == nil {
			ret = err
		}
	}
	if v.packetConn != nil {
		if err := v.packetConn.Close(); ret == nil {
			ret = err
		}
	}
	if v.listener != nil {
		if err := v.listener.Close(); ret == nil {
			ret = err
		}
	}

	return ret
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenTCP))
}
