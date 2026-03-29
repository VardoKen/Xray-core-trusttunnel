package inbound

import (
	"context"
	"net/http"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet"
	itls "github.com/xtls/xray-core/transport/internet/tls"
)

type trustTunnelH3Capable interface {
	proxy.Inbound
	ServeHTTP3(ctx context.Context, w http.ResponseWriter, req *http.Request, dispatcher routing.Dispatcher, inboundTemplate *session.Inbound)
}

func isTrustTunnelH3Capable(p proxy.Inbound) bool {
	_, ok := p.(trustTunnelH3Capable)
	return ok
}

func isH3Stream(mss *internet.MemoryStreamConfig) bool {
	cfg := itls.ConfigFromStreamSettings(mss)
	if cfg == nil {
		return false
	}
	tlsCfg := cfg.GetTLSConfig()
	if tlsCfg == nil {
		return false
	}
	return len(tlsCfg.NextProtos) == 1 && tlsCfg.NextProtos[0] == "h3"
}

type trustTunnelH3Worker struct {
	address         net.Address
	port            net.Port
	proxy           proxy.Inbound
	stream          *internet.MemoryStreamConfig
	tag             string
	dispatcher      routing.Dispatcher
	sniffingConfig  *proxyman.SniffingConfig
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter

	pktConn  net.PacketConn
	listener *quic.EarlyListener
	server   *http3.Server

	ctx context.Context
}

func (w *trustTunnelH3Worker) Proxy() proxy.Inbound {
	return w.proxy
}

func (w *trustTunnelH3Worker) Port() net.Port {
	return w.port
}

func (w *trustTunnelH3Worker) Start() error {
	h3proxy, ok := w.proxy.(trustTunnelH3Capable)
	if !ok {
		return errors.New("proxy does not support trusttunnel h3 inbound")
	}

	tlsCfgObj := itls.ConfigFromStreamSettings(w.stream)
	if tlsCfgObj == nil {
		return errors.New("tls config is nil for trusttunnel h3 inbound")
	}

	tlsCfg := tlsCfgObj.GetTLSConfig()
	if tlsCfg == nil {
		return errors.New("tls config is empty for trusttunnel h3 inbound")
	}
	if len(tlsCfg.NextProtos) == 0 {
		tlsCfg.NextProtos = []string{"h3"}
	}

	pktConn, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{
		IP:   w.address.IP(),
		Port: int(w.port),
	}, w.stream.SocketSettings)
	if err != nil {
		return errors.New("failed to listen UDP on ", w.address, ":", w.port).Base(err)
	}

	listener, err := quic.ListenEarly(pktConn, tlsCfg, &quic.Config{})
	if err != nil {
		_ = pktConn.Close()
		return errors.New("failed to listen QUIC on ", w.address, ":", w.port).Base(err)
	}

	w.pktConn = pktConn
	w.listener = listener

	handler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctxReq, cancel := context.WithCancel(w.ctx)
		defer cancel()

		sid := session.NewID()
		ctxReq = c.ContextWithID(ctxReq, sid)
		ctxReq = session.ContextWithOutbounds(ctxReq, []*session.Outbound{{}})

		remoteAddr, err := net.ResolveUDPAddr("udp", req.RemoteAddr)
		if err != nil {
			remoteAddr = &net.UDPAddr{
				IP:   []byte{0, 0, 0, 0},
				Port: 0,
			}
		}

		inbound := &session.Inbound{
			Source:  net.DestinationFromAddr(remoteAddr),
			Local:   net.UDPDestination(w.address, w.port),
			Gateway: net.UDPDestination(w.address, w.port),
			Tag:     w.tag,
		}
		ctxReq = session.ContextWithInbound(ctxReq, inbound)

		content := new(session.Content)
		if w.sniffingConfig != nil {
			content.SniffingRequest.Enabled = w.sniffingConfig.Enabled
			content.SniffingRequest.OverrideDestinationForProtocol = w.sniffingConfig.DestinationOverride
			content.SniffingRequest.ExcludeForDomain = w.sniffingConfig.DomainsExcluded
			content.SniffingRequest.MetadataOnly = w.sniffingConfig.MetadataOnly
			content.SniffingRequest.RouteOnly = w.sniffingConfig.RouteOnly
		}
		ctxReq = session.ContextWithContent(ctxReq, content)

		h3proxy.ServeHTTP3(ctxReq, rw, req.WithContext(ctxReq), w.dispatcher, inbound)
	})

	w.server = &http3.Server{
		Handler: handler,
	}

	go func() {
		for {
			conn, err := w.listener.Accept(context.Background())
			if err != nil {
				errors.LogInfoInner(w.ctx, err, "trusttunnel h3 listener closed")
				return
			}

			go func() {
				if err := w.server.ServeQUICConn(conn); err != nil {
					errors.LogDebugInner(w.ctx, err, "trusttunnel h3 connection ended")
				}
				_ = conn.CloseWithError(0, "")
			}()
		}
	}()

	return nil
}

func (w *trustTunnelH3Worker) Close() error {
	var errs []interface{}

	if w.server != nil {
		if err := w.server.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if w.listener != nil {
		if err := w.listener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if w.pktConn != nil {
		if err := w.pktConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if w.proxy != nil {
		if err := common.Close(w.proxy); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.New("failed to close trusttunnel h3 worker").Base(errors.New(errs...))
	}

	return nil
}
