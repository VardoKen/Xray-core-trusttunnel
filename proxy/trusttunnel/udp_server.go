package trusttunnel

import (
	"context"
	"io"
	stdnet "net"
	"net/http"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/features/routing"
	udp_transport "github.com/xtls/xray-core/transport/internet/udp"
)

type trustTunnelUDPFlowKey struct {
	clientSource string
	target       string
}

type trustTunnelUDPFlow struct {
	clientSource *stdnet.UDPAddr
	target       *stdnet.UDPAddr
	dispatcher   *udp_transport.Dispatcher
	timeout      time.Duration
	onTimeout    func()
	timer        *time.Timer
	timerMu      sync.Mutex
	closeOnce    sync.Once
}

func (f *trustTunnelUDPFlow) touch() {
	if f == nil || f.timeout <= 0 || f.onTimeout == nil {
		return
	}

	f.timerMu.Lock()
	defer f.timerMu.Unlock()

	if f.timer == nil {
		f.timer = time.AfterFunc(f.timeout, f.onTimeout)
		return
	}

	f.timer.Reset(f.timeout)
}

func (f *trustTunnelUDPFlow) close() {
	if f == nil {
		return
	}

	f.closeOnce.Do(func() {
		f.timerMu.Lock()
		if f.timer != nil {
			f.timer.Stop()
			f.timer = nil
		}
		f.timerMu.Unlock()

		if f.dispatcher != nil {
			f.dispatcher.RemoveRay()
		}
	})
}

func isTrustTunnelUDPHost(host string) bool {
	return host == trustTunnelUDPPseudoHost || host == trustTunnelLegacyUDPPseudoHost
}

func trustTunnelCloneUDPAddr(addr *stdnet.UDPAddr) *stdnet.UDPAddr {
	if addr == nil {
		return nil
	}
	ip := append(stdnet.IP(nil), addr.IP...)
	return &stdnet.UDPAddr{
		IP:   ip,
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func (s *Server) serveUDPMuxRequest(proto string, ctx context.Context, w http.ResponseWriter, req *http.Request, dispatcher routing.Dispatcher) {
	errors.LogInfo(ctx, "trusttunnel ", proto, " UDP mux accepted")

	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}

	var flusher http.Flusher
	if f, ok := w.(http.Flusher); ok {
		flusher = f
	}

	writer := &flushWriter{
		w: w,
		f: flusher,
	}

	var writeMu sync.Mutex
	var flowsMu sync.Mutex
	flows := make(map[trustTunnelUDPFlowKey]*trustTunnelUDPFlow)
	udpTimeout := s.config.udpConnectionsTimeout()

	getOrCreateFlow := func(pkt trustTunnelUDPRequestPacket) (*trustTunnelUDPFlow, error) {
		if pkt.Source == nil {
			return nil, errors.New("trusttunnel udp request source is nil")
		}
		if pkt.Destination == nil {
			return nil, errors.New("trusttunnel udp request destination is nil")
		}

		key := trustTunnelUDPFlowKey{
			clientSource: pkt.Source.String(),
			target:       pkt.Destination.String(),
		}

		flowsMu.Lock()
		defer flowsMu.Unlock()

		if flow, found := flows[key]; found {
			return flow, nil
		}

		clientSource := trustTunnelCloneUDPAddr(pkt.Source)
		target := trustTunnelCloneUDPAddr(pkt.Destination)

		flow := &trustTunnelUDPFlow{
			clientSource: clientSource,
			target:       target,
			timeout:      udpTimeout,
		}
		flow.onTimeout = func() {
			flowsMu.Lock()
			if current, found := flows[key]; found && current == flow {
				delete(flows, key)
			}
			flowsMu.Unlock()
			flow.close()
		}

		flow.dispatcher = udp_transport.NewDispatcher(dispatcher, func(cbCtx context.Context, packet *udp_proto.Packet) {
			defer packet.Payload.Release()

			sourceAddr, err := trustTunnelDestinationToUDPAddr(packet.Source)
			if err != nil {
				errors.LogWarningInner(cbCtx, err, "failed to convert trusttunnel udp response source")
				return
			}

			wire, err := encodeTrustTunnelUDPResponse(trustTunnelUDPResponsePacket{
				Source:      sourceAddr,
				Destination: trustTunnelCloneUDPAddr(flow.clientSource),
				Payload:     append([]byte(nil), packet.Payload.Bytes()...),
			})
			if err != nil {
				errors.LogWarningInner(cbCtx, err, "failed to encode trusttunnel udp response")
				return
			}

			writeMu.Lock()
			_, err = writer.Write(wire)
			writeMu.Unlock()
			if err != nil {
				errors.LogWarningInner(cbCtx, err, "failed to write trusttunnel udp response")
			}
			flow.touch()
		})

		flows[key] = flow
		flow.touch()
		return flow, nil
	}

	defer func() {
		flowsMu.Lock()
		defer flowsMu.Unlock()
		for _, flow := range flows {
			flow.close()
		}
	}()

	var decoder trustTunnelUDPRequestDecoder
	tmp := make([]byte, 64*1024)

	for {
		n, err := req.Body.Read(tmp)
		if n > 0 {
			packets, derr := decoder.Feed(tmp[:n])
			if derr != nil {
				errors.LogWarningInner(ctx, derr, "failed to decode trusttunnel udp request")
				return
			}

			for _, pkt := range packets {
				flow, ferr := getOrCreateFlow(pkt)
				if ferr != nil {
					errors.LogWarningInner(ctx, ferr, "failed to create trusttunnel udp flow")
					continue
				}
				flow.touch()

				targetDest := xnet.DestinationFromAddr(flow.target)

				payload := buf.New()
				if _, werr := payload.Write(pkt.Payload); werr != nil {
					payload.Release()
					errors.LogWarningInner(ctx, werr, "failed to build trusttunnel udp payload")
					continue
				}
				payload.UDP = &targetDest

				flow.dispatcher.Dispatch(ctx, targetDest, payload)
			}
		}

		if err != nil {
			if err != io.EOF {
				errors.LogWarningInner(ctx, err, "trusttunnel udp mux read error")
			}
			return
		}
	}
}
