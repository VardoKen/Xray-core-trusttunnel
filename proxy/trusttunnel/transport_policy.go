package trusttunnel

import (
	"context"
	stderrors "errors"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

const trustTunnelHTTP3FallbackProbeTimeout = 1500 * time.Millisecond

type trustTunnelHTTP3ConnectError struct {
	err              error
	fallbackEligible bool
}

func (e *trustTunnelHTTP3ConnectError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *trustTunnelHTTP3ConnectError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func trustTunnelWrapHTTP3ConnectError(err error, fallbackEligible bool) error {
	if err == nil {
		return nil
	}
	return &trustTunnelHTTP3ConnectError{
		err:              err,
		fallbackEligible: fallbackEligible,
	}
}

func trustTunnelHTTP3FallbackEligible(err error) bool {
	var connectErr *trustTunnelHTTP3ConnectError
	return stderrors.As(err, &connectErr) && connectErr.fallbackEligible
}

func trustTunnelHTTP3AttemptPolicy(cfg *ClientConfig, dialer internet.Dialer) (attempt bool, skipReason string, err error) {
	switch cfg.GetTransport() {
	case TransportProtocol_HTTP3:
		if cfg.GetAntiDpi() {
			return false, "", errors.New("trusttunnel antiDpi is supported only for http2 over TLS or REALITY: http3 has no compatible QUIC anti-DPI runtime").AtWarning()
		}
		if trustTunnelHTTP3RealityUnsupported(dialer) {
			return false, "", errors.New("trusttunnel http3 with REALITY is unsupported: current Xray REALITY transport is TCP-only").AtWarning()
		}
		return true, "", nil
	case TransportProtocol_AUTO:
		if cfg.GetAntiDpi() {
			return false, "antiDpi requires the TCP-based HTTP/2 handshake path", nil
		}
		if trustTunnelHTTP3RealityUnsupported(dialer) {
			return false, "REALITY currently provides only the TCP-based HTTP/2 path", nil
		}
		return true, "", nil
	default:
		return false, "", nil
	}
}

func trustTunnelTransportAllowsHTTP2Fallback(cfg *ClientConfig) bool {
	switch cfg.GetTransport() {
	case TransportProtocol_HTTP3, TransportProtocol_AUTO:
		return true
	default:
		return false
	}
}

func trustTunnelContextWithHTTP3FallbackTimeout(ctx context.Context, cfg *ClientConfig) (context.Context, context.CancelFunc) {
	if !trustTunnelTransportAllowsHTTP2Fallback(cfg) {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, trustTunnelHTTP3FallbackProbeTimeout)
}

var trustTunnelConnectHTTP3Func = connectHTTP3
