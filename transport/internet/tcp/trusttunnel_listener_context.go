package tcp

import (
	"context"
	"time"
)

type TrustTunnelServerTimeouts struct {
	TLSHandshakeTimeout   time.Duration
	ClientListenerTimeout time.Duration
}

type trustTunnelServerTimeoutsKey struct{}

func ContextWithTrustTunnelServerTimeouts(ctx context.Context, timeouts TrustTunnelServerTimeouts) context.Context {
	if timeouts.TLSHandshakeTimeout <= 0 && timeouts.ClientListenerTimeout <= 0 {
		return ctx
	}
	return context.WithValue(ctx, trustTunnelServerTimeoutsKey{}, timeouts)
}

func trustTunnelServerTimeoutsFromContext(ctx context.Context) TrustTunnelServerTimeouts {
	if ctx == nil {
		return TrustTunnelServerTimeouts{}
	}
	if timeouts, ok := ctx.Value(trustTunnelServerTimeoutsKey{}).(TrustTunnelServerTimeouts); ok {
		return timeouts
	}
	return TrustTunnelServerTimeouts{}
}
