package tcp

import (
	"context"
	"time"
)

type TrustTunnelServerTimeouts struct {
	TLSHandshakeTimeout   time.Duration
	ClientListenerTimeout time.Duration
}

type TrustTunnelServerTransportHints struct {
	WantsHTTP3 bool
}

type trustTunnelServerTimeoutsKey struct{}
type trustTunnelServerTransportHintsKey struct{}

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

func ContextWithTrustTunnelServerTransportHints(ctx context.Context, hints TrustTunnelServerTransportHints) context.Context {
	if !hints.WantsHTTP3 {
		return ctx
	}
	return context.WithValue(ctx, trustTunnelServerTransportHintsKey{}, hints)
}

func trustTunnelServerTransportHintsFromContext(ctx context.Context) TrustTunnelServerTransportHints {
	if ctx == nil {
		return TrustTunnelServerTransportHints{}
	}
	if hints, ok := ctx.Value(trustTunnelServerTransportHintsKey{}).(TrustTunnelServerTransportHints); ok {
		return hints
	}
	return TrustTunnelServerTransportHints{}
}
