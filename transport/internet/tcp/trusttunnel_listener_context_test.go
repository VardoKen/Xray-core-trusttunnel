package tcp

import (
	"context"
	"testing"
	"time"
)

func TestContextWithTrustTunnelServerTimeouts(t *testing.T) {
	want := TrustTunnelServerTimeouts{
		TLSHandshakeTimeout:   11 * time.Second,
		ClientListenerTimeout: 13 * time.Minute,
	}

	ctx := ContextWithTrustTunnelServerTimeouts(context.Background(), want)
	got := trustTunnelServerTimeoutsFromContext(ctx)

	if got != want {
		t.Fatalf("timeouts = %+v, want %+v", got, want)
	}
}

func TestContextWithTrustTunnelServerTransportHints(t *testing.T) {
	want := TrustTunnelServerTransportHints{WantsHTTP3: true}

	ctx := ContextWithTrustTunnelServerTransportHints(context.Background(), want)
	got := trustTunnelServerTransportHintsFromContext(ctx)

	if got != want {
		t.Fatalf("hints = %+v, want %+v", got, want)
	}
}
