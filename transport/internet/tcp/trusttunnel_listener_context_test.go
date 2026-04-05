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
