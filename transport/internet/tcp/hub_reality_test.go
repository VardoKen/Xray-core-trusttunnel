package tcp

import (
	"context"
	"strings"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestListenTCPRejectsTrustTunnelHTTP3WithReality(t *testing.T) {
	ctx := ContextWithTrustTunnelServerTransportHints(context.Background(), TrustTunnelServerTransportHints{
		WantsHTTP3: true,
	})

	_, err := ListenTCP(ctx, xnet.LocalHostIP, xnet.Port(0), &internet.MemoryStreamConfig{
		ProtocolName:     "tcp",
		ProtocolSettings: &Config{},
		SecurityType:     "reality",
		SecuritySettings: &xreality.Config{},
	}, func(conn stat.Connection) {})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "http3 with REALITY is unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
}
