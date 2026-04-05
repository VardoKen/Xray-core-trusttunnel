package trusttunnel

import (
	"context"
	"strings"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

func TestClientProcessRejectsIncompleteICMPLink(t *testing.T) {
	client := &Client{
		config: &ClientConfig{},
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(9443)),
			&protocol.MemoryUser{
				Account: &MemoryAccount{
					Username: "u1",
					Password: "p1",
				},
			},
		),
	}

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{
		{
			Target: xnet.ICMPDestination(xnet.ParseAddress("1.1.1.1")),
		},
	})

	err := client.Process(ctx, &transport.Link{}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "icmp link is incomplete") {
		t.Fatalf("unexpected error: %v", err)
	}
}
