package trusttunnel

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtlstls "github.com/xtls/xray-core/transport/internet/tls"
)

type trustTunnelClientRandomProvider interface {
	TrustTunnelClientRandom() string
}

func trustTunnelClientRandomFromConn(conn stat.Connection) string {
	iConn := stat.TryUnwrapStatsConn(conn)

	switch c := iConn.(type) {
	case *xtlstls.Conn:
		if provider, ok := c.Conn.NetConn().(trustTunnelClientRandomProvider); ok {
			return strings.ToLower(provider.TrustTunnelClientRandom())
		}
	case *xtlstls.UConn:
		if provider, ok := c.Conn.NetConn().(trustTunnelClientRandomProvider); ok {
			return strings.ToLower(provider.TrustTunnelClientRandom())
		}
	default:
		if provider, ok := iConn.(trustTunnelClientRandomProvider); ok {
			return strings.ToLower(provider.TrustTunnelClientRandom())
		}
	}

	return ""
}

func attachTrustTunnelClientRandom(ctx context.Context, value string) context.Context {
	if value == "" {
		return ctx
	}

	content := session.ContentFromContext(ctx)
	if content == nil {
		content = &session.Content{}
		ctx = session.ContextWithContent(ctx, content)
	}

	content.SetAttribute("trusttunnel.client_random", value)
	return ctx
}
