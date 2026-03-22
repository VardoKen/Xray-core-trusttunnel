package trusttunnel

import (
	"context"

	"github.com/xtls/xray-core/common"
	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

type Server struct {
	config *ServerConfig
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	_ = ctx
	return &Server{config: config}, nil
}

func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	_ = ctx
	_ = network
	_ = dispatcher
	_ = conn.Close()
	return xerrors.New("trusttunnel inbound is not implemented yet").AtWarning()
}
