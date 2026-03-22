package trusttunnel

import (
	"context"

	"github.com/xtls/xray-core/common"
	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
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
	users  *UserStore
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	_ = ctx

	store := &UserStore{}

	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, xerrors.New("failed to get trusttunnel user").Base(err).AtError()
		}
		if err := store.Add(u); err != nil {
			return nil, xerrors.New("failed to add trusttunnel user").Base(err).AtError()
		}
	}

	return &Server{
		config: config,
		users:  store,
	}, nil
}

func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	_ = ctx
	return s.users.Add(u)
}

func (s *Server) RemoveUser(ctx context.Context, email string) error {
	_ = ctx
	return s.users.Del(email)
}

func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	_ = ctx
	return s.users.GetByEmail(email)
}

func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	_ = ctx
	return s.users.GetAll()
}

func (s *Server) GetUsersCount(ctx context.Context) int64 {
	_ = ctx
	return s.users.GetCount()
}

func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	_ = ctx
	_ = network
	_ = dispatcher
	_ = conn.Close()
	return xerrors.New("trusttunnel inbound transport is not implemented yet").AtWarning()
}
