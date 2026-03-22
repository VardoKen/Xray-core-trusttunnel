package trusttunnel

import (
	"context"

	"github.com/xtls/xray-core/common"
	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

type Client struct {
	config *ClientConfig
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	_ = ctx
	if config.Server == nil {
		return nil, xerrors.New("no target trusttunnel server found")
	}
	return &Client{config: config}, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	_ = ctx
	_ = link
	_ = dialer
	return xerrors.New("trusttunnel outbound is not implemented yet").AtWarning()
}
