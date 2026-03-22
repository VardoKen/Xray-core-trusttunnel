package trusttunnel

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

type Client struct {
	config        *ClientConfig
	server        *protocol.ServerSpec
	policyManager policy.Manager
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config.Server == nil {
		return nil, errors.New("no target trusttunnel server found")
	}

	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get trusttunnel server spec").Base(err)
	}

	v := core.MustFromContext(ctx)

	return &Client{
		config:        config,
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "trusttunnel"

	rawConn, err := dialer.Dial(ctx, c.server.Destination)
	if err != nil {
		return errors.New("failed to dial trusttunnel server").Base(err).AtWarning()
	}
	conn := rawConn.(stat.Connection)
	defer conn.Close()

	user := c.server.User
	account, ok := user.Account.(*MemoryAccount)
	if !ok {
		return errors.New("trusttunnel user account is not valid")
	}

	host := ob.Target.NetAddr()
	if host == "" {
		return errors.New("invalid target address")
	}

	req, err := http.NewRequest(http.MethodConnect, "http://"+host, nil)
	if err != nil {
		return errors.New("failed to create CONNECT request").Base(err)
	}
	req.Host = host
	req.Header.Set("Host", host)
	req.Header.Set("Proxy-Authorization", buildBasicAuthValue(account.Username, account.Password))
	req.Header.Set("Proxy-Connection", "Keep-Alive")
	req.Header.Set("User-Agent", "trusttunnel-xray-mvp/1")

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return errors.New("failed to set deadline").Base(err).AtWarning()
	}

	if err := req.Write(conn); err != nil {
		return errors.New("failed to write CONNECT request").Base(err).AtWarning()
	}

	br := bufio.NewReaderSize(conn, 64*1024)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return errors.New("failed to read CONNECT response").Base(err).AtWarning()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return errors.New("trusttunnel CONNECT failed with status ", resp.StatusCode, ": ", string(body)).AtWarning()
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return errors.New("failed to clear deadline").Base(err).AtWarning()
	}

	var upstreamReader buf.Reader = buf.NewReader(conn)
	if br.Buffered() > 0 {
		payload, err := buf.ReadFrom(io.LimitReader(br, int64(br.Buffered())))
		if err != nil {
			return errors.New("failed to read buffered response payload").Base(err).AtWarning()
		}
		upstreamReader = &buf.BufferedReader{
			Reader: upstreamReader,
			Buffer: payload,
		}
	}

	requestDone := func() error {
		return buf.Copy(link.Reader, buf.NewWriter(conn))
	}

	responseDone := func() error {
		return buf.Copy(upstreamReader, link.Writer)
	}

	requestDonePost := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDonePost, responseDone); err != nil {
		return errors.New("trusttunnel connection ends").Base(err).AtInfo()
	}

	return nil
}
