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
	xtlstls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/net/http2"
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

func buildConnectRequest(host string, account *MemoryAccount) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodConnect, "http://"+host, nil)
	if err != nil {
		return nil, err
	}
	req.Host = host
	req.Header.Set("Host", host)
	req.Header.Set("Proxy-Authorization", buildBasicAuthValue(account.Username, account.Password))
	req.Header.Set("Proxy-Connection", "Keep-Alive")
	req.Header.Set("User-Agent", "trusttunnel-xray-mvp/1")
	return req, nil
}

func connectHTTP1(rawConn stat.Connection, req *http.Request) (io.ReadWriteCloser, error) {
	if err := req.Write(rawConn); err != nil {
		rawConn.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReaderSize(rawConn, 64*1024), req)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		rawConn.Close()
		return nil, errors.New("trusttunnel CONNECT failed with status ", resp.StatusCode, ": ", string(body))
	}

	return rawConn, nil
}

func connectHTTP2(rawConn stat.Connection, req *http.Request) (io.ReadWriteCloser, error) {
	pr, pw := io.Pipe()
	req.Body = pr

	t := http2.Transport{}
	h2clientConn, err := t.NewClientConn(rawConn)
	if err != nil {
		pr.Close()
		pw.Close()
		rawConn.Close()
		return nil, err
	}

	resp, err := h2clientConn.RoundTrip(req)
	if err != nil {
		pr.Close()
		pw.Close()
		rawConn.Close()
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		pr.Close()
		pw.Close()
		rawConn.Close()
		return nil, errors.New("trusttunnel CONNECT failed with status ", resp.StatusCode, ": ", string(body))
	}

	return newHTTP2Conn(rawConn, pw, resp.Body), nil
}

func newHTTP2Conn(c stat.Connection, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) io.ReadWriteCloser {
	return &http2Conn{Connection: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	stat.Connection
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	_ = h.in.Close()
	_ = h.out.Close()
	return h.Connection.Close()
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "trusttunnel"

	if c.config.GetTransport() == TransportProtocol_HTTP3 {
		return errors.New("trusttunnel http3 is not implemented yet").AtWarning()
	}

	rawConn, err := dialer.Dial(ctx, c.server.Destination)
	if err != nil {
		return errors.New("failed to dial trusttunnel server").Base(err).AtWarning()
	}
	conn := rawConn.(stat.Connection)

	user := c.server.User
	account, ok := user.Account.(*MemoryAccount)
	if !ok {
		conn.Close()
		return errors.New("trusttunnel user account is not valid")
	}

	host := ob.Target.NetAddr()
	if host == "" {
		conn.Close()
		return errors.New("invalid target address")
	}

	req, err := buildConnectRequest(host, account)
	if err != nil {
		conn.Close()
		return errors.New("failed to create CONNECT request").Base(err)
	}

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		return errors.New("failed to set deadline").Base(err).AtWarning()
	}

	nextProto := ""
	iConn := stat.TryUnwrapStatsConn(conn)
	if tlsConn, ok := iConn.(*xtlstls.Conn); ok {
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return errors.New("failed TLS handshake").Base(err).AtWarning()
		}
		nextProto = tlsConn.ConnectionState().NegotiatedProtocol
	} else if tlsConn, ok := iConn.(*xtlstls.UConn); ok {
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return errors.New("failed uTLS handshake").Base(err).AtWarning()
		}
		nextProto = tlsConn.ConnectionState().NegotiatedProtocol
	}

	var tunnelConn io.ReadWriteCloser

	switch {
	case c.config.GetTransport() == TransportProtocol_HTTP2 && nextProto == "h2":
		tunnelConn, err = connectHTTP2(conn, req)
	case c.config.GetTransport() == TransportProtocol_HTTP2 && nextProto != "h2":
		errors.LogWarning(ctx, "trusttunnel transport=http2 requested, but negotiated protocol is [", nextProto, "], falling back to HTTP/1.1 CONNECT")
		tunnelConn, err = connectHTTP1(conn, req)
	default:
		tunnelConn, err = connectHTTP1(conn, req)
	}

	if err != nil {
		conn.Close()
		return errors.New("failed to establish trusttunnel CONNECT").Base(err).AtWarning()
	}
	defer tunnelConn.Close()

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return errors.New("failed to clear deadline").Base(err).AtWarning()
	}

	requestDone := func() error {
		return buf.Copy(link.Reader, buf.NewWriter(tunnelConn))
	}

	responseDone := func() error {
		return buf.Copy(buf.NewReader(tunnelConn), link.Writer)
	}

	requestDonePost := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDonePost, responseDone); err != nil {
		return errors.New("trusttunnel connection ends").Base(err).AtInfo()
	}

	return nil
}
