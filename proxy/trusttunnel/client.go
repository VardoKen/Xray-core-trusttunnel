package trusttunnel

import (
	"bufio"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtlstls "github.com/xtls/xray-core/transport/internet/tls"
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

func (c *Client) validateOutboundTarget(target xnet.Destination) error {
	if !c.config.GetHasIpv6() && target.Address != nil {
		switch {
		case target.Address.Family().IsIPv6():
			return errors.New("trusttunnel IPv6 target is disabled by hasIpv6=false").AtWarning()
		case target.Address.Family().IsDomain():
			return errors.New(trustTunnelPostQuantumDomainStrategyError).AtWarning()
		}
	}

	return nil
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
		_ = pr.Close()
		_ = pw.Close()
		_ = rawConn.Close()
		return nil, err
	}

	resp, err := h2clientConn.RoundTrip(req)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = rawConn.Close()
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		_ = rawConn.Close()
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

func runTrustTunnelStreamTunnel(ctx context.Context, link *transport.Link, tunnelConn io.ReadWriteCloser) error {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	responseClosed := make(chan struct{})
	requestFinished := make(chan struct{})

	abortTunnel := func() {
		cancel()
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		_ = tunnelConn.Close()
	}

	requestDone := func() error {
		defer close(requestFinished)

		err := buf.Copy(link.Reader, buf.NewWriter(tunnelConn))
		if err == nil {
			return nil
		}

		select {
		case <-responseClosed:
			// The remote side has already closed cleanly, so any local interruption
			// used to tear down the opposite direction is expected.
			return nil
		default:
		}

		return err
	}

	responseDone := func() error {
		err := buf.Copy(buf.NewReader(tunnelConn), link.Writer)
		if err == nil {
			close(responseClosed)

			select {
			case <-requestFinished:
			case <-time.After(50 * time.Millisecond):
				common.Interrupt(link.Reader)
			}

			_ = tunnelConn.Close()
		}
		return err
	}

	responseDonePost := task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(sessionCtx, requestDone, responseDonePost); err != nil {
		abortTunnel()
		return errors.New("trusttunnel connection ends").Base(err).AtInfo()
	}

	return nil
}

func verifyTrustTunnelTLS(peerCerts []*x509.Certificate, cfg *ClientConfig) error {
	if cfg.GetSkipVerification() {
		return nil
	}

	if cfg.GetHostname() == "" && cfg.GetCertificatePem() == "" {
		return nil
	}

	if len(peerCerts) == 0 {
		return errors.New("peer certificate is missing")
	}

	opts := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
	}

	for _, cert := range peerCerts[1:] {
		opts.Intermediates.AddCert(cert)
	}

	if cfg.GetHostname() != "" {
		opts.DNSName = cfg.GetHostname()
	}

	if pemData := cfg.GetCertificatePem(); pemData != "" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(pemData)) {
			return errors.New("failed to parse certificate_pem")
		}
		opts.Roots = roots
	}

	if _, err := peerCerts[0].Verify(opts); err != nil {
		return err
	}

	return nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "trusttunnel"

	user := c.server.User
	account, ok := user.Account.(*MemoryAccount)
	if !ok {
		return errors.New("trusttunnel user account is not valid")
	}

	if err := c.validateOutboundTarget(ob.Target); err != nil {
		return err
	}

	if ob.Target.Network == xnet.Network_ICMP {
		return c.processICMP(ctx, link, dialer, account, ob.Target)
	}

	host := ob.Target.NetAddr()
	if host == "" {
		return errors.New("invalid target address")
	}

	if ob.Target.Network == xnet.Network_UDP {
		return c.processUDP(ctx, link, dialer, account, ob.Target)
	}

	ctx = xtlstls.ContextWithClientHelloRandomSpec(ctx, c.config.GetClientRandom())
	updatedCtx, tlsHandledByStreamSettings, err := trustTunnelContextWithTransportSecurityOverrides(ctx, dialer, c.config)
	if err != nil {
		return err
	}
	ctx = updatedCtx

	attemptHTTP3, skipHTTP3Reason, err := trustTunnelHTTP3AttemptPolicy(c.config, dialer)
	if err != nil {
		return err
	}
	if attemptHTTP3 {
		serverAddr := c.server.Destination.NetAddr()
		if serverAddr == "" {
			return errors.New("invalid trusttunnel server address")
		}

		http3Ctx, cancelHTTP3 := trustTunnelContextWithHTTP3FallbackTimeout(ctx, c.config)
		tunnelConn, err := trustTunnelConnectHTTP3Func(http3Ctx, serverAddr, host, account, c.config)
		cancelHTTP3()
		if err != nil {
			if !trustTunnelTransportAllowsHTTP2Fallback(c.config) || !trustTunnelHTTP3FallbackEligible(err) {
				return errors.New("failed to establish trusttunnel HTTP/3 CONNECT").Base(err).AtWarning()
			}
			errors.LogWarning(ctx, "trusttunnel HTTP/3 CONNECT failed; falling back to HTTP/2 path: ", err)
		} else {
			defer tunnelConn.Close()
			return runTrustTunnelStreamTunnel(ctx, link, tunnelConn)
		}
	} else if c.config.GetTransport() == TransportProtocol_AUTO && skipHTTP3Reason != "" {
		errors.LogInfo(ctx, "trusttunnel transport=auto bypasses HTTP/3: ", skipHTTP3Reason)
	}

	rawConn, err := dialer.Dial(ctx, c.server.Destination)
	if err != nil {
		return errors.New("failed to dial trusttunnel server").Base(err).AtWarning()
	}
	conn := rawConn.(stat.Connection)

	req, err := buildConnectRequest(host, account)
	if err != nil {
		_ = conn.Close()
		return errors.New("failed to create CONNECT request").Base(err)
	}

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		_ = conn.Close()
		return errors.New("failed to set deadline").Base(err).AtWarning()
	}

	securityState, err := trustTunnelClientSecurityState(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return err
	}

	if !securityState.UsesReality && !tlsHandledByStreamSettings {
		if err := verifyTrustTunnelTLS(securityState.PeerCertificates, c.config); err != nil {
			_ = conn.Close()
			return errors.New("trusttunnel TLS verification failed").Base(err).AtWarning()
		}
	}

	var tunnelConn io.ReadWriteCloser

	switch {
	case trustTunnelShouldUseHTTP2(securityState):
		if securityState.UsesReality && securityState.NegotiatedProtocol == "" {
			errors.LogInfo(ctx, "trusttunnel HTTP/2 path selected with REALITY and empty negotiated ALPN; using HTTP/2 preface path")
		}
		tunnelConn, err = connectHTTP2(conn, req)
	default:
		errors.LogWarning(ctx, "trusttunnel HTTP/2-compatible path requested, but negotiated protocol is [", securityState.NegotiatedProtocol, "], falling back to HTTP/1.1 CONNECT")
		tunnelConn, err = connectHTTP1(conn, req)
	}

	if err != nil {
		_ = conn.Close()
		return errors.New("failed to establish trusttunnel CONNECT").Base(err).AtWarning()
	}
	defer tunnelConn.Close()

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return errors.New("failed to clear deadline").Base(err).AtWarning()
	}
	return runTrustTunnelStreamTunnel(ctx, link, tunnelConn)
}
