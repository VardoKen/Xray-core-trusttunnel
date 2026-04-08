package trusttunnel

import (
	"bufio"
	"bytes"
	"context"
	goerrors "errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type testDispatcher struct {
	dispatchCount int
	dispatchFn    func(context.Context, xnet.Destination) (*transport.Link, error)
	dispatchLink  func(context.Context, xnet.Destination, *transport.Link) error
}

func (*testDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func (*testDispatcher) Start() error {
	return nil
}

func (*testDispatcher) Close() error {
	return nil
}

func (d *testDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	d.dispatchCount++
	if d.dispatchFn != nil {
		return d.dispatchFn(ctx, dest)
	}
	return nil, goerrors.New("unexpected Dispatch call")
}

func (d *testDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	d.dispatchCount++
	if d.dispatchLink != nil {
		return d.dispatchLink(ctx, dest, link)
	}
	return goerrors.New("unexpected DispatchLink call")
}

func newTestTrustTunnelServer(t *testing.T, cfg *ServerConfig) *Server {
	t.Helper()

	if cfg == nil {
		cfg = &ServerConfig{}
	}
	if cfg.AuthFailureStatusCode == 0 {
		cfg.AuthFailureStatusCode = http.StatusProxyAuthRequired
	}

	store := &UserStore{}
	err := store.Add(&protocol.MemoryUser{
		Email: "u1",
		Account: &MemoryAccount{
			Username: "u1",
			Password: "p1",
		},
	})
	if err != nil {
		t.Fatalf("failed to add test user: %v", err)
	}

	return &Server{
		config:            cfg,
		users:             store,
		connectionLimiter: newTrustTunnelConnectionLimiter(store.GetAll(), cfg.GetDefaultMaxHttp2ConnsPerClient(), cfg.GetDefaultMaxHttp3ConnsPerClient()),
		newICMPSession: func(trustTunnelICMPSessionOptions) (trustTunnelICMPHandler, error) {
			return nil, goerrors.New("icmp unavailable in unit test")
		},
	}
}

func newTestConnectRequest(host string, authHeader string) *http.Request {
	req := &http.Request{
		Method:     http.MethodConnect,
		Host:       host,
		Header:     make(http.Header),
		RemoteAddr: "127.0.0.1:54321",
		Body:       io.NopCloser(strings.NewReader("")),
	}
	if authHeader != "" {
		req.Header.Set("Proxy-Authorization", authHeader)
	}
	return req.WithContext(context.Background())
}

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

type negotiatedProtocolConn struct {
	net.Conn
	protocol string
}

func (c *negotiatedProtocolConn) NegotiatedProtocol() string {
	return c.protocol
}

func runTestHTTP1ConnectRequest(t *testing.T, server *Server, host string, authHeader string, dispatcher routing.Dispatcher) (*http.Response, error) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	done := make(chan error, 1)

	go func() {
		reader := bufio.NewReader(serverConn)
		err := server.processHTTP1(context.Background(), serverConn, reader, dispatcher, nil, "")
		_ = serverConn.Close()
		done <- err
	}()

	var raw strings.Builder
	raw.WriteString("CONNECT ")
	raw.WriteString(host)
	raw.WriteString(" HTTP/1.1\r\n")
	raw.WriteString("Host: ")
	raw.WriteString(host)
	raw.WriteString("\r\n")
	if authHeader != "" {
		raw.WriteString("Proxy-Authorization: ")
		raw.WriteString(authHeader)
		raw.WriteString("\r\n")
	}
	raw.WriteString("\r\n")

	if _, err := io.WriteString(clientConn, raw.String()); err != nil {
		_ = clientConn.Close()
		t.Fatalf("failed to write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = clientConn.Close()
		t.Fatalf("failed to read response: %v", err)
	}

	_ = clientConn.Close()
	return resp, <-done
}

func TestServeHTTP2ConnectAuthFailureUsesConfiguredStatus(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		AuthFailureStatusCode: http.StatusProxyAuthRequired,
	})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest("example.com:443", "")

	server.serveHTTP2Request(nil, recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusProxyAuthRequired {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusProxyAuthRequired)
	}
	if got := recorder.Header().Get("Proxy-Authenticate"); got != `Basic realm="trusttunnel"` {
		t.Fatalf("unexpected Proxy-Authenticate header: got %q", got)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestServeHTTP2CheckReturnsOKWithoutDispatch(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest("_check:443", buildBasicAuthValue("u1", "p1"))

	server.serveHTTP2Request(nil, recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusOK)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestProcessHTTP1ConnectConnectionLimitExceededReturnsTooManyRequests(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		DefaultMaxHttp2ConnsPerClient: 1,
	})
	dispatcher := &testDispatcher{}

	guard := server.connectionLimiter.tryAcquire(buildBasicAuthValue("u1", "p1"), trustTunnelConnectionProtocolHTTP2)
	if guard == nil {
		t.Fatal("expected pre-acquired connection guard")
	}
	defer guard.Release()

	resp, err := runTestHTTP1ConnectRequest(t, server, "example.com:443", buildBasicAuthValue("u1", "p1"), dispatcher)
	defer resp.Body.Close()

	if err == nil || !strings.Contains(err.Error(), "connection limit exceeded") {
		t.Fatalf("unexpected server error: %v", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestServeHTTP2ConnectConnectionLimitExceededReturnsTooManyRequests(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		DefaultMaxHttp2ConnsPerClient: 1,
	})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest("example.com:443", buildBasicAuthValue("u1", "p1"))

	guard := server.connectionLimiter.tryAcquire(buildBasicAuthValue("u1", "p1"), trustTunnelConnectionProtocolHTTP2)
	if guard == nil {
		t.Fatal("expected pre-acquired connection guard")
	}
	defer guard.Release()

	server.serveHTTP2Request(&bufferedConn{}, recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusTooManyRequests)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestServeHTTP2CheckIgnoresConnectionLimit(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		DefaultMaxHttp2ConnsPerClient: 1,
	})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest("_check:443", buildBasicAuthValue("u1", "p1"))

	guard := server.connectionLimiter.tryAcquire(buildBasicAuthValue("u1", "p1"), trustTunnelConnectionProtocolHTTP2)
	if guard == nil {
		t.Fatal("expected pre-acquired connection guard")
	}
	defer guard.Release()

	server.serveHTTP2Request(&bufferedConn{}, recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusOK)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestServeHTTP2ConnectDispatchFailureAbortsHandlerAndClosesRequestBody(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher := &testDispatcher{
		dispatchFn: func(context.Context, xnet.Destination) (*transport.Link, error) {
			return nil, goerrors.New("dial failed")
		},
	}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest("example.com:443", buildBasicAuthValue("u1", "p1"))
	body := &closeTrackingBody{Reader: strings.NewReader("")}
	req.Body = body

	defer func() {
		if r := recover(); r != http.ErrAbortHandler {
			t.Fatalf("panic = %v, want %v", r, http.ErrAbortHandler)
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusOK)
		}
		if !body.closed {
			t.Fatal("expected request body to be closed on CONNECT dispatch failure")
		}
		if dispatcher.dispatchCount != 1 {
			t.Fatalf("unexpected dispatch count: got %d, want 1", dispatcher.dispatchCount)
		}
	}()

	server.serveHTTP2Request(nil, recorder, req, dispatcher, nil, "")
}

func TestTrustTunnelNegotiatedProtocolUnwrapsStatsConn(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	got := trustTunnelNegotiatedProtocol(&stat.CounterConnection{
		Connection: &negotiatedProtocolConn{
			Conn:     serverConn,
			protocol: "h2",
		},
	})
	if got != "h2" {
		t.Fatalf("trustTunnelNegotiatedProtocol() = %q, want %q", got, "h2")
	}
}

func TestServeHTTP2CheckAuthFailureUsesConfiguredStatus(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		AuthFailureStatusCode: http.StatusProxyAuthRequired,
	})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest("_check:443", "")

	server.serveHTTP2Request(nil, recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusProxyAuthRequired {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusProxyAuthRequired)
	}
	if got := recorder.Header().Get("Proxy-Authenticate"); got != `Basic realm="trusttunnel"` {
		t.Fatalf("unexpected Proxy-Authenticate header: got %q", got)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestServeHTTP2UDPAuthFailureUsesConfiguredStatus(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		AuthFailureStatusCode: http.StatusProxyAuthRequired,
		EnableUdp:             true,
	})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest("_udp2:0", "")

	server.serveHTTP2Request(nil, recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusProxyAuthRequired {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusProxyAuthRequired)
	}
	if got := recorder.Header().Get("Proxy-Authenticate"); got != `Basic realm="trusttunnel"` {
		t.Fatalf("unexpected Proxy-Authenticate header: got %q", got)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestServeHTTP2UDPAuthFailureAcceptsAuthorityWithoutPort(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		AuthFailureStatusCode: http.StatusProxyAuthRequired,
		EnableUdp:             true,
	})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest("_udp2", "")

	server.serveHTTP2Request(nil, recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusProxyAuthRequired {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusProxyAuthRequired)
	}
	if got := recorder.Header().Get("Proxy-Authenticate"); got != `Basic realm="trusttunnel"` {
		t.Fatalf("unexpected Proxy-Authenticate header: got %q", got)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestServeHTTP2ICMPAuthFailureUsesConfiguredStatus(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		AuthFailureStatusCode: http.StatusProxyAuthRequired,
	})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest("_icmp:0", "")

	server.serveHTTP2Request(nil, recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusProxyAuthRequired {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusProxyAuthRequired)
	}
	if got := recorder.Header().Get("Proxy-Authenticate"); got != `Basic realm="trusttunnel"` {
		t.Fatalf("unexpected Proxy-Authenticate header: got %q", got)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestServeHTTP2ICMPUnavailableReturnsServiceUnavailableWithoutDispatch(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest("_icmp:0", buildBasicAuthValue("u1", "p1"))

	server.serveHTTP2Request(nil, recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

type fakeTrustTunnelICMPSession struct {
	reply trustTunnelICMPReplyPacket
	err   error
	ok    bool
	reqs  []trustTunnelICMPRequestPacket
}

func (s *fakeTrustTunnelICMPSession) HandleRequest(_ context.Context, pkt trustTunnelICMPRequestPacket) (trustTunnelICMPReplyPacket, bool, error) {
	s.reqs = append(s.reqs, pkt)
	return s.reply, s.ok, s.err
}

func (*fakeTrustTunnelICMPSession) Close() error {
	return nil
}

func TestServeHTTP2ICMPReturnsReplyFrameWithoutDispatch(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	reqBody, err := encodeTrustTunnelICMPRequest(trustTunnelICMPRequestPacket{
		ID:          0x1234,
		Destination: net.IPv4(127, 0, 0, 1),
		Sequence:    7,
		TTL:         64,
		DataSize:    32,
	})
	if err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}

	fake := &fakeTrustTunnelICMPSession{
		reply: trustTunnelICMPReplyPacket{
			ID:       0x1234,
			Source:   net.IPv4(127, 0, 0, 1),
			Type:     0,
			Code:     0,
			Sequence: 7,
		},
		ok: true,
	}
	server.newICMPSession = func(trustTunnelICMPSessionOptions) (trustTunnelICMPHandler, error) {
		return fake, nil
	}

	req := newTestConnectRequest("_icmp:0", buildBasicAuthValue("u1", "p1"))
	req.Body = io.NopCloser(bytes.NewReader(reqBody))

	server.serveHTTP2Request(nil, recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusOK)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
	if len(fake.reqs) != 1 {
		t.Fatalf("unexpected request count: got %d, want 1", len(fake.reqs))
	}

	got := recorder.Body.Bytes()
	want, err := encodeTrustTunnelICMPReply(fake.reply)
	if err != nil {
		t.Fatalf("failed to encode reply: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected body: got %v, want %v", got, want)
	}
}

func TestServeHTTP2CheckRuleDenyBlocksBeforeHealthcheck(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		Rules: []*Rule{
			{Allow: false},
		},
	})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest("_check:443", buildBasicAuthValue("u1", "p1"))

	server.serveHTTP2Request(nil, recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestProcessHTTP1CheckReturnsOKWithoutDispatch(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher := &testDispatcher{}

	resp, err := runTestHTTP1ConnectRequest(t, server, "_check", buildBasicAuthValue("u1", "p1"), dispatcher)
	defer resp.Body.Close()

	if err != nil {
		t.Fatalf("unexpected server error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestProcessHTTP1UDPReservedHostRejectedWithoutDispatch(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		EnableUdp: true,
	})
	dispatcher := &testDispatcher{}

	resp, err := runTestHTTP1ConnectRequest(t, server, "_udp2:0", buildBasicAuthValue("u1", "p1"), dispatcher)
	defer resp.Body.Close()

	if err != nil {
		t.Fatalf("unexpected server error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestProcessHTTP1UDPPseudoHostAuthFailureUsesConfiguredStatus(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		AuthFailureStatusCode: http.StatusProxyAuthRequired,
		EnableUdp:             true,
	})
	dispatcher := &testDispatcher{}

	resp, _ := runTestHTTP1ConnectRequest(t, server, "_udp2:0", "", dispatcher)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got != `Basic realm="trusttunnel"` {
		t.Fatalf("unexpected Proxy-Authenticate header: got %q", got)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestProcessHTTP1UDPPseudoHostWithoutPortRejectedWithoutDispatch(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		EnableUdp: true,
	})
	dispatcher := &testDispatcher{}

	resp, err := runTestHTTP1ConnectRequest(t, server, "_udp2", buildBasicAuthValue("u1", "p1"), dispatcher)
	defer resp.Body.Close()

	if err != nil {
		t.Fatalf("unexpected server error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestProcessHTTP1ICMPReturnsNotImplementedWithoutDispatch(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher := &testDispatcher{}

	resp, err := runTestHTTP1ConnectRequest(t, server, "_icmp:0", buildBasicAuthValue("u1", "p1"), dispatcher)
	defer resp.Body.Close()

	if err != nil {
		t.Fatalf("unexpected server error: %v", err)
	}
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusNotImplemented)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}
