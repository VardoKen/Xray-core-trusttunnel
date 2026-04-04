package trusttunnel

import (
	"bufio"
	"context"
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
)

type testDispatcher struct {
	dispatchCount int
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

func (*testDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	panic("unexpected Dispatch call")
}

func (d *testDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	d.dispatchCount++
	panic("unexpected DispatchLink call")
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
		config: cfg,
		users:  store,
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

	server.serveHTTP2Request(recorder, req, dispatcher, nil, "")

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

	server.serveHTTP2Request(recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusOK)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
	}
}

func TestServeHTTP2CheckAuthFailureUsesConfiguredStatus(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{
		AuthFailureStatusCode: http.StatusProxyAuthRequired,
	})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest("_check:443", "")

	server.serveHTTP2Request(recorder, req, dispatcher, nil, "")

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

	server.serveHTTP2Request(recorder, req, dispatcher, nil, "")

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

	server.serveHTTP2Request(recorder, req, dispatcher, nil, "")

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

func TestServeHTTP2ICMPReturnsNotImplementedWithoutDispatch(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest("_icmp:0", buildBasicAuthValue("u1", "p1"))

	server.serveHTTP2Request(recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusNotImplemented {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusNotImplemented)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("unexpected dispatch count: got %d, want 0", dispatcher.dispatchCount)
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

	server.serveHTTP2Request(recorder, req, dispatcher, nil, "")

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
