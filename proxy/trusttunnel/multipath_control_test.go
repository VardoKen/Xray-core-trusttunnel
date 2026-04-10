package trusttunnel

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testTrustTunnelMemoryAccount() *MemoryAccount {
	return &MemoryAccount{
		Username: "u1",
		Password: "p1",
	}
}

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

func TestBuildAndParseTrustTunnelMultipathOpenRequest(t *testing.T) {
	req, err := buildTrustTunnelMultipathOpenRequest("example.com:443", testTrustTunnelMemoryAccount(), &MultipathConfig{
		Enabled:           true,
		MinChannels:       2,
		MaxChannels:       3,
		Scheduler:         MultipathScheduler_MULTIPATH_SCHEDULER_ROUND_ROBIN,
		AttachTimeoutSecs: 7,
		Strict:            true,
	})
	if err != nil {
		t.Fatalf("buildTrustTunnelMultipathOpenRequest() error: %v", err)
	}

	parsed, err := parseTrustTunnelMultipathOpenRequest(req)
	if err != nil {
		t.Fatalf("parseTrustTunnelMultipathOpenRequest() error: %v", err)
	}
	if parsed.TargetHost != "example.com:443" {
		t.Fatalf("TargetHost = %q, want %q", parsed.TargetHost, "example.com:443")
	}
	if parsed.MinChannels != 2 || parsed.MaxChannels != 3 {
		t.Fatalf("channels = %d/%d, want 2/3", parsed.MinChannels, parsed.MaxChannels)
	}
	if parsed.AttachTimeout != 7*time.Second {
		t.Fatalf("AttachTimeout = %v, want 7s", parsed.AttachTimeout)
	}
	if !parsed.Strict {
		t.Fatal("Strict = false, want true")
	}
}

func TestBuildAndParseTrustTunnelMultipathAttachRequest(t *testing.T) {
	now := time.Unix(1712700000, 0)
	req, err := buildTrustTunnelMultipathAttachRequestAt("sess-1", trustTunnelMultipathAttachSecretHeaderValue([]byte("0123456789abcdef0123456789abcdef")), 2, "example.com:443", testTrustTunnelMemoryAccount(), now, "nonce-1")
	if err != nil {
		t.Fatalf("buildTrustTunnelMultipathAttachRequestAt() error: %v", err)
	}

	parsed, err := parseTrustTunnelMultipathAttachRequest(req)
	if err != nil {
		t.Fatalf("parseTrustTunnelMultipathAttachRequest() error: %v", err)
	}
	if parsed.SessionID != "sess-1" {
		t.Fatalf("SessionID = %q, want %q", parsed.SessionID, "sess-1")
	}
	if parsed.ChannelID != 2 {
		t.Fatalf("ChannelID = %d, want 2", parsed.ChannelID)
	}
	if parsed.TargetHost != "example.com:443" {
		t.Fatalf("TargetHost = %q, want %q", parsed.TargetHost, "example.com:443")
	}
	if parsed.Nonce != "nonce-1" {
		t.Fatalf("Nonce = %q, want %q", parsed.Nonce, "nonce-1")
	}
}

func TestServeHTTP2MultipathOpenCreatesSession(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher := &testDispatcher{}
	recorder := httptest.NewRecorder()
	req := newTestConnectRequest(trustTunnelMultipathOpenHost, buildBasicAuthValue("u1", "p1"))
	req.Header.Set(trustTunnelMultipathHeaderTarget, "example.com:443")
	req.Header.Set(trustTunnelMultipathHeaderMinChannels, "2")
	req.Header.Set(trustTunnelMultipathHeaderMaxChannels, "3")
	req.Header.Set(trustTunnelMultipathHeaderStrict, "true")
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, dummyAddr("192.168.1.50:9443")))

	server.serveHTTP2Request(&bufferedConn{}, recorder, req, dispatcher, nil, "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("dispatchCount = %d, want 0", dispatcher.dispatchCount)
	}
	sessionID := recorder.Header().Get(trustTunnelMultipathHeaderSessionID)
	if sessionID == "" {
		t.Fatal("missing multipath session id header")
	}
	sessionState, ok := server.multipathSessions.Get(sessionID)
	if !ok {
		t.Fatal("multipath session not stored in registry")
	}
	if got := sessionState.ActiveChannelCount(); got != 1 {
		t.Fatalf("ActiveChannelCount() = %d, want 1", got)
	}
	if state := sessionState.State(); state != trustTunnelMultipathSessionOpening {
		t.Fatalf("state = %v, want opening", state)
	}
	if sessionState.TargetHost() != "example.com:443" {
		t.Fatalf("TargetHost = %q, want %q", sessionState.TargetHost(), "example.com:443")
	}
}

func TestServeHTTP2MultipathAttachAddsSecondaryChannel(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher := &testDispatcher{}
	now := time.Now()

	openRecorder := httptest.NewRecorder()
	openReq := newTestConnectRequest(trustTunnelMultipathOpenHost, buildBasicAuthValue("u1", "p1"))
	openReq.Header.Set(trustTunnelMultipathHeaderTarget, "example.com:443")
	openReq.Header.Set(trustTunnelMultipathHeaderMinChannels, "2")
	openReq.Header.Set(trustTunnelMultipathHeaderMaxChannels, "3")
	openReq = openReq.WithContext(context.WithValue(openReq.Context(), http.LocalAddrContextKey, dummyAddr("192.168.1.50:9443")))

	server.serveHTTP2Request(&bufferedConn{}, openRecorder, openReq, dispatcher, nil, "")

	sessionID := openRecorder.Header().Get(trustTunnelMultipathHeaderSessionID)
	attachSecret := openRecorder.Header().Get(trustTunnelMultipathHeaderAttachSecret)
	if sessionID == "" || attachSecret == "" {
		t.Fatalf("missing open response headers: sessionID=%q secret=%q", sessionID, attachSecret)
	}

	attachReq, err := buildTrustTunnelMultipathAttachRequestAt(sessionID, attachSecret, 2, "example.com:443", testTrustTunnelMemoryAccount(), now, "nonce-2")
	if err != nil {
		t.Fatalf("buildTrustTunnelMultipathAttachRequestAt() error: %v", err)
	}
	attachReq.RemoteAddr = "127.0.0.1:54321"
	attachReq = attachReq.WithContext(context.WithValue(attachReq.Context(), http.LocalAddrContextKey, dummyAddr("192.168.1.51:9443")))

	attachRecorder := httptest.NewRecorder()
	server.serveHTTP2Request(&bufferedConn{}, attachRecorder, attachReq, dispatcher, nil, "")

	if attachRecorder.Code != http.StatusOK {
		t.Fatalf("attach status = %d, want 200", attachRecorder.Code)
	}
	sessionState, ok := server.multipathSessions.Get(sessionID)
	if !ok {
		t.Fatal("multipath session not found after attach")
	}
	if got := sessionState.ActiveChannelCount(); got != 2 {
		t.Fatalf("ActiveChannelCount() = %d, want 2", got)
	}
	if state := sessionState.State(); state != trustTunnelMultipathSessionActive {
		t.Fatalf("state = %v, want active", state)
	}
}

func TestServeHTTP2MultipathAttachRejectsInvalidProof(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher := &testDispatcher{}
	now := time.Now()

	openRecorder := httptest.NewRecorder()
	openReq := newTestConnectRequest(trustTunnelMultipathOpenHost, buildBasicAuthValue("u1", "p1"))
	openReq.Header.Set(trustTunnelMultipathHeaderTarget, "example.com:443")
	openReq.Header.Set(trustTunnelMultipathHeaderMinChannels, "2")
	openReq.Header.Set(trustTunnelMultipathHeaderMaxChannels, "2")
	server.serveHTTP2Request(&bufferedConn{}, openRecorder, openReq, dispatcher, nil, "")

	sessionID := openRecorder.Header().Get(trustTunnelMultipathHeaderSessionID)
	attachSecret := openRecorder.Header().Get(trustTunnelMultipathHeaderAttachSecret)
	attachReq, err := buildTrustTunnelMultipathAttachRequestAt(sessionID, attachSecret, 2, "example.com:443", testTrustTunnelMemoryAccount(), now, "nonce-3")
	if err != nil {
		t.Fatalf("buildTrustTunnelMultipathAttachRequestAt() error: %v", err)
	}
	attachReq.Header.Set(trustTunnelMultipathHeaderAttachProof, "broken-proof")
	attachReq.RemoteAddr = "127.0.0.1:54321"

	attachRecorder := httptest.NewRecorder()
	server.serveHTTP2Request(&bufferedConn{}, attachRecorder, attachReq, dispatcher, nil, "")

	if attachRecorder.Code != http.StatusForbidden {
		t.Fatalf("attach status = %d, want 403", attachRecorder.Code)
	}
	sessionState, ok := server.multipathSessions.Get(sessionID)
	if !ok {
		t.Fatal("multipath session not found after invalid attach")
	}
	if got := sessionState.ActiveChannelCount(); got != 1 {
		t.Fatalf("ActiveChannelCount() = %d, want 1", got)
	}
}

func TestServeHTTP2MultipathAttachRejectsDuplicateChannel(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher := &testDispatcher{}
	now := time.Now()

	openRecorder := httptest.NewRecorder()
	openReq := newTestConnectRequest(trustTunnelMultipathOpenHost, buildBasicAuthValue("u1", "p1"))
	openReq.Header.Set(trustTunnelMultipathHeaderTarget, "example.com:443")
	openReq.Header.Set(trustTunnelMultipathHeaderMinChannels, "2")
	openReq.Header.Set(trustTunnelMultipathHeaderMaxChannels, "2")
	server.serveHTTP2Request(&bufferedConn{}, openRecorder, openReq, dispatcher, nil, "")

	sessionID := openRecorder.Header().Get(trustTunnelMultipathHeaderSessionID)
	attachSecret := openRecorder.Header().Get(trustTunnelMultipathHeaderAttachSecret)
	buildAttach := func(nonce string) *http.Request {
		req, err := buildTrustTunnelMultipathAttachRequestAt(sessionID, attachSecret, 2, "example.com:443", testTrustTunnelMemoryAccount(), now, nonce)
		if err != nil {
			t.Fatalf("buildTrustTunnelMultipathAttachRequestAt() error: %v", err)
		}
		req.RemoteAddr = "127.0.0.1:54321"
		return req
	}

	firstRecorder := httptest.NewRecorder()
	server.serveHTTP2Request(&bufferedConn{}, firstRecorder, buildAttach("nonce-4"), dispatcher, nil, "")
	if firstRecorder.Code != http.StatusOK {
		t.Fatalf("first attach status = %d, want 200", firstRecorder.Code)
	}

	secondRecorder := httptest.NewRecorder()
	server.serveHTTP2Request(&bufferedConn{}, secondRecorder, buildAttach("nonce-5"), dispatcher, nil, "")
	if secondRecorder.Code != http.StatusConflict {
		t.Fatalf("duplicate attach status = %d, want 409", secondRecorder.Code)
	}
}

func TestProcessHTTP1RejectsMultipathPseudoHosts(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher := &testDispatcher{}

	clientConn, serverConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverConn)
		err := server.processHTTP1(context.Background(), serverConn, reader, dispatcher, nil, "")
		_ = serverConn.Close()
		done <- err
	}()

	raw := strings.Join([]string{
		"CONNECT _mptcp_open:0 HTTP/1.1",
		"Host: _mptcp_open:0",
		"Proxy-Authorization: " + buildBasicAuthValue("u1", "p1"),
		"X-TrustTunnel-Multipath-Target: example.com:443",
		"",
		"",
	}, "\r\n")
	if _, err := clientConn.Write([]byte(raw)); err != nil {
		t.Fatalf("failed to write H1 multipath request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("failed to read H1 multipath response: %v", err)
	}
	defer resp.Body.Close()
	_ = clientConn.Close()

	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
	if err := <-done; err != nil {
		t.Fatalf("processHTTP1() error = %v, want nil", err)
	}
}
