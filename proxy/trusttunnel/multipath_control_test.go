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
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func waitForMultipathSessionInRegistry(t *testing.T, server *Server, sessionID string) *trustTunnelMultipathSession {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if session, ok := server.multipathSessions.Get(sessionID); ok {
			return session
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("multipath session %q was not stored in registry", sessionID)
	return nil
}

func newBlockingMultipathRequest(t *testing.T, host string, authHeader string) (*http.Request, func()) {
	t.Helper()

	req := newTestConnectRequest(host, authHeader)
	reader, writer := io.Pipe()
	req.Body = reader
	return req, func() {
		_ = writer.Close()
	}
}

func attachBlockingMultipathBody(req *http.Request) func() {
	reader, writer := io.Pipe()
	req.Body = reader
	return func() {
		_ = writer.Close()
	}
}

func newBlockingMultipathDispatcher() (*testDispatcher, func()) {
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())

	dispatcher := &testDispatcher{
		dispatchFn: func(context.Context, xnet.Destination) (*transport.Link, error) {
			return &transport.Link{
				Reader: downlinkReader,
				Writer: uplinkWriter,
			}, nil
		},
	}

	return dispatcher, func() {
		_ = uplinkWriter.Close()
		_ = downlinkWriter.Close()
		common.Interrupt(uplinkReader)
		common.Interrupt(downlinkReader)
	}
}

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
	req, closeReqBody := newBlockingMultipathRequest(t, trustTunnelMultipathOpenHost, buildBasicAuthValue("u1", "p1"))
	defer closeReqBody()
	req.Header.Set(trustTunnelMultipathHeaderTarget, "example.com:443")
	req.Header.Set(trustTunnelMultipathHeaderMinChannels, "2")
	req.Header.Set(trustTunnelMultipathHeaderMaxChannels, "3")
	req.Header.Set(trustTunnelMultipathHeaderStrict, "true")
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, dummyAddr("192.168.1.50:9443")))

	done := make(chan struct{})
	go func() {
		server.serveHTTP2Request(&bufferedConn{}, recorder, req, dispatcher, nil, "")
		close(done)
	}()

	time.Sleep(20 * time.Millisecond)
	sessionID := recorder.Header().Get(trustTunnelMultipathHeaderSessionID)
	if sessionID == "" {
		t.Fatal("missing multipath session id header")
	}
	sessionState := waitForMultipathSessionInRegistry(t, server, sessionID)
	if got := sessionState.ActiveChannelCount(); got != 1 {
		t.Fatalf("ActiveChannelCount() = %d, want 1", got)
	}
	if state := sessionState.State(); state != trustTunnelMultipathSessionOpening {
		t.Fatalf("state = %v, want opening", state)
	}
	if sessionState.TargetHost() != "example.com:443" {
		t.Fatalf("TargetHost = %q, want %q", sessionState.TargetHost(), "example.com:443")
	}
	if dispatcher.dispatchCount != 0 {
		t.Fatalf("dispatchCount = %d, want 0", dispatcher.dispatchCount)
	}

	sessionState.Close(nil)
	<-done
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
}

func TestServeHTTP2MultipathAttachAddsSecondaryChannel(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher, cleanupDispatch := newBlockingMultipathDispatcher()
	defer cleanupDispatch()
	now := time.Now()

	openRecorder := httptest.NewRecorder()
	openReq, closeOpenBody := newBlockingMultipathRequest(t, trustTunnelMultipathOpenHost, buildBasicAuthValue("u1", "p1"))
	defer closeOpenBody()
	openReq.Header.Set(trustTunnelMultipathHeaderTarget, "example.com:443")
	openReq.Header.Set(trustTunnelMultipathHeaderMinChannels, "2")
	openReq.Header.Set(trustTunnelMultipathHeaderMaxChannels, "3")
	openReq = openReq.WithContext(context.WithValue(openReq.Context(), http.LocalAddrContextKey, dummyAddr("192.168.1.50:9443")))

	openDone := make(chan struct{})
	go func() {
		server.serveHTTP2Request(&bufferedConn{}, openRecorder, openReq, dispatcher, nil, "")
		close(openDone)
	}()

	time.Sleep(20 * time.Millisecond)
	sessionID := openRecorder.Header().Get(trustTunnelMultipathHeaderSessionID)
	attachSecret := openRecorder.Header().Get(trustTunnelMultipathHeaderAttachSecret)
	if sessionID == "" || attachSecret == "" {
		t.Fatalf("missing open response headers: sessionID=%q secret=%q", sessionID, attachSecret)
	}
	sessionState := waitForMultipathSessionInRegistry(t, server, sessionID)

	attachReq, err := buildTrustTunnelMultipathAttachRequestAt(sessionID, attachSecret, 2, "example.com:443", testTrustTunnelMemoryAccount(), now, "nonce-2")
	if err != nil {
		t.Fatalf("buildTrustTunnelMultipathAttachRequestAt() error: %v", err)
	}
	attachReq.RemoteAddr = "127.0.0.1:54321"
	attachReq = attachReq.WithContext(context.WithValue(attachReq.Context(), http.LocalAddrContextKey, dummyAddr("192.168.1.51:9443")))
	closeAttachBody := attachBlockingMultipathBody(attachReq)
	defer closeAttachBody()

	attachRecorder := httptest.NewRecorder()
	attachDone := make(chan struct{})
	go func() {
		server.serveHTTP2Request(&bufferedConn{}, attachRecorder, attachReq, dispatcher, nil, "")
		close(attachDone)
	}()

	time.Sleep(50 * time.Millisecond)
	if got := sessionState.ActiveChannelCount(); got != 2 {
		t.Fatalf("ActiveChannelCount() = %d, want 2", got)
	}
	if state := sessionState.State(); state != trustTunnelMultipathSessionActive {
		t.Fatalf("state = %v, want active", state)
	}
	if dispatcher.dispatchCount != 1 {
		t.Fatalf("dispatchCount = %d, want 1", dispatcher.dispatchCount)
	}

	sessionState.Close(nil)
	<-attachDone
	<-openDone
	if attachRecorder.Code != http.StatusOK {
		t.Fatalf("attach status = %d, want 200", attachRecorder.Code)
	}
}

func TestServeHTTP2MultipathAttachRejectsInvalidProof(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher := &testDispatcher{}
	now := time.Now()

	openRecorder := httptest.NewRecorder()
	openReq, closeOpenBody := newBlockingMultipathRequest(t, trustTunnelMultipathOpenHost, buildBasicAuthValue("u1", "p1"))
	defer closeOpenBody()
	openReq.Header.Set(trustTunnelMultipathHeaderTarget, "example.com:443")
	openReq.Header.Set(trustTunnelMultipathHeaderMinChannels, "2")
	openReq.Header.Set(trustTunnelMultipathHeaderMaxChannels, "2")
	openDone := make(chan struct{})
	go func() {
		server.serveHTTP2Request(&bufferedConn{}, openRecorder, openReq, dispatcher, nil, "")
		close(openDone)
	}()

	time.Sleep(20 * time.Millisecond)
	sessionID := openRecorder.Header().Get(trustTunnelMultipathHeaderSessionID)
	attachSecret := openRecorder.Header().Get(trustTunnelMultipathHeaderAttachSecret)
	sessionState := waitForMultipathSessionInRegistry(t, server, sessionID)
	attachReq, err := buildTrustTunnelMultipathAttachRequestAt(sessionID, attachSecret, 2, "example.com:443", testTrustTunnelMemoryAccount(), now, "nonce-3")
	if err != nil {
		t.Fatalf("buildTrustTunnelMultipathAttachRequestAt() error: %v", err)
	}
	attachReq.Header.Set(trustTunnelMultipathHeaderAttachProof, "broken-proof")
	attachReq.RemoteAddr = "127.0.0.1:54321"
	closeAttachBody := attachBlockingMultipathBody(attachReq)
	defer closeAttachBody()

	attachRecorder := httptest.NewRecorder()
	server.serveHTTP2Request(&bufferedConn{}, attachRecorder, attachReq, dispatcher, nil, "")

	if attachRecorder.Code != http.StatusForbidden {
		t.Fatalf("attach status = %d, want 403", attachRecorder.Code)
	}
	if got := sessionState.ActiveChannelCount(); got != 1 {
		t.Fatalf("ActiveChannelCount() = %d, want 1", got)
	}

	sessionState.Close(nil)
	<-openDone
}

func TestServeHTTP2MultipathAttachRejectsDuplicateChannel(t *testing.T) {
	server := newTestTrustTunnelServer(t, &ServerConfig{})
	dispatcher, cleanupDispatch := newBlockingMultipathDispatcher()
	defer cleanupDispatch()
	now := time.Now()

	openRecorder := httptest.NewRecorder()
	openReq, closeOpenBody := newBlockingMultipathRequest(t, trustTunnelMultipathOpenHost, buildBasicAuthValue("u1", "p1"))
	defer closeOpenBody()
	openReq.Header.Set(trustTunnelMultipathHeaderTarget, "example.com:443")
	openReq.Header.Set(trustTunnelMultipathHeaderMinChannels, "2")
	openReq.Header.Set(trustTunnelMultipathHeaderMaxChannels, "2")
	openDone := make(chan struct{})
	go func() {
		server.serveHTTP2Request(&bufferedConn{}, openRecorder, openReq, dispatcher, nil, "")
		close(openDone)
	}()

	time.Sleep(20 * time.Millisecond)
	sessionID := openRecorder.Header().Get(trustTunnelMultipathHeaderSessionID)
	attachSecret := openRecorder.Header().Get(trustTunnelMultipathHeaderAttachSecret)
	sessionState := waitForMultipathSessionInRegistry(t, server, sessionID)
	buildAttach := func(nonce string) *http.Request {
		req, err := buildTrustTunnelMultipathAttachRequestAt(sessionID, attachSecret, 2, "example.com:443", testTrustTunnelMemoryAccount(), now, nonce)
		if err != nil {
			t.Fatalf("buildTrustTunnelMultipathAttachRequestAt() error: %v", err)
		}
		req.RemoteAddr = "127.0.0.1:54321"
		return req
	}

	firstRecorder := httptest.NewRecorder()
	firstReq := buildAttach("nonce-4")
	closeFirstAttachBody := attachBlockingMultipathBody(firstReq)
	defer closeFirstAttachBody()
	firstDone := make(chan struct{})
	go func() {
		server.serveHTTP2Request(&bufferedConn{}, firstRecorder, firstReq, dispatcher, nil, "")
		close(firstDone)
	}()
	time.Sleep(50 * time.Millisecond)
	if firstRecorder.Code != http.StatusOK {
		t.Fatalf("first attach status = %d, want 200", firstRecorder.Code)
	}
	if dispatcher.dispatchCount != 1 {
		t.Fatalf("dispatchCount = %d, want 1", dispatcher.dispatchCount)
	}
	if got := sessionState.ActiveChannelCount(); got != 2 {
		t.Fatalf("ActiveChannelCount() after first attach = %d, want 2", got)
	}

	secondRecorder := httptest.NewRecorder()
	secondReq := buildAttach("nonce-5")
	closeSecondAttachBody := attachBlockingMultipathBody(secondReq)
	defer closeSecondAttachBody()
	server.serveHTTP2Request(&bufferedConn{}, secondRecorder, secondReq, dispatcher, nil, "")
	if secondRecorder.Code != http.StatusConflict {
		t.Fatalf("duplicate attach status = %d, want 409", secondRecorder.Code)
	}

	sessionState.Close(nil)
	<-firstDone
	<-openDone
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
