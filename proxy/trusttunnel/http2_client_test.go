package trusttunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestConnectHTTP2StreamsBodyAfterConnectResponse(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	account := &MemoryAccount{
		Username: "u1",
		Password: "p1",
	}
	req, err := buildConnectRequest("_icmp:0", account)
	if err != nil {
		t.Fatalf("failed to build CONNECT request: %v", err)
	}

	payload := []byte("trusttunnel-h2-icmp-payload")
	serverBodyCh := make(chan []byte, 1)
	serverErrCh := make(chan error, 1)
	serveDone := make(chan struct{})

	go func() {
		defer close(serveDone)

		h2s := &http2.Server{}
		h2s.ServeConn(serverConn, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodConnect {
					serverErrCh <- errors.New("unexpected method: " + req.Method)
					return
				}
				if req.Host != "_icmp:0" {
					serverErrCh <- errors.New("unexpected host: " + req.Host)
					return
				}

				w.WriteHeader(http.StatusOK)
				if fl, ok := w.(http.Flusher); ok {
					fl.Flush()
				}

				got := make([]byte, len(payload))
				if _, err := io.ReadFull(req.Body, got); err != nil {
					serverErrCh <- err
					return
				}
				serverBodyCh <- got

				if _, err := w.Write(got); err != nil {
					serverErrCh <- err
					return
				}
				if fl, ok := w.(http.Flusher); ok {
					fl.Flush()
				}
			}),
		})
	}()

	tunnelConn, err := connectHTTP2(clientConn, req)
	if err != nil {
		t.Fatalf("connectHTTP2 failed: %v", err)
	}

	if _, err := tunnelConn.Write(payload); err != nil {
		t.Fatalf("failed to write CONNECT body: %v", err)
	}

	gotReply := make([]byte, len(payload))
	if _, err := io.ReadFull(tunnelConn, gotReply); err != nil {
		t.Fatalf("failed to read CONNECT response body: %v", err)
	}
	if !bytes.Equal(gotReply, payload) {
		t.Fatalf("unexpected echoed payload: got %q want %q", gotReply, payload)
	}

	select {
	case serverErr := <-serverErrCh:
		t.Fatalf("server failed: %v", serverErr)
	case gotBody := <-serverBodyCh:
		if !bytes.Equal(gotBody, payload) {
			t.Fatalf("server received unexpected payload: got %q want %q", gotBody, payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server payload")
	}

	if err := tunnelConn.Close(); err != nil {
		t.Fatalf("failed to close h2 tunnel conn: %v", err)
	}

	select {
	case <-serveDone:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for h2 server to stop")
	}
}
