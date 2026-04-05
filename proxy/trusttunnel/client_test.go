package trusttunnel

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestClientProcessRejectsIncompleteICMPLink(t *testing.T) {
	client := &Client{
		config: &ClientConfig{},
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(9443)),
			&protocol.MemoryUser{
				Account: &MemoryAccount{
					Username: "u1",
					Password: "p1",
				},
			},
		),
	}

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{
		{
			Target: xnet.ICMPDestination(xnet.ParseAddress("1.1.1.1")),
		},
	})

	err := client.Process(ctx, &transport.Link{}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "icmp link is incomplete") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type fakeTrustTunnelStreamConn struct {
	readBuf  bytes.Buffer
	writeBuf bytes.Buffer
	closed   bool
}

func newFakeTrustTunnelStreamConn(response []byte) *fakeTrustTunnelStreamConn {
	conn := &fakeTrustTunnelStreamConn{}
	_, _ = conn.readBuf.Write(response)
	return conn
}

func (c *fakeTrustTunnelStreamConn) Read(p []byte) (int, error) {
	if c.readBuf.Len() == 0 {
		return 0, io.EOF
	}
	return c.readBuf.Read(p)
}

func (c *fakeTrustTunnelStreamConn) Write(p []byte) (int, error) {
	return c.writeBuf.Write(p)
}

func (c *fakeTrustTunnelStreamConn) Close() error {
	c.closed = true
	return nil
}

func TestRunTrustTunnelStreamTunnelRoundTrip(t *testing.T) {
	reqReader, reqWriter := pipe.New()
	respReader, respWriter := pipe.New()
	link := &transport.Link{
		Reader: reqReader,
		Writer: respWriter,
	}

	requestPayload := []byte("ping")
	responsePayload := []byte("pong")
	tunnelConn := newFakeTrustTunnelStreamConn(responsePayload)

	go func() {
		b := buf.New()
		_, _ = b.Write(requestPayload)
		_ = reqWriter.WriteMultiBuffer(buf.MultiBuffer{b})
		_ = reqWriter.Close()
	}()

	if err := runTrustTunnelStreamTunnel(context.Background(), link, tunnelConn); err != nil {
		t.Fatalf("runTrustTunnelStreamTunnel() error = %v", err)
	}

	var gotResponse bytes.Buffer
	for {
		mb, err := respReader.ReadMultiBuffer()
		for _, b := range mb {
			_, _ = gotResponse.Write(b.Bytes())
			b.Release()
		}
		buf.ReleaseMulti(mb)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("respReader.ReadMultiBuffer() error = %v", err)
		}
	}

	if got := tunnelConn.writeBuf.Bytes(); !bytes.Equal(got, requestPayload) {
		t.Fatalf("tunnel request payload = %q, want %q", string(got), string(requestPayload))
	}
	if got := gotResponse.Bytes(); !bytes.Equal(got, responsePayload) {
		t.Fatalf("response payload = %q, want %q", string(got), string(responsePayload))
	}
}
