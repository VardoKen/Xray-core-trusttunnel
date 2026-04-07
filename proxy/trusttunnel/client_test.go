package trusttunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	internettls "github.com/xtls/xray-core/transport/internet/tls"
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

type fakeTrustTunnelDialerWithStreamSettings struct {
	streamSettings *internet.MemoryStreamConfig
	dialCalls      int
	lastCtx        context.Context
	err            error
}

func (d *fakeTrustTunnelDialerWithStreamSettings) Dial(ctx context.Context, destination xnet.Destination) (stat.Connection, error) {
	d.dialCalls++
	d.lastCtx = ctx
	if d.err != nil {
		return nil, d.err
	}
	return nil, io.EOF
}

func (*fakeTrustTunnelDialerWithStreamSettings) DestIpAddress() net.IP {
	return nil
}

func (*fakeTrustTunnelDialerWithStreamSettings) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {
}

func (d *fakeTrustTunnelDialerWithStreamSettings) StreamSettings() *internet.MemoryStreamConfig {
	return d.streamSettings
}

func TestClientProcessRejectsHTTP3Reality(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			Transport: TransportProtocol_HTTP3,
		},
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
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
			Target: xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		},
	})
	dialer := &fakeTrustTunnelDialerWithStreamSettings{
		streamSettings: &internet.MemoryStreamConfig{
			SecurityType:     "reality",
			SecuritySettings: &reality.Config{},
		},
	}

	err := client.Process(ctx, &transport.Link{}, dialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "http3 with REALITY is unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
	if dialer.dialCalls != 0 {
		t.Fatalf("dialCalls = %d, want 0", dialer.dialCalls)
	}
}

func TestClientProcessRejectsAntiDpi(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			AntiDpi: true,
		},
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
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
			Target: xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		},
	})
	dialer := &fakeTrustTunnelDialerWithStreamSettings{}

	err := client.Process(ctx, &transport.Link{}, dialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "antiDpi is unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
	if dialer.dialCalls != 0 {
		t.Fatalf("dialCalls = %d, want 0", dialer.dialCalls)
	}
}

func TestClientProcessRejectsIPv6TargetWhenHasIpv6Disabled(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			HasIpv6: false,
		},
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
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
			Target: xnet.TCPDestination(xnet.ParseAddress("2606:4700:4700::1111"), xnet.Port(443)),
		},
	})
	dialer := &fakeTrustTunnelDialerWithStreamSettings{}

	err := client.Process(ctx, &transport.Link{}, dialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "IPv6 target is disabled by hasIpv6=false") {
		t.Fatalf("unexpected error: %v", err)
	}
	if dialer.dialCalls != 0 {
		t.Fatalf("dialCalls = %d, want 0", dialer.dialCalls)
	}
}

func TestClientProcessAllowsIPv4TargetWhenHasIpv6Disabled(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			HasIpv6: false,
		},
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
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
			Target: xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		},
	})
	dialer := &fakeTrustTunnelDialerWithStreamSettings{}

	err := client.Process(ctx, &transport.Link{}, dialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to dial trusttunnel server") {
		t.Fatalf("unexpected error: %v", err)
	}
	if dialer.dialCalls != 1 {
		t.Fatalf("dialCalls = %d, want 1", dialer.dialCalls)
	}
}

func TestClientProcessRejectsDomainTargetWhenHasIpv6Disabled(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			HasIpv6: false,
		},
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
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
			Target: xnet.TCPDestination(xnet.DomainAddress("example.com"), xnet.Port(443)),
		},
	})
	dialer := &fakeTrustTunnelDialerWithStreamSettings{}

	err := client.Process(ctx, &transport.Link{}, dialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "requires outbound targetStrategy useipv4/forceipv4") {
		t.Fatalf("unexpected error: %v", err)
	}
	if dialer.dialCalls != 0 {
		t.Fatalf("dialCalls = %d, want 0", dialer.dialCalls)
	}
}

func TestClientProcessAppliesPostQuantumRealityOverride(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			PostQuantumGroupEnabled: PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_ENABLED,
		},
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
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
			Target: xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		},
	})
	originalSettings := &internet.MemoryStreamConfig{
		SecurityType: "reality",
		SecuritySettings: &reality.Config{
			Fingerprint: "chrome",
		},
	}
	dialer := &fakeTrustTunnelDialerWithStreamSettings{
		streamSettings: originalSettings,
	}

	err := client.Process(ctx, &transport.Link{}, dialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to dial trusttunnel server") {
		t.Fatalf("unexpected error: %v", err)
	}
	if dialer.dialCalls != 1 {
		t.Fatalf("dialCalls = %d, want 1", dialer.dialCalls)
	}

	override := internet.StreamSettingsOverrideFromContext(dialer.lastCtx)
	if override == nil {
		t.Fatal("expected stream settings override, got nil")
	}
	realityConfig := reality.ConfigFromStreamSettings(override)
	if realityConfig == nil {
		t.Fatal("expected reality override config, got nil")
	}
	if got := realityConfig.GetFingerprint(); got != trustTunnelPostQuantumChromeFingerprintPQ {
		t.Fatalf("fingerprint = %q, want %q", got, trustTunnelPostQuantumChromeFingerprintPQ)
	}
	originalReality := reality.ConfigFromStreamSettings(originalSettings)
	if got := originalReality.GetFingerprint(); got != "chrome" {
		t.Fatalf("original fingerprint = %q, want chrome", got)
	}
}

func TestClientProcessAppliesPostQuantumTLSDisableOverride(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			PostQuantumGroupEnabled: PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_DISABLED,
		},
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
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
			Target: xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		},
	})
	dialer := &fakeTrustTunnelDialerWithStreamSettings{
		streamSettings: &internet.MemoryStreamConfig{
			SecurityType: "tls",
			SecuritySettings: &internettls.Config{
				Fingerprint: trustTunnelPostQuantumChromeFingerprintPQ,
			},
		},
	}

	err := client.Process(ctx, &transport.Link{}, dialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to dial trusttunnel server") {
		t.Fatalf("unexpected error: %v", err)
	}

	override := internet.StreamSettingsOverrideFromContext(dialer.lastCtx)
	if override == nil {
		t.Fatal("expected stream settings override, got nil")
	}
	tlsConfig := internettls.ConfigFromStreamSettings(override)
	if tlsConfig == nil {
		t.Fatal("expected tls override config, got nil")
	}
	if got := tlsConfig.GetFingerprint(); got != trustTunnelPostQuantumChromeFingerprint {
		t.Fatalf("fingerprint = %q, want %q", got, trustTunnelPostQuantumChromeFingerprint)
	}
	if got := tlsConfig.GetCurvePreferences(); len(got) != 1 || got[0] != "x25519" {
		t.Fatalf("curvePreferences = %v, want [x25519]", got)
	}
}

func TestClientProcessRejectsPostQuantumWithoutSecurityStreamSettings(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			PostQuantumGroupEnabled: PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_ENABLED,
		},
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
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
			Target: xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		},
	})
	dialer := &fakeTrustTunnelDialerWithStreamSettings{}

	err := client.Process(ctx, &transport.Link{}, dialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "postQuantumGroupEnabled is unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
	if dialer.dialCalls != 0 {
		t.Fatalf("dialCalls = %d, want 0", dialer.dialCalls)
	}
}

func TestClientProcessRejectsPostQuantumUnsupportedFingerprint(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			PostQuantumGroupEnabled: PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_ENABLED,
		},
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
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
			Target: xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		},
	})
	dialer := &fakeTrustTunnelDialerWithStreamSettings{
		streamSettings: &internet.MemoryStreamConfig{
			SecurityType: "reality",
			SecuritySettings: &reality.Config{
				Fingerprint: "firefox",
			},
		},
	}

	err := client.Process(ctx, &transport.Link{}, dialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "only default Chrome-family TLS/REALITY fingerprints can be toggled today") {
		t.Fatalf("unexpected error: %v", err)
	}
	if dialer.dialCalls != 0 {
		t.Fatalf("dialCalls = %d, want 0", dialer.dialCalls)
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

func TestRunTrustTunnelStreamTunnelStopsWhenResponseSideCloses(t *testing.T) {
	reqReader, _ := pipe.New()
	respReader, respWriter := pipe.New()
	link := &transport.Link{
		Reader: reqReader,
		Writer: respWriter,
	}

	tunnelConn := newFakeTrustTunnelStreamConn(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runTrustTunnelStreamTunnel(ctx, link, tunnelConn)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runTrustTunnelStreamTunnel() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("runTrustTunnelStreamTunnel() did not return after clean response-side EOF")
	}

	mb, err := respReader.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	if err != io.EOF {
		t.Fatalf("respReader.ReadMultiBuffer() error = %v, want EOF", err)
	}
	if !tunnelConn.closed {
		t.Fatal("tunnelConn.Close() was not called")
	}
}
