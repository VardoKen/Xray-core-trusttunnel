package trusttunnel

import (
	"bytes"
	"context"
	stderrors "errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
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

type fakeTrustTunnelServerSequenceDialer struct {
	streamSettings *internet.MemoryStreamConfig
	callOrder      []string
	errs           map[string]error
}

type nopReadWriteCloser struct{}

func (nopReadWriteCloser) Read([]byte) (int, error)  { return 0, io.EOF }
func (nopReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopReadWriteCloser) Close() error { return nil }

func withTrustTunnelHTTP3Connector(t *testing.T, fn func(context.Context, string, string, *MemoryAccount, *ClientConfig) (io.ReadWriteCloser, error)) {
	t.Helper()
	original := trustTunnelConnectHTTP3Func
	trustTunnelConnectHTTP3Func = fn
	t.Cleanup(func() {
		trustTunnelConnectHTTP3Func = original
	})
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

func (d *fakeTrustTunnelServerSequenceDialer) Dial(ctx context.Context, destination xnet.Destination) (stat.Connection, error) {
	addr := destination.NetAddr()
	d.callOrder = append(d.callOrder, addr)
	if err, ok := d.errs[addr]; ok {
		return nil, err
	}
	return nil, io.EOF
}

func (*fakeTrustTunnelServerSequenceDialer) DestIpAddress() net.IP {
	return nil
}

func (*fakeTrustTunnelServerSequenceDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {
}

func (d *fakeTrustTunnelServerSequenceDialer) StreamSettings() *internet.MemoryStreamConfig {
	return d.streamSettings
}

func withTrustTunnelLookupIPAddrs(t *testing.T, fn func(context.Context, string) ([]net.IPAddr, error)) {
	t.Helper()
	original := trustTunnelLookupIPAddrs
	trustTunnelLookupIPAddrs = fn
	t.Cleanup(func() {
		trustTunnelLookupIPAddrs = original
	})
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

func TestNewClientUsesConfiguredServerList(t *testing.T) {
	servers, err := trustTunnelServersFromConfig(context.Background(), &ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: xnet.NewIPOrDomain(xnet.ParseAddress("127.0.0.1")),
			Port:    9443,
			User: &protocol.User{
				Account: serial.ToTypedMessage(&Account{
					Username: "u1",
					Password: "p1",
				}),
			},
		},
		Servers: []*protocol.ServerEndpoint{
			{
				Address: xnet.NewIPOrDomain(xnet.ParseAddress("127.0.0.1")),
				Port:    9443,
				User: &protocol.User{
					Account: serial.ToTypedMessage(&Account{
						Username: "u1",
						Password: "p1",
					}),
				},
			},
			{
				Address: xnet.NewIPOrDomain(xnet.ParseAddress("127.0.0.2")),
				Port:    9444,
				User: &protocol.User{
					Account: serial.ToTypedMessage(&Account{
						Username: "u1",
						Password: "p1",
					}),
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("trustTunnelServersFromConfig() failed: %v", err)
	}

	if len(servers) != 2 {
		t.Fatalf("len(servers) = %d, want 2", len(servers))
	}
	if got := servers[1].Destination.NetAddr(); got != "127.0.0.2:9444" {
		t.Fatalf("servers[1] = %q, want %q", got, "127.0.0.2:9444")
	}
}

func TestTrustTunnelServersFromConfigExpandsResolvedDomainEndpoint(t *testing.T) {
	withTrustTunnelLookupIPAddrs(t, func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host != "edge.example.com" {
			t.Fatalf("unexpected host: %q", host)
		}
		return []net.IPAddr{
			{IP: net.ParseIP("127.0.0.1")},
			{IP: net.ParseIP("127.0.0.2")},
		}, nil
	})

	servers, err := trustTunnelServersFromConfig(context.Background(), &ClientConfig{
		Servers: []*protocol.ServerEndpoint{
			{
				Address: xnet.NewIPOrDomain(xnet.DomainAddress("edge.example.com")),
				Port:    9443,
				User: &protocol.User{
					Account: serial.ToTypedMessage(&Account{
						Username: "u1",
						Password: "p1",
					}),
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("trustTunnelServersFromConfig() failed: %v", err)
	}

	if got, want := len(servers), 2; got != want {
		t.Fatalf("len(servers) = %d, want %d", got, want)
	}
	if got := servers[0].Destination.NetAddr(); got != "127.0.0.1:9443" {
		t.Fatalf("servers[0] = %q, want %q", got, "127.0.0.1:9443")
	}
	if got := servers[1].Destination.NetAddr(); got != "127.0.0.2:9443" {
		t.Fatalf("servers[1] = %q, want %q", got, "127.0.0.2:9443")
	}
}

func TestTrustTunnelServersFromConfigSkipsUnresolvedDomainWhenOthersExist(t *testing.T) {
	withTrustTunnelLookupIPAddrs(t, func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host == "bad.example.com" {
			return nil, stderrors.New("lookup failed")
		}
		t.Fatalf("unexpected host: %q", host)
		return nil, nil
	})

	servers, err := trustTunnelServersFromConfig(context.Background(), &ClientConfig{
		Servers: []*protocol.ServerEndpoint{
			{
				Address: xnet.NewIPOrDomain(xnet.DomainAddress("bad.example.com")),
				Port:    9443,
				User: &protocol.User{
					Account: serial.ToTypedMessage(&Account{
						Username: "u1",
						Password: "p1",
					}),
				},
			},
			{
				Address: xnet.NewIPOrDomain(xnet.ParseAddress("127.0.0.2")),
				Port:    9444,
				User: &protocol.User{
					Account: serial.ToTypedMessage(&Account{
						Username: "u1",
						Password: "p1",
					}),
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("trustTunnelServersFromConfig() failed: %v", err)
	}

	if got, want := len(servers), 1; got != want {
		t.Fatalf("len(servers) = %d, want %d", got, want)
	}
	if got := servers[0].Destination.NetAddr(); got != "127.0.0.2:9444" {
		t.Fatalf("servers[0] = %q, want %q", got, "127.0.0.2:9444")
	}
}

func TestTrustTunnelServersFromConfigFailsWhenNoResolvedServersRemain(t *testing.T) {
	withTrustTunnelLookupIPAddrs(t, func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return nil, stderrors.New("lookup failed")
	})

	_, err := trustTunnelServersFromConfig(context.Background(), &ClientConfig{
		Servers: []*protocol.ServerEndpoint{
			{
				Address: xnet.NewIPOrDomain(xnet.DomainAddress("bad.example.com")),
				Port:    9443,
				User: &protocol.User{
					Account: serial.ToTypedMessage(&Account{
						Username: "u1",
						Password: "p1",
					}),
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to resolve any trusttunnel server addresses") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientProcessFallsBackToNextConfiguredServer(t *testing.T) {
	client := &Client{
		config: &ClientConfig{},
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
			&protocol.MemoryUser{
				Account: &MemoryAccount{
					Username: "u1",
					Password: "p1",
				},
			},
		),
		servers: []*protocol.ServerSpec{
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
				&protocol.MemoryUser{
					Account: &MemoryAccount{
						Username: "u1",
						Password: "p1",
					},
				},
			),
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.2"), xnet.Port(9444)),
				&protocol.MemoryUser{
					Account: &MemoryAccount{
						Username: "u1",
						Password: "p1",
					},
				},
			),
		},
	}

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{
		{
			Target: xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		},
	})
	dialer := &fakeTrustTunnelServerSequenceDialer{
		streamSettings: &internet.MemoryStreamConfig{
			SecurityType: "tls",
			SecuritySettings: &internettls.Config{
				ServerName: "vpn.example.com",
			},
		},
		errs: map[string]error{
			"127.0.0.1:9443": stderrors.New("first endpoint down"),
			"127.0.0.2:9444": io.EOF,
		},
	}

	err := client.Process(ctx, &transport.Link{}, dialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to dial trusttunnel server") {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"127.0.0.1:9443", "127.0.0.2:9444"}
	if len(dialer.callOrder) != len(want) {
		t.Fatalf("callOrder = %v, want %v", dialer.callOrder, want)
	}
	for i := range want {
		if dialer.callOrder[i] != want[i] {
			t.Fatalf("callOrder[%d] = %q, want %q", i, dialer.callOrder[i], want[i])
		}
	}
}

func TestClientServerAttemptsPreferLastSuccessfulEndpoint(t *testing.T) {
	client := &Client{
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
			&protocol.MemoryUser{
				Account: &MemoryAccount{
					Username: "u1",
					Password: "p1",
				},
			},
		),
		servers: []*protocol.ServerSpec{
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
				&protocol.MemoryUser{
					Account: &MemoryAccount{
						Username: "u1",
						Password: "p1",
					},
				},
			),
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.2"), xnet.Port(9444)),
				&protocol.MemoryUser{
					Account: &MemoryAccount{
						Username: "u1",
						Password: "p1",
					},
				},
			),
		},
	}

	attempts := client.serverAttempts()
	if len(attempts) != 2 {
		t.Fatalf("len(attempts) = %d, want 2", len(attempts))
	}
	if got := attempts[0].server.Destination.NetAddr(); got != "127.0.0.1:9443" {
		t.Fatalf("attempts[0] = %q, want %q", got, "127.0.0.1:9443")
	}

	client.noteServerSuccess(1)
	attempts = client.serverAttempts()
	if got := attempts[0].server.Destination.NetAddr(); got != "127.0.0.2:9444" {
		t.Fatalf("attempts[0] after success = %q, want %q", got, "127.0.0.2:9444")
	}
	if got := attempts[1].server.Destination.NetAddr(); got != "127.0.0.1:9443" {
		t.Fatalf("attempts[1] after success = %q, want %q", got, "127.0.0.1:9443")
	}
}

func TestClientServerAttemptsMoveCoolingDownEndpointToBack(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	client := &Client{
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
			&protocol.MemoryUser{
				Account: &MemoryAccount{Username: "u1", Password: "p1"},
			},
		),
		servers: []*protocol.ServerSpec{
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
				&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
			),
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.2"), xnet.Port(9444)),
				&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
			),
		},
	}

	client.noteServerFailureUntil(0, now.Add(time.Second))
	attempts := client.serverAttemptsAt(now)
	if got := attempts[0].server.Destination.NetAddr(); got != "127.0.0.2:9444" {
		t.Fatalf("attempts[0] during cooldown = %q, want %q", got, "127.0.0.2:9444")
	}
	if got := attempts[1].server.Destination.NetAddr(); got != "127.0.0.1:9443" {
		t.Fatalf("attempts[1] during cooldown = %q, want %q", got, "127.0.0.1:9443")
	}

	attempts = client.serverAttemptsAt(now.Add(2 * time.Second))
	if got := attempts[0].server.Destination.NetAddr(); got != "127.0.0.1:9443" {
		t.Fatalf("attempts[0] after cooldown = %q, want %q", got, "127.0.0.1:9443")
	}
}

func TestClientServerAttemptsCoolingDownPreferredEndpointTemporarilyUsesNextServer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	client := &Client{
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
			&protocol.MemoryUser{
				Account: &MemoryAccount{Username: "u1", Password: "p1"},
			},
		),
		servers: []*protocol.ServerSpec{
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
				&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
			),
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.2"), xnet.Port(9444)),
				&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
			),
		},
	}

	client.noteServerSuccess(1)
	client.noteServerFailureUntil(1, now.Add(time.Second))

	attempts := client.serverAttemptsAt(now)
	if got := attempts[0].server.Destination.NetAddr(); got != "127.0.0.1:9443" {
		t.Fatalf("attempts[0] with preferred cooling down = %q, want %q", got, "127.0.0.1:9443")
	}
	if got := attempts[1].server.Destination.NetAddr(); got != "127.0.0.2:9444" {
		t.Fatalf("attempts[1] with preferred cooling down = %q, want %q", got, "127.0.0.2:9444")
	}

	attempts = client.serverAttemptsAt(now.Add(2 * time.Second))
	if got := attempts[0].server.Destination.NetAddr(); got != "127.0.0.2:9444" {
		t.Fatalf("attempts[0] after preferred cooldown expires = %q, want %q", got, "127.0.0.2:9444")
	}
}

func TestClientConnectWithEndpointPolicyUsesDelayedRaceWinner(t *testing.T) {
	originalDelay := trustTunnelEndpointRaceDelay
	trustTunnelEndpointRaceDelay = 10 * time.Millisecond
	t.Cleanup(func() {
		trustTunnelEndpointRaceDelay = originalDelay
	})

	client := &Client{
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
			&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
		),
		servers: []*protocol.ServerSpec{
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
				&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
			),
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.2"), xnet.Port(9444)),
				&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
			),
		},
	}

	attempts := client.serverAttempts()
	var callOrder []string
	start := time.Now()
	conn, err := client.connectWithEndpointPolicy(context.Background(), attempts, "endpoint", func(ctx context.Context, attempt trustTunnelServerAttempt) (io.ReadWriteCloser, error) {
		callOrder = append(callOrder, attempt.server.Destination.NetAddr())
		if attempt.index == 0 {
			select {
			case <-time.After(100 * time.Millisecond):
				return nopReadWriteCloser{}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return nopReadWriteCloser{}, nil
	}, nil)
	if err != nil {
		t.Fatalf("connectWithEndpointPolicy() error = %v", err)
	}
	if conn == nil {
		t.Fatal("connectWithEndpointPolicy() returned nil conn")
	}
	if elapsed := time.Since(start); elapsed >= 80*time.Millisecond {
		t.Fatalf("delayed race took too long: %v", elapsed)
	}
	want := []string{"127.0.0.1:9443", "127.0.0.2:9444"}
	if len(callOrder) != len(want) {
		t.Fatalf("callOrder = %v, want %v", callOrder, want)
	}
	for i := range want {
		if callOrder[i] != want[i] {
			t.Fatalf("callOrder[%d] = %q, want %q", i, callOrder[i], want[i])
		}
	}
	attempts = client.serverAttempts()
	if got := attempts[0].server.Destination.NetAddr(); got != "127.0.0.2:9444" {
		t.Fatalf("preferred endpoint after race = %q, want %q", got, "127.0.0.2:9444")
	}
}

func TestClientConnectWithEndpointPolicyStartsSecondaryImmediatelyOnPrimaryFailure(t *testing.T) {
	originalDelay := trustTunnelEndpointRaceDelay
	trustTunnelEndpointRaceDelay = 100 * time.Millisecond
	t.Cleanup(func() {
		trustTunnelEndpointRaceDelay = originalDelay
	})

	client := &Client{
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
			&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
		),
		servers: []*protocol.ServerSpec{
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
				&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
			),
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.2"), xnet.Port(9444)),
				&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
			),
		},
	}

	attempts := client.serverAttempts()
	var callOrder []string
	start := time.Now()
	conn, err := client.connectWithEndpointPolicy(context.Background(), attempts, "endpoint", func(ctx context.Context, attempt trustTunnelServerAttempt) (io.ReadWriteCloser, error) {
		callOrder = append(callOrder, attempt.server.Destination.NetAddr())
		if attempt.index == 0 {
			return nil, stderrors.New("primary failed immediately")
		}
		return nopReadWriteCloser{}, nil
	}, nil)
	if err != nil {
		t.Fatalf("connectWithEndpointPolicy() error = %v", err)
	}
	if conn == nil {
		t.Fatal("connectWithEndpointPolicy() returned nil conn")
	}
	if elapsed := time.Since(start); elapsed >= 80*time.Millisecond {
		t.Fatalf("secondary was not started immediately after primary failure: %v", elapsed)
	}
	want := []string{"127.0.0.1:9443", "127.0.0.2:9444"}
	if len(callOrder) != len(want) {
		t.Fatalf("callOrder = %v, want %v", callOrder, want)
	}
}

func TestClientConnectWithEndpointPolicyFallsBackAfterRacedPairFails(t *testing.T) {
	originalDelay := trustTunnelEndpointRaceDelay
	trustTunnelEndpointRaceDelay = 10 * time.Millisecond
	t.Cleanup(func() {
		trustTunnelEndpointRaceDelay = originalDelay
	})

	client := &Client{
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
			&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
		),
		servers: []*protocol.ServerSpec{
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
				&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
			),
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.2"), xnet.Port(9444)),
				&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
			),
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.3"), xnet.Port(9445)),
				&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
			),
		},
	}

	attempts := client.serverAttempts()
	var callOrder []string
	conn, err := client.connectWithEndpointPolicy(context.Background(), attempts, "endpoint", func(ctx context.Context, attempt trustTunnelServerAttempt) (io.ReadWriteCloser, error) {
		callOrder = append(callOrder, attempt.server.Destination.NetAddr())
		if attempt.index < 2 {
			select {
			case <-time.After(15 * time.Millisecond):
				return nil, stderrors.New("raced pair failed")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return nopReadWriteCloser{}, nil
	}, nil)
	if err != nil {
		t.Fatalf("connectWithEndpointPolicy() error = %v", err)
	}
	if conn == nil {
		t.Fatal("connectWithEndpointPolicy() returned nil conn")
	}
	want := []string{"127.0.0.1:9443", "127.0.0.2:9444", "127.0.0.3:9445"}
	if len(callOrder) != len(want) {
		t.Fatalf("callOrder = %v, want %v", callOrder, want)
	}
	for i := range want {
		if callOrder[i] != want[i] {
			t.Fatalf("callOrder[%d] = %q, want %q", i, callOrder[i], want[i])
		}
	}
}

func TestClientConnectWithEndpointPolicyRestoresCoolingEndpointViaActiveProbe(t *testing.T) {
	originalInterval := trustTunnelEndpointActiveProbeInterval
	originalTimeout := trustTunnelEndpointActiveProbeTimeout
	trustTunnelEndpointActiveProbeInterval = 10 * time.Millisecond
	trustTunnelEndpointActiveProbeTimeout = 20 * time.Millisecond
	t.Cleanup(func() {
		trustTunnelEndpointActiveProbeInterval = originalInterval
		trustTunnelEndpointActiveProbeTimeout = originalTimeout
	})

	client := &Client{
		server: protocol.NewServerSpec(
			xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
			&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
		),
		servers: []*protocol.ServerSpec{
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
				&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
			),
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.2"), xnet.Port(9444)),
				&protocol.MemoryUser{Account: &MemoryAccount{Username: "u1", Password: "p1"}},
			),
		},
	}

	attempts := client.serverAttempts()
	conn, err := client.connectWithEndpointPolicy(context.Background(), attempts, "endpoint", func(ctx context.Context, attempt trustTunnelServerAttempt) (io.ReadWriteCloser, error) {
		if attempt.index == 0 {
			return nil, stderrors.New("primary failed")
		}
		return nopReadWriteCloser{}, nil
	}, func(ctx context.Context, attempt trustTunnelServerAttempt) error {
		if attempt.index != 0 {
			t.Fatalf("probe called for unexpected endpoint %d", attempt.index)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("connectWithEndpointPolicy() error = %v", err)
	}
	if conn == nil {
		t.Fatal("connectWithEndpointPolicy() returned nil conn")
	}

	deadline := time.Now().Add(300 * time.Millisecond)
	for {
		if got := client.serverAttempts()[0].server.Destination.NetAddr(); got == "127.0.0.1:9443" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("active probe did not restore preferred endpoint, attempts=%v", client.serverAttempts())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestClientProcessFallsBackToHTTP2WhenHTTP3FailsTransport(t *testing.T) {
	withTrustTunnelHTTP3Connector(t, func(context.Context, string, string, *MemoryAccount, *ClientConfig) (io.ReadWriteCloser, error) {
		return nil, trustTunnelWrapHTTP3ConnectError(io.EOF, true)
	})

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
			SecurityType: "tls",
			SecuritySettings: &internettls.Config{
				ServerName: "vpn.example.com",
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
	if dialer.dialCalls != 1 {
		t.Fatalf("dialCalls = %d, want 1", dialer.dialCalls)
	}
}

func TestClientProcessKeepsHTTP3ErrorWhenFallbackIsNotEligible(t *testing.T) {
	withTrustTunnelHTTP3Connector(t, func(context.Context, string, string, *MemoryAccount, *ClientConfig) (io.ReadWriteCloser, error) {
		return nil, trustTunnelWrapHTTP3ConnectError(io.EOF, false)
	})

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
			SecurityType: "tls",
			SecuritySettings: &internettls.Config{
				ServerName: "vpn.example.com",
			},
		},
	}

	err := client.Process(ctx, &transport.Link{}, dialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to establish trusttunnel HTTP/3 CONNECT") {
		t.Fatalf("unexpected error: %v", err)
	}
	if dialer.dialCalls != 0 {
		t.Fatalf("dialCalls = %d, want 0", dialer.dialCalls)
	}
}

func TestClientProcessAutoFallsBackToHTTP2WhenHTTP3FailsTransport(t *testing.T) {
	withTrustTunnelHTTP3Connector(t, func(context.Context, string, string, *MemoryAccount, *ClientConfig) (io.ReadWriteCloser, error) {
		return nil, trustTunnelWrapHTTP3ConnectError(io.EOF, true)
	})

	client := &Client{
		config: &ClientConfig{
			Transport: TransportProtocol_AUTO,
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
				ServerName: "vpn.example.com",
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
	if dialer.dialCalls != 1 {
		t.Fatalf("dialCalls = %d, want 1", dialer.dialCalls)
	}
}

func TestClientProcessAppliesAntiDpiOnHTTP2TLS(t *testing.T) {
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
	dialer := &fakeTrustTunnelDialerWithStreamSettings{
		streamSettings: &internet.MemoryStreamConfig{
			SecurityType: "tls",
			SecuritySettings: &internettls.Config{
				ServerName: "vpn.example.com",
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
	if dialer.dialCalls != 1 {
		t.Fatalf("dialCalls = %d, want 1", dialer.dialCalls)
	}
	if !internettls.AntiDPIEnabledFromContext(dialer.lastCtx) {
		t.Fatal("antiDpi context flag = false, want true")
	}
}

func TestClientProcessRejectsAntiDpiWithoutTLSSecurityStreamSettings(t *testing.T) {
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
	if !strings.Contains(err.Error(), "antiDpi is supported only for http2 over TLS or REALITY") {
		t.Fatalf("unexpected error: %v", err)
	}
	if dialer.dialCalls != 0 {
		t.Fatalf("dialCalls = %d, want 0", dialer.dialCalls)
	}
}

func TestClientProcessAutoSkipsHTTP3ForAntiDpi(t *testing.T) {
	h3Calls := 0
	withTrustTunnelHTTP3Connector(t, func(context.Context, string, string, *MemoryAccount, *ClientConfig) (io.ReadWriteCloser, error) {
		h3Calls++
		return nil, trustTunnelWrapHTTP3ConnectError(io.EOF, true)
	})

	client := &Client{
		config: &ClientConfig{
			Transport: TransportProtocol_AUTO,
			AntiDpi:   true,
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
				ServerName: "vpn.example.com",
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
	if h3Calls != 0 {
		t.Fatalf("h3Calls = %d, want 0", h3Calls)
	}
	if dialer.dialCalls != 1 {
		t.Fatalf("dialCalls = %d, want 1", dialer.dialCalls)
	}
	if !internettls.AntiDPIEnabledFromContext(dialer.lastCtx) {
		t.Fatal("antiDpi context flag = false, want true")
	}
}

func TestClientProcessAppliesAntiDpiOnHTTP2Reality(t *testing.T) {
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
	dialer := &fakeTrustTunnelDialerWithStreamSettings{
		streamSettings: &internet.MemoryStreamConfig{
			SecurityType: "reality",
			SecuritySettings: &reality.Config{
				ServerName:  "vpn.example.com",
				Fingerprint: "chrome",
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
	if dialer.dialCalls != 1 {
		t.Fatalf("dialCalls = %d, want 1", dialer.dialCalls)
	}
	if !internettls.AntiDPIEnabledFromContext(dialer.lastCtx) {
		t.Fatal("antiDpi context flag = false, want true")
	}
}

func TestClientProcessAutoSkipsHTTP3ForReality(t *testing.T) {
	h3Calls := 0
	withTrustTunnelHTTP3Connector(t, func(context.Context, string, string, *MemoryAccount, *ClientConfig) (io.ReadWriteCloser, error) {
		h3Calls++
		return nil, trustTunnelWrapHTTP3ConnectError(io.EOF, true)
	})

	client := &Client{
		config: &ClientConfig{
			Transport: TransportProtocol_AUTO,
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
				ServerName:  "vpn.example.com",
				Fingerprint: "chrome",
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
	if h3Calls != 0 {
		t.Fatalf("h3Calls = %d, want 0", h3Calls)
	}
	if dialer.dialCalls != 1 {
		t.Fatalf("dialCalls = %d, want 1", dialer.dialCalls)
	}
}

func TestClientProcessRejectsAntiDpiOnHTTP3(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			Transport: TransportProtocol_HTTP3,
			AntiDpi:   true,
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
	if !strings.Contains(err.Error(), "antiDpi is supported only for http2 over TLS or REALITY") {
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

func TestClientProcessAppliesTLSCompatibilityOverride(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			Hostname:         "vpn.example.com",
			SkipVerification: false,
			CertificatePem:   "-----BEGIN CERTIFICATE-----\ncompat-ca\n-----END CERTIFICATE-----\n",
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
				AllowInsecure: true,
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
	if tlsConfig.GetAllowInsecure() {
		t.Fatal("allowInsecure = true, want false")
	}
	if got := tlsConfig.GetServerName(); got != "vpn.example.com" {
		t.Fatalf("serverName = %q, want %q", got, "vpn.example.com")
	}
	if !tlsConfig.GetDisableSystemRoot() {
		t.Fatal("disableSystemRoot = false, want true")
	}
	if len(tlsConfig.GetCertificate()) != 1 {
		t.Fatalf("certificate entries = %d, want 1", len(tlsConfig.GetCertificate()))
	}
	if usage := tlsConfig.GetCertificate()[0].GetUsage(); usage != internettls.Certificate_AUTHORITY_VERIFY {
		t.Fatalf("certificate usage = %v, want AUTHORITY_VERIFY", usage)
	}
	if got := string(tlsConfig.GetCertificate()[0].GetCertificate()); got != client.config.GetCertificatePem() {
		t.Fatalf("certificate bytes = %q, want %q", got, client.config.GetCertificatePem())
	}
}

func TestClientProcessAppliesTLSSkipVerificationCompatibilityOverride(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			Hostname:         "vpn.example.com",
			SkipVerification: true,
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
				AllowInsecure: false,
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
	if !tlsConfig.GetAllowInsecure() {
		t.Fatal("allowInsecure = false, want true")
	}
	if got := tlsConfig.GetServerName(); got != "vpn.example.com" {
		t.Fatalf("serverName = %q, want %q", got, "vpn.example.com")
	}
}

func TestTrustTunnelStreamSettingsWithTLSCompatibilityKeepsExplicitVerifySurface(t *testing.T) {
	streamSettings := &internet.MemoryStreamConfig{
		SecurityType: "tls",
		SecuritySettings: &internettls.Config{
			ServerName:           "vpn.example.com",
			AllowInsecure:        true,
			VerifyPeerCertByName: []string{"example.com"},
		},
	}

	override, changed, handled := trustTunnelStreamSettingsWithTLSCompatibility(streamSettings, &ClientConfig{
		Hostname:         "vpn.example.com",
		SkipVerification: false,
		CertificatePem:   "-----BEGIN CERTIFICATE-----\ncompat-ca\n-----END CERTIFICATE-----\n",
	})

	if !handled {
		t.Fatal("handled = false, want true")
	}
	if changed {
		t.Fatal("changed = true, want false")
	}
	if override != streamSettings {
		t.Fatal("override pointer changed unexpectedly")
	}
}

func TestTrustTunnelStreamSettingsWithTLSCompatibilityFillsServerNameForExplicitVerifySurface(t *testing.T) {
	streamSettings := &internet.MemoryStreamConfig{
		SecurityType: "tls",
		SecuritySettings: &internettls.Config{
			VerifyPeerCertByName: []string{"example.com"},
		},
	}

	override, changed, handled := trustTunnelStreamSettingsWithTLSCompatibility(streamSettings, &ClientConfig{
		Hostname:         "vpn.example.com",
		SkipVerification: false,
	})

	if !handled {
		t.Fatal("handled = false, want true")
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if override == streamSettings {
		t.Fatal("override pointer was not cloned")
	}

	tlsConfig := internettls.ConfigFromStreamSettings(override)
	if tlsConfig == nil {
		t.Fatal("expected tls override config, got nil")
	}
	if got := tlsConfig.GetServerName(); got != "vpn.example.com" {
		t.Fatalf("serverName = %q, want %q", got, "vpn.example.com")
	}
	if got := tlsConfig.GetVerifyPeerCertByName(); len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("verifyPeerCertByName = %v, want [example.com]", got)
	}
	if tlsConfig.GetAllowInsecure() {
		t.Fatal("allowInsecure = true, want false")
	}
}

func TestConnectUDPTunnelFallsBackToHTTP2WhenHTTP3FailsTransport(t *testing.T) {
	withTrustTunnelHTTP3Connector(t, func(context.Context, string, string, *MemoryAccount, *ClientConfig) (io.ReadWriteCloser, error) {
		return nil, trustTunnelWrapHTTP3ConnectError(io.EOF, true)
	})

	client := &Client{
		config: &ClientConfig{
			Transport: TransportProtocol_HTTP3,
			EnableUdp: true,
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

	dialer := &fakeTrustTunnelDialerWithStreamSettings{
		streamSettings: &internet.MemoryStreamConfig{
			SecurityType: "tls",
			SecuritySettings: &internettls.Config{
				ServerName: "vpn.example.com",
			},
		},
	}

	_, err := client.connectUDPTunnel(context.Background(), dialer)
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

func TestConnectUDPTunnelPrefersLastSuccessfulServer(t *testing.T) {
	http3Calls := make([]string, 0, 3)
	withTrustTunnelHTTP3Connector(t, func(_ context.Context, serverAddr string, _ string, _ *MemoryAccount, _ *ClientConfig) (io.ReadWriteCloser, error) {
		http3Calls = append(http3Calls, serverAddr)
		switch len(http3Calls) {
		case 1:
			return nil, trustTunnelWrapHTTP3ConnectError(io.EOF, true)
		case 2, 3:
			return newFakeTrustTunnelStreamConn(nil), nil
		default:
			return nil, io.EOF
		}
	})

	client := &Client{
		config: &ClientConfig{
			Transport: TransportProtocol_HTTP3,
			EnableUdp: true,
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
		servers: []*protocol.ServerSpec{
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(9443)),
				&protocol.MemoryUser{
					Account: &MemoryAccount{
						Username: "u1",
						Password: "p1",
					},
				},
			),
			protocol.NewServerSpec(
				xnet.TCPDestination(xnet.ParseAddress("127.0.0.2"), xnet.Port(9444)),
				&protocol.MemoryUser{
					Account: &MemoryAccount{
						Username: "u1",
						Password: "p1",
					},
				},
			),
		},
	}

	dialer := &fakeTrustTunnelServerSequenceDialer{
		streamSettings: &internet.MemoryStreamConfig{
			SecurityType: "tls",
			SecuritySettings: &internettls.Config{
				ServerName: "vpn.example.com",
			},
		},
		errs: map[string]error{
			"127.0.0.1:9443": io.EOF,
		},
	}

	tunnelConn, err := client.connectUDPTunnel(context.Background(), dialer)
	if err != nil {
		t.Fatalf("first connectUDPTunnel() failed: %v", err)
	}
	_ = tunnelConn.Close()

	tunnelConn, err = client.connectUDPTunnel(context.Background(), dialer)
	if err != nil {
		t.Fatalf("second connectUDPTunnel() failed: %v", err)
	}
	_ = tunnelConn.Close()

	wantHTTP3 := []string{"127.0.0.1:9443", "127.0.0.2:9444", "127.0.0.2:9444"}
	if len(http3Calls) != len(wantHTTP3) {
		t.Fatalf("http3Calls = %v, want %v", http3Calls, wantHTTP3)
	}
	for i := range wantHTTP3 {
		if http3Calls[i] != wantHTTP3[i] {
			t.Fatalf("http3Calls[%d] = %q, want %q", i, http3Calls[i], wantHTTP3[i])
		}
	}

	wantDialOrder := []string{"127.0.0.1:9443"}
	if len(dialer.callOrder) != len(wantDialOrder) {
		t.Fatalf("dialer.callOrder = %v, want %v", dialer.callOrder, wantDialOrder)
	}
	for i := range wantDialOrder {
		if dialer.callOrder[i] != wantDialOrder[i] {
			t.Fatalf("dialer.callOrder[%d] = %q, want %q", i, dialer.callOrder[i], wantDialOrder[i])
		}
	}
}

func TestConnectICMPTunnelFallsBackToHTTP2WhenHTTP3FailsTransport(t *testing.T) {
	withTrustTunnelHTTP3Connector(t, func(context.Context, string, string, *MemoryAccount, *ClientConfig) (io.ReadWriteCloser, error) {
		return nil, trustTunnelWrapHTTP3ConnectError(io.EOF, true)
	})

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

	dialer := &fakeTrustTunnelDialerWithStreamSettings{
		streamSettings: &internet.MemoryStreamConfig{
			SecurityType: "tls",
			SecuritySettings: &internettls.Config{
				ServerName: "vpn.example.com",
			},
		},
	}

	_, err := client.connectICMPTunnel(context.Background(), dialer)
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
