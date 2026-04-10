package scenarios

import (
	"bytes"
	"context"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	v2http "github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/trusttunnel"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	ttls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func trustTunnelTestAccount(username, password string) *trusttunnel.Account {
	return &trusttunnel.Account{
		Username: username,
		Password: password,
	}
}

func trustTunnelTestServerUser(email, username, password string) *protocol.User {
	return &protocol.User{
		Email:   email,
		Account: serial.ToTypedMessage(trustTunnelTestAccount(username, password)),
	}
}

func trustTunnelTestServerUserWithLimits(email, username, password string, maxHTTP2, maxHTTP3 uint32) *protocol.User {
	return &protocol.User{
		Email: email,
		Account: serial.ToTypedMessage(&trusttunnel.Account{
			Username:      username,
			Password:      password,
			MaxHttp2Conns: maxHTTP2,
			MaxHttp3Conns: maxHTTP3,
		}),
	}
}

func trustTunnelTestServerEndpoint(port net.Port, username, password string) *protocol.ServerEndpoint {
	return &protocol.ServerEndpoint{
		Address: net.NewIPOrDomain(net.LocalHostIP),
		Port:    uint32(port),
		User: &protocol.User{
			Account: serial.ToTypedMessage(trustTunnelTestAccount(username, password)),
		},
	}
}

func trustTunnelTestOutbound(port net.Port, username, password string) *trusttunnel.ClientConfig {
	return &trusttunnel.ClientConfig{
		Server:           trustTunnelTestServerEndpoint(port, username, password),
		Hostname:         "localhost",
		Transport:        trusttunnel.TransportProtocol_HTTP2,
		HasIpv6:          true,
		SkipVerification: true,
	}
}

func trustTunnelTestReceiverConfig(port net.Port, stream *internet.StreamConfig) *proxyman.ReceiverConfig {
	return &proxyman.ReceiverConfig{
		PortList:       &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
		Listen:         net.NewIPOrDomain(net.LocalHostIP),
		StreamSettings: stream,
	}
}

func trustTunnelTestInboundConfig(port net.Port, users ...*protocol.User) *core.InboundHandlerConfig {
	return trustTunnelTestInboundConfigWithStream(port, nil, users...)
}

func trustTunnelTestInboundConfigWithStream(port net.Port, stream *internet.StreamConfig, users ...*protocol.User) *core.InboundHandlerConfig {
	return trustTunnelTestInboundConfigWithStreamAndTransports(port, stream, []trusttunnel.TransportProtocol{trusttunnel.TransportProtocol_HTTP2}, users...)
}

func trustTunnelTestInboundConfigWithStreamAndTransports(port net.Port, stream *internet.StreamConfig, transports []trusttunnel.TransportProtocol, users ...*protocol.User) *core.InboundHandlerConfig {
	if len(transports) == 0 {
		transports = []trusttunnel.TransportProtocol{trusttunnel.TransportProtocol_HTTP2}
	}
	return &core.InboundHandlerConfig{
		Tag:              "tt",
		ReceiverSettings: serial.ToTypedMessage(trustTunnelTestReceiverConfig(port, stream)),
		ProxySettings: serial.ToTypedMessage(&trusttunnel.ServerConfig{
			Users:      users,
			Transports: transports,
		}),
	}
}

func trustTunnelTestTLSStreamConfig(cfg *ttls.Config) *internet.StreamConfig {
	return &internet.StreamConfig{
		SecurityType: serial.GetMessageType(&ttls.Config{}),
		SecuritySettings: []*serial.TypedMessage{
			serial.ToTypedMessage(cfg),
		},
	}
}

type trustTunnelScenarioH2Tunnel struct {
	rawConn  stdnet.Conn
	reqBody  *io.PipeWriter
	respBody io.ReadCloser
}

type trustTunnelScenarioH3Tunnel struct {
	conn   *quic.Conn
	stream *http3.RequestStream
}

func (t *trustTunnelScenarioH2Tunnel) Read(p []byte) (int, error) {
	return t.respBody.Read(p)
}

func (t *trustTunnelScenarioH2Tunnel) Write(p []byte) (int, error) {
	return t.reqBody.Write(p)
}

func (t *trustTunnelScenarioH2Tunnel) Close() error {
	if t.reqBody != nil {
		_ = t.reqBody.Close()
	}
	if t.respBody != nil {
		_ = t.respBody.Close()
	}
	if t.rawConn != nil {
		return t.rawConn.Close()
	}
	return nil
}

func (t *trustTunnelScenarioH3Tunnel) Close() error {
	if t.stream != nil {
		t.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		t.stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		_ = t.stream.Close()
	}
	if t.conn != nil {
		return t.conn.CloseWithError(0, "")
	}
	return nil
}

func trustTunnelScenarioOpenH2Tunnel(serverPort net.Port, target string, username string, password string) (*trustTunnelScenarioH2Tunnel, int, error) {
	rawConn, err := gotls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), &gotls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	})
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequest(http.MethodConnect, "http://"+target, nil)
	if err != nil {
		_ = rawConn.Close()
		return nil, 0, err
	}
	req.Host = target
	req.Header.Set("Host", target)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))

	pr, pw := io.Pipe()
	req.Body = pr

	h2Transport := http2.Transport{}
	h2Conn, err := h2Transport.NewClientConn(rawConn)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = rawConn.Close()
		return nil, 0, err
	}

	resp, err := h2Conn.RoundTrip(req)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = rawConn.Close()
		return nil, 0, err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		_ = rawConn.Close()
		return nil, resp.StatusCode, fmt.Errorf("status=%d body=%s", resp.StatusCode, string(body))
	}

	return &trustTunnelScenarioH2Tunnel{
		rawConn:  rawConn,
		reqBody:  pw,
		respBody: resp.Body,
	}, resp.StatusCode, nil
}

func trustTunnelScenarioOpenH3Tunnel(serverPort net.Port, target string, username string, password string) (*trustTunnelScenarioH3Tunnel, int, error) {
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	tlsCfg := &gotls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	transport := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig:      &quic.Config{},
	}
	conn, err := quic.DialAddr(context.Background(), serverAddr, tlsCfg, transport.QUICConfig)
	if err != nil {
		return nil, 0, err
	}

	clientConn := transport.NewClientConn(conn)
	stream, err := clientConn.OpenRequestStream(context.Background())
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, 0, err
	}

	req, err := http.NewRequest(http.MethodConnect, "https://"+serverAddr, nil)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		_ = conn.CloseWithError(0, "")
		return nil, 0, err
	}
	req.Host = target
	req.Header.Set("Host", target)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))

	if err := stream.SendRequestHeader(req); err != nil {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		_ = conn.CloseWithError(0, "")
		return nil, 0, err
	}

	resp, err := stream.ReadResponse()
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, 0, err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		_ = conn.CloseWithError(0, "")
		return nil, resp.StatusCode, fmt.Errorf("status=%d body=%s", resp.StatusCode, string(body))
	}

	return &trustTunnelScenarioH3Tunnel{
		conn:   conn,
		stream: stream,
	}, resp.StatusCode, nil
}

func trustTunnelScenarioH3ConnectStatus(serverPort net.Port, target string, username string, password string) (int, error) {
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	tlsCfg := &gotls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	transport := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig:      &quic.Config{},
	}
	defer transport.Close()

	req, err := http.NewRequest(http.MethodConnect, "https://"+serverAddr, nil)
	if err != nil {
		return 0, err
	}
	req.Host = target
	req.Header.Set("Host", target)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))

	resp, err := transport.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}

func TestTrustTunnelCommanderAddRemoveUser(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	cmdPort := tcp.PickPort()
	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()

	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&commander.Config{
				Tag: "api",
				Service: []*serial.TypedMessage{
					serial.ToTypedMessage(&command.Config{}),
				},
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{
						InboundTag: []string{"api"},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "api",
						},
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfig(serverPort),
			{
				Tag: "api",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(cmdPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
		},
	}

	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "d",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(trustTunnelTestOutbound(serverPort, "tt-user", "tt-pass")),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err == nil {
		t.Fatal("expected auth failure before AddUser")
	}

	cmdConn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", cmdPort), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	common.Must(err)
	defer cmdConn.Close()

	hsClient := command.NewHandlerServiceClient(cmdConn)
	if _, err := hsClient.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag: "tt",
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass"),
		}),
	}); err != nil {
		t.Fatalf("AddUser failed: %v", err)
	}

	countResp, err := hsClient.GetInboundUsersCount(context.Background(), &command.GetInboundUserRequest{Tag: "tt"})
	common.Must(err)
	if countResp.GetCount() != 1 {
		t.Fatalf("GetInboundUsersCount() = %d, want 1", countResp.GetCount())
	}

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err != nil {
		t.Fatalf("traffic after AddUser failed: %v", err)
	}

	if _, err := hsClient.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag:       "tt",
		Operation: serial.ToTypedMessage(&command.RemoveUserOperation{Email: "tt@example.com"}),
	}); err != nil {
		t.Fatalf("RemoveUser failed: %v", err)
	}

	countResp, err = hsClient.GetInboundUsersCount(context.Background(), &command.GetInboundUserRequest{Tag: "tt"})
	common.Must(err)
	if countResp.GetCount() != 0 {
		t.Fatalf("GetInboundUsersCount() = %d, want 0", countResp.GetCount())
	}

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err == nil {
		t.Fatal("expected auth failure after RemoveUser")
	}
}

func TestTrustTunnelOutboundHTTP3FallsBackToHTTP2TLS(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverCert, serverHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfigWithStream(
				serverPort,
				trustTunnelTestTLSStreamConfig(&ttls.Config{
					Certificate: []*ttls.Certificate{ttls.ParseCertificate(serverCert)},
				}),
				trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass"),
			),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	}

	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: trustTunnelTestTLSStreamConfig(&ttls.Config{
						ServerName:           "localhost",
						PinnedPeerCertSha256: [][]byte{serverHash[:]},
					}),
				}),
				ProxySettings: serial.ToTypedMessage(&trusttunnel.ClientConfig{
					Server:           trustTunnelTestServerEndpoint(serverPort, "tt-user", "tt-pass"),
					Hostname:         "localhost",
					Transport:        trusttunnel.TransportProtocol_HTTP3,
					HasIpv6:          true,
					SkipVerification: true,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err != nil {
		t.Fatalf("traffic with http3->http2 fallback failed: %v", err)
	}
}

func TestTrustTunnelInboundConnectionLimitHTTP2(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverCert, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverPort := tcp.PickPort()

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfigWithStream(
				serverPort,
				trustTunnelTestTLSStreamConfig(&ttls.Config{
					Certificate: []*ttls.Certificate{ttls.ParseCertificate(serverCert)},
				}),
				trustTunnelTestServerUserWithLimits("tt@example.com", "tt-user", "tt-pass", 1, 0),
			),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	tunnel1, status, err := trustTunnelScenarioOpenH2Tunnel(serverPort, dest.NetAddr(), "tt-user", "tt-pass")
	if err != nil {
		t.Fatalf("failed to open first H2 tunnel: status=%d err=%v", status, err)
	}
	defer tunnel1.Close()

	payload := make([]byte, 256)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("failed to generate payload: %v", err)
	}
	if _, err := tunnel1.Write(payload); err != nil {
		t.Fatalf("failed to write first tunnel payload: %v", err)
	}
	_ = tunnel1.rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(tunnel1, reply); err != nil {
		t.Fatalf("failed to read first tunnel reply: %v", err)
	}
	_ = tunnel1.rawConn.SetReadDeadline(time.Time{})
	if !bytes.Equal(reply, xor(payload)) {
		t.Fatalf("first tunnel reply mismatch")
	}

	time.Sleep(200 * time.Millisecond)

	tunnel2, status, err := trustTunnelScenarioOpenH2Tunnel(serverPort, dest.NetAddr(), "tt-user", "tt-pass")
	if err == nil {
		tunnel2.Close()
		t.Fatal("expected second H2 tunnel to be rejected while first slot is held")
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("second tunnel status = %d, want %d (err=%v)", status, http.StatusTooManyRequests, err)
	}

	tunnel1.Close()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		tunnel3, status, err := trustTunnelScenarioOpenH2Tunnel(serverPort, dest.NetAddr(), "tt-user", "tt-pass")
		if err == nil {
			tunnel3.Close()
			return
		}
		lastErr = fmt.Errorf("status=%d err=%w", status, err)
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("third tunnel after release failed: %v", lastErr)
}

func TestTrustTunnelInboundConnectionLimitHTTP3(t *testing.T) {
	targetListener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer targetListener.Close()

	targetAccepts := make(chan stdnet.Conn, 8)
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			targetAccepts <- conn
		}
	}()
	defer func() {
		_ = targetListener.Close()
		for {
			select {
			case conn := <-targetAccepts:
				if conn != nil {
					_ = conn.Close()
				}
			default:
				select {
				case <-targetDone:
					return
				default:
					return
				}
			}
		}
	}()

	serverCert, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverPort := tcp.PickPort()

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfigWithStreamAndTransports(
				serverPort,
				trustTunnelTestTLSStreamConfig(&ttls.Config{
					Certificate:  []*ttls.Certificate{ttls.ParseCertificate(serverCert)},
					NextProtocol: []string{"h3"},
				}),
				[]trusttunnel.TransportProtocol{trusttunnel.TransportProtocol_HTTP3},
				trustTunnelTestServerUserWithLimits("tt@example.com", "tt-user", "tt-pass", 0, 1),
			),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	targetAddr := targetListener.Addr().String()
	tunnel1, status, err := trustTunnelScenarioOpenH3Tunnel(serverPort, targetAddr, "tt-user", "tt-pass")
	if err != nil {
		t.Fatalf("failed to open first H3 tunnel: status=%d err=%v", status, err)
	}
	defer tunnel1.Close()

	var upstreamConns []stdnet.Conn
	waitAccepts := func(want int, timeout time.Duration) error {
		deadline := time.NewTimer(timeout)
		defer deadline.Stop()
		for len(upstreamConns) < want {
			select {
			case conn := <-targetAccepts:
				upstreamConns = append(upstreamConns, conn)
			case <-deadline.C:
				return fmt.Errorf("accepted=%d want=%d", len(upstreamConns), want)
			}
		}
		return nil
	}

	if err := waitAccepts(1, 5*time.Second); err != nil {
		t.Fatalf("first H3 tunnel did not open upstream target connection: %v", err)
	}

	_, _ = trustTunnelScenarioH3ConnectStatus(serverPort, targetAddr, "tt-user", "tt-pass")
	time.Sleep(300 * time.Millisecond)
	if len(upstreamConns) != 1 {
		t.Fatalf("second H3 tunnel unexpectedly opened extra upstream connections: got %d, want 1", len(upstreamConns))
	}

	tunnel1.Close()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		tunnel3, status, err := trustTunnelScenarioOpenH3Tunnel(serverPort, targetAddr, "tt-user", "tt-pass")
		if err == nil {
			defer tunnel3.Close()
			if waitErr := waitAccepts(2, 2*time.Second); waitErr != nil {
				t.Fatalf("third H3 tunnel opened but upstream target connection count did not increase: %v", waitErr)
			}
			_ = tunnel3.Close()
			return
		}
		lastErr = fmt.Errorf("status=%d err=%w", status, err)
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("third H3 tunnel after release failed: %v", lastErr)
}

func TestTrustTunnelOutboundAutoFallsBackToHTTP2TLS(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverCert, serverHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfigWithStream(
				serverPort,
				trustTunnelTestTLSStreamConfig(&ttls.Config{
					Certificate: []*ttls.Certificate{ttls.ParseCertificate(serverCert)},
				}),
				trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass"),
			),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	}

	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: trustTunnelTestTLSStreamConfig(&ttls.Config{
						ServerName:           "localhost",
						PinnedPeerCertSha256: [][]byte{serverHash[:]},
					}),
				}),
				ProxySettings: serial.ToTypedMessage(&trusttunnel.ClientConfig{
					Server:           trustTunnelTestServerEndpoint(serverPort, "tt-user", "tt-pass"),
					Hostname:         "localhost",
					Transport:        trusttunnel.TransportProtocol_AUTO,
					HasIpv6:          true,
					SkipVerification: true,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err != nil {
		t.Fatalf("traffic with auto->http2 fallback failed: %v", err)
	}
}

func TestTrustTunnelOutboundFallsBackToNextConfiguredServerTLS(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverCert, serverHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	deadServerPort := tcp.PickPort()
	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfigWithStream(
				serverPort,
				trustTunnelTestTLSStreamConfig(&ttls.Config{
					Certificate: []*ttls.Certificate{ttls.ParseCertificate(serverCert)},
				}),
				trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass"),
			),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	}

	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: trustTunnelTestTLSStreamConfig(&ttls.Config{
						ServerName:           "localhost",
						PinnedPeerCertSha256: [][]byte{serverHash[:]},
					}),
				}),
				ProxySettings: serial.ToTypedMessage(&trusttunnel.ClientConfig{
					Server:           trustTunnelTestServerEndpoint(deadServerPort, "tt-user", "tt-pass"),
					Servers:          []*protocol.ServerEndpoint{trustTunnelTestServerEndpoint(deadServerPort, "tt-user", "tt-pass"), trustTunnelTestServerEndpoint(serverPort, "tt-user", "tt-pass")},
					Hostname:         "localhost",
					Transport:        trusttunnel.TransportProtocol_HTTP2,
					HasIpv6:          true,
					SkipVerification: true,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err != nil {
		t.Fatalf("traffic with next-server fallback failed: %v", err)
	}
}

func TestTrustTunnelOutboundProxySettings(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := tcp.PickPort()
	proxyPort := tcp.PickPort()
	clientPort := tcp.PickPort()
	proxyUserID := protocol.NewID(uuid.New())

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfig(serverPort, trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass")),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
		},
	}

	proxyConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(proxyPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					User: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id: proxyUserID.String(),
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
		},
	}

	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "tt-out",
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					ProxySettings: &internet.ProxyConfig{Tag: "proxy"},
				}),
				ProxySettings: serial.ToTypedMessage(trustTunnelTestOutbound(serverPort, "tt-user", "tt-pass")),
			},
			{
				Tag: "proxy",
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Receiver: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(proxyPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id: proxyUserID.String(),
							}),
						},
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, proxyConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err != nil {
		t.Fatalf("traffic through proxySettings failed: %v", err)
	}
}

func TestTrustTunnelOutboundMux(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfig(serverPort, trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass")),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
		},
	}

	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					MultiplexSettings: &proxyman.MultiplexingConfig{
						Enabled:     true,
						Concurrency: 8,
					},
				}),
				ProxySettings: serial.ToTypedMessage(trustTunnelTestOutbound(serverPort, "tt-user", "tt-pass")),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	var wg sync.WaitGroup
	errCh := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := testTCPConn(clientPort, 8*1024, 5*time.Second)(); err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("mux traffic failed: %v", err)
	}
}

func TestTrustTunnelOutboundSendThroughOrigin(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()
	logPath := filepath.Join(t.TempDir(), "trusttunnel-sendthrough-origin.log")

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfig(serverPort, trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass")),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
		},
	}

	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_File,
				ErrorLogPath:  logPath,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					Via: net.NewIPOrDomain(net.DomainAddress("origin")),
				}),
				ProxySettings: serial.ToTypedMessage(trustTunnelTestOutbound(serverPort, "tt-user", "tt-pass")),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err != nil {
		t.Fatalf("traffic through sendThrough=origin failed: %v", err)
	}

	if err := waitForFileContains(logPath, "use inbound local ip as sendthrough: 127.0.0.1", 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestTrustTunnelOutboundTargetStrategyUseIPv4(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfig(serverPort, trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass")),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
		},
	}

	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(net.DomainAddress("localhost")),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					TargetStrategy: internet.DomainStrategy_USE_IP4,
				}),
				ProxySettings: serial.ToTypedMessage(&trusttunnel.ClientConfig{
					Server:           trustTunnelTestServerEndpoint(serverPort, "tt-user", "tt-pass"),
					Hostname:         "localhost",
					Transport:        trusttunnel.TransportProtocol_HTTP2,
					HasIpv6:          false,
					SkipVerification: true,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err != nil {
		t.Fatalf("traffic with targetStrategy=useipv4 and hasIpv6=false failed: %v", err)
	}
}

func TestTrustTunnelInboundSniffingRouteOnly(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "sniffed-ok")
	}))
	defer tlsServer.Close()

	host, portText, err := stdnet.SplitHostPort(tlsServer.Listener.Addr().String())
	common.Must(err)
	destPort, err := stdnet.LookupPort("tcp", portText)
	common.Must(err)

	serverPort := tcp.PickPort()
	proxyPort := tcp.PickPort()

	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{
						InboundTag: []string{"tt"},
						Domain: []*router.Domain{
							{
								Type:  router.Domain_Full,
								Value: "sniffed.test",
							},
						},
						TargetTag: &router.RoutingRule_Tag{Tag: "direct"},
					},
					{
						InboundTag: []string{"tt"},
						TargetTag:  &router.RoutingRule_Tag{Tag: "blocked"},
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "tt",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
					SniffingSettings: &proxyman.SniffingConfig{
						Enabled:             true,
						DestinationOverride: []string{"tls"},
						RouteOnly:           true,
					},
				}),
				ProxySettings: serial.ToTypedMessage(&trusttunnel.ServerConfig{
					Users: []*protocol.User{
						trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass"),
					},
					Transports: []trusttunnel.TransportProtocol{trusttunnel.TransportProtocol_HTTP2},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag:           "direct",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
			{
				Tag:           "blocked",
				ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
			},
		},
	}

	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(proxyPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&v2http.ServerConfig{}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(trustTunnelTestOutbound(serverPort, "tt-user", "tt-pass")),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	proxyURL, err := url.Parse("http://127.0.0.1:" + proxyPort.String())
	common.Must(err)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &gotls.Config{
				InsecureSkipVerify: true,
				ServerName:         "sniffed.test",
			},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s:%d/", host, destPort))
	if err != nil {
		t.Fatalf("sniffed request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "sniffed-ok" {
		t.Fatalf("body = %q, want %q", string(body), "sniffed-ok")
	}
}

func TestTrustTunnelOutboundTLSPinnedPeerCertSha256(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverCert, serverHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfigWithStream(
				serverPort,
				trustTunnelTestTLSStreamConfig(&ttls.Config{
					Certificate: []*ttls.Certificate{ttls.ParseCertificate(serverCert)},
				}),
				trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass"),
			),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	}

	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: trustTunnelTestTLSStreamConfig(&ttls.Config{
						PinnedPeerCertSha256: [][]byte{serverHash[:]},
					}),
				}),
				ProxySettings: serial.ToTypedMessage(&trusttunnel.ClientConfig{
					Server:           trustTunnelTestServerEndpoint(serverPort, "tt-user", "tt-pass"),
					Hostname:         "localhost",
					Transport:        trusttunnel.TransportProtocol_HTTP2,
					HasIpv6:          true,
					SkipVerification: true,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err != nil {
		t.Fatalf("traffic with pinnedPeerCertSha256 failed: %v", err)
	}
}

func TestTrustTunnelOutboundTLSPinnedPeerCertSha256WrongCert(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverCert, serverHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()
	badHash := append([]byte(nil), serverHash[:]...)
	badHash[0] ^= 0xff

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfigWithStream(
				serverPort,
				trustTunnelTestTLSStreamConfig(&ttls.Config{
					Certificate: []*ttls.Certificate{ttls.ParseCertificate(serverCert)},
				}),
				trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass"),
			),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	}

	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: trustTunnelTestTLSStreamConfig(&ttls.Config{
						PinnedPeerCertSha256: [][]byte{badHash},
					}),
				}),
				ProxySettings: serial.ToTypedMessage(&trusttunnel.ClientConfig{
					Server:           trustTunnelTestServerEndpoint(serverPort, "tt-user", "tt-pass"),
					Hostname:         "localhost",
					Transport:        trusttunnel.TransportProtocol_HTTP2,
					HasIpv6:          true,
					SkipVerification: true,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err == nil {
		t.Fatal("expected wrong pinnedPeerCertSha256 to fail")
	}
}

func TestTrustTunnelOutboundTLSServerNameAuthorityVerify(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	caCert, err := cert.Generate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment|x509.KeyUsageCertSign))
	common.Must(err)
	caCertPEM, caKeyPEM := caCert.ToPEM()

	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfigWithStream(
				serverPort,
				trustTunnelTestTLSStreamConfig(&ttls.Config{
					Certificate: []*ttls.Certificate{{
						Certificate: caCertPEM,
						Key:         caKeyPEM,
						Usage:       ttls.Certificate_AUTHORITY_ISSUE,
					}},
				}),
				trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass"),
			),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	}

	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: trustTunnelTestTLSStreamConfig(&ttls.Config{
						ServerName:        "example.com",
						DisableSystemRoot: true,
						Certificate: []*ttls.Certificate{{
							Certificate: caCertPEM,
							Usage:       ttls.Certificate_AUTHORITY_VERIFY,
						}},
					}),
				}),
				ProxySettings: serial.ToTypedMessage(&trusttunnel.ClientConfig{
					Server:           trustTunnelTestServerEndpoint(serverPort, "tt-user", "tt-pass"),
					Hostname:         "localhost",
					Transport:        trusttunnel.TransportProtocol_HTTP2,
					HasIpv6:          true,
					SkipVerification: true,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err != nil {
		t.Fatalf("traffic with generic serverName + authority verify failed: %v", err)
	}
}

func TestTrustTunnelOutboundTLSVerifyPeerCertByName(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	caCert, err := cert.Generate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment|x509.KeyUsageCertSign))
	common.Must(err)
	serverCert, err := cert.Generate(caCert, cert.CommonName("example.com"), cert.DNSNames("example.com"))
	common.Must(err)

	caCertPEM, _ := caCert.ToPEM()
	serverCertPEM, serverKeyPEM := serverCert.ToPEM()
	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfigWithStream(
				serverPort,
				trustTunnelTestTLSStreamConfig(&ttls.Config{
					Certificate: []*ttls.Certificate{{
						Certificate: bytes.Join([][]byte{serverCertPEM, caCertPEM}, []byte("\n")),
						Key:         serverKeyPEM,
					}},
				}),
				trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass"),
			),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	}

	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: trustTunnelTestTLSStreamConfig(&ttls.Config{
						VerifyPeerCertByName: []string{"example.com"},
						DisableSystemRoot:    true,
						Certificate: []*ttls.Certificate{{
							Certificate: caCertPEM,
							Usage:       ttls.Certificate_AUTHORITY_VERIFY,
						}},
					}),
				}),
				ProxySettings: serial.ToTypedMessage(&trusttunnel.ClientConfig{
					Server:           trustTunnelTestServerEndpoint(serverPort, "tt-user", "tt-pass"),
					Hostname:         "localhost",
					Transport:        trusttunnel.TransportProtocol_HTTP2,
					HasIpv6:          true,
					SkipVerification: true,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err != nil {
		t.Fatalf("traffic with verifyPeerCertByName failed: %v", err)
	}
}

func TestTrustTunnelOutboundTLSFingerprintPinnedPeerCert(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverCert, serverHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfigWithStream(
				serverPort,
				trustTunnelTestTLSStreamConfig(&ttls.Config{
					Certificate: []*ttls.Certificate{ttls.ParseCertificate(serverCert)},
				}),
				trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass"),
			),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	}

	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(dest.Address),
					Port:     uint32(dest.Port),
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: trustTunnelTestTLSStreamConfig(&ttls.Config{
						Fingerprint:          "random",
						PinnedPeerCertSha256: [][]byte{serverHash[:]},
					}),
				}),
				ProxySettings: serial.ToTypedMessage(&trusttunnel.ClientConfig{
					Server:           trustTunnelTestServerEndpoint(serverPort, "tt-user", "tt-pass"),
					Hostname:         "localhost",
					Transport:        trusttunnel.TransportProtocol_HTTP2,
					HasIpv6:          true,
					SkipVerification: true,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, 5*time.Second)(); err != nil {
		t.Fatalf("traffic with generic fingerprint + pinning failed: %v", err)
	}
}

func TestTrustTunnelInboundRejectUnknownSNI(t *testing.T) {
	tcpServer := tcp.Server{MsgProcessor: xor}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverCert, serverHash := cert.MustGenerate(nil, cert.CommonName("allowed.test"), cert.DNSNames("allowed.test"))
	serverPort := tcp.PickPort()
	goodClientPort := tcp.PickPort()
	badClientPort := tcp.PickPort()

	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			trustTunnelTestInboundConfigWithStream(
				serverPort,
				trustTunnelTestTLSStreamConfig(&ttls.Config{
					RejectUnknownSni: true,
					Certificate: []*ttls.Certificate{
						ttls.ParseCertificate(serverCert),
					},
				}),
				trustTunnelTestServerUser("tt@example.com", "tt-user", "tt-pass"),
			),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
		},
	}

	buildClientConfig := func(port net.Port, serverName string) *core.Config {
		return &core.Config{
			Inbound: []*core.InboundHandlerConfig{
				{
					ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
						PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
						Listen:   net.NewIPOrDomain(net.LocalHostIP),
					}),
					ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
						Address:  net.NewIPOrDomain(dest.Address),
						Port:     uint32(dest.Port),
						Networks: []net.Network{net.Network_TCP},
					}),
				},
			},
			Outbound: []*core.OutboundHandlerConfig{
				{
					SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
						StreamSettings: trustTunnelTestTLSStreamConfig(&ttls.Config{
							ServerName:           serverName,
							PinnedPeerCertSha256: [][]byte{serverHash[:]},
						}),
					}),
					ProxySettings: serial.ToTypedMessage(&trusttunnel.ClientConfig{
						Server:           trustTunnelTestServerEndpoint(serverPort, "tt-user", "tt-pass"),
						Hostname:         "localhost",
						Transport:        trusttunnel.TransportProtocol_HTTP2,
						HasIpv6:          true,
						SkipVerification: true,
					}),
				},
			},
		}
	}

	servers, err := InitializeServerConfigs(serverConfig, buildClientConfig(goodClientPort, "allowed.test"), buildClientConfig(badClientPort, "wrong.test"))
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(goodClientPort, 1024, 5*time.Second)(); err != nil {
		t.Fatalf("traffic with allowed SNI failed: %v", err)
	}

	if err := testTCPConn(badClientPort, 1024, 5*time.Second)(); err == nil {
		t.Fatal("expected rejectUnknownSni to reject wrong SNI")
	}
}

func waitForFileContains(path, marker string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		content, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(content), marker) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s while waiting for marker %q: %w", path, marker, err)
	}
	return fmt.Errorf("log %s does not contain marker %q; content: %s", path, marker, string(content))
}
