package scenarios

import (
	"context"
	gotls "crypto/tls"
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

	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
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

func trustTunnelTestInboundConfig(port net.Port, users ...*protocol.User) *core.InboundHandlerConfig {
	return &core.InboundHandlerConfig{
		Tag: "tt",
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
			Listen:   net.NewIPOrDomain(net.LocalHostIP),
		}),
		ProxySettings: serial.ToTypedMessage(&trusttunnel.ServerConfig{
			Users:      users,
			Transports: []trusttunnel.TransportProtocol{trusttunnel.TransportProtocol_HTTP2},
		}),
	}
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
