package conf

import (
	"os"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/trusttunnel"
	"google.golang.org/protobuf/proto"
)

func init() {
	if err := inboundConfigLoader.cache.RegisterCreator("trusttunnel", func() interface{} {
		return new(TrustTunnelServerConfig)
	}); err != nil {
		panic(err)
	}

	if err := outboundConfigLoader.cache.RegisterCreator("trusttunnel", func() interface{} {
		return new(TrustTunnelClientConfig)
	}); err != nil {
		panic(err)
	}
}

type TrustTunnelEndpointConfig struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
}

type TrustTunnelClientConfig struct {
	Address            *Address                     `json:"address"`
	Port               uint16                       `json:"port"`
	Level              byte                         `json:"level"`
	Email              string                       `json:"email"`
	Username           string                       `json:"username"`
	Password           string                       `json:"password"`
	Servers            []*TrustTunnelEndpointConfig `json:"servers"`
	Hostname           string                       `json:"hostname"`
	Transport          string                       `json:"transport"`
	HasIPv6            bool                         `json:"hasIpv6"`
	SkipVerification   bool                         `json:"skipVerification"`
	CertificatePEM     string                       `json:"certificatePem"`
	CertificatePEMFile string                       `json:"certificatePemFile"`
	ClientRandom       string                       `json:"clientRandom"`
	AntiDpi            bool                         `json:"antiDpi"`
	PostQuantumGroup   *bool                        `json:"postQuantumGroupEnabled"`
	UDP                bool                         `json:"udp"`
}

func parseTrustTunnelTransport(v string) (trusttunnel.TransportProtocol, error) {
	switch strings.ToLower(v) {
	case "", "http2":
		return trusttunnel.TransportProtocol_HTTP2, nil
	case "auto":
		return trusttunnel.TransportProtocol_AUTO, nil
	case "http3", "quic", "http3/quic":
		return trusttunnel.TransportProtocol_HTTP3, nil
	default:
		return trusttunnel.TransportProtocol_HTTP2, errors.New("unsupported trusttunnel transport: ", v)
	}
}

func (c *TrustTunnelClientConfig) Build() (proto.Message, error) {
	if c.Address != nil {
		if len(c.Servers) > 0 {
			return nil, errors.New(`TrustTunnel settings: use either "address"/"port" or "servers", not both`)
		}
		c.Servers = []*TrustTunnelEndpointConfig{
			{
				Address: c.Address,
				Port:    c.Port,
			},
		}
	}

	if len(c.Servers) == 0 {
		return nil, errors.New(`TrustTunnel settings: "servers" must contain at least one member`)
	}
	if c.Username == "" {
		return nil, errors.New("TrustTunnel username is not specified")
	}
	if c.Password == "" {
		return nil, errors.New("TrustTunnel password is not specified")
	}
	if c.Hostname == "" {
		return nil, errors.New("TrustTunnel hostname is not specified")
	}

	transport, err := parseTrustTunnelTransport(c.Transport)
	if err != nil {
		return nil, err
	}

	certificatePEM := c.CertificatePEM
	if certificatePEM == "" && c.CertificatePEMFile != "" {
		raw, err := os.ReadFile(c.CertificatePEMFile)
		if err != nil {
			return nil, errors.New("failed to read certificatePemFile").Base(err)
		}
		certificatePEM = string(raw)
	}

	config := &trusttunnel.ClientConfig{
		Hostname:         c.Hostname,
		Transport:        transport,
		HasIpv6:          c.HasIPv6,
		SkipVerification: c.SkipVerification,
		CertificatePem:   certificatePEM,
		ClientRandom:     c.ClientRandom,
		AntiDpi:          c.AntiDpi,
		EnableUdp:        c.UDP,
		Servers:          make([]*protocol.ServerEndpoint, 0, len(c.Servers)),
	}

	for _, rec := range c.Servers {
		if rec == nil || rec.Address == nil {
			return nil, errors.New("TrustTunnel server address is not set")
		}
		if rec.Port == 0 {
			return nil, errors.New("Invalid TrustTunnel port")
		}

		endpoint := &protocol.ServerEndpoint{
			Address: rec.Address.Build(),
			Port:    uint32(rec.Port),
			User: &protocol.User{
				Level: uint32(c.Level),
				Email: c.Email,
				Account: serial.ToTypedMessage(&trusttunnel.Account{
					Username: c.Username,
					Password: c.Password,
				}),
			},
		}

		if config.Server == nil {
			config.Server = endpoint
		}
		config.Servers = append(config.Servers, endpoint)
	}

	if c.PostQuantumGroup != nil {
		if *c.PostQuantumGroup {
			config.PostQuantumGroupEnabled = trusttunnel.PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_ENABLED
		} else {
			config.PostQuantumGroupEnabled = trusttunnel.PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_DISABLED
		}
	}

	return config, nil
}

type TrustTunnelUserConfig struct {
	Email         string `json:"email"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	Level         byte   `json:"level"`
	MaxHTTP2Conns uint32 `json:"maxHttp2Conns"`
	MaxHTTP3Conns uint32 `json:"maxHttp3Conns"`
}

type TrustTunnelHostConfig struct {
	Hostname        string `json:"hostname"`
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
}

type TrustTunnelRuleConfig struct {
	CIDR         string `json:"cidr"`
	ClientRandom string `json:"clientRandom"`
	Allow        bool   `json:"allow"`
}

type TrustTunnelICMPConfig struct {
	InterfaceName            string `json:"interfaceName"`
	RequestTimeoutSecs       uint32 `json:"requestTimeoutSecs"`
	RecvMessageQueueCapacity uint32 `json:"recvMessageQueueCapacity"`
}

type TrustTunnelServerConfig struct {
	Users                              []*TrustTunnelUserConfig `json:"users"`
	Hosts                              []*TrustTunnelHostConfig `json:"hosts"`
	Transports                         []string                 `json:"transports"`
	Rules                              []*TrustTunnelRuleConfig `json:"rules"`
	IPv6Available                      bool                     `json:"ipv6Available"`
	AllowPrivateNetworkConnections     bool                     `json:"allowPrivateNetworkConnections"`
	AuthFailureStatusCode              uint32                   `json:"authFailureStatusCode"`
	TLSHandshakeTimeoutSecs            uint32                   `json:"tlsHandshakeTimeoutSecs"`
	ClientListenerTimeoutSecs          uint32                   `json:"clientListenerTimeoutSecs"`
	ConnectionEstablishmentTimeoutSecs uint32                   `json:"connectionEstablishmentTimeoutSecs"`
	TCPConnectionsTimeoutSecs          uint32                   `json:"tcpConnectionsTimeoutSecs"`
	UDPConnectionsTimeoutSecs          uint32                   `json:"udpConnectionsTimeoutSecs"`
	DefaultMaxHTTP2ConnsPerClient      uint32                   `json:"defaultMaxHttp2ConnsPerClient"`
	DefaultMaxHTTP3ConnsPerClient      uint32                   `json:"defaultMaxHttp3ConnsPerClient"`
	UDP                                bool                     `json:"udp"`
	ICMP                               *TrustTunnelICMPConfig   `json:"icmp"`
}

func (c *TrustTunnelServerConfig) Build() (proto.Message, error) {
	config := &trusttunnel.ServerConfig{
		Users:                              make([]*protocol.User, 0, len(c.Users)),
		Hosts:                              make([]*trusttunnel.ServerHost, 0, len(c.Hosts)),
		Transports:                         make([]trusttunnel.TransportProtocol, 0, len(c.Transports)),
		Rules:                              make([]*trusttunnel.Rule, 0, len(c.Rules)),
		Ipv6Available:                      c.IPv6Available,
		AllowPrivateNetworkConnections:     c.AllowPrivateNetworkConnections,
		AuthFailureStatusCode:              c.AuthFailureStatusCode,
		TlsHandshakeTimeoutSecs:            c.TLSHandshakeTimeoutSecs,
		ClientListenerTimeoutSecs:          c.ClientListenerTimeoutSecs,
		ConnectionEstablishmentTimeoutSecs: c.ConnectionEstablishmentTimeoutSecs,
		TcpConnectionsTimeoutSecs:          c.TCPConnectionsTimeoutSecs,
		UdpConnectionsTimeoutSecs:          c.UDPConnectionsTimeoutSecs,
		DefaultMaxHttp2ConnsPerClient:      c.DefaultMaxHTTP2ConnsPerClient,
		DefaultMaxHttp3ConnsPerClient:      c.DefaultMaxHTTP3ConnsPerClient,
		EnableUdp:                          c.UDP,
	}

	if c.ICMP != nil {
		config.IcmpInterfaceName = c.ICMP.InterfaceName
		config.IcmpRequestTimeoutSecs = c.ICMP.RequestTimeoutSecs
		config.IcmpRecvMessageQueueCapacity = c.ICMP.RecvMessageQueueCapacity
	}

	for _, u := range c.Users {
		if u.Username == "" {
			return nil, errors.New("TrustTunnel user.username is empty")
		}
		if u.Password == "" {
			return nil, errors.New("TrustTunnel user.password is empty")
		}

		config.Users = append(config.Users, &protocol.User{
			Level: uint32(u.Level),
			Email: u.Email,
			Account: serial.ToTypedMessage(&trusttunnel.Account{
				Username:      u.Username,
				Password:      u.Password,
				MaxHttp2Conns: u.MaxHTTP2Conns,
				MaxHttp3Conns: u.MaxHTTP3Conns,
			}),
		})
	}

	for _, h := range c.Hosts {
		if h.Hostname == "" {
			return nil, errors.New("TrustTunnel host.hostname is empty")
		}
		if h.CertificateFile == "" {
			return nil, errors.New("TrustTunnel host.certificateFile is empty")
		}
		if h.KeyFile == "" {
			return nil, errors.New("TrustTunnel host.keyFile is empty")
		}

		config.Hosts = append(config.Hosts, &trusttunnel.ServerHost{
			Hostname:        h.Hostname,
			CertificatePath: h.CertificateFile,
			KeyPath:         h.KeyFile,
		})
	}

	if len(c.Transports) == 0 {
		c.Transports = []string{"http2"}
	}

	for _, t := range c.Transports {
		transport, err := parseTrustTunnelTransport(t)
		if err != nil {
			return nil, err
		}
		config.Transports = append(config.Transports, transport)
	}

	for _, r := range c.Rules {
		config.Rules = append(config.Rules, &trusttunnel.Rule{
			Cidr:         r.CIDR,
			ClientRandom: r.ClientRandom,
			Allow:        r.Allow,
		})
	}

	if config.AuthFailureStatusCode == 0 {
		config.AuthFailureStatusCode = 407
	}

	return config, nil
}
