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
	UDP                bool                         `json:"udp"`
}

func parseTrustTunnelTransport(v string) (trusttunnel.TransportProtocol, error) {
	switch strings.ToLower(v) {
	case "", "http2":
		return trusttunnel.TransportProtocol_HTTP2, nil
	case "http3", "quic", "http3/quic":
		return trusttunnel.TransportProtocol_HTTP3, nil
	default:
		return trusttunnel.TransportProtocol_HTTP2, errors.New("unsupported trusttunnel transport: ", v)
	}
}

func (c *TrustTunnelClientConfig) Build() (proto.Message, error) {
	if c.Address != nil {
		c.Servers = []*TrustTunnelEndpointConfig{
			{
				Address: c.Address,
				Port:    c.Port,
			},
		}
	}

	if len(c.Servers) != 1 {
		return nil, errors.New(`TrustTunnel settings: "servers" should have one and only one member`)
	}

	rec := c.Servers[0]
	if rec.Address == nil {
		return nil, errors.New("TrustTunnel server address is not set")
	}
	if rec.Port == 0 {
		return nil, errors.New("Invalid TrustTunnel port")
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
		Server: &protocol.ServerEndpoint{
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
		},
	}

	return config, nil
}

type TrustTunnelUserConfig struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
	Level    byte   `json:"level"`
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
	Users                          []*TrustTunnelUserConfig `json:"users"`
	Hosts                          []*TrustTunnelHostConfig `json:"hosts"`
	Transports                     []string                 `json:"transports"`
	Rules                          []*TrustTunnelRuleConfig `json:"rules"`
	IPv6Available                  bool                     `json:"ipv6Available"`
	AllowPrivateNetworkConnections bool                     `json:"allowPrivateNetworkConnections"`
	AuthFailureStatusCode          uint32                   `json:"authFailureStatusCode"`
	UDP                            bool                     `json:"udp"`
	ICMP                           *TrustTunnelICMPConfig   `json:"icmp"`
}

func (c *TrustTunnelServerConfig) Build() (proto.Message, error) {
	config := &trusttunnel.ServerConfig{
		Users:                          make([]*protocol.User, 0, len(c.Users)),
		Hosts:                          make([]*trusttunnel.ServerHost, 0, len(c.Hosts)),
		Transports:                     make([]trusttunnel.TransportProtocol, 0, len(c.Transports)),
		Rules:                          make([]*trusttunnel.Rule, 0, len(c.Rules)),
		Ipv6Available:                  c.IPv6Available,
		AllowPrivateNetworkConnections: c.AllowPrivateNetworkConnections,
		AuthFailureStatusCode:          c.AuthFailureStatusCode,
		EnableUdp:                      c.UDP,
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
				Username: u.Username,
				Password: u.Password,
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
