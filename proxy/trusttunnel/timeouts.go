package trusttunnel

import "time"

const (
	defaultTrustTunnelTLSHandshakeTimeout         = 10 * time.Second
	defaultTrustTunnelClientListenerTimeout       = 10 * time.Minute
	defaultTrustTunnelConnectionEstablishmentTime = 30 * time.Second
	defaultTrustTunnelTCPConnectionsTimeout       = 7 * 24 * time.Hour
	defaultTrustTunnelUDPConnectionsTimeout       = 5 * time.Minute
)

func trustTunnelTimeoutFromSeconds(seconds uint32, fallback time.Duration) time.Duration {
	if seconds == 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

func (c *ServerConfig) tlsHandshakeTimeout() time.Duration {
	return trustTunnelTimeoutFromSeconds(c.GetTlsHandshakeTimeoutSecs(), defaultTrustTunnelTLSHandshakeTimeout)
}

func (c *ServerConfig) clientListenerTimeout() time.Duration {
	return trustTunnelTimeoutFromSeconds(c.GetClientListenerTimeoutSecs(), defaultTrustTunnelClientListenerTimeout)
}

func (c *ServerConfig) connectionEstablishmentTimeout() time.Duration {
	return trustTunnelTimeoutFromSeconds(c.GetConnectionEstablishmentTimeoutSecs(), defaultTrustTunnelConnectionEstablishmentTime)
}

func (c *ServerConfig) tcpConnectionsTimeout() time.Duration {
	return trustTunnelTimeoutFromSeconds(c.GetTcpConnectionsTimeoutSecs(), defaultTrustTunnelTCPConnectionsTimeout)
}

func (c *ServerConfig) udpConnectionsTimeout() time.Duration {
	return trustTunnelTimeoutFromSeconds(c.GetUdpConnectionsTimeoutSecs(), defaultTrustTunnelUDPConnectionsTimeout)
}
