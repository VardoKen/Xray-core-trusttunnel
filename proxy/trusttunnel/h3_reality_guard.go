package trusttunnel

import (
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
)

type trustTunnelStreamSettingsProvider interface {
	StreamSettings() *internet.MemoryStreamConfig
}

func trustTunnelHTTP3RealityUnsupported(dialer internet.Dialer) bool {
	if dialer == nil {
		return false
	}
	provider, ok := dialer.(trustTunnelStreamSettingsProvider)
	if !ok {
		return false
	}
	return reality.ConfigFromStreamSettings(provider.StreamSettings()) != nil
}
