package conf

import (
	"encoding/json"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/trusttunnel"
)

func init() {
	RegisterConfigureFilePostProcessingStage("TrustTunnel", &TrustTunnelPostProcessingStage{})
}

type TrustTunnelPostProcessingStage struct{}

func (TrustTunnelPostProcessingStage) Process(conf *Config) error {
	for _, inbound := range conf.InboundConfigs {
		if !strings.EqualFold(inbound.Protocol, "trusttunnel") {
			continue
		}
		if err := validateTrustTunnelInboundConfig(inbound); err != nil {
			return err
		}
	}

	for _, outbound := range conf.OutboundConfigs {
		if !strings.EqualFold(outbound.Protocol, "trusttunnel") {
			continue
		}
		if err := validateTrustTunnelOutboundConfig(outbound); err != nil {
			return err
		}
	}

	return nil
}

func validateTrustTunnelInboundConfig(inbound InboundDetourConfig) error {
	settings := &TrustTunnelServerConfig{}
	if inbound.Settings != nil {
		if err := json.Unmarshal([]byte(*inbound.Settings), settings); err != nil {
			return errors.New("invalid TrustTunnel inbound settings").Base(err)
		}
	}

	if trustTunnelSecurityIsReality(inbound.StreamSetting) && trustTunnelServerSupportsHTTP3(settings) {
		return errors.New("trusttunnel http3 with REALITY is unsupported: current Xray REALITY transport is TCP-only").AtError()
	}

	return nil
}

func validateTrustTunnelOutboundConfig(outbound OutboundDetourConfig) error {
	settings := &TrustTunnelClientConfig{}
	if outbound.Settings != nil {
		if err := json.Unmarshal([]byte(*outbound.Settings), settings); err != nil {
			return errors.New("invalid TrustTunnel outbound settings").Base(err)
		}
	}

	transport, err := parseTrustTunnelTransport(settings.Transport)
	if err != nil {
		return err
	}

	if settings.AntiDpi {
		return errors.New("trusttunnel antiDpi is unsupported: current Xray transport layer has no compatible anti-DPI runtime").AtWarning()
	}

	if trustTunnelSecurityIsReality(outbound.StreamSetting) && transport == trusttunnel.TransportProtocol_HTTP3 {
		return errors.New("trusttunnel http3 with REALITY is unsupported: current Xray REALITY transport is TCP-only").AtError()
	}

	if settings.PostQuantumGroup != nil && transport != trusttunnel.TransportProtocol_HTTP3 && !trustTunnelSecuritySupportsPostQuantum(outbound.StreamSetting) {
		return errors.New("trusttunnel postQuantumGroupEnabled is unsupported: current outbound streamSettings have no TLS/REALITY security").AtWarning()
	}

	return nil
}

func trustTunnelServerSupportsHTTP3(settings *TrustTunnelServerConfig) bool {
	if settings == nil || len(settings.Transports) == 0 {
		return false
	}

	for _, transportName := range settings.Transports {
		transport, err := parseTrustTunnelTransport(transportName)
		if err != nil {
			continue
		}
		if transport == trusttunnel.TransportProtocol_HTTP3 {
			return true
		}
	}

	return false
}

func trustTunnelSecurityIsReality(stream *StreamConfig) bool {
	if stream == nil {
		return false
	}
	return strings.EqualFold(stream.Security, "reality")
}

func trustTunnelSecuritySupportsPostQuantum(stream *StreamConfig) bool {
	if stream == nil {
		return false
	}

	switch strings.ToLower(stream.Security) {
	case "tls", "reality":
		return true
	default:
		return false
	}
}
