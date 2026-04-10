package conf

import (
	"encoding/json"
	"strconv"
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
		if transport == trusttunnel.TransportProtocol_HTTP3 {
			return errors.New("trusttunnel antiDpi is supported only for http2 over TLS or REALITY: http3 has no compatible QUIC anti-DPI runtime").AtWarning()
		}
		if outbound.StreamSetting == nil || (!strings.EqualFold(outbound.StreamSetting.Security, "tls") && !strings.EqualFold(outbound.StreamSetting.Security, "reality")) {
			return errors.New("trusttunnel antiDpi is supported only for http2 over TLS or REALITY: current outbound streamSettings have no compatible security").AtWarning()
		}
	}

	if trustTunnelSecurityIsReality(outbound.StreamSetting) && transport == trusttunnel.TransportProtocol_HTTP3 {
		return errors.New("trusttunnel http3 with REALITY is unsupported: current Xray REALITY transport is TCP-only").AtError()
	}

	if err := validateTrustTunnelOutboundTLSCompatibility(outbound.StreamSetting, settings, transport); err != nil {
		return err
	}

	if err := validateTrustTunnelOutboundMultipath(outbound.StreamSetting, settings, transport); err != nil {
		return err
	}

	if settings.PostQuantumGroup != nil && transport == trusttunnel.TransportProtocol_HTTP2 && !trustTunnelSecuritySupportsPostQuantum(outbound.StreamSetting) {
		return errors.New("trusttunnel postQuantumGroupEnabled is unsupported: current outbound streamSettings have no TLS/REALITY security").AtWarning()
	}

	return nil
}

func validateTrustTunnelOutboundMultipath(stream *StreamConfig, settings *TrustTunnelClientConfig, transport trusttunnel.TransportProtocol) error {
	if settings == nil || settings.Multipath == nil || !settings.Multipath.Enabled {
		return nil
	}

	multipath := settings.Multipath
	minChannels := multipath.MinChannels
	if minChannels == 0 {
		minChannels = 2
	}
	maxChannels := multipath.MaxChannels
	if maxChannels == 0 {
		maxChannels = minChannels
	}

	if minChannels < 2 {
		return errors.New("trusttunnel multipath requires multipath.minChannels >= 2").AtError()
	}
	if maxChannels < minChannels {
		return errors.New("trusttunnel multipath requires multipath.maxChannels >= multipath.minChannels").AtError()
	}
	if transport != trusttunnel.TransportProtocol_HTTP2 {
		return errors.New("trusttunnel multipath phase 1 supports only transport=http2").AtError()
	}
	if stream == nil || !strings.EqualFold(stream.Security, "tls") {
		return errors.New("trusttunnel multipath phase 1 supports only HTTP/2 over TLS").AtError()
	}
	if settings.UDP {
		return errors.New("trusttunnel multipath phase 1 is TCP-only and does not support udp=true").AtError()
	}
	if !trustTunnelConfigHasMultipathEndpointPool(settings) {
		return errors.New("trusttunnel multipath requires a multi-endpoint pool: use multiple servers entries or a domain-valued address that can resolve to multiple IPs").AtError()
	}
	if _, err := parseTrustTunnelMultipathScheduler(multipath.Scheduler); err != nil {
		return err
	}

	return nil
}

func validateTrustTunnelOutboundTLSCompatibility(stream *StreamConfig, settings *TrustTunnelClientConfig, transport trusttunnel.TransportProtocol) error {
	if settings == nil || stream == nil || stream.TLSSettings == nil || transport == trusttunnel.TransportProtocol_HTTP3 || !strings.EqualFold(stream.Security, "tls") {
		return nil
	}

	tlsSettings := stream.TLSSettings
	explicitVerifySurface := trustTunnelTLSSettingsHaveExplicitVerifySurface(tlsSettings)

	if settings.Hostname != "" && tlsSettings.ServerName != "" && !strings.EqualFold(settings.Hostname, tlsSettings.ServerName) {
		return errors.New("trusttunnel hostname conflicts with tlsSettings.serverName on non-HTTP3 path: generic tlsSettings are authoritative").AtError()
	}

	if settings.SkipVerification && explicitVerifySurface {
		return errors.New("trusttunnel skipVerification conflicts with generic tlsSettings verification surface on non-HTTP3 path; choose one authoritative verification source").AtError()
	}

	if settings.SkipVerification && (settings.CertificatePEM != "" || settings.CertificatePEMFile != "") {
		return errors.New("trusttunnel skipVerification conflicts with certificatePem/certificatePemFile on non-HTTP3 path; choose either insecure skip or certificate verification").AtError()
	}

	if (settings.CertificatePEM != "" || settings.CertificatePEMFile != "") && explicitVerifySurface {
		return errors.New("trusttunnel certificatePem/certificatePemFile conflicts with generic tlsSettings verification surface on non-HTTP3 path; choose one authoritative verification source").AtError()
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

func trustTunnelConfigHasMultipathEndpointPool(settings *TrustTunnelClientConfig) bool {
	if settings == nil {
		return false
	}

	endpoints := settings.Servers
	if len(endpoints) == 0 && settings.Address != nil {
		endpoints = []*TrustTunnelEndpointConfig{{
			Address: settings.Address,
			Port:    settings.Port,
		}}
	}

	if len(endpoints) == 0 {
		return false
	}
	if len(endpoints) == 1 {
		return trustTunnelEndpointIsDomain(endpoints[0])
	}

	seen := make(map[string]struct{}, len(endpoints))
	domainFound := false
	for _, endpoint := range endpoints {
		if endpoint == nil || endpoint.Address == nil || endpoint.Address.Address == nil {
			continue
		}
		if endpoint.Address.Family().IsDomain() {
			domainFound = true
			continue
		}
		key := endpoint.Address.String() + ":" + strconv.Itoa(int(endpoint.Port))
		seen[key] = struct{}{}
	}
	return domainFound || len(seen) >= 2
}

func trustTunnelEndpointIsDomain(endpoint *TrustTunnelEndpointConfig) bool {
	if endpoint == nil || endpoint.Address == nil || endpoint.Address.Address == nil {
		return false
	}
	return endpoint.Address.Family().IsDomain()
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

func trustTunnelTLSSettingsHaveExplicitVerifySurface(settings *TLSConfig) bool {
	if settings == nil {
		return false
	}

	if strings.TrimSpace(settings.PinnedPeerCertSha256) != "" || strings.TrimSpace(settings.VerifyPeerCertByName) != "" {
		return true
	}

	for _, cert := range settings.Certs {
		if cert != nil && strings.EqualFold(cert.Usage, "verify") {
			return true
		}
	}

	return false
}
