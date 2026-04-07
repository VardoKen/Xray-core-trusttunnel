package trusttunnel

import (
	"context"
	gotls "crypto/tls"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	xtlstls "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

const (
	trustTunnelPostQuantumChromeFingerprint       = "hellochrome_120"
	trustTunnelPostQuantumChromeFingerprintPQ     = "hellochrome_120_pq"
	trustTunnelPostQuantumDomainStrategyError     = "trusttunnel hasIpv6=false requires outbound targetStrategy useipv4/forceipv4 for domain targets"
	trustTunnelPostQuantumUnsupportedSecurityText = "trusttunnel postQuantumGroupEnabled is unsupported: current outbound streamSettings have no TLS/REALITY security"
)

func trustTunnelContextWithPostQuantumOverride(ctx context.Context, dialer internet.Dialer, cfg *ClientConfig) (context.Context, error) {
	mode := cfg.GetPostQuantumGroupEnabled()
	if mode == PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_AUTO {
		return ctx, nil
	}

	provider, ok := dialer.(trustTunnelStreamSettingsProvider)
	if !ok {
		return nil, errors.New(trustTunnelPostQuantumUnsupportedSecurityText).AtWarning()
	}

	override, err := trustTunnelStreamSettingsWithPostQuantum(provider.StreamSettings(), mode)
	if err != nil {
		return nil, err
	}

	return internet.ContextWithStreamSettingsOverride(ctx, override), nil
}

func trustTunnelStreamSettingsWithPostQuantum(streamSettings *internet.MemoryStreamConfig, mode PostQuantumGroupSetting) (*internet.MemoryStreamConfig, error) {
	if mode == PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_AUTO {
		return streamSettings, nil
	}
	if streamSettings == nil {
		return nil, errors.New(trustTunnelPostQuantumUnsupportedSecurityText).AtWarning()
	}

	override := cloneTrustTunnelStreamSettings(streamSettings)

	switch {
	case xtlstls.ConfigFromStreamSettings(override) != nil:
		tlsConfig := xtlstls.ConfigFromStreamSettings(override)
		fingerprint, err := trustTunnelFingerprintWithPostQuantum(tlsConfig.GetFingerprint(), mode)
		if err != nil {
			return nil, err
		}
		tlsConfig.Fingerprint = fingerprint
		tlsConfig.CurvePreferences = trustTunnelCurvePreferencesForMode(tlsConfig.CurvePreferences, mode)
		return override, nil
	case reality.ConfigFromStreamSettings(override) != nil:
		realityConfig := reality.ConfigFromStreamSettings(override)
		fingerprint, err := trustTunnelFingerprintWithPostQuantum(realityConfig.GetFingerprint(), mode)
		if err != nil {
			return nil, err
		}
		realityConfig.Fingerprint = fingerprint
		return override, nil
	default:
		return nil, errors.New(trustTunnelPostQuantumUnsupportedSecurityText).AtWarning()
	}
}

func trustTunnelApplyHTTP3PostQuantum(tlsConfig *gotls.Config, cfg *ClientConfig) {
	if tlsConfig == nil {
		return
	}

	switch cfg.GetPostQuantumGroupEnabled() {
	case PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_ENABLED:
		tlsConfig.CurvePreferences = []gotls.CurveID{
			gotls.X25519MLKEM768,
			gotls.X25519,
		}
	case PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_DISABLED:
		tlsConfig.CurvePreferences = []gotls.CurveID{
			gotls.X25519,
		}
	}
}

func trustTunnelFingerprintWithPostQuantum(current string, mode PostQuantumGroupSetting) (string, error) {
	switch mode {
	case PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_ENABLED:
		switch normalizeTrustTunnelFingerprint(current) {
		case "", "chrome", "hellochrome_auto", trustTunnelPostQuantumChromeFingerprint, trustTunnelPostQuantumChromeFingerprintPQ:
			return trustTunnelPostQuantumChromeFingerprintPQ, nil
		}
	case PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_DISABLED:
		switch normalizeTrustTunnelFingerprint(current) {
		case "", "chrome", "hellochrome_auto", trustTunnelPostQuantumChromeFingerprint, trustTunnelPostQuantumChromeFingerprintPQ:
			return trustTunnelPostQuantumChromeFingerprint, nil
		}
	default:
		return current, nil
	}

	return "", errors.New("trusttunnel postQuantumGroupEnabled is unsupported for fingerprint ", current, ": only default Chrome-family TLS/REALITY fingerprints can be toggled today").AtWarning()
}

func trustTunnelCurvePreferencesForMode(current []string, mode PostQuantumGroupSetting) []string {
	switch mode {
	case PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_ENABLED:
		return normalizeTrustTunnelCurvePreferences(current, true)
	case PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_DISABLED:
		return normalizeTrustTunnelCurvePreferences(current, false)
	default:
		return append([]string(nil), current...)
	}
}

func normalizeTrustTunnelCurvePreferences(current []string, enablePQ bool) []string {
	seen := make(map[string]struct{}, len(current)+2)
	curves := make([]string, 0, len(current)+2)

	appendCurve := func(name string) {
		if name == "" {
			return
		}
		if _, found := seen[name]; found {
			return
		}
		seen[name] = struct{}{}
		curves = append(curves, name)
	}

	if enablePQ {
		appendCurve("x25519mlkem768")
		appendCurve("x25519")
	} else {
		appendCurve("x25519")
	}

	for _, curve := range current {
		normalized := strings.ToLower(strings.TrimSpace(curve))
		switch normalized {
		case "", "x25519mlkem768", "secp256r1mlkem768", "secp384r1mlkem1024":
			if enablePQ {
				continue
			}
			continue
		case "x25519":
			continue
		default:
			appendCurve(normalized)
		}
	}

	return curves
}

func cloneTrustTunnelStreamSettings(base *internet.MemoryStreamConfig) *internet.MemoryStreamConfig {
	if base == nil {
		return nil
	}

	clone := *base
	if base.Destination != nil {
		destination := *base.Destination
		clone.Destination = &destination
	}
	if base.SocketSettings != nil {
		clone.SocketSettings = proto.Clone(base.SocketSettings).(*internet.SocketConfig)
	}
	if base.DownloadSettings != nil {
		clone.DownloadSettings = cloneTrustTunnelStreamSettings(base.DownloadSettings)
	}

	switch security := base.SecuritySettings.(type) {
	case *xtlstls.Config:
		clone.SecuritySettings = proto.Clone(security).(*xtlstls.Config)
	case *reality.Config:
		clone.SecuritySettings = proto.Clone(security).(*reality.Config)
	default:
		clone.SecuritySettings = base.SecuritySettings
	}

	return &clone
}

func normalizeTrustTunnelFingerprint(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
