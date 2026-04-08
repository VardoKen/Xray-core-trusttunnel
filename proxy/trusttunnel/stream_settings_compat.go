package trusttunnel

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	xtlstls "github.com/xtls/xray-core/transport/internet/tls"
)

func trustTunnelContextWithTransportSecurityOverrides(ctx context.Context, dialer internet.Dialer, cfg *ClientConfig) (context.Context, bool, error) {
	mode := cfg.GetPostQuantumGroupEnabled()

	provider, ok := dialer.(trustTunnelStreamSettingsProvider)
	if !ok {
		if mode != PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_AUTO {
			return nil, false, errors.New(trustTunnelPostQuantumUnsupportedSecurityText).AtWarning()
		}
		return ctx, false, nil
	}

	base := provider.StreamSettings()
	effective := base
	changed := false

	if mode != PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_AUTO {
		override, err := trustTunnelStreamSettingsWithPostQuantum(base, mode)
		if err != nil {
			return nil, false, err
		}
		effective = override
		changed = true
	}

	override, compatibilityChanged, tlsHandledByStreamSettings := trustTunnelStreamSettingsWithTLSCompatibility(effective, cfg)
	if compatibilityChanged {
		effective = override
		changed = true
	}

	if changed {
		ctx = internet.ContextWithStreamSettingsOverride(ctx, effective)
	}

	if cfg.GetAntiDpi() {
		if cfg.GetTransport() != TransportProtocol_HTTP2 {
			return nil, false, errors.New("trusttunnel antiDpi is supported only for http2 over TLS: current transport is not compatible").AtWarning()
		}
		if xtlstls.ConfigFromStreamSettings(effective) == nil {
			return nil, false, errors.New("trusttunnel antiDpi is supported only for http2 over TLS: current outbound streamSettings have no TLS security").AtWarning()
		}
		ctx = xtlstls.ContextWithAntiDPI(ctx)
	}

	return ctx, tlsHandledByStreamSettings, nil
}

func trustTunnelStreamSettingsWithTLSCompatibility(streamSettings *internet.MemoryStreamConfig, cfg *ClientConfig) (*internet.MemoryStreamConfig, bool, bool) {
	tlsConfig := xtlstls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return streamSettings, false, false
	}

	needServerName := tlsConfig.GetServerName() == "" && cfg.GetHostname() != ""
	explicitVerifySurface := trustTunnelTLSConfigHasExplicitVerifySurface(tlsConfig)

	// For non-H3 paths, generic tlsSettings are the authoritative TLS surface.
	// TrustTunnel compatibility fields only fill missing generic pieces.
	if cfg.GetSkipVerification() {
		needAllowInsecure := !tlsConfig.GetAllowInsecure() && !explicitVerifySurface
		if !needServerName && !needAllowInsecure {
			return streamSettings, false, true
		}

		override := cloneTrustTunnelStreamSettings(streamSettings)
		tlsOverride := xtlstls.ConfigFromStreamSettings(override)
		if tlsOverride == nil {
			return streamSettings, false, false
		}

		if tlsOverride.GetServerName() == "" && cfg.GetHostname() != "" {
			tlsOverride.ServerName = cfg.GetHostname()
		}
		if !explicitVerifySurface {
			tlsOverride.AllowInsecure = true
		}

		return override, true, true
	}

	if explicitVerifySurface {
		if !needServerName {
			return streamSettings, false, true
		}

		override := cloneTrustTunnelStreamSettings(streamSettings)
		tlsOverride := xtlstls.ConfigFromStreamSettings(override)
		if tlsOverride == nil {
			return streamSettings, false, false
		}
		tlsOverride.ServerName = cfg.GetHostname()
		return override, true, true
	}

	needAllowInsecure := tlsConfig.GetAllowInsecure()
	needAuthorityVerify := cfg.GetCertificatePem() != "" && trustTunnelTLSConfigNeedsCompatibilityAuthorityVerify(tlsConfig)

	if !needServerName && !needAllowInsecure && !needAuthorityVerify {
		return streamSettings, false, true
	}

	override := cloneTrustTunnelStreamSettings(streamSettings)
	tlsOverride := xtlstls.ConfigFromStreamSettings(override)
	if tlsOverride == nil {
		return streamSettings, false, false
	}

	if tlsOverride.GetServerName() == "" && cfg.GetHostname() != "" {
		tlsOverride.ServerName = cfg.GetHostname()
	}
	tlsOverride.AllowInsecure = false

	if cfg.GetCertificatePem() != "" && trustTunnelTLSConfigNeedsCompatibilityAuthorityVerify(tlsOverride) {
		tlsOverride.Certificate = append(tlsOverride.Certificate, &xtlstls.Certificate{
			Certificate: []byte(cfg.GetCertificatePem()),
			Usage:       xtlstls.Certificate_AUTHORITY_VERIFY,
		})
		tlsOverride.DisableSystemRoot = true
	}

	return override, true, true
}

func trustTunnelTLSConfigHasExplicitVerifySurface(tlsConfig *xtlstls.Config) bool {
	if tlsConfig == nil {
		return false
	}

	if len(tlsConfig.GetPinnedPeerCertSha256()) > 0 || len(tlsConfig.GetVerifyPeerCertByName()) > 0 {
		return true
	}

	for _, cert := range tlsConfig.GetCertificate() {
		if cert != nil && cert.GetUsage() == xtlstls.Certificate_AUTHORITY_VERIFY {
			return true
		}
	}

	return false
}

func trustTunnelTLSConfigNeedsCompatibilityAuthorityVerify(tlsConfig *xtlstls.Config) bool {
	if tlsConfig == nil {
		return false
	}

	return !trustTunnelTLSConfigHasExplicitVerifySurface(tlsConfig)
}
