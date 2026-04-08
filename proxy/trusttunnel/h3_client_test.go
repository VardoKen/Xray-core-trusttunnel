package trusttunnel

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	xtlstls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestTrustTunnelBuildHTTP3TLSConfigUsesStreamSettingsVerifySurface(t *testing.T) {
	caCert, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	leafCert, _ := cert.MustGenerate(caCert, cert.DNSNames("override.example"))
	leaf := common.Must2(x509.ParseCertificate(leafCert.Certificate))
	ca := common.Must2(x509.ParseCertificate(caCert.Certificate))

	streamSettings := &internet.MemoryStreamConfig{
		SecurityType: "tls",
		SecuritySettings: &xtlstls.Config{
			DisableSystemRoot: true,
			Certificate: []*xtlstls.Certificate{
				{
					Usage:       xtlstls.Certificate_AUTHORITY_VERIFY,
					Certificate: caCert.Certificate,
				},
			},
		},
	}
	ctx := internet.ContextWithStreamSettingsOverride(context.Background(), streamSettings)

	cfg := &ClientConfig{
		Hostname: "override.example",
	}

	tlsCfg := trustTunnelBuildHTTP3TLSConfig(ctx, cfg)
	if tlsCfg.ServerName != "override.example" {
		t.Fatalf("ServerName = %q, want override.example", tlsCfg.ServerName)
	}
	if len(tlsCfg.NextProtos) != 1 || tlsCfg.NextProtos[0] != "h3" {
		t.Fatalf("NextProtos = %v, want [h3]", tlsCfg.NextProtos)
	}
	if tlsCfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify = true, want false when generic tlsSettings provide verification")
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Fatal("VerifyPeerCertificate = nil, want generic tls verification hook")
	}
	if err := tlsCfg.VerifyPeerCertificate([][]byte{leaf.Raw, ca.Raw}, nil); err != nil {
		t.Fatalf("VerifyPeerCertificate() error = %v, want nil", err)
	}
}

func TestTrustTunnelBuildHTTP3TLSConfigFallsBackToTrustTunnelCompatibilityFields(t *testing.T) {
	cfg := &ClientConfig{
		Hostname:         "tt.example",
		SkipVerification: true,
	}

	tlsCfg := trustTunnelBuildHTTP3TLSConfig(context.Background(), cfg)
	if tlsCfg.ServerName != "tt.example" {
		t.Fatalf("ServerName = %q, want tt.example", tlsCfg.ServerName)
	}
	if len(tlsCfg.NextProtos) != 1 || tlsCfg.NextProtos[0] != "h3" {
		t.Fatalf("NextProtos = %v, want [h3]", tlsCfg.NextProtos)
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify = false, want true for trusttunnel compatibility fallback")
	}
}
