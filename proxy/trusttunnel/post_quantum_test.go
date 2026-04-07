package trusttunnel

import (
	"crypto/tls"
	"testing"
)

func TestTrustTunnelApplyHTTP3PostQuantumEnabled(t *testing.T) {
	tlsConfig := &tls.Config{}

	trustTunnelApplyHTTP3PostQuantum(tlsConfig, &ClientConfig{
		PostQuantumGroupEnabled: PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_ENABLED,
	})

	if len(tlsConfig.CurvePreferences) != 2 {
		t.Fatalf("curvePreferences len = %d, want 2", len(tlsConfig.CurvePreferences))
	}
	if tlsConfig.CurvePreferences[0] != tls.X25519MLKEM768 || tlsConfig.CurvePreferences[1] != tls.X25519 {
		t.Fatalf("curvePreferences = %v, want [X25519MLKEM768 X25519]", tlsConfig.CurvePreferences)
	}
}

func TestTrustTunnelApplyHTTP3PostQuantumDisabled(t *testing.T) {
	tlsConfig := &tls.Config{}

	trustTunnelApplyHTTP3PostQuantum(tlsConfig, &ClientConfig{
		PostQuantumGroupEnabled: PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_DISABLED,
	})

	if len(tlsConfig.CurvePreferences) != 1 || tlsConfig.CurvePreferences[0] != tls.X25519 {
		t.Fatalf("curvePreferences = %v, want [X25519]", tlsConfig.CurvePreferences)
	}
}

func TestTrustTunnelCurvePreferencesForModeEnabledKeepsCustomCurves(t *testing.T) {
	got := trustTunnelCurvePreferencesForMode([]string{"curvep256"}, PostQuantumGroupSetting_POST_QUANTUM_GROUP_SETTING_ENABLED)

	want := []string{"x25519mlkem768", "x25519", "curvep256"}
	if len(got) != len(want) {
		t.Fatalf("curvePreferences len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("curvePreferences[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
