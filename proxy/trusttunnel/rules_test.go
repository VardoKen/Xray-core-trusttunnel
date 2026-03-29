package trusttunnel

import "testing"

func TestRulesCIDRAllowDeny(t *testing.T) {
	t.Run("allow by cidr", func(t *testing.T) {
		rules := []*Rule{
			{Cidr: "127.0.0.0/8", Allow: true},
			{Allow: false},
		}

		allow, reason := isTrustTunnelAllowed(rules, "127.0.0.1:12345", "")
		if !allow {
			t.Fatalf("expected allow, got deny: %s", reason)
		}
	})

	t.Run("deny by catch all", func(t *testing.T) {
		rules := []*Rule{
			{Cidr: "10.0.0.0/8", Allow: true},
			{Allow: false},
		}

		allow, reason := isTrustTunnelAllowed(rules, "127.0.0.1:12345", "")
		if allow {
			t.Fatalf("expected deny, got allow: %s", reason)
		}
	})
}

func TestRulesClientRandomPrefix(t *testing.T) {
	rules := []*Rule{
		{ClientRandom: "deadbeef", Allow: true},
		{Allow: false},
	}

	allow, reason := isTrustTunnelAllowed(rules, "127.0.0.1:12345", "deadbeefa90be1b31235cf85c0ec76bf853ff14837190fae6c0c6b834608ce83")
	if !allow {
		t.Fatalf("expected allow, got deny: %s", reason)
	}

	allow, reason = isTrustTunnelAllowed(rules, "127.0.0.1:12345", "feedbeefa90be1b31235cf85c0ec76bf853ff14837190fae6c0c6b834608ce83")
	if allow {
		t.Fatalf("expected deny, got allow: %s", reason)
	}
}

func TestRulesClientRandomMask(t *testing.T) {
	rules := []*Rule{
		{ClientRandom: "d0adbeef/f0ffffff", Allow: true},
		{Allow: false},
	}

	allow, reason := isTrustTunnelAllowed(rules, "127.0.0.1:12345", "deadbeefa90be1b31235cf85c0ec76bf853ff14837190fae6c0c6b834608ce83")
	if !allow {
		t.Fatalf("expected allow, got deny: %s", reason)
	}

	allow, reason = isTrustTunnelAllowed(rules, "127.0.0.1:12345", "c0adbeefa90be1b31235cf85c0ec76bf853ff14837190fae6c0c6b834608ce83")
	if allow {
		t.Fatalf("expected deny, got allow: %s", reason)
	}
}
