package trusttunnel

import (
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

func TestNewTrustTunnelMultipathSessionAppliesDefaults(t *testing.T) {
	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:     "sess-1",
		Target: xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
	})

	if session.ID() != "sess-1" {
		t.Fatalf("session ID = %q, want %q", session.ID(), "sess-1")
	}
	if session.minChannels != 2 {
		t.Fatalf("minChannels = %d, want 2", session.minChannels)
	}
	if session.maxChannels != 2 {
		t.Fatalf("maxChannels = %d, want 2", session.maxChannels)
	}
	if session.scheduler != MultipathScheduler_MULTIPATH_SCHEDULER_ROUND_ROBIN {
		t.Fatalf("scheduler = %v, want ROUND_ROBIN", session.scheduler)
	}
	if session.State() != trustTunnelMultipathSessionOpening {
		t.Fatalf("state = %v, want opening", session.State())
	}
}

func TestTrustTunnelMultipathSessionTracksChannelLifecycle(t *testing.T) {
	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:          "sess-2",
		MinChannels: 2,
		MaxChannels: 3,
		Target:      xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:  "1.1.1.1:443",
		Strict:      true,
	})

	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443"}); err != nil {
		t.Fatalf("AddChannel(first) returned error: %v", err)
	}
	if got := session.ActiveChannelCount(); got != 1 {
		t.Fatalf("ActiveChannelCount() = %d, want 1", got)
	}
	if state := session.State(); state != trustTunnelMultipathSessionOpening {
		t.Fatalf("state after first channel = %v, want opening", state)
	}

	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443"}); err != nil {
		t.Fatalf("AddChannel(second) returned error: %v", err)
	}
	if got := session.ActiveChannelCount(); got != 2 {
		t.Fatalf("ActiveChannelCount() = %d, want 2", got)
	}
	if state := session.State(); state != trustTunnelMultipathSessionActive {
		t.Fatalf("state after reaching quorum = %v, want active", state)
	}

	session.RemoveChannel(1)
	if got := session.ActiveChannelCount(); got != 1 {
		t.Fatalf("ActiveChannelCount() after remove = %d, want 1", got)
	}
	if state := session.State(); state != trustTunnelMultipathSessionDegraded {
		t.Fatalf("state after falling below quorum = %v, want degraded", state)
	}
}

func TestTrustTunnelMultipathSessionRegistryLifecycle(t *testing.T) {
	registry := newTrustTunnelMultipathSessionRegistry()
	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:     "sess-3",
		Target: xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
	})

	registry.Add(session)
	got, ok := registry.Get("sess-3")
	if !ok {
		t.Fatal("registry.Get() = not found, want found")
	}
	if got != session {
		t.Fatal("registry returned unexpected session instance")
	}

	registry.Delete("sess-3")
	if _, ok := registry.Get("sess-3"); ok {
		t.Fatal("registry.Get() after Delete = found, want not found")
	}
}

func TestTrustTunnelMultipathSessionAttachChannelValidatesProof(t *testing.T) {
	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:            "sess-4",
		Target:        xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:    "1.1.1.1:443",
		MinChannels:   2,
		MaxChannels:   3,
		AttachSecret:  []byte("0123456789abcdef0123456789abcdef"),
		AttachTimeout: 5 * time.Second,
		Strict:        true,
	})
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: trustTunnelMultipathPrimaryChannelID, endpoint: "192.168.1.50:9443"}); err != nil {
		t.Fatalf("AddChannel(primary) returned error: %v", err)
	}

	now := time.Unix(1712700000, 0)
	req := &trustTunnelMultipathAttachRequest{
		SessionID:  "sess-4",
		ChannelID:  2,
		TargetHost: "1.1.1.1:443",
		Nonce:      "nonce-1",
		Timestamp:  now,
	}
	req.Proof = trustTunnelMultipathComputeAttachProof([]byte("0123456789abcdef0123456789abcdef"), session.ID(), req.ChannelID, req.Nonce, req.Timestamp.Unix(), req.TargetHost)

	if err := session.AttachChannel(req, "192.168.1.51:9443", now); err != nil {
		t.Fatalf("AttachChannel() returned error: %v", err)
	}
	if got := session.ActiveChannelCount(); got != 2 {
		t.Fatalf("ActiveChannelCount() = %d, want 2", got)
	}
	if state := session.State(); state != trustTunnelMultipathSessionActive {
		t.Fatalf("state = %v, want active", state)
	}

	replay := *req
	if err := session.AttachChannel(&replay, "192.168.1.52:9443", now); err == nil || !strings.Contains(err.Error(), trustTunnelMultipathAttachReplayText) {
		t.Fatalf("AttachChannel(replay) error = %v, want text %q", err, trustTunnelMultipathAttachReplayText)
	}
}
