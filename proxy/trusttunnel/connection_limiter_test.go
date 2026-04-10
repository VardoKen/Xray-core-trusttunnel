package trusttunnel

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func testTrustTunnelMemoryUser(username, password string, maxHTTP2, maxHTTP3 uint32) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Email: username,
		Account: &MemoryAccount{
			Username:      username,
			Password:      password,
			BasicAuth:     buildBasicAuthValue(username, password),
			MaxHTTP2Conns: maxHTTP2,
			MaxHTTP3Conns: maxHTTP3,
		},
	}
}

func TestNewTrustTunnelConnectionLimiterNilWithoutConfiguredLimits(t *testing.T) {
	limiter := newTrustTunnelConnectionLimiter([]*protocol.MemoryUser{
		testTrustTunnelMemoryUser("u1", "p1", 0, 0),
	}, 0, 0)
	if limiter != nil {
		t.Fatal("expected nil limiter without configured limits")
	}
}

func TestTrustTunnelConnectionLimiterEnforcesGlobalHTTP2Limit(t *testing.T) {
	user := testTrustTunnelMemoryUser("u1", "p1", 0, 0)
	limiter := newTrustTunnelConnectionLimiter([]*protocol.MemoryUser{user}, 1, 0)
	if limiter == nil {
		t.Fatal("expected limiter")
	}

	basicAuth := user.Account.(*MemoryAccount).BasicAuth
	guard1 := limiter.tryAcquire(basicAuth, trustTunnelConnectionProtocolHTTP2)
	if guard1 == nil {
		t.Fatal("expected first HTTP/2 guard")
	}
	if guard2 := limiter.tryAcquire(basicAuth, trustTunnelConnectionProtocolHTTP2); guard2 != nil {
		t.Fatal("expected second HTTP/2 guard to be rejected")
	}

	guard1.Release()
	if guard3 := limiter.tryAcquire(basicAuth, trustTunnelConnectionProtocolHTTP2); guard3 == nil {
		t.Fatal("expected HTTP/2 guard after release")
	} else {
		guard3.Release()
	}
}

func TestTrustTunnelConnectionLimiterEnforcesPerUserOverride(t *testing.T) {
	user := testTrustTunnelMemoryUser("u1", "p1", 2, 0)
	limiter := newTrustTunnelConnectionLimiter([]*protocol.MemoryUser{user}, 1, 0)
	if limiter == nil {
		t.Fatal("expected limiter")
	}

	basicAuth := user.Account.(*MemoryAccount).BasicAuth
	guard1 := limiter.tryAcquire(basicAuth, trustTunnelConnectionProtocolHTTP2)
	guard2 := limiter.tryAcquire(basicAuth, trustTunnelConnectionProtocolHTTP2)
	if guard1 == nil || guard2 == nil {
		t.Fatal("expected per-user HTTP/2 override to allow two guards")
	}
	if guard3 := limiter.tryAcquire(basicAuth, trustTunnelConnectionProtocolHTTP2); guard3 != nil {
		t.Fatal("expected third HTTP/2 guard to be rejected")
	}

	guard1.Release()
	guard2.Release()
}

func TestTrustTunnelConnectionLimiterSeparatesHTTP2AndHTTP3Buckets(t *testing.T) {
	user := testTrustTunnelMemoryUser("u1", "p1", 1, 1)
	limiter := newTrustTunnelConnectionLimiter([]*protocol.MemoryUser{user}, 0, 0)
	if limiter == nil {
		t.Fatal("expected limiter")
	}

	basicAuth := user.Account.(*MemoryAccount).BasicAuth
	guardHTTP2 := limiter.tryAcquire(basicAuth, trustTunnelConnectionProtocolHTTP2)
	guardHTTP3 := limiter.tryAcquire(basicAuth, trustTunnelConnectionProtocolHTTP3)
	if guardHTTP2 == nil || guardHTTP3 == nil {
		t.Fatal("expected both protocol buckets to acquire independently")
	}
	if limiter.tryAcquire(basicAuth, trustTunnelConnectionProtocolHTTP2) != nil {
		t.Fatal("expected HTTP/2 bucket to be full")
	}
	if limiter.tryAcquire(basicAuth, trustTunnelConnectionProtocolHTTP3) != nil {
		t.Fatal("expected HTTP/3 bucket to be full")
	}

	guardHTTP2.Release()
	guardHTTP3.Release()
}
