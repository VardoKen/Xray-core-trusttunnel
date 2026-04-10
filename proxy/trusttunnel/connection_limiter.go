package trusttunnel

import (
	"sync"

	"github.com/xtls/xray-core/common/protocol"
)

type trustTunnelConnectionProtocol uint8

const (
	trustTunnelConnectionProtocolHTTP2 trustTunnelConnectionProtocol = iota
	trustTunnelConnectionProtocolHTTP3
)

type trustTunnelConnectionLimitEntry struct {
	maxHTTP2Conns uint32
	maxHTTP3Conns uint32
	http2Count    uint32
	http3Count    uint32
}

type trustTunnelConnectionLimiter struct {
	mu              sync.Mutex
	clients         map[string]*trustTunnelConnectionLimitEntry
	defaultHTTP2Max uint32
	defaultHTTP3Max uint32
}

type trustTunnelConnectionGuard struct {
	limiter   *trustTunnelConnectionLimiter
	basicAuth string
	protocol  trustTunnelConnectionProtocol
	once      sync.Once
}

func newTrustTunnelConnectionLimiter(users []*protocol.MemoryUser, defaultHTTP2Max uint32, defaultHTTP3Max uint32) *trustTunnelConnectionLimiter {
	needsLimiter := defaultHTTP2Max > 0 || defaultHTTP3Max > 0
	clients := make(map[string]*trustTunnelConnectionLimitEntry, len(users))

	for _, user := range users {
		if user == nil {
			continue
		}
		acc, ok := user.Account.(*MemoryAccount)
		if !ok || acc == nil || acc.BasicAuth == "" {
			continue
		}
		if acc.MaxHTTP2Conns > 0 || acc.MaxHTTP3Conns > 0 {
			needsLimiter = true
		}
		clients[acc.BasicAuth] = &trustTunnelConnectionLimitEntry{
			maxHTTP2Conns: acc.MaxHTTP2Conns,
			maxHTTP3Conns: acc.MaxHTTP3Conns,
		}
	}

	if !needsLimiter {
		return nil
	}

	return &trustTunnelConnectionLimiter{
		clients:         clients,
		defaultHTTP2Max: defaultHTTP2Max,
		defaultHTTP3Max: defaultHTTP3Max,
	}
}

func trustTunnelConnectionProtocolFromLabel(label string) trustTunnelConnectionProtocol {
	if label == "H3" {
		return trustTunnelConnectionProtocolHTTP3
	}
	return trustTunnelConnectionProtocolHTTP2
}

func (l *trustTunnelConnectionLimiter) tryAcquire(basicAuth string, protocol trustTunnelConnectionProtocol) *trustTunnelConnectionGuard {
	if l == nil || basicAuth == "" {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry := l.clients[basicAuth]
	if entry == nil {
		return nil
	}

	var current *uint32
	var limit uint32
	switch protocol {
	case trustTunnelConnectionProtocolHTTP3:
		current = &entry.http3Count
		limit = entry.maxHTTP3Conns
		if limit == 0 {
			limit = l.defaultHTTP3Max
		}
	default:
		current = &entry.http2Count
		limit = entry.maxHTTP2Conns
		if limit == 0 {
			limit = l.defaultHTTP2Max
		}
	}

	if limit > 0 && *current >= limit {
		return nil
	}

	*current++
	return &trustTunnelConnectionGuard{
		limiter:   l,
		basicAuth: basicAuth,
		protocol:  protocol,
	}
}

func (l *trustTunnelConnectionLimiter) release(basicAuth string, protocol trustTunnelConnectionProtocol) {
	if l == nil || basicAuth == "" {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry := l.clients[basicAuth]
	if entry == nil {
		return
	}

	switch protocol {
	case trustTunnelConnectionProtocolHTTP3:
		if entry.http3Count > 0 {
			entry.http3Count--
		}
	default:
		if entry.http2Count > 0 {
			entry.http2Count--
		}
	}
}

func (g *trustTunnelConnectionGuard) Release() {
	if g == nil {
		return
	}

	g.once.Do(func() {
		g.limiter.release(g.basicAuth, g.protocol)
	})
}
