package trusttunnel

import (
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

type trustTunnelMultipathSessionState uint8

const (
	trustTunnelMultipathSessionOpening trustTunnelMultipathSessionState = iota
	trustTunnelMultipathSessionActive
	trustTunnelMultipathSessionDegraded
	trustTunnelMultipathSessionClosing
)

type trustTunnelMultipathSessionOptions struct {
	ID          string
	Target      xnet.Destination
	MinChannels uint32
	MaxChannels uint32
	Scheduler   MultipathScheduler
	Strict      bool
}

type trustTunnelMultipathSession struct {
	id          string
	target      xnet.Destination
	createdAt   time.Time
	minChannels uint32
	maxChannels uint32
	scheduler   MultipathScheduler
	strict      bool

	mu       sync.RWMutex
	state    trustTunnelMultipathSessionState
	channels map[uint32]*trustTunnelMultipathChannel
}

type trustTunnelMultipathChannel struct {
	id         uint32
	endpoint   string
	createdAt  time.Time
	lastSeenAt time.Time
	closing    bool
}

func newTrustTunnelMultipathSession(options trustTunnelMultipathSessionOptions) *trustTunnelMultipathSession {
	minChannels := options.MinChannels
	if minChannels == 0 {
		minChannels = 2
	}
	maxChannels := options.MaxChannels
	if maxChannels == 0 {
		maxChannels = minChannels
	}
	scheduler := options.Scheduler
	if scheduler == MultipathScheduler_MULTIPATH_SCHEDULER_UNSPECIFIED {
		scheduler = MultipathScheduler_MULTIPATH_SCHEDULER_ROUND_ROBIN
	}

	return &trustTunnelMultipathSession{
		id:          options.ID,
		target:      options.Target,
		createdAt:   time.Now(),
		minChannels: minChannels,
		maxChannels: maxChannels,
		scheduler:   scheduler,
		strict:      options.Strict,
		state:       trustTunnelMultipathSessionOpening,
		channels:    make(map[uint32]*trustTunnelMultipathChannel),
	}
}

func (s *trustTunnelMultipathSession) ID() string {
	if s == nil {
		return ""
	}
	return s.id
}

func (s *trustTunnelMultipathSession) AddChannel(channel *trustTunnelMultipathChannel) {
	if s == nil || channel == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if channel.createdAt.IsZero() {
		channel.createdAt = now
	}
	channel.lastSeenAt = now
	s.channels[channel.id] = channel
	if uint32(len(s.channels)) >= s.minChannels {
		s.state = trustTunnelMultipathSessionActive
	}
}

func (s *trustTunnelMultipathSession) RemoveChannel(channelID uint32) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.channels, channelID)
	if len(s.channels) == 0 {
		s.state = trustTunnelMultipathSessionOpening
		return
	}
	if uint32(len(s.channels)) < s.minChannels {
		s.state = trustTunnelMultipathSessionDegraded
	}
}

func (s *trustTunnelMultipathSession) ActiveChannelCount() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.channels)
}

func (s *trustTunnelMultipathSession) State() trustTunnelMultipathSessionState {
	if s == nil {
		return trustTunnelMultipathSessionClosing
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

type trustTunnelMultipathSessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]*trustTunnelMultipathSession
}

func newTrustTunnelMultipathSessionRegistry() *trustTunnelMultipathSessionRegistry {
	return &trustTunnelMultipathSessionRegistry{
		sessions: make(map[string]*trustTunnelMultipathSession),
	}
}

func (r *trustTunnelMultipathSessionRegistry) Add(session *trustTunnelMultipathSession) {
	if r == nil || session == nil || session.id == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[session.id] = session
}

func (r *trustTunnelMultipathSessionRegistry) Get(id string) (*trustTunnelMultipathSession, bool) {
	if r == nil || id == "" {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, ok := r.sessions[id]
	return session, ok
}

func (r *trustTunnelMultipathSessionRegistry) Delete(id string) {
	if r == nil || id == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
}
