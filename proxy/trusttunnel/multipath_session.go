package trusttunnel

import (
	"crypto/hmac"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
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
	ID            string
	Target        xnet.Destination
	TargetHost    string
	MinChannels   uint32
	MaxChannels   uint32
	Scheduler     MultipathScheduler
	Strict        bool
	AttachTimeout time.Duration
	AttachSecret  []byte
}

type trustTunnelMultipathSession struct {
	id             string
	target         xnet.Destination
	targetHost     string
	createdAt      time.Time
	minChannels    uint32
	maxChannels    uint32
	scheduler      MultipathScheduler
	strict         bool
	attachSecret   []byte
	attachDeadline time.Time

	mu         sync.RWMutex
	state      trustTunnelMultipathSessionState
	channels   map[uint32]*trustTunnelMultipathChannel
	usedNonces map[string]time.Time
}

type trustTunnelMultipathChannel struct {
	id         uint32
	endpoint   string
	createdAt  time.Time
	lastSeenAt time.Time
	closing    bool
}

const (
	trustTunnelMultipathPrimaryChannelID = 1

	trustTunnelMultipathAttachReplayText       = "trusttunnel multipath attach replay detected"
	trustTunnelMultipathAttachExpiredText      = "trusttunnel multipath attach window expired"
	trustTunnelMultipathAttachTargetMismatch   = "trusttunnel multipath attach target mismatch"
	trustTunnelMultipathAttachProofInvalidText = "trusttunnel multipath attach proof is invalid"
	trustTunnelMultipathDuplicateChannelText   = "trusttunnel multipath channel already exists"
	trustTunnelMultipathChannelLimitText       = "trusttunnel multipath channel limit reached"
)

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
	targetHost := strings.TrimSpace(options.TargetHost)
	if targetHost == "" {
		targetHost = options.Target.NetAddr()
	}
	attachTimeout := options.AttachTimeout
	if attachTimeout <= 0 {
		attachTimeout = trustTunnelMultipathDefaultAttachTimeout
	}

	return &trustTunnelMultipathSession{
		id:             options.ID,
		target:         options.Target,
		targetHost:     targetHost,
		createdAt:      time.Now(),
		minChannels:    minChannels,
		maxChannels:    maxChannels,
		scheduler:      scheduler,
		strict:         options.Strict,
		attachSecret:   append([]byte(nil), options.AttachSecret...),
		attachDeadline: time.Now().Add(attachTimeout),
		state:          trustTunnelMultipathSessionOpening,
		channels:       make(map[uint32]*trustTunnelMultipathChannel),
		usedNonces:     make(map[string]time.Time),
	}
}

func (s *trustTunnelMultipathSession) ID() string {
	if s == nil {
		return ""
	}
	return s.id
}

func (s *trustTunnelMultipathSession) TargetHost() string {
	if s == nil {
		return ""
	}
	return s.targetHost
}

func (s *trustTunnelMultipathSession) AttachSecretHeaderValue() string {
	if s == nil || len(s.attachSecret) == 0 {
		return ""
	}
	return trustTunnelMultipathAttachSecretHeaderValue(s.attachSecret)
}

func (s *trustTunnelMultipathSession) PrimaryChannelID() uint32 {
	return trustTunnelMultipathPrimaryChannelID
}

func (s *trustTunnelMultipathSession) AddChannel(channel *trustTunnelMultipathChannel) error {
	if s == nil || channel == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addChannelLocked(channel)
}

func (s *trustTunnelMultipathSession) addChannelLocked(channel *trustTunnelMultipathChannel) error {
	if channel == nil {
		return nil
	}
	if channel.id == 0 {
		return errors.New("trusttunnel multipath channel id is invalid").AtInfo()
	}
	if _, exists := s.channels[channel.id]; exists {
		return errors.New(trustTunnelMultipathDuplicateChannelText).AtInfo()
	}
	if s.maxChannels > 0 && uint32(len(s.channels)) >= s.maxChannels {
		return errors.New(trustTunnelMultipathChannelLimitText).AtInfo()
	}
	now := time.Now()
	if channel.createdAt.IsZero() {
		channel.createdAt = now
	}
	channel.lastSeenAt = now
	s.channels[channel.id] = channel
	if uint32(len(s.channels)) >= s.minChannels {
		s.state = trustTunnelMultipathSessionActive
	} else {
		s.state = trustTunnelMultipathSessionOpening
	}
	return nil
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

func (s *trustTunnelMultipathSession) AttachChannel(request *trustTunnelMultipathAttachRequest, endpoint string, now time.Time) error {
	if s == nil {
		return errors.New("trusttunnel multipath session is nil").AtInfo()
	}
	if request == nil {
		return errors.New("trusttunnel multipath attach request is nil").AtInfo()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.attachDeadline.IsZero() && now.After(s.attachDeadline) {
		return errors.New(trustTunnelMultipathAttachExpiredText).AtInfo()
	}
	if request.Timestamp.Before(now.Add(-trustTunnelMultipathAttachSkewWindow)) || request.Timestamp.After(now.Add(trustTunnelMultipathAttachSkewWindow)) {
		return errors.New(trustTunnelMultipathAttachExpiredText).AtInfo()
	}
	if !strings.EqualFold(strings.TrimSpace(request.TargetHost), s.targetHost) {
		return errors.New(trustTunnelMultipathAttachTargetMismatch).AtInfo()
	}

	s.cleanupUsedNoncesLocked(now.Add(-trustTunnelMultipathAttachSkewWindow))
	if _, seen := s.usedNonces[request.Nonce]; seen {
		return errors.New(trustTunnelMultipathAttachReplayText).AtInfo()
	}

	expectedProof := trustTunnelMultipathComputeAttachProof(s.attachSecret, s.id, request.ChannelID, request.Nonce, request.Timestamp.Unix(), s.targetHost)
	if !hmac.Equal([]byte(expectedProof), []byte(request.Proof)) {
		return errors.New(trustTunnelMultipathAttachProofInvalidText).AtInfo()
	}

	if err := s.addChannelLocked(&trustTunnelMultipathChannel{
		id:       request.ChannelID,
		endpoint: endpoint,
	}); err != nil {
		return err
	}
	s.usedNonces[request.Nonce] = now
	return nil
}

func (s *trustTunnelMultipathSession) cleanupUsedNoncesLocked(cutoff time.Time) {
	if s == nil {
		return
	}
	for nonce, usedAt := range s.usedNonces {
		if usedAt.Before(cutoff) {
			delete(s.usedNonces, nonce)
		}
	}
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

func (r *trustTunnelMultipathSessionRegistry) Count() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}
