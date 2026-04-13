package trusttunnel

import (
	"context"
	"crypto/hmac"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	ReorderWindow int
	GapTimeout    time.Duration
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
	rejoinGrace    time.Duration

	mu         sync.RWMutex
	state      trustTunnelMultipathSessionState
	channels   map[uint32]*trustTunnelMultipathChannel
	usedNonces map[string]time.Time
	readyCh    chan struct{}
	closedCh   chan struct{}
	updatesCh  chan struct{}
	closeErr   error
	startOnce  sync.Once
	closeOnce  sync.Once

	quorumLossGeneration uint64
	reorderWindow        int
	gapTimeout           time.Duration
}

type trustTunnelMultipathChannel struct {
	id          uint32
	endpoint    string
	createdAt   time.Time
	lastSeenAt  time.Time
	closing     bool
	stream      io.ReadWriteCloser
	writeMu     sync.Mutex
	readFrames  uint64
	readBytes   uint64
	writeFrames uint64
	writeBytes  uint64
}

const (
	trustTunnelMultipathPrimaryChannelID     = 1
	trustTunnelMultipathDefaultReorderWindow = 1 << 20
	trustTunnelMultipathDefaultGapTimeout    = 3 * time.Second

	trustTunnelMultipathAttachReplayText       = "trusttunnel multipath attach replay detected"
	trustTunnelMultipathAttachExpiredText      = "trusttunnel multipath attach window expired"
	trustTunnelMultipathAttachTargetMismatch   = "trusttunnel multipath attach target mismatch"
	trustTunnelMultipathAttachProofInvalidText = "trusttunnel multipath attach proof is invalid"
	trustTunnelMultipathDuplicateChannelText   = "trusttunnel multipath channel already exists"
	trustTunnelMultipathChannelLimitText       = "trusttunnel multipath channel limit reached"
	trustTunnelMultipathChannelQuorumLostText  = "trusttunnel multipath channel quorum lost"
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
	reorderWindow := options.ReorderWindow
	if reorderWindow <= 0 {
		reorderWindow = trustTunnelMultipathDefaultReorderWindow
	}
	gapTimeout := options.GapTimeout
	if gapTimeout <= 0 {
		gapTimeout = trustTunnelMultipathDefaultGapTimeout
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
		readyCh:        make(chan struct{}),
		closedCh:       make(chan struct{}),
		updatesCh:      make(chan struct{}, 1),
		rejoinGrace:    attachTimeout,
		reorderWindow:  reorderWindow,
		gapTimeout:     gapTimeout,
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
	prevState := s.state
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
		s.quorumLossGeneration++
		s.markReadyLocked()
	} else {
		if s.readyReachedLocked() {
			s.state = trustTunnelMultipathSessionDegraded
		} else {
			s.state = trustTunnelMultipathSessionOpening
		}
	}
	s.notifyUpdatedLocked()
	if prevState == trustTunnelMultipathSessionDegraded && s.state == trustTunnelMultipathSessionActive {
		errors.LogInfo(context.Background(), "trusttunnel multipath quorum restored session=", s.id, " channels=", len(s.channels))
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
		if s.readyReachedLocked() {
			s.state = trustTunnelMultipathSessionDegraded
		} else {
			s.state = trustTunnelMultipathSessionOpening
		}
		s.notifyUpdatedLocked()
		return
	}
	if uint32(len(s.channels)) < s.minChannels {
		s.state = trustTunnelMultipathSessionDegraded
	}
	s.notifyUpdatedLocked()
}

func (s *trustTunnelMultipathSession) HandleChannelFailure(channelID uint32, cause error) error {
	if s == nil {
		return cause
	}

	var channel *trustTunnelMultipathChannel
	var remaining int
	var minChannels uint32
	var strict bool
	var startGrace bool
	var grace time.Duration
	var generation uint64
	var sessionWasReady bool

	s.mu.Lock()
	sessionWasReady = s.readyReachedLocked()
	channel = s.channels[channelID]
	if channel != nil {
		delete(s.channels, channelID)
		channel.closing = true
	}
	remaining = len(s.channels)
	minChannels = s.minChannels
	strict = s.strict
	switch {
	case remaining == 0:
		if sessionWasReady {
			s.state = trustTunnelMultipathSessionDegraded
		} else {
			s.state = trustTunnelMultipathSessionOpening
		}
	case uint32(remaining) < s.minChannels:
		if sessionWasReady {
			s.state = trustTunnelMultipathSessionDegraded
			if strict {
				s.quorumLossGeneration++
				generation = s.quorumLossGeneration
				startGrace = true
				grace = s.rejoinGrace
			}
		} else {
			s.state = trustTunnelMultipathSessionOpening
		}
	default:
		s.state = trustTunnelMultipathSessionActive
	}
	s.notifyUpdatedLocked()
	s.mu.Unlock()

	if channel != nil && channel.stream != nil {
		_ = channel.stream.Close()
	}

	if startGrace {
		errors.LogWarning(context.Background(), "trusttunnel multipath quorum degraded session=", s.id, " got=", remaining, " want=", minChannels, "; waiting ", grace)
		s.startQuorumLossGrace(generation, cause)
	}

	return nil
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

	if !s.attachDeadline.IsZero() && now.After(s.attachDeadline) && !s.readyReachedLocked() {
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

func (s *trustTunnelMultipathSession) SetChannelStream(channelID uint32, stream io.ReadWriteCloser) error {
	if s == nil {
		return errors.New("trusttunnel multipath session is nil").AtInfo()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	channel, exists := s.channels[channelID]
	if !exists || channel == nil {
		return errors.New("trusttunnel multipath channel is unknown").AtInfo()
	}
	channel.stream = stream
	channel.lastSeenAt = time.Now()
	s.notifyUpdatedLocked()
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

func (s *trustTunnelMultipathSession) markReadyLocked() {
	if s == nil {
		return
	}
	select {
	case <-s.readyCh:
	default:
		close(s.readyCh)
	}
}

func (s *trustTunnelMultipathSession) Ready() <-chan struct{} {
	if s == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return s.readyCh
}

func (s *trustTunnelMultipathSession) Closed() <-chan struct{} {
	if s == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return s.closedCh
}

func (s *trustTunnelMultipathSession) Updates() <-chan struct{} {
	if s == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return s.updatesCh
}

func (s *trustTunnelMultipathSession) Close(err error) {
	if s == nil {
		return
	}

	var channels []*trustTunnelMultipathChannel
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.state = trustTunnelMultipathSessionClosing
		s.closeErr = err
		channels = make([]*trustTunnelMultipathChannel, 0, len(s.channels))
		for _, channel := range s.channels {
			channels = append(channels, channel)
		}
		s.notifyUpdatedLocked()
		s.mu.Unlock()

		for _, channel := range channels {
			if channel == nil || channel.stream == nil {
				continue
			}
			_ = channel.stream.Close()
		}

		close(s.closedCh)
	})
}

func (s *trustTunnelMultipathSession) CloseErr() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closeErr
}

func (s *trustTunnelMultipathSession) IsClosed() bool {
	if s == nil {
		return true
	}
	select {
	case <-s.closedCh:
		return true
	default:
		return false
	}
}

func (s *trustTunnelMultipathSession) ChannelSnapshot() []*trustTunnelMultipathChannel {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]int, 0, len(s.channels))
	for channelID := range s.channels {
		ids = append(ids, int(channelID))
	}
	sort.Ints(ids)

	channels := make([]*trustTunnelMultipathChannel, 0, len(ids))
	for _, channelID := range ids {
		if channel := s.channels[uint32(channelID)]; channel != nil {
			channels = append(channels, channel)
		}
	}
	return channels
}

func (s *trustTunnelMultipathSession) ReorderWindow() int {
	if s == nil {
		return trustTunnelMultipathDefaultReorderWindow
	}
	return s.reorderWindow
}

func (s *trustTunnelMultipathSession) GapTimeout() time.Duration {
	if s == nil {
		return trustTunnelMultipathDefaultGapTimeout
	}
	return s.gapTimeout
}

func (s *trustTunnelMultipathSession) MinChannels() uint32 {
	if s == nil {
		return 0
	}
	return s.minChannels
}

func (s *trustTunnelMultipathSession) Strict() bool {
	if s == nil {
		return false
	}
	return s.strict
}

func (s *trustTunnelMultipathSession) WaitForQuorum(ctx context.Context) error {
	if s == nil || !s.strict {
		return nil
	}

	for {
		s.mu.RLock()
		enough := len(s.channels) >= int(s.minChannels)
		closeErr := s.closeErr
		updatesCh := s.updatesCh
		closedCh := s.closedCh
		s.mu.RUnlock()

		if enough {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-closedCh:
			if closeErr != nil {
				return closeErr
			}
			return io.EOF
		case <-updatesCh:
		}
	}
}

func (s *trustTunnelMultipathSession) readyReachedLocked() bool {
	if s == nil {
		return false
	}
	select {
	case <-s.readyCh:
		return true
	default:
		return false
	}
}

func (s *trustTunnelMultipathSession) notifyUpdatedLocked() {
	if s == nil {
		return
	}
	select {
	case s.updatesCh <- struct{}{}:
	default:
	}
}

func (s *trustTunnelMultipathSession) startQuorumLossGrace(generation uint64, cause error) {
	if s == nil {
		return
	}
	if s.rejoinGrace <= 0 {
		s.Close(newTrustTunnelMultipathQuorumLostError(0, s.minChannels, cause))
		return
	}

	go func() {
		timer := time.NewTimer(s.rejoinGrace)
		defer timer.Stop()

		select {
		case <-s.closedCh:
			return
		case <-timer.C:
		}

		s.mu.RLock()
		remaining := len(s.channels)
		minChannels := s.minChannels
		state := s.state
		stillCurrent := s.quorumLossGeneration == generation
		s.mu.RUnlock()

		if state != trustTunnelMultipathSessionDegraded || !stillCurrent || uint32(remaining) >= minChannels {
			return
		}

		err := newTrustTunnelMultipathQuorumLostError(remaining, minChannels, cause)
		errors.LogWarningInner(context.Background(), err, "trusttunnel multipath quorum grace expired")
		s.Close(err)
	}()
}

func newTrustTunnelMultipathQuorumLostError(remaining int, minChannels uint32, cause error) error {
	if cause == nil {
		return errors.New(trustTunnelMultipathChannelQuorumLostText, ": got ", remaining, ", want ", minChannels).AtWarning()
	}
	return errors.New(trustTunnelMultipathChannelQuorumLostText, ": got ", remaining, ", want ", minChannels).Base(cause).AtWarning()
}

func (c *trustTunnelMultipathChannel) noteRead(payloadLen int) {
	if c == nil {
		return
	}
	atomic.AddUint64(&c.readFrames, 1)
	if payloadLen > 0 {
		atomic.AddUint64(&c.readBytes, uint64(payloadLen))
	}
}

func (c *trustTunnelMultipathChannel) noteWrite(payloadLen int) {
	if c == nil {
		return
	}
	atomic.AddUint64(&c.writeFrames, 1)
	if payloadLen > 0 {
		atomic.AddUint64(&c.writeBytes, uint64(payloadLen))
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
