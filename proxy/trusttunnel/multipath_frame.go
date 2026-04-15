package trusttunnel

import (
	"context"
	"encoding/binary"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	trustTunnelMultipathFrameMagic          uint32 = 0x4d505431
	trustTunnelMultipathFrameHeaderSize            = 20
	trustTunnelMultipathFrameMaxPayload            = 32 * 1024
	trustTunnelMultipathFrameFlagFIN        uint8  = 1 << 0
	trustTunnelMultipathFrameFlagControl    uint8  = 1 << 1
	trustTunnelMultipathControlWriteTimeout        = 100 * time.Millisecond
)

type trustTunnelMultipathFrame struct {
	Seq     uint64
	Flags   uint8
	Payload []byte
}

const (
	trustTunnelMultipathControlChannelClosed  uint8 = 1
	trustTunnelMultipathControlSessionClosing uint8 = 2
	trustTunnelMultipathControlAck            uint8 = 3
	trustTunnelMultipathControlResendFrom     uint8 = 4

	trustTunnelMultipathControlCloseReasonNormal     uint8 = 0
	trustTunnelMultipathControlCloseReasonQuorumLost uint8 = 1
)

type trustTunnelMultipathStream struct {
	session   *trustTunnelMultipathSession
	recv      *trustTunnelMultipathFrameReassembler
	send      *trustTunnelMultipathFrameWriter
	closeOnce sync.Once
	readerMu  sync.Mutex
	readers   map[uint32]struct{}
}

type trustTunnelMultipathFrameReassembler struct {
	mu          sync.Mutex
	cond        *sync.Cond
	nextSeq     uint64
	current     *trustTunnelMultipathFrame
	currentOff  int
	pending     map[uint64]*trustTunnelMultipathFrame
	pendingSize int
	windowBytes int
	gapTimeout  time.Duration
	onAdvance   func(uint64)
	onGap       func(uint64) bool
	closed      bool
	eof         bool
	err         error
}

type trustTunnelMultipathFrameWriter struct {
	mu         sync.Mutex
	cond       *sync.Cond
	session    *trustTunnelMultipathSession
	nextSeq    uint64
	nextChan   int
	finSent    bool
	closed     bool
	maxPayload int
	maxInFlightBytes int
	sentBytes        int
	sent       map[uint64]*trustTunnelMultipathFrame
}

func newTrustTunnelMultipathStream(session *trustTunnelMultipathSession) (*trustTunnelMultipathStream, error) {
	if session == nil {
		return nil, errors.New("trusttunnel multipath session is nil")
	}

	channels := session.ChannelSnapshot()
	if len(channels) < int(session.minChannels) {
		return nil, errors.New("trusttunnel multipath session does not have enough active channels")
	}
	for _, channel := range channels {
		if channel == nil || channel.stream == nil {
			return nil, errors.New("trusttunnel multipath channel stream is unavailable")
		}
	}

	reassembler := newTrustTunnelMultipathFrameReassembler(session.ReorderWindow(), session.GapTimeout())
	writer := newTrustTunnelMultipathFrameWriter(session)
	stream := &trustTunnelMultipathStream{
		session: session,
		recv:    reassembler,
		send:    writer,
		readers: make(map[uint32]struct{}),
	}
	reassembler.onAdvance = stream.sendAck
	reassembler.onGap = stream.requestResend

	stream.startAvailableReaders(channels)
	go stream.watchSessionChannels()

	return stream, nil
}

func newTrustTunnelMultipathFrameReassembler(windowBytes int, gapTimeout time.Duration) *trustTunnelMultipathFrameReassembler {
	if windowBytes <= 0 {
		windowBytes = trustTunnelMultipathDefaultReorderWindow
	}
	if gapTimeout <= 0 {
		gapTimeout = trustTunnelMultipathDefaultGapTimeout
	}
	r := &trustTunnelMultipathFrameReassembler{
		pending:     make(map[uint64]*trustTunnelMultipathFrame),
		windowBytes: windowBytes,
		gapTimeout:  gapTimeout,
	}
	r.cond = sync.NewCond(&r.mu)
	return r
}

func newTrustTunnelMultipathFrameWriter(session *trustTunnelMultipathSession) *trustTunnelMultipathFrameWriter {
	maxInFlightBytes := trustTunnelMultipathDefaultReorderWindow
	if session != nil && session.ReorderWindow() > 0 {
		maxInFlightBytes = session.ReorderWindow()
	}
	writer := &trustTunnelMultipathFrameWriter{
		session:    session,
		maxPayload: trustTunnelMultipathFrameMaxPayload,
		maxInFlightBytes: maxInFlightBytes,
		sent:       make(map[uint64]*trustTunnelMultipathFrame),
	}
	writer.cond = sync.NewCond(&writer.mu)
	return writer
}

func (s *trustTunnelMultipathStream) Read(p []byte) (int, error) {
	if s == nil || s.recv == nil {
		return 0, io.EOF
	}
	return s.recv.Read(p)
}

func (s *trustTunnelMultipathStream) Write(p []byte) (int, error) {
	if s == nil || s.send == nil {
		return 0, io.EOF
	}
	return s.send.Write(p)
}

func (s *trustTunnelMultipathStream) CloseWrite() error {
	if s == nil || s.send == nil {
		return io.EOF
	}
	return s.send.CloseWrite()
}

func (s *trustTunnelMultipathStream) sendAck(nextSeq uint64) {
	if s == nil || s.send == nil {
		return
	}
	if err := s.send.SendAck(nextSeq); err != nil && s.session != nil && !s.session.IsClosed() {
		errors.LogDebugInner(context.Background(), err, "trusttunnel multipath failed to send ack")
	}
}

func (s *trustTunnelMultipathStream) requestResend(nextSeq uint64) bool {
	if s == nil || s.send == nil {
		return false
	}
	if err := s.send.RequestResendFrom(nextSeq); err != nil {
		if s.session != nil && !s.session.IsClosed() {
			errors.LogWarningInner(context.Background(), err, "trusttunnel multipath failed to request resend")
		}
		return false
	}
	return true
}

func (s *trustTunnelMultipathStream) Close() error {
	if s == nil {
		return nil
	}
	s.close(nil)
	return nil
}

func (s *trustTunnelMultipathStream) close(err error) {
	s.closeOnce.Do(func() {
		if s.send != nil {
			s.send.Close()
		}
		if s.recv != nil {
			s.recv.CloseWithError(err)
		}
		if s.session != nil {
			s.session.Close(err)
		}
	})
}

func (s *trustTunnelMultipathStream) closeRemote(err error) {
	s.closeOnce.Do(func() {
		if s.send != nil {
			s.send.Close()
		}
		if s.recv != nil {
			s.recv.CloseWithError(err)
		}
		if s.session != nil {
			s.session.close(err, false)
		}
	})
}

func (s *trustTunnelMultipathStream) watchSessionChannels() {
	if s == nil || s.session == nil {
		return
	}

	for {
		select {
		case <-s.session.Closed():
			if s.recv != nil {
				s.recv.CloseWithError(s.session.CloseErr())
			}
			return
		case <-s.session.Updates():
			s.startAvailableReaders(nil)
		}
	}
}

func (s *trustTunnelMultipathStream) startAvailableReaders(snapshot []*trustTunnelMultipathChannel) {
	if s == nil || s.session == nil {
		return
	}
	if snapshot == nil {
		snapshot = s.session.ChannelSnapshot()
	}

	for _, channel := range snapshot {
		if channel == nil || channel.stream == nil || channel.closing {
			continue
		}

		s.readerMu.Lock()
		if _, exists := s.readers[channel.id]; exists {
			s.readerMu.Unlock()
			continue
		}
		s.readers[channel.id] = struct{}{}
		s.readerMu.Unlock()

		go s.runChannelReader(channel)
	}
}

func (s *trustTunnelMultipathStream) runChannelReader(channel *trustTunnelMultipathChannel) {
	if s == nil || channel == nil || channel.stream == nil {
		s.close(errors.New("trusttunnel multipath channel stream is unavailable"))
		return
	}

	for {
		frame, err := trustTunnelReadMultipathFrame(channel.stream)
		if err != nil {
			if s.session != nil && s.session.IsClosed() {
				return
			}
			channelErr := err
			if err == io.EOF {
				channelErr = errors.New("trusttunnel multipath channel closed unexpectedly")
			} else {
				channelErr = errors.New("failed to read trusttunnel multipath frame").Base(err)
			}
			if s.session != nil {
				if closeErr := s.session.HandleChannelFailure(channel.id, channelErr); closeErr != nil {
					errors.LogWarningInner(context.Background(), closeErr, "trusttunnel multipath stream closing after channel failure")
					s.close(closeErr)
				} else if s.send != nil && s.session.State() != trustTunnelMultipathSessionClosing {
					s.send.NotifyChannelClosed(channel.id)
				}
			}
			return
		}
		if frame.Flags&trustTunnelMultipathFrameFlagControl != 0 {
			stop, err := s.handleControlFrame(frame)
			if err != nil {
				errors.LogWarningInner(context.Background(), err, "trusttunnel multipath control frame handling failed")
				s.close(err)
				return
			}
			if stop {
				return
			}
			continue
		}
		channel.noteRead(len(frame.Payload))
		if err := s.recv.PushFrame(frame); err != nil {
			errors.LogWarningInner(context.Background(), err, "trusttunnel multipath stream reassembly failed")
			s.close(err)
			return
		}
	}
}

func (s *trustTunnelMultipathStream) handleControlFrame(frame *trustTunnelMultipathFrame) (bool, error) {
	if s == nil || s.session == nil || frame == nil {
		return false, nil
	}
	if len(frame.Payload) == 0 {
		return false, errors.New("trusttunnel multipath control frame is too short")
	}

	switch frame.Payload[0] {
	case trustTunnelMultipathControlChannelClosed:
		if len(frame.Payload) < 5 {
			return false, errors.New("trusttunnel multipath channel-closed control frame is too short")
		}
		channelID := binary.BigEndian.Uint32(frame.Payload[1:5])
		if closeErr := s.session.HandleChannelFailure(channelID, errors.New("peer reported trusttunnel multipath channel loss")); closeErr != nil {
			return false, closeErr
		}
		return false, nil
	case trustTunnelMultipathControlSessionClosing:
		if len(frame.Payload) < 2 {
			return false, errors.New("trusttunnel multipath session-closing control frame is too short")
		}
		err := trustTunnelMultipathSessionCloseErrorFromReason(frame.Payload[1])
		s.closeRemote(err)
		return true, nil
	case trustTunnelMultipathControlAck:
		if len(frame.Payload) < 9 {
			return false, errors.New("trusttunnel multipath ack control frame is too short")
		}
		if s.send != nil {
			s.send.Ack(binary.BigEndian.Uint64(frame.Payload[1:9]))
		}
		return false, nil
	case trustTunnelMultipathControlResendFrom:
		if len(frame.Payload) < 9 {
			return false, errors.New("trusttunnel multipath resend-from control frame is too short")
		}
		if s.send != nil {
			if err := s.send.RetransmitFrom(binary.BigEndian.Uint64(frame.Payload[1:9])); err != nil {
				return false, err
			}
		}
		return false, nil
	default:
		return false, errors.New("trusttunnel multipath control frame type is unsupported")
	}
}

func (w *trustTunnelMultipathFrameWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}

	written := 0
	for written < len(p) {
		chunkLen := len(p) - written
		if chunkLen > w.maxPayload {
			chunkLen = w.maxPayload
		}
		frame := &trustTunnelMultipathFrame{
			Seq:     w.nextSeq,
			Payload: append([]byte(nil), p[written:written+chunkLen]...),
		}
		if err := w.waitForSendWindowLocked(len(frame.Payload)); err != nil {
			return written, err
		}
		if err := w.writeFrameLocked(frame); err != nil {
			return written, err
		}
		w.trackFrameLocked(frame)
		w.nextSeq++
		written += chunkLen
	}

	return written, nil
}

func (w *trustTunnelMultipathFrameWriter) CloseWrite() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed || w.finSent {
		return nil
	}
	frame := &trustTunnelMultipathFrame{
		Seq:   w.nextSeq,
		Flags: trustTunnelMultipathFrameFlagFIN,
	}
	if err := w.writeFrameLocked(frame); err != nil {
		return err
	}
	w.trackFrameLocked(frame)
	w.nextSeq++
	w.finSent = true
	return nil
}

func (w *trustTunnelMultipathFrameWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	if w.cond != nil {
		w.cond.Broadcast()
	}
}

func (w *trustTunnelMultipathFrameWriter) NotifyChannelClosed(channelID uint32) {
	if w == nil || channelID == 0 {
		return
	}

	frame := trustTunnelMultipathChannelClosedControlFrame(channelID)
	go func() {
		if err := w.writeControlFrame(frame); err != nil {
			errors.LogWarningInner(context.Background(), err, "trusttunnel multipath failed to notify peer about lost channel")
		}
	}()
}

func (w *trustTunnelMultipathFrameWriter) SendAck(nextSeq uint64) error {
	return w.writeControlFrame(trustTunnelMultipathAckControlFrame(nextSeq))
}

func (w *trustTunnelMultipathFrameWriter) RequestResendFrom(nextSeq uint64) error {
	return w.writeControlFrame(trustTunnelMultipathResendFromControlFrame(nextSeq))
}

func (w *trustTunnelMultipathFrameWriter) Ack(nextSeq uint64) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	for seq := range w.sent {
		if seq >= nextSeq {
			continue
		}
		w.sentBytesSubtractLocked(w.sent[seq])
		delete(w.sent, seq)
	}
	if w.cond != nil {
		w.cond.Broadcast()
	}
}

func (w *trustTunnelMultipathFrameWriter) RetransmitFrom(nextSeq uint64) error {
	if w == nil {
		return errors.New("trusttunnel multipath writer has no session")
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.sent) == 0 {
		return nil
	}

	seqs := make([]uint64, 0, len(w.sent))
	for seq := range w.sent {
		if seq >= nextSeq {
			seqs = append(seqs, seq)
		}
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for _, seq := range seqs {
		frame := w.sent[seq]
		if frame == nil {
			continue
		}
		if err := w.writeFrameLocked(frame); err != nil {
			return err
		}
	}
	return nil
}

func trustTunnelMultipathChannelClosedControlFrame(channelID uint32) *trustTunnelMultipathFrame {
	payload := make([]byte, 5)
	payload[0] = trustTunnelMultipathControlChannelClosed
	binary.BigEndian.PutUint32(payload[1:5], channelID)
	return &trustTunnelMultipathFrame{
		Flags:   trustTunnelMultipathFrameFlagControl,
		Payload: payload,
	}
}

func trustTunnelMultipathAckControlFrame(nextSeq uint64) *trustTunnelMultipathFrame {
	payload := make([]byte, 9)
	payload[0] = trustTunnelMultipathControlAck
	binary.BigEndian.PutUint64(payload[1:9], nextSeq)
	return &trustTunnelMultipathFrame{
		Flags:   trustTunnelMultipathFrameFlagControl,
		Payload: payload,
	}
}

func trustTunnelMultipathResendFromControlFrame(nextSeq uint64) *trustTunnelMultipathFrame {
	payload := make([]byte, 9)
	payload[0] = trustTunnelMultipathControlResendFrom
	binary.BigEndian.PutUint64(payload[1:9], nextSeq)
	return &trustTunnelMultipathFrame{
		Flags:   trustTunnelMultipathFrameFlagControl,
		Payload: payload,
	}
}

func trustTunnelMultipathSessionClosingControlFrame(reason uint8) *trustTunnelMultipathFrame {
	return &trustTunnelMultipathFrame{
		Flags:   trustTunnelMultipathFrameFlagControl,
		Payload: []byte{trustTunnelMultipathControlSessionClosing, reason},
	}
}

func trustTunnelMultipathSessionCloseErrorFromReason(reason uint8) error {
	switch reason {
	case trustTunnelMultipathControlCloseReasonNormal:
		return io.EOF
	case trustTunnelMultipathControlCloseReasonQuorumLost:
		return errors.New(trustTunnelMultipathChannelQuorumLostText).AtWarning()
	default:
		return errors.New("trusttunnel multipath peer closed session").AtWarning()
	}
}

func (w *trustTunnelMultipathFrameWriter) writeFrameLocked(frame *trustTunnelMultipathFrame) error {
	if w.session == nil {
		return errors.New("trusttunnel multipath writer has no session")
	}

	for {
		channels := w.session.ChannelSnapshot()
		if len(channels) == 0 {
			if err := w.session.WaitForQuorum(context.Background()); err != nil {
				return err
			}
			continue
		}
		if w.session.Strict() && len(channels) < int(w.session.MinChannels()) {
			if err := w.session.WaitForQuorum(context.Background()); err != nil {
				return err
			}
			continue
		}
		if w.nextChan >= len(channels) {
			w.nextChan = 0
		}

		channel := channels[w.nextChan%len(channels)]
		w.nextChan = (w.nextChan + 1) % len(channels)
		if channel == nil || channel.stream == nil {
			continue
		}
		if err := channel.writeFrame(frame); err != nil {
			if closeErr := w.session.HandleChannelFailure(channel.id, err); closeErr != nil {
				errors.LogWarningInner(context.Background(), closeErr, "trusttunnel multipath stream write path lost quorum")
				return closeErr
			}
			w.NotifyChannelClosed(channel.id)
			continue
		}
		channel.noteWrite(len(frame.Payload))
		return nil
	}
}

func (w *trustTunnelMultipathFrameWriter) writeControlFrame(frame *trustTunnelMultipathFrame) error {
	if w == nil || w.session == nil {
		return errors.New("trusttunnel multipath writer has no session")
	}

	channels := w.session.ChannelSnapshot()
	if len(channels) == 0 {
		return errors.New("trusttunnel multipath writer has no channels")
	}

	for i := 0; i < len(channels); i++ {
		channel := channels[i]
		if channel == nil || channel.stream == nil {
			continue
		}
		if err := channel.writeControlFrame(frame, trustTunnelMultipathControlWriteTimeout); err != nil {
			if closeErr := w.session.HandleChannelFailure(channel.id, err); closeErr != nil {
				return closeErr
			}
			continue
		}
		return nil
	}

	return errors.New("trusttunnel multipath writer could not deliver control frame")
}

func (w *trustTunnelMultipathFrameWriter) trackFrameLocked(frame *trustTunnelMultipathFrame) {
	if w == nil || frame == nil {
		return
	}
	dup := &trustTunnelMultipathFrame{
		Seq:     frame.Seq,
		Flags:   frame.Flags,
		Payload: append([]byte(nil), frame.Payload...),
	}
	w.sent[dup.Seq] = dup
	w.sentBytes += len(dup.Payload)
}

func (w *trustTunnelMultipathFrameWriter) sentBytesSubtractLocked(frame *trustTunnelMultipathFrame) {
	if w == nil || frame == nil {
		return
	}
	w.sentBytes -= len(frame.Payload)
	if w.sentBytes < 0 {
		w.sentBytes = 0
	}
}

func (w *trustTunnelMultipathFrameWriter) waitForSendWindowLocked(frameBytes int) error {
	if w == nil || frameBytes <= 0 || w.maxInFlightBytes <= 0 {
		return nil
	}
	for !w.closed && w.sentBytes+frameBytes > w.maxInFlightBytes {
		if w.cond == nil {
			break
		}
		w.cond.Wait()
	}
	if w.closed {
		return io.ErrClosedPipe
	}
	return nil
}

func (r *trustTunnelMultipathFrameReassembler) PushFrame(frame *trustTunnelMultipathFrame) error {
	if frame == nil {
		return errors.New("trusttunnel multipath frame is nil")
	}
	if len(frame.Payload) > trustTunnelMultipathFrameMaxPayload {
		return errors.New("trusttunnel multipath frame payload is too large")
	}

	waitStarted := time.Time{}
	gapRequested := false

	for {
		var onGap func(uint64) bool
		var gapSeq uint64

		r.mu.Lock()

		if r.closed {
			if r.err != nil {
				err := r.err
				r.mu.Unlock()
				return err
			}
			r.mu.Unlock()
			return io.EOF
		}
		if frame.Seq < r.nextSeq {
			r.mu.Unlock()
			return nil
		}
		if _, exists := r.pending[frame.Seq]; exists {
			r.mu.Unlock()
			return nil
		}
		if frame.Seq == r.nextSeq || r.pendingSize+len(frame.Payload) <= r.windowBytes {
			r.pending[frame.Seq] = frame
			r.pendingSize += len(frame.Payload)
			r.cond.Broadcast()
			r.mu.Unlock()
			return nil
		}
		if !gapRequested && r.onGap != nil {
			onGap = r.onGap
			gapSeq = r.nextSeq
		} else if waitStarted.IsZero() {
			waitStarted = time.Now()
		} else if r.gapTimeout > 0 && time.Since(waitStarted) >= r.gapTimeout {
			r.closed = true
			r.err = errors.New("trusttunnel multipath reorder window exceeded")
			err := r.err
			r.cond.Broadcast()
			r.mu.Unlock()
			return err
		}

		r.mu.Unlock()
		if onGap != nil {
			if onGap(gapSeq) {
				gapRequested = true
				waitStarted = time.Time{}
				continue
			}
		}
		sleepFor := 10 * time.Millisecond
		if r.gapTimeout > 0 && r.gapTimeout < sleepFor {
			sleepFor = r.gapTimeout
		}
		time.Sleep(sleepFor)
	}
}

func (r *trustTunnelMultipathFrameReassembler) CloseWithError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	if err != nil && err != io.EOF {
		r.err = err
	} else {
		r.eof = true
	}
	r.cond.Broadcast()
}

func (r *trustTunnelMultipathFrameReassembler) Read(p []byte) (int, error) {
	waitStarted := time.Time{}
	gapRequested := false

	for {
		var onAdvance func(uint64)
		var advancedSeq uint64
		var onGap func(uint64) bool
		var gapSeq uint64

		r.mu.Lock()
		if r.current == nil {
			if frame, ok := r.pending[r.nextSeq]; ok {
				delete(r.pending, r.nextSeq)
				r.pendingSize -= len(frame.Payload)
				r.cond.Broadcast()
				r.current = frame
				r.currentOff = 0
				waitStarted = time.Time{}
			}
		}

		if r.current != nil {
			if len(r.current.Payload) > r.currentOff {
				n := copy(p, r.current.Payload[r.currentOff:])
				r.currentOff += n
				if r.currentOff == len(r.current.Payload) {
					fin := r.current.Flags&trustTunnelMultipathFrameFlagFIN != 0
					r.current = nil
					r.currentOff = 0
					r.nextSeq++
					onAdvance = r.onAdvance
					advancedSeq = r.nextSeq
					gapRequested = false
					if fin {
						r.closed = true
						r.eof = true
					}
				}
				r.mu.Unlock()
				if onAdvance != nil {
					onAdvance(advancedSeq)
				}
				return n, nil
			}

			fin := r.current.Flags&trustTunnelMultipathFrameFlagFIN != 0
			r.current = nil
			r.currentOff = 0
			r.nextSeq++
			onAdvance = r.onAdvance
			advancedSeq = r.nextSeq
			gapRequested = false
			if fin {
				r.closed = true
				r.eof = true
			}
			r.mu.Unlock()
			if onAdvance != nil {
				onAdvance(advancedSeq)
			}
			continue
		}

		if r.closed {
			if r.err != nil {
				err := r.err
				r.mu.Unlock()
				return 0, err
			}
			r.mu.Unlock()
			return 0, io.EOF
		}

		hasGap := len(r.pending) > 0
		if hasGap {
			if waitStarted.IsZero() {
				waitStarted = time.Now()
			} else if r.gapTimeout > 0 && time.Since(waitStarted) >= r.gapTimeout {
				if !gapRequested && r.onGap != nil {
					onGap = r.onGap
					gapSeq = r.nextSeq
				} else {
					r.closed = true
					r.err = errors.New("trusttunnel multipath reorder gap timed out")
					err := r.err
					r.mu.Unlock()
					return 0, err
				}
			}
		} else {
			waitStarted = time.Time{}
			gapRequested = false
		}

		r.mu.Unlock()
		if onGap != nil {
			if onGap(gapSeq) {
				gapRequested = true
				waitStarted = time.Time{}
				continue
			}
		}
		sleepFor := 10 * time.Millisecond
		if r.gapTimeout > 0 && r.gapTimeout < sleepFor {
			sleepFor = r.gapTimeout
		}
		time.Sleep(sleepFor)
	}
}

func (c *trustTunnelMultipathChannel) writeFrame(frame *trustTunnelMultipathFrame) error {
	if c == nil || c.stream == nil {
		return errors.New("trusttunnel multipath channel stream is unavailable")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return trustTunnelWriteMultipathFrame(c.stream, frame)
}

func (c *trustTunnelMultipathChannel) writeControlFrame(frame *trustTunnelMultipathFrame, timeout time.Duration) error {
	if c == nil || c.stream == nil {
		return errors.New("trusttunnel multipath channel stream is unavailable")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var clearDeadline func()
	if timeout > 0 {
		if deadliner, ok := c.stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = deadliner.SetWriteDeadline(time.Now().Add(timeout))
			clearDeadline = func() {
				_ = deadliner.SetWriteDeadline(time.Time{})
			}
		}
	}
	if clearDeadline != nil {
		defer clearDeadline()
	}

	return trustTunnelWriteMultipathFrame(c.stream, frame)
}

func trustTunnelWriteMultipathFrame(writer io.Writer, frame *trustTunnelMultipathFrame) error {
	if frame == nil {
		return errors.New("trusttunnel multipath frame is nil")
	}
	if len(frame.Payload) > trustTunnelMultipathFrameMaxPayload {
		return errors.New("trusttunnel multipath frame payload is too large")
	}

	header := make([]byte, trustTunnelMultipathFrameHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], trustTunnelMultipathFrameMagic)
	header[4] = frame.Flags
	binary.BigEndian.PutUint64(header[8:16], frame.Seq)
	binary.BigEndian.PutUint32(header[16:20], uint32(len(frame.Payload)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if len(frame.Payload) == 0 {
		return nil
	}
	_, err := writer.Write(frame.Payload)
	return err
}

func trustTunnelReadMultipathFrame(reader io.Reader) (*trustTunnelMultipathFrame, error) {
	header := make([]byte, trustTunnelMultipathFrameHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if magic := binary.BigEndian.Uint32(header[0:4]); magic != trustTunnelMultipathFrameMagic {
		return nil, errors.New("invalid trusttunnel multipath frame magic")
	}

	payloadLen := binary.BigEndian.Uint32(header[16:20])
	if payloadLen > trustTunnelMultipathFrameMaxPayload {
		return nil, errors.New("invalid trusttunnel multipath frame payload length")
	}

	frame := &trustTunnelMultipathFrame{
		Flags: header[4],
		Seq:   binary.BigEndian.Uint64(header[8:16]),
	}
	if payloadLen == 0 {
		return frame, nil
	}

	frame.Payload = make([]byte, payloadLen)
	if _, err := io.ReadFull(reader, frame.Payload); err != nil {
		return nil, err
	}
	return frame, nil
}
