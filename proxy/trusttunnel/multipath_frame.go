package trusttunnel

import (
	"encoding/binary"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

const (
	trustTunnelMultipathFrameMagic      uint32 = 0x4d505431
	trustTunnelMultipathFrameHeaderSize        = 20
	trustTunnelMultipathFrameMaxPayload        = 32 * 1024
	trustTunnelMultipathFrameFlagFIN    uint8  = 1 << 0
)

type trustTunnelMultipathFrame struct {
	Seq     uint64
	Flags   uint8
	Payload []byte
}

type trustTunnelMultipathStream struct {
	session   *trustTunnelMultipathSession
	recv      *trustTunnelMultipathFrameReassembler
	send      *trustTunnelMultipathFrameWriter
	closeOnce sync.Once
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
	closed      bool
	eof         bool
	err         error
}

type trustTunnelMultipathFrameWriter struct {
	mu         sync.Mutex
	channels   []*trustTunnelMultipathChannel
	nextSeq    uint64
	nextChan   int
	finSent    bool
	closed     bool
	maxPayload int
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

	reassembler := newTrustTunnelMultipathFrameReassembler(session.ReorderWindow())
	writer := newTrustTunnelMultipathFrameWriter(channels)
	stream := &trustTunnelMultipathStream{
		session: session,
		recv:    reassembler,
		send:    writer,
	}

	for _, channel := range channels {
		go stream.runChannelReader(channel)
	}

	return stream, nil
}

func newTrustTunnelMultipathFrameReassembler(windowBytes int) *trustTunnelMultipathFrameReassembler {
	if windowBytes <= 0 {
		windowBytes = trustTunnelMultipathDefaultReorderWindow
	}
	r := &trustTunnelMultipathFrameReassembler{
		pending:     make(map[uint64]*trustTunnelMultipathFrame),
		windowBytes: windowBytes,
	}
	r.cond = sync.NewCond(&r.mu)
	return r
}

func newTrustTunnelMultipathFrameWriter(channels []*trustTunnelMultipathChannel) *trustTunnelMultipathFrameWriter {
	return &trustTunnelMultipathFrameWriter{
		channels:   channels,
		maxPayload: trustTunnelMultipathFrameMaxPayload,
	}
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
			if err == io.EOF {
				s.close(errors.New("trusttunnel multipath channel closed unexpectedly"))
			} else {
				s.close(errors.New("failed to read trusttunnel multipath frame").Base(err))
			}
			return
		}
		if err := s.recv.PushFrame(frame); err != nil {
			s.close(err)
			return
		}
	}
}

func (w *trustTunnelMultipathFrameWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, io.ErrClosedPipe
	}
	if len(w.channels) == 0 {
		return 0, errors.New("trusttunnel multipath writer has no channels")
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
		if err := w.writeFrameLocked(frame); err != nil {
			return written, err
		}
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
	w.nextSeq++
	w.finSent = true
	return nil
}

func (w *trustTunnelMultipathFrameWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
}

func (w *trustTunnelMultipathFrameWriter) writeFrameLocked(frame *trustTunnelMultipathFrame) error {
	if len(w.channels) == 0 {
		return errors.New("trusttunnel multipath writer has no channels")
	}
	channel := w.channels[w.nextChan%len(w.channels)]
	w.nextChan = (w.nextChan + 1) % len(w.channels)
	if channel == nil || channel.stream == nil {
		return errors.New("trusttunnel multipath channel stream is unavailable")
	}
	return channel.writeFrame(frame)
}

func (r *trustTunnelMultipathFrameReassembler) PushFrame(frame *trustTunnelMultipathFrame) error {
	if frame == nil {
		return errors.New("trusttunnel multipath frame is nil")
	}
	if len(frame.Payload) > trustTunnelMultipathFrameMaxPayload {
		return errors.New("trusttunnel multipath frame payload is too large")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		if r.err != nil {
			return r.err
		}
		return io.EOF
	}
	if frame.Seq < r.nextSeq {
		return errors.New("trusttunnel multipath frame sequence regressed")
	}
	if _, exists := r.pending[frame.Seq]; exists {
		return errors.New("trusttunnel multipath frame sequence duplicated")
	}
	if r.pendingSize+len(frame.Payload) > r.windowBytes {
		r.closed = true
		r.err = errors.New("trusttunnel multipath reorder window exceeded")
		r.cond.Broadcast()
		return r.err
	}

	r.pending[frame.Seq] = frame
	r.pendingSize += len(frame.Payload)
	r.cond.Broadcast()
	return nil
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
	r.mu.Lock()
	defer r.mu.Unlock()

	for {
		if r.current == nil {
			if frame, ok := r.pending[r.nextSeq]; ok {
				delete(r.pending, r.nextSeq)
				r.pendingSize -= len(frame.Payload)
				r.current = frame
				r.currentOff = 0
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
					if fin {
						r.closed = true
						r.eof = true
					}
				}
				return n, nil
			}

			fin := r.current.Flags&trustTunnelMultipathFrameFlagFIN != 0
			r.current = nil
			r.currentOff = 0
			r.nextSeq++
			if fin {
				r.closed = true
				r.eof = true
			}
			continue
		}

		if r.closed {
			if r.err != nil {
				return 0, r.err
			}
			return 0, io.EOF
		}

		r.cond.Wait()
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
