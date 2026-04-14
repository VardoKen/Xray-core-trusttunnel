package trusttunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

func TestTrustTunnelMultipathStreamWritesRoundRobinAcrossChannels(t *testing.T) {
	channel1Client, channel1Server := net.Pipe()
	channel2Client, channel2Server := net.Pipe()
	defer channel1Server.Close()
	defer channel2Server.Close()

	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:          "sess-write",
		Target:      xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:  "1.1.1.1:443",
		MinChannels: 2,
		MaxChannels: 2,
	})
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443", stream: channel1Client}); err != nil {
		t.Fatalf("AddChannel(primary) error: %v", err)
	}
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443", stream: channel2Client}); err != nil {
		t.Fatalf("AddChannel(secondary) error: %v", err)
	}

	stream, err := newTrustTunnelMultipathStream(session)
	if err != nil {
		t.Fatalf("newTrustTunnelMultipathStream() error: %v", err)
	}
	defer stream.Close()

	readFrame := func(conn net.Conn, ch chan<- *trustTunnelMultipathFrame) {
		frame, err := trustTunnelReadMultipathFrame(conn)
		if err != nil {
			t.Errorf("trustTunnelReadMultipathFrame() error: %v", err)
			ch <- nil
			return
		}
		ch <- frame
	}

	frameCh1 := make(chan *trustTunnelMultipathFrame, 1)
	frameCh2 := make(chan *trustTunnelMultipathFrame, 1)
	go readFrame(channel1Server, frameCh1)
	go readFrame(channel2Server, frameCh2)

	payload := bytes.Repeat([]byte("x"), trustTunnelMultipathFrameMaxPayload+16)
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("stream.Write() error: %v", err)
	}

	frame1 := <-frameCh1
	frame2 := <-frameCh2
	if frame1 == nil || frame2 == nil {
		t.Fatal("expected frames on both channels")
	}
	if frame1.Seq != 0 {
		t.Fatalf("channel1 frame seq = %d, want 0", frame1.Seq)
	}
	if frame2.Seq != 1 {
		t.Fatalf("channel2 frame seq = %d, want 1", frame2.Seq)
	}
	if len(frame1.Payload) != trustTunnelMultipathFrameMaxPayload {
		t.Fatalf("channel1 payload len = %d, want %d", len(frame1.Payload), trustTunnelMultipathFrameMaxPayload)
	}
	if len(frame2.Payload) != 16 {
		t.Fatalf("channel2 payload len = %d, want 16", len(frame2.Payload))
	}
}

func TestTrustTunnelMultipathStreamCloseWriteSendsFIN(t *testing.T) {
	channel1Client, channel1Server := net.Pipe()
	channel2Client, channel2Server := net.Pipe()
	defer channel1Server.Close()
	defer channel2Server.Close()

	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:          "sess-closewrite",
		Target:      xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:  "1.1.1.1:443",
		MinChannels: 2,
		MaxChannels: 2,
	})
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443", stream: channel1Client}); err != nil {
		t.Fatalf("AddChannel(primary) error: %v", err)
	}
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443", stream: channel2Client}); err != nil {
		t.Fatalf("AddChannel(secondary) error: %v", err)
	}

	stream, err := newTrustTunnelMultipathStream(session)
	if err != nil {
		t.Fatalf("newTrustTunnelMultipathStream() error: %v", err)
	}
	defer stream.Close()

	frameCh1 := make(chan *trustTunnelMultipathFrame, 1)
	frameCh2 := make(chan *trustTunnelMultipathFrame, 1)
	go func() {
		frame, err := trustTunnelReadMultipathFrame(channel1Server)
		if err != nil {
			frameCh1 <- nil
			return
		}
		frameCh1 <- frame
	}()
	go func() {
		frame, err := trustTunnelReadMultipathFrame(channel2Server)
		if err != nil {
			frameCh2 <- nil
			return
		}
		frameCh2 <- frame
	}()

	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error: %v", err)
	}

	readFrame := func(ch <-chan *trustTunnelMultipathFrame) *trustTunnelMultipathFrame {
		select {
		case frame := <-ch:
			return frame
		case <-time.After(200 * time.Millisecond):
			return nil
		}
	}

	frame1 := readFrame(frameCh1)
	frame2 := readFrame(frameCh2)
	finCount := 0
	for _, frame := range []*trustTunnelMultipathFrame{frame1, frame2} {
		if frame != nil && frame.Flags&trustTunnelMultipathFrameFlagFIN != 0 {
			finCount++
		}
	}
	if finCount != 1 {
		t.Fatalf("CloseWrite() sent FIN on %d channels, want 1", finCount)
	}
}

func TestTrustTunnelMultipathStreamReassemblesOutOfOrderFrames(t *testing.T) {
	channel1Client, channel1Server := net.Pipe()
	channel2Client, channel2Server := net.Pipe()
	defer channel1Server.Close()
	defer channel2Server.Close()

	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:          "sess-read",
		Target:      xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:  "1.1.1.1:443",
		MinChannels: 2,
		MaxChannels: 2,
	})
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443", stream: channel1Client}); err != nil {
		t.Fatalf("AddChannel(primary) error: %v", err)
	}
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443", stream: channel2Client}); err != nil {
		t.Fatalf("AddChannel(secondary) error: %v", err)
	}

	stream, err := newTrustTunnelMultipathStream(session)
	if err != nil {
		t.Fatalf("newTrustTunnelMultipathStream() error: %v", err)
	}
	defer stream.Close()

	go func() {
		_ = trustTunnelWriteMultipathFrame(channel2Server, &trustTunnelMultipathFrame{
			Seq:     1,
			Payload: []byte("beta"),
		})
		time.Sleep(50 * time.Millisecond)
		_ = trustTunnelWriteMultipathFrame(channel1Server, &trustTunnelMultipathFrame{
			Seq:     0,
			Payload: []byte("alpha"),
		})
		_ = trustTunnelWriteMultipathFrame(channel2Server, &trustTunnelMultipathFrame{
			Seq:   2,
			Flags: trustTunnelMultipathFrameFlagFIN,
		})
	}()

	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if string(got) != "alphabeta" {
		t.Fatalf("payload = %q, want %q", string(got), "alphabeta")
	}
}

func TestTrustTunnelMultipathReassemblerGapTimeout(t *testing.T) {
	reassembler := newTrustTunnelMultipathFrameReassembler(1024, 25*time.Millisecond)
	if err := reassembler.PushFrame(&trustTunnelMultipathFrame{
		Seq:     1,
		Payload: []byte("beta"),
	}); err != nil {
		t.Fatalf("PushFrame() error: %v", err)
	}

	start := time.Now()
	buf := make([]byte, 8)
	_, err := reassembler.Read(buf)
	if err == nil {
		t.Fatal("expected gap-timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "reorder gap timed out") {
		t.Fatalf("unexpected error: %v", err)
	}
	if time.Since(start) < 20*time.Millisecond {
		t.Fatalf("gap timeout fired too early: %v", time.Since(start))
	}
}

func TestTrustTunnelMultipathReassemblerRequestsResendBeforeTimingOut(t *testing.T) {
	reassembler := newTrustTunnelMultipathFrameReassembler(1024, 25*time.Millisecond)
	reassembler.onGap = func(nextSeq uint64) bool {
		if nextSeq != 0 {
			t.Fatalf("onGap(nextSeq) = %d, want 0", nextSeq)
		}
		go func() {
			time.Sleep(5 * time.Millisecond)
			_ = reassembler.PushFrame(&trustTunnelMultipathFrame{
				Seq:     0,
				Payload: []byte("alpha"),
			})
			_ = reassembler.PushFrame(&trustTunnelMultipathFrame{
				Seq:   2,
				Flags: trustTunnelMultipathFrameFlagFIN,
			})
		}()
		return true
	}
	if err := reassembler.PushFrame(&trustTunnelMultipathFrame{
		Seq:     1,
		Payload: []byte("beta"),
	}); err != nil {
		t.Fatalf("PushFrame(seq1) error: %v", err)
	}

	payload, err := io.ReadAll(reassemblerReader{reassembler: reassembler})
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if string(payload) != "alphabeta" {
		t.Fatalf("payload = %q, want %q", string(payload), "alphabeta")
	}
}

func TestTrustTunnelMultipathReassemblerIgnoresDuplicateRetransmitFrame(t *testing.T) {
	reassembler := newTrustTunnelMultipathFrameReassembler(1024, 200*time.Millisecond)
	if err := reassembler.PushFrame(&trustTunnelMultipathFrame{
		Seq:     1,
		Payload: []byte("beta"),
	}); err != nil {
		t.Fatalf("PushFrame(seq1) error: %v", err)
	}
	if err := reassembler.PushFrame(&trustTunnelMultipathFrame{
		Seq:     0,
		Payload: []byte("alpha"),
	}); err != nil {
		t.Fatalf("PushFrame(seq0) error: %v", err)
	}
	if err := reassembler.PushFrame(&trustTunnelMultipathFrame{
		Seq:     1,
		Payload: []byte("beta"),
	}); err != nil {
		t.Fatalf("duplicate PushFrame(seq1) error: %v", err)
	}
	if err := reassembler.PushFrame(&trustTunnelMultipathFrame{
		Seq:   2,
		Flags: trustTunnelMultipathFrameFlagFIN,
	}); err != nil {
		t.Fatalf("PushFrame(fin) error: %v", err)
	}

	payload, err := io.ReadAll(reassemblerReader{reassembler: reassembler})
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if string(payload) != "alphabeta" {
		t.Fatalf("payload = %q, want %q", string(payload), "alphabeta")
	}
}

func TestTrustTunnelMultipathReassemblerDoesNotTimeoutOnIdleWithoutGap(t *testing.T) {
	reassembler := newTrustTunnelMultipathFrameReassembler(1024, 25*time.Millisecond)

	readCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		payload, err := io.ReadAll(reassemblerReader{reassembler: reassembler})
		if err != nil {
			errCh <- err
			return
		}
		readCh <- payload
	}()

	time.Sleep(60 * time.Millisecond)
	if err := reassembler.PushFrame(&trustTunnelMultipathFrame{
		Seq:     0,
		Payload: []byte("idle-ok"),
	}); err != nil {
		t.Fatalf("PushFrame(seq0) error: %v", err)
	}
	if err := reassembler.PushFrame(&trustTunnelMultipathFrame{
		Seq:   1,
		Flags: trustTunnelMultipathFrameFlagFIN,
	}); err != nil {
		t.Fatalf("PushFrame(fin) error: %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReadAll() error: %v", err)
	case payload := <-readCh:
		if string(payload) != "idle-ok" {
			t.Fatalf("payload = %q, want %q", string(payload), "idle-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadAll() did not complete")
	}
}

func TestTrustTunnelMultipathReassemblerBackpressuresUntilGapCloses(t *testing.T) {
	reassembler := newTrustTunnelMultipathFrameReassembler(4, 200*time.Millisecond)
	if err := reassembler.PushFrame(&trustTunnelMultipathFrame{
		Seq:     1,
		Payload: []byte("bbbb"),
	}); err != nil {
		t.Fatalf("PushFrame(seq1) error: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- reassembler.PushFrame(&trustTunnelMultipathFrame{
			Seq:     2,
			Payload: []byte("cccc"),
		})
	}()

	select {
	case err := <-errCh:
		t.Fatalf("PushFrame(seq2) returned too early: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	if err := reassembler.PushFrame(&trustTunnelMultipathFrame{
		Seq:     0,
		Payload: []byte("aaaa"),
	}); err != nil {
		t.Fatalf("PushFrame(seq0) error: %v", err)
	}

	buf := make([]byte, 4)
	if _, err := reassembler.Read(buf); err != nil {
		t.Fatalf("Read(seq0) error: %v", err)
	}
	if _, err := reassembler.Read(buf); err != nil {
		t.Fatalf("Read(seq1) error: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("PushFrame(seq2) error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("PushFrame(seq2) did not unblock after gap closed")
	}
}

func TestTrustTunnelMultipathReassemblerBackpressureRequestsResendBeforeWindowExceeded(t *testing.T) {
	reassembler := newTrustTunnelMultipathFrameReassembler(4, 200*time.Millisecond)
	reassembler.onGap = func(nextSeq uint64) bool {
		if nextSeq != 0 {
			t.Fatalf("onGap(nextSeq) = %d, want 0", nextSeq)
		}
		go func() {
			time.Sleep(5 * time.Millisecond)
			_ = reassembler.PushFrame(&trustTunnelMultipathFrame{
				Seq:     0,
				Payload: []byte("aaaa"),
			})
			buf := make([]byte, 4)
			_, _ = reassembler.Read(buf)
			_, _ = reassembler.Read(buf)
		}()
		return true
	}
	if err := reassembler.PushFrame(&trustTunnelMultipathFrame{
		Seq:     1,
		Payload: []byte("bbbb"),
	}); err != nil {
		t.Fatalf("PushFrame(seq1) error: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- reassembler.PushFrame(&trustTunnelMultipathFrame{
			Seq:     2,
			Payload: []byte("cccc"),
		})
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("PushFrame(seq2) error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("PushFrame(seq2) did not complete after resend request")
	}
}

func TestTrustTunnelMultipathFrameWriterRetransmitFromResendsBufferedFrames(t *testing.T) {
	stream1 := &recordingMultipathStream{}
	stream2 := &recordingMultipathStream{}

	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:          "sess-retransmit",
		Target:      xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:  "1.1.1.1:443",
		MinChannels: 2,
		MaxChannels: 2,
		Strict:      true,
	})
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443", stream: stream1}); err != nil {
		t.Fatalf("AddChannel(channel1) error: %v", err)
	}
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443", stream: stream2}); err != nil {
		t.Fatalf("AddChannel(channel2) error: %v", err)
	}

	writer := newTrustTunnelMultipathFrameWriter(session)
	writer.maxPayload = 5
	if _, err := writer.Write([]byte("alphabeta")); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	writer.Ack(1)

	readFrames := func(data []byte) []*trustTunnelMultipathFrame {
		reader := bytes.NewReader(data)
		frames := make([]*trustTunnelMultipathFrame, 0, 2)
		for reader.Len() > 0 {
			frame, err := trustTunnelReadMultipathFrame(reader)
			if err != nil {
				t.Fatalf("trustTunnelReadMultipathFrame() error: %v", err)
			}
			frames = append(frames, frame)
		}
		return frames
	}

	frames1 := readFrames(stream1.Bytes())
	frames2 := readFrames(stream2.Bytes())
	if len(frames1) != 1 || len(frames2) != 1 {
		t.Fatalf("initial frame counts = (%d, %d), want (1, 1)", len(frames1), len(frames2))
	}
	frame1 := frames1[0]
	frame2 := frames2[0]
	if frame1.Seq != 0 || frame2.Seq != 1 {
		t.Fatalf("initial seqs = (%d, %d), want (0, 1)", frame1.Seq, frame2.Seq)
	}

	if err := writer.RetransmitFrom(1); err != nil {
		t.Fatalf("RetransmitFrom() error: %v", err)
	}

	frames1 = readFrames(stream1.Bytes())
	if len(frames1) != 2 {
		t.Fatalf("stream1 frame count after retransmit = %d, want 2", len(frames1))
	}
	if frames1[1].Seq != 1 {
		t.Fatalf("replayed seq = %d, want 1", frames1[1].Seq)
	}
}

func TestTrustTunnelMultipathFrameWriterSkipsFailedChannelWithinQuorum(t *testing.T) {
	channel2Client, channel2Server := net.Pipe()
	channel3Client, channel3Server := net.Pipe()
	defer channel2Client.Close()
	defer channel2Server.Close()
	defer channel3Client.Close()
	defer channel3Server.Close()

	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:          "sess-writer-failover",
		Target:      xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:  "1.1.1.1:443",
		MinChannels: 2,
		MaxChannels: 3,
		Strict:      true,
	})
	channel1 := &trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443", stream: failingReadWriteCloser{writeErr: io.ErrClosedPipe}}
	channel2 := &trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443", stream: channel2Client}
	channel3 := &trustTunnelMultipathChannel{id: 3, endpoint: "192.168.1.52:9443", stream: channel3Client}
	if err := session.AddChannel(channel1); err != nil {
		t.Fatalf("AddChannel(channel1) error: %v", err)
	}
	if err := session.AddChannel(channel2); err != nil {
		t.Fatalf("AddChannel(channel2) error: %v", err)
	}
	if err := session.AddChannel(channel3); err != nil {
		t.Fatalf("AddChannel(channel3) error: %v", err)
	}

	writer := newTrustTunnelMultipathFrameWriter(session)

	frameCh2 := make(chan *trustTunnelMultipathFrame, 1)
	frameCh3 := make(chan *trustTunnelMultipathFrame, 1)
	go func() {
		for {
			frame, err := trustTunnelReadMultipathFrame(channel2Server)
			if err != nil {
				t.Errorf("channel2 frame read error: %v", err)
				frameCh2 <- nil
				return
			}
			if frame.Flags&trustTunnelMultipathFrameFlagControl != 0 {
				continue
			}
			frameCh2 <- frame
			return
		}
	}()
	go func() {
		for {
			frame, err := trustTunnelReadMultipathFrame(channel3Server)
			if err != nil {
				t.Errorf("channel3 frame read error: %v", err)
				frameCh3 <- nil
				return
			}
			if frame.Flags&trustTunnelMultipathFrameFlagControl != 0 {
				continue
			}
			frameCh3 <- frame
			return
		}
	}()

	if _, err := writer.Write([]byte("alpha")); err != nil {
		t.Fatalf("writer.Write(alpha) error: %v", err)
	}
	if _, err := writer.Write([]byte("beta")); err != nil {
		t.Fatalf("writer.Write(beta) error: %v", err)
	}

	got2 := <-frameCh2
	got3 := <-frameCh3
	if got2 == nil || got3 == nil {
		t.Fatal("expected frames on both surviving channels")
	}
	seqs := map[uint64]bool{
		got2.Seq: true,
		got3.Seq: true,
	}
	if !seqs[0] || !seqs[1] || len(seqs) != 2 {
		t.Fatalf("surviving channels carried seqs {%d,%d}, want {0,1}", got2.Seq, got3.Seq)
	}
	if got := session.ActiveChannelCount(); got != 2 {
		t.Fatalf("ActiveChannelCount() = %d, want 2", got)
	}
	if got := atomic.LoadUint64(&channel2.writeFrames); got != 1 {
		t.Fatalf("channel2.writeFrames = %d, want 1", got)
	}
	if got := atomic.LoadUint64(&channel3.writeFrames); got != 1 {
		t.Fatalf("channel3.writeFrames = %d, want 1", got)
	}
}

func TestTrustTunnelMultipathStreamReportsStrictQuorumLossOnChannelEOF(t *testing.T) {
	channel1Client, channel1Server := net.Pipe()
	channel2Client, channel2Server := net.Pipe()
	defer channel2Server.Close()

	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:            "sess-quorum-loss",
		Target:        xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:    "1.1.1.1:443",
		MinChannels:   2,
		MaxChannels:   2,
		Strict:        true,
		AttachTimeout: 40 * time.Millisecond,
		GapTimeout:    500 * time.Millisecond,
	})
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443", stream: channel1Client}); err != nil {
		t.Fatalf("AddChannel(channel1) error: %v", err)
	}
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443", stream: channel2Client}); err != nil {
		t.Fatalf("AddChannel(channel2) error: %v", err)
	}

	stream, err := newTrustTunnelMultipathStream(session)
	if err != nil {
		t.Fatalf("newTrustTunnelMultipathStream() error: %v", err)
	}
	defer stream.Close()

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 32)
		_, err := stream.Read(buf)
		errCh <- err
	}()

	time.Sleep(30 * time.Millisecond)
	_ = channel1Server.Close()

	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), trustTunnelMultipathChannelQuorumLostText) {
			t.Fatalf("stream.Read() error = %v, want %q", err, trustTunnelMultipathChannelQuorumLostText)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream.Read() did not return after strict quorum loss")
	}
}

func TestTrustTunnelMultipathStreamStartsReaderForRejoinedChannel(t *testing.T) {
	channel1Client, channel1Server := net.Pipe()
	channel2Client, channel2Server := net.Pipe()
	channel3Client, channel3Server := net.Pipe()
	defer channel1Server.Close()
	defer channel2Server.Close()
	defer channel3Server.Close()

	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:            "sess-rejoin-reader",
		Target:        xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:    "1.1.1.1:443",
		MinChannels:   2,
		MaxChannels:   3,
		Strict:        true,
		AttachTimeout: 500 * time.Millisecond,
		GapTimeout:    500 * time.Millisecond,
	})
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443", stream: channel1Client}); err != nil {
		t.Fatalf("AddChannel(channel1) error: %v", err)
	}
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443", stream: channel2Client}); err != nil {
		t.Fatalf("AddChannel(channel2) error: %v", err)
	}

	stream, err := newTrustTunnelMultipathStream(session)
	if err != nil {
		t.Fatalf("newTrustTunnelMultipathStream() error: %v", err)
	}
	defer stream.Close()

	if err := session.HandleChannelFailure(1, io.EOF); err != nil {
		t.Fatalf("HandleChannelFailure() error: %v", err)
	}
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 3, endpoint: "192.168.1.52:9443"}); err != nil {
		t.Fatalf("AddChannel(channel3) error: %v", err)
	}
	if err := session.SetChannelStream(3, channel3Client); err != nil {
		t.Fatalf("SetChannelStream(channel3) error: %v", err)
	}

	go func() {
		_ = trustTunnelWriteMultipathFrame(channel3Server, &trustTunnelMultipathFrame{
			Seq:     0,
			Payload: []byte("hello"),
		})
		_ = trustTunnelWriteMultipathFrame(channel3Server, &trustTunnelMultipathFrame{
			Seq:   1,
			Flags: trustTunnelMultipathFrameFlagFIN,
		})
	}()

	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("payload = %q, want %q", string(got), "hello")
	}
}

func TestTrustTunnelMultipathWriterWaitsForQuorumRestore(t *testing.T) {
	channel1Client, channel1Server := net.Pipe()
	channel2Client, channel2Server := net.Pipe()
	channel3Client, channel3Server := net.Pipe()
	defer channel2Server.Close()
	defer channel3Server.Close()

	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:            "sess-rejoin-writer",
		Target:        xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:    "1.1.1.1:443",
		MinChannels:   2,
		MaxChannels:   3,
		Strict:        true,
		AttachTimeout: 500 * time.Millisecond,
	})
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443", stream: channel1Client}); err != nil {
		t.Fatalf("AddChannel(channel1) error: %v", err)
	}
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443", stream: channel2Client}); err != nil {
		t.Fatalf("AddChannel(channel2) error: %v", err)
	}

	writer := newTrustTunnelMultipathFrameWriter(session)
	_ = channel1Server.Close()

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := writer.Write([]byte("alpha"))
		writeErrCh <- err
	}()

	time.Sleep(40 * time.Millisecond)
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 3, endpoint: "192.168.1.52:9443", stream: channel3Client}); err != nil {
		t.Fatalf("AddChannel(channel3) error: %v", err)
	}

	frameCh := make(chan *trustTunnelMultipathFrame, 1)
	go func() {
		frame, err := trustTunnelReadMultipathFrame(channel3Server)
		if err != nil {
			t.Errorf("trustTunnelReadMultipathFrame(channel3) error: %v", err)
			frameCh <- nil
			return
		}
		frameCh <- frame
	}()

	select {
	case err := <-writeErrCh:
		if err != nil {
			t.Fatalf("writer.Write() error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("writer.Write() did not resume after quorum restore")
	}

	frame := <-frameCh
	if frame == nil {
		t.Fatal("expected frame on rejoined channel")
	}
	if string(frame.Payload) != "alpha" {
		t.Fatalf("payload = %q, want %q", string(frame.Payload), "alpha")
	}
}

func TestTrustTunnelMultipathControlChannelClosedDegradesPeerSession(t *testing.T) {
	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:            "sess-control-close",
		Target:        xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:    "1.1.1.1:443",
		MinChannels:   2,
		MaxChannels:   2,
		Strict:        true,
		AttachTimeout: 500 * time.Millisecond,
	})
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443"}); err != nil {
		t.Fatalf("AddChannel(channel1) error: %v", err)
	}
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443"}); err != nil {
		t.Fatalf("AddChannel(channel2) error: %v", err)
	}

	stream := &trustTunnelMultipathStream{session: session}
	payload := make([]byte, 5)
	payload[0] = trustTunnelMultipathControlChannelClosed
	binary.BigEndian.PutUint32(payload[1:5], 1)

	stop, err := stream.handleControlFrame(&trustTunnelMultipathFrame{
		Flags:   trustTunnelMultipathFrameFlagControl,
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("handleControlFrame() error: %v", err)
	}
	if stop {
		t.Fatal("handleControlFrame() stop = true, want false")
	}

	if got := session.ActiveChannelCount(); got != 1 {
		t.Fatalf("ActiveChannelCount() = %d, want 1", got)
	}
	if got := session.State(); got != trustTunnelMultipathSessionDegraded {
		t.Fatalf("State() = %v, want %v", got, trustTunnelMultipathSessionDegraded)
	}
}

func TestTrustTunnelMultipathSessionCloseNotifiesPeerOnQuorumLoss(t *testing.T) {
	stream1 := &recordingMultipathStream{}
	stream2 := &recordingMultipathStream{}
	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:          "sess-notify-close",
		Target:      xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:  "1.1.1.1:443",
		MinChannels: 2,
		MaxChannels: 2,
		Strict:      true,
	})
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443", stream: stream1}); err != nil {
		t.Fatalf("AddChannel(channel1) error: %v", err)
	}
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443", stream: stream2}); err != nil {
		t.Fatalf("AddChannel(channel2) error: %v", err)
	}

	session.Close(newTrustTunnelMultipathQuorumLostError(1, 2, io.EOF))

	frame1, err := trustTunnelReadMultipathFrame(bytes.NewReader(stream1.Bytes()))
	if err != nil {
		t.Fatalf("trustTunnelReadMultipathFrame(channel1) error: %v", err)
	}
	frame2, err := trustTunnelReadMultipathFrame(bytes.NewReader(stream2.Bytes()))
	if err != nil {
		t.Fatalf("trustTunnelReadMultipathFrame(channel2) error: %v", err)
	}

	for i, frame := range []*trustTunnelMultipathFrame{frame1, frame2} {
		if frame.Flags&trustTunnelMultipathFrameFlagControl == 0 {
			t.Fatalf("frame%d is not control", i+1)
		}
		if len(frame.Payload) != 2 {
			t.Fatalf("frame%d payload len = %d, want 2", i+1, len(frame.Payload))
		}
		if frame.Payload[0] != trustTunnelMultipathControlSessionClosing {
			t.Fatalf("frame%d control type = %d, want %d", i+1, frame.Payload[0], trustTunnelMultipathControlSessionClosing)
		}
		if frame.Payload[1] != trustTunnelMultipathControlCloseReasonQuorumLost {
			t.Fatalf("frame%d close reason = %d, want %d", i+1, frame.Payload[1], trustTunnelMultipathControlCloseReasonQuorumLost)
		}
	}
}

func TestTrustTunnelMultipathControlSessionClosingSurfacesPeerMarker(t *testing.T) {
	channel1Client, channel1Server := net.Pipe()
	channel2Client, channel2Server := net.Pipe()
	defer channel1Server.Close()
	defer channel2Server.Close()

	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:            "sess-peer-close",
		Target:        xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:    "1.1.1.1:443",
		MinChannels:   2,
		MaxChannels:   2,
		Strict:        true,
		AttachTimeout: 500 * time.Millisecond,
	})
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443", stream: channel1Client}); err != nil {
		t.Fatalf("AddChannel(channel1) error: %v", err)
	}
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443", stream: channel2Client}); err != nil {
		t.Fatalf("AddChannel(channel2) error: %v", err)
	}

	stream, err := newTrustTunnelMultipathStream(session)
	if err != nil {
		t.Fatalf("newTrustTunnelMultipathStream() error: %v", err)
	}
	defer stream.Close()

	go func() {
		_ = trustTunnelWriteMultipathFrame(channel1Server, trustTunnelMultipathSessionClosingControlFrame(trustTunnelMultipathControlCloseReasonQuorumLost))
	}()

	buf := make([]byte, 32)
	_, err = stream.Read(buf)
	if err == nil || !strings.Contains(err.Error(), trustTunnelMultipathChannelQuorumLostText) {
		t.Fatalf("stream.Read() error = %v, want %q", err, trustTunnelMultipathChannelQuorumLostText)
	}
	if !session.IsClosed() {
		t.Fatal("session.IsClosed() = false, want true")
	}
}

func TestTrustTunnelMultipathSessionCloseSendsNormalPeerClose(t *testing.T) {
	stream1 := &recordingMultipathStream{}
	stream2 := &recordingMultipathStream{}

	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:          "sess-normal-close",
		Target:      xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:  "1.1.1.1:443",
		MinChannels: 2,
		MaxChannels: 2,
		Strict:      true,
	})
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443", stream: stream1}); err != nil {
		t.Fatalf("AddChannel(channel1) error: %v", err)
	}
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443", stream: stream2}); err != nil {
		t.Fatalf("AddChannel(channel2) error: %v", err)
	}

	session.Close(nil)

	frame1, err := trustTunnelReadMultipathFrame(bytes.NewReader(stream1.Bytes()))
	if err != nil {
		t.Fatalf("trustTunnelReadMultipathFrame(channel1) error: %v", err)
	}
	frame2, err := trustTunnelReadMultipathFrame(bytes.NewReader(stream2.Bytes()))
	if err != nil {
		t.Fatalf("trustTunnelReadMultipathFrame(channel2) error: %v", err)
	}

	for i, frame := range []*trustTunnelMultipathFrame{frame1, frame2} {
		if frame.Flags&trustTunnelMultipathFrameFlagControl == 0 {
			t.Fatalf("frame%d is not control", i+1)
		}
		if len(frame.Payload) != 2 {
			t.Fatalf("frame%d payload len = %d, want 2", i+1, len(frame.Payload))
		}
		if frame.Payload[0] != trustTunnelMultipathControlSessionClosing {
			t.Fatalf("frame%d control type = %d, want %d", i+1, frame.Payload[0], trustTunnelMultipathControlSessionClosing)
		}
		if frame.Payload[1] != trustTunnelMultipathControlCloseReasonNormal {
			t.Fatalf("frame%d close reason = %d, want %d", i+1, frame.Payload[1], trustTunnelMultipathControlCloseReasonNormal)
		}
	}
}

func TestTrustTunnelMultipathControlSessionClosingNormalEndsWithEOF(t *testing.T) {
	channel1Client, channel1Server := net.Pipe()
	channel2Client, channel2Server := net.Pipe()
	defer channel1Server.Close()
	defer channel2Server.Close()

	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:            "sess-peer-close-normal",
		Target:        xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:    "1.1.1.1:443",
		MinChannels:   2,
		MaxChannels:   2,
		Strict:        true,
		AttachTimeout: 500 * time.Millisecond,
	})
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443", stream: channel1Client}); err != nil {
		t.Fatalf("AddChannel(channel1) error: %v", err)
	}
	if err := session.AddChannel(&trustTunnelMultipathChannel{id: 2, endpoint: "192.168.1.51:9443", stream: channel2Client}); err != nil {
		t.Fatalf("AddChannel(channel2) error: %v", err)
	}

	stream, err := newTrustTunnelMultipathStream(session)
	if err != nil {
		t.Fatalf("newTrustTunnelMultipathStream() error: %v", err)
	}
	defer stream.Close()

	go func() {
		_ = trustTunnelWriteMultipathFrame(channel1Server, trustTunnelMultipathSessionClosingControlFrame(trustTunnelMultipathControlCloseReasonNormal))
	}()

	buf := make([]byte, 32)
	_, err = stream.Read(buf)
	if err != io.EOF {
		t.Fatalf("stream.Read() error = %v, want EOF", err)
	}
	if !session.IsClosed() {
		t.Fatal("session.IsClosed() = false, want true")
	}
	if closeErr := session.CloseErr(); closeErr != io.EOF {
		t.Fatalf("session.CloseErr() = %v, want EOF", closeErr)
	}
}

type failingReadWriteCloser struct {
	writeErr error
}

func (failingReadWriteCloser) Read([]byte) (int, error) { return 0, io.EOF }
func (f failingReadWriteCloser) Write([]byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return 0, io.EOF
}
func (failingReadWriteCloser) Close() error { return nil }

type reassemblerReader struct {
	reassembler *trustTunnelMultipathFrameReassembler
}

func (r reassemblerReader) Read(p []byte) (int, error) {
	if r.reassembler == nil {
		return 0, io.EOF
	}
	return r.reassembler.Read(p)
}

type recordingMultipathStream struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
}

func (r *recordingMultipathStream) Read([]byte) (int, error) { return 0, io.EOF }

func (r *recordingMultipathStream) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, io.ErrClosedPipe
	}
	return r.buf.Write(p)
}

func (r *recordingMultipathStream) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func (r *recordingMultipathStream) Bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf.Bytes()...)
}
