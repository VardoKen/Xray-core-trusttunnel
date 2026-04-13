package trusttunnel

import (
	"bytes"
	"io"
	"net"
	"strings"
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

func TestTrustTunnelMultipathFrameWriterSkipsFailedChannelWithinQuorum(t *testing.T) {
	channel1Client, channel1Server := net.Pipe()
	channel2Client, channel2Server := net.Pipe()
	channel3Client, channel3Server := net.Pipe()
	defer channel2Server.Close()
	defer channel3Server.Close()

	session := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:          "sess-writer-failover",
		Target:      xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:  "1.1.1.1:443",
		MinChannels: 2,
		MaxChannels: 3,
		Strict:      true,
	})
	channel1 := &trustTunnelMultipathChannel{id: 1, endpoint: "192.168.1.50:9443", stream: channel1Client}
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
	_ = channel1Server.Close()

	frameCh2 := make(chan *trustTunnelMultipathFrame, 1)
	frameCh3 := make(chan *trustTunnelMultipathFrame, 1)
	go func() {
		frame, err := trustTunnelReadMultipathFrame(channel2Server)
		if err != nil {
			t.Errorf("channel2 frame read error: %v", err)
			frameCh2 <- nil
			return
		}
		frameCh2 <- frame
	}()
	go func() {
		frame, err := trustTunnelReadMultipathFrame(channel3Server)
		if err != nil {
			t.Errorf("channel3 frame read error: %v", err)
			frameCh3 <- nil
			return
		}
		frameCh3 <- frame
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
		ID:          "sess-quorum-loss",
		Target:      xnet.TCPDestination(xnet.ParseAddress("1.1.1.1"), xnet.Port(443)),
		TargetHost:  "1.1.1.1:443",
		MinChannels: 2,
		MaxChannels: 2,
		Strict:      true,
		GapTimeout:  500 * time.Millisecond,
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
