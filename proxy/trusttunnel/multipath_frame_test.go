package trusttunnel

import (
	"bytes"
	"io"
	"net"
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
