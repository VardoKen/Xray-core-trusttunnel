package tls

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestBuildClientHelloRandomPrefix(t *testing.T) {
	base := bytes.NewReader(bytes.Repeat([]byte{0xaa}, clientHelloRandomLen))

	random, err := BuildClientHelloRandom("deadbeef", base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := len(random), clientHelloRandomLen; got != want {
		t.Fatalf("unexpected random length: got %d, want %d", got, want)
	}
	if got, want := random[:4], []byte{0xde, 0xad, 0xbe, 0xef}; !bytes.Equal(got, want) {
		t.Fatalf("unexpected prefix: got %x, want %x", got, want)
	}
	if got, want := random[4:], bytes.Repeat([]byte{0xaa}, clientHelloRandomLen-4); !bytes.Equal(got, want) {
		t.Fatalf("unexpected tail: got %x, want %x", got, want)
	}
}

func TestBuildClientHelloRandomMask(t *testing.T) {
	base := bytes.NewReader(bytes.Repeat([]byte{0x55}, clientHelloRandomLen))

	random, err := BuildClientHelloRandom("d0adbeef/f0ffffff", base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := random[:4], []byte{0xd5, 0xad, 0xbe, 0xef}; !bytes.Equal(got, want) {
		t.Fatalf("unexpected masked prefix: got %x, want %x", got, want)
	}
	if got, want := random[4:], bytes.Repeat([]byte{0x55}, clientHelloRandomLen-4); !bytes.Equal(got, want) {
		t.Fatalf("unexpected tail: got %x, want %x", got, want)
	}
}

func TestNewClientHelloRandomReader(t *testing.T) {
	base := bytes.NewReader(bytes.Repeat([]byte{0x11}, clientHelloRandomLen*2))

	reader, err := NewClientHelloRandomReader("deadbeef", base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	buf := make([]byte, clientHelloRandomLen+5)
	n, err := io.ReadFull(reader, buf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if got, want := n, len(buf); got != want {
		t.Fatalf("unexpected read size: got %d, want %d", got, want)
	}
	if got, want := buf[:4], []byte{0xde, 0xad, 0xbe, 0xef}; !bytes.Equal(got, want) {
		t.Fatalf("unexpected prefix: got %x, want %x", got, want)
	}
	if got, want := buf[4:clientHelloRandomLen], bytes.Repeat([]byte{0x11}, clientHelloRandomLen-4); !bytes.Equal(got, want) {
		t.Fatalf("unexpected random tail: got %x, want %x", got, want)
	}
	if got, want := buf[clientHelloRandomLen:], bytes.Repeat([]byte{0x11}, 5); !bytes.Equal(got, want) {
		t.Fatalf("unexpected subsequent bytes: got %x, want %x", got, want)
	}
}

func TestClientHelloRandomSpecContext(t *testing.T) {
	ctx := ContextWithClientHelloRandomSpec(context.Background(), " DE AD BE EF ")

	if got, want := ClientHelloRandomSpecFromContext(ctx), "deadbeef"; got != want {
		t.Fatalf("unexpected spec from context: got %q, want %q", got, want)
	}
}

func TestBuildClientHelloRandomRejectsInvalidMaskLength(t *testing.T) {
	if _, err := BuildClientHelloRandom("deadbeef/ff", bytes.NewReader(bytes.Repeat([]byte{0x00}, clientHelloRandomLen))); err == nil {
		t.Fatal("expected error for invalid mask length")
	}
}
