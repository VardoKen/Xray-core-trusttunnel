package tls

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"strings"

	"github.com/xtls/xray-core/common/session"
)

const (
	clientHelloRandomLen = 32
	clientHelloRandomKey = "tls.client_hello_random_spec"
)

type clientHelloRandomReader struct {
	base   io.Reader
	random []byte
	offset int
}

func ContextWithClientHelloRandomSpec(ctx context.Context, spec string) context.Context {
	spec = normalizeClientHelloRandomHex(spec)
	if spec == "" {
		return ctx
	}

	content := session.ContentFromContext(ctx)
	if content == nil {
		content = &session.Content{}
		ctx = session.ContextWithContent(ctx, content)
	}
	content.SetAttribute(clientHelloRandomKey, spec)
	return ctx
}

func ClientHelloRandomSpecFromContext(ctx context.Context) string {
	content := session.ContentFromContext(ctx)
	if content == nil {
		return ""
	}

	return normalizeClientHelloRandomHex(content.Attribute(clientHelloRandomKey))
}

func BuildClientHelloRandom(spec string, base io.Reader) ([]byte, error) {
	spec = normalizeClientHelloRandomHex(spec)
	if spec == "" {
		return nil, nil
	}

	if base == nil {
		base = rand.Reader
	}

	random := make([]byte, clientHelloRandomLen)
	if _, err := io.ReadFull(base, random); err != nil {
		return nil, err
	}

	parts := strings.SplitN(spec, "/", 2)

	prefix, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	if len(prefix) == 0 || len(prefix) > clientHelloRandomLen {
		return nil, io.ErrUnexpectedEOF
	}

	if len(parts) == 1 {
		copy(random, prefix)
		return random, nil
	}

	mask, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	if len(mask) != len(prefix) {
		return nil, io.ErrUnexpectedEOF
	}

	for i := range prefix {
		random[i] = (random[i] &^ mask[i]) | (prefix[i] & mask[i])
	}

	return random, nil
}

func NewClientHelloRandomReader(spec string, base io.Reader) (io.Reader, error) {
	random, err := BuildClientHelloRandom(spec, base)
	if err != nil || len(random) == 0 {
		return nil, err
	}

	if base == nil {
		base = rand.Reader
	}

	return &clientHelloRandomReader{
		base:   base,
		random: random,
	}, nil
}

func (r *clientHelloRandomReader) Read(p []byte) (int, error) {
	if len(r.random) == 0 {
		return r.base.Read(p)
	}

	n := copy(p, r.random[r.offset:])
	r.offset += n
	if r.offset >= len(r.random) {
		r.random = nil
		r.offset = 0
	}

	if n == len(p) {
		return n, nil
	}

	m, err := r.base.Read(p[n:])
	return n + m, err
}

func normalizeClientHelloRandomHex(spec string) string {
	spec = strings.ToLower(strings.TrimSpace(spec))
	spec = strings.ReplaceAll(spec, " ", "")
	spec = strings.ReplaceAll(spec, "\t", "")
	spec = strings.ReplaceAll(spec, "\n", "")
	spec = strings.ReplaceAll(spec, "\r", "")
	return spec
}
