package tls

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

const (
	antiDPIKey                        = "tls.anti_dpi"
	antiDPIClientHelloSplitSize       = 1
	antiDPIClientHelloSplitDelay      = 25 * time.Millisecond
	tlsHandshakeRecordType       byte = 0x16
	tlsClientHelloType           byte = 0x01
)

type antiDPIConn struct {
	net.Conn
	once sync.Once
}

func ContextWithAntiDPI(ctx context.Context) context.Context {
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = &session.Content{}
		ctx = session.ContextWithContent(ctx, content)
	}
	content.SetAttribute(antiDPIKey, "1")
	return ctx
}

func AntiDPIEnabledFromContext(ctx context.Context) bool {
	content := session.ContentFromContext(ctx)
	if content == nil {
		return false
	}
	return content.Attribute(antiDPIKey) == "1"
}

func WrapConnWithAntiDPI(conn net.Conn) net.Conn {
	if conn == nil {
		return nil
	}
	if _, ok := conn.(*antiDPIConn); ok {
		return conn
	}
	if noDelay, ok := conn.(interface{ SetNoDelay(bool) error }); ok {
		_ = noDelay.SetNoDelay(true)
	}
	return &antiDPIConn{Conn: conn}
}

func (c *antiDPIConn) Write(p []byte) (int, error) {
	if len(p) == 0 || !isTLSClientHelloRecord(p) {
		return c.Conn.Write(p)
	}

	split := false
	c.once.Do(func() {
		split = true
	})
	if !split {
		return c.Conn.Write(p)
	}

	n, err := c.Conn.Write(p[:antiDPIClientHelloSplitSize])
	if err != nil {
		return n, err
	}
	if n != antiDPIClientHelloSplitSize {
		return n, io.ErrShortWrite
	}

	time.Sleep(antiDPIClientHelloSplitDelay)

	m, err := c.Conn.Write(p[antiDPIClientHelloSplitSize:])
	return n + m, err
}

func isTLSClientHelloRecord(p []byte) bool {
	if len(p) <= antiDPIClientHelloSplitSize+4 {
		return false
	}
	return p[0] == tlsHandshakeRecordType && p[5] == tlsClientHelloType
}
