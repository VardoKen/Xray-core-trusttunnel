package tcp

import (
	stderrors "errors"
	"io"
	"net/http"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common/net"
)

type HTTP3RequestConn interface {
	net.Conn
	http.ResponseWriter
	http.Flusher
	H3Method() string
	H3Host() string
	H3Header() http.Header
	H3ClientRandom() string
}

type http3RequestConn struct {
	body         io.ReadCloser
	rw           http.ResponseWriter
	method       string
	host         string
	header       http.Header
	clientRandom string
	remote       net.Addr
	local        net.Addr
}

func newHTTP3RequestConn(req *http.Request, rw http.ResponseWriter, remote net.Addr, local net.Addr, clientRandom string) *http3RequestConn {
	header := make(http.Header, len(req.Header))
	for k, v := range req.Header {
		header[k] = append([]string(nil), v...)
	}

	return &http3RequestConn{
		body:         req.Body,
		rw:           rw,
		method:       req.Method,
		host:         req.Host,
		header:       header,
		clientRandom: clientRandom,
		remote:       remote,
		local:        local,
	}
}

func (c *http3RequestConn) H3Method() string {
	return c.method
}

func (c *http3RequestConn) H3Host() string {
	return c.host
}

func (c *http3RequestConn) H3Header() http.Header {
	return c.header.Clone()
}

func (c *http3RequestConn) H3ClientRandom() string {
	return c.clientRandom
}

func isHTTP3NoError(err error) bool {
	if err == nil {
		return false
	}

	var h3Err *http3.Error
	if stderrors.As(err, &h3Err) && h3Err.ErrorCode == http3.ErrCodeNoError {
		return true
	}

	var appErr *quic.ApplicationError
	if stderrors.As(err, &appErr) && appErr.ErrorCode == quic.ApplicationErrorCode(http3.ErrCodeNoError) {
		return true
	}

	var streamErr *quic.StreamError
	if stderrors.As(err, &streamErr) && streamErr.ErrorCode == quic.StreamErrorCode(http3.ErrCodeNoError) {
		return true
	}

	return false
}

func (c *http3RequestConn) Read(p []byte) (int, error) {
	if c.body == nil {
		return 0, io.EOF
	}

	n, err := c.body.Read(p)
	if isHTTP3NoError(err) {
		return n, io.EOF
	}

	return n, err
}

func (c *http3RequestConn) Write(p []byte) (int, error) {
	return c.rw.Write(p)
}

func (c *http3RequestConn) Close() error {
	if c.body != nil {
		return c.body.Close()
	}
	return nil
}

func (c *http3RequestConn) LocalAddr() net.Addr {
	return c.local
}

func (c *http3RequestConn) RemoteAddr() net.Addr {
	return c.remote
}

func (*http3RequestConn) SetDeadline(time.Time) error {
	return nil
}

func (*http3RequestConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*http3RequestConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *http3RequestConn) Header() http.Header {
	return c.rw.Header()
}

func (c *http3RequestConn) WriteHeader(statusCode int) {
	c.rw.WriteHeader(statusCode)
}

func (c *http3RequestConn) Flush() {
	if f, ok := c.rw.(http.Flusher); ok {
		f.Flush()
	}
}
