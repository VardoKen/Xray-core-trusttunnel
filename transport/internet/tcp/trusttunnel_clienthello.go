package tcp

import (
	"encoding/hex"
	stderrors "errors"
	"io"

	"github.com/xtls/xray-core/common/net"
)

const (
	tlsRecordTypeHandshake      = 22
	tlsHandshakeTypeClientHello = 1
	tlsRecordHeaderLen          = 5
	tlsHandshakeHeaderLen       = 4
	tlsClientHelloFixedPartLen  = 34
)

var errNotTLSClientHello = stderrors.New("not a tls client hello")

type trustTunnelClientRandomConn struct {
	net.Conn
	prefix       []byte
	clientRandom string
}

func (c *trustTunnelClientRandomConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *trustTunnelClientRandomConn) TrustTunnelClientRandom() string {
	return c.clientRandom
}

func wrapTrustTunnelClientRandomConn(conn net.Conn) net.Conn {
	wrapped, _, _ := readTrustTunnelClientHello(conn)
	return wrapped
}

func readTrustTunnelClientHello(conn net.Conn) (*trustTunnelClientRandomConn, string, error) {
	recordHeader, err := readExact(conn, tlsRecordHeaderLen)
	prefix := append([]byte{}, recordHeader...)
	if err != nil {
		return &trustTunnelClientRandomConn{Conn: conn, prefix: prefix}, "", err
	}

	if len(recordHeader) != tlsRecordHeaderLen || recordHeader[0] != tlsRecordTypeHandshake {
		return &trustTunnelClientRandomConn{Conn: conn, prefix: prefix}, "", errNotTLSClientHello
	}

	recordLen := int(recordHeader[3])<<8 | int(recordHeader[4])

	recordBody, err := readExact(conn, recordLen)
	prefix = append(prefix, recordBody...)
	if err != nil {
		return &trustTunnelClientRandomConn{Conn: conn, prefix: prefix}, "", err
	}

	if len(recordBody) < tlsHandshakeHeaderLen || recordBody[0] != tlsHandshakeTypeClientHello {
		return &trustTunnelClientRandomConn{Conn: conn, prefix: prefix}, "", errNotTLSClientHello
	}

	handshakeLen := int(recordBody[1])<<16 | int(recordBody[2])<<8 | int(recordBody[3])
	handshakeBody := append([]byte{}, recordBody[tlsHandshakeHeaderLen:]...)

	for len(handshakeBody) < handshakeLen {
		nextHeader, err := readExact(conn, tlsRecordHeaderLen)
		prefix = append(prefix, nextHeader...)
		if err != nil {
			return &trustTunnelClientRandomConn{Conn: conn, prefix: prefix}, "", err
		}
		if len(nextHeader) != tlsRecordHeaderLen || nextHeader[0] != tlsRecordTypeHandshake {
			return &trustTunnelClientRandomConn{Conn: conn, prefix: prefix}, "", errNotTLSClientHello
		}

		nextLen := int(nextHeader[3])<<8 | int(nextHeader[4])

		nextBody, err := readExact(conn, nextLen)
		prefix = append(prefix, nextBody...)
		if err != nil {
			return &trustTunnelClientRandomConn{Conn: conn, prefix: prefix}, "", err
		}

		handshakeBody = append(handshakeBody, nextBody...)
	}

	if len(handshakeBody) < tlsClientHelloFixedPartLen {
		return &trustTunnelClientRandomConn{Conn: conn, prefix: prefix}, "", io.ErrUnexpectedEOF
	}

	clientRandom := hex.EncodeToString(handshakeBody[2:34])

	return &trustTunnelClientRandomConn{
		Conn:         conn,
		prefix:       prefix,
		clientRandom: clientRandom,
	}, clientRandom, nil
}

func readExact(r io.Reader, size int) ([]byte, error) {
	buf := make([]byte, size)
	offset := 0

	for offset < size {
		n, err := r.Read(buf[offset:])
		if n > 0 {
			offset += n
		}
		if err != nil {
			return buf[:offset], err
		}
		if n == 0 {
			return buf[:offset], io.ErrNoProgress
		}
	}

	return buf, nil
}
